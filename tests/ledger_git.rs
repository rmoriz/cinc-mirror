//! Advisory ledger lease and the push side of the ledger branch.
//!
//! The lease lives on its own ref so a heartbeat never touches an event file.
//! These tests drive a real bare repository over `file://`, including a racing
//! writer installed as a `pre-receive` hook, because the interesting behaviour
//! is exactly what happens when two processes disagree about the remote.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::Duration;

use chrono::{DateTime, Utc};
use cinc_mirror::ledger::git::LEASE_REF;
use cinc_mirror::ledger::{Event, EventKind, Lease, LeaseError, LedgerGitError, LedgerStore};
use serde_json::{json, Value};

const BRANCH: &str = "ledger";
const LEASE_TTL: Duration = Duration::from_secs(600);

fn require_git() {
    match Command::new("git").arg("--version").output() {
        Ok(output) if output.status.success() => {}
        Ok(output) => panic!(
            "git is required for the ledger tests but `git --version` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(error) => panic!("git is required for the ledger tests but could not run: {error}"),
    }
}

fn git(dir: &Path, args: &[&str]) -> String {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args(args)
        .output()
        .expect("run git");
    assert!(
        output.status.success(),
        "git {args:?} failed in {}: {}",
        dir.display(),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

fn commit(workdir: &Path, message: &str) {
    let output = Command::new("git")
        .arg("-C")
        .arg(workdir)
        .args([
            "-c",
            "user.name=test",
            "-c",
            "user.email=test@localhost",
            "commit",
            "-m",
            message,
        ])
        .output()
        .expect("run git commit");
    assert!(
        output.status.success(),
        "git commit failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
}

fn install_hook(hooks: &Path, name: &str, script: &str) {
    fs::create_dir_all(hooks).expect("hooks directory");
    let path = hooks.join(name);
    fs::write(&path, script).expect("write hook");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(&path).expect("hook metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&path, permissions).expect("make hook executable");
    }
}

/// A temporary bare repository plus the state directories of the stores.
struct Fixture {
    root: tempfile::TempDir,
    remote: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        require_git();
        let root = tempfile::tempdir().expect("temporary root");
        let remote = root.path().join("remote.git");
        let output = Command::new("git")
            .args(["init", "--bare", "--quiet"])
            .arg(&remote)
            .output()
            .expect("run git init --bare");
        assert!(
            output.status.success(),
            "git init --bare failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        Self { root, remote }
    }

    fn state(&self, name: &str) -> PathBuf {
        self.root.path().join(name)
    }

    fn url(&self) -> String {
        format!("file://{}", self.remote.display())
    }

    fn store(&self, name: &str) -> LedgerStore {
        LedgerStore::new(
            self.state(name).join("ledger-repo"),
            self.url(),
            BRANCH.to_string(),
        )
    }

    fn workdir(&self, name: &str) -> PathBuf {
        self.state(name).join("ledger-repo")
    }

    /// The lease blob on the remote, if the lease ref exists.
    fn remote_lease(&self) -> Option<Value> {
        let output = Command::new("git")
            .arg("-C")
            .arg(&self.remote)
            .args(["show", &format!("{LEASE_REF}:lease.json")])
            .output()
            .expect("run git show");
        if !output.status.success() {
            return None;
        }
        Some(serde_json::from_slice(&output.stdout).expect("parse the lease json"))
    }

    fn lease_oid(&self) -> Option<String> {
        let output = Command::new("git")
            .args(["ls-remote", "--heads"])
            .arg(&self.remote)
            .arg(LEASE_REF)
            .output()
            .expect("run git ls-remote");
        assert!(output.status.success(), "git ls-remote failed");
        String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .next()
            .map(ToString::to_string)
    }
}

fn event(run_id: &str) -> Event {
    Event::new(
        run_id,
        1,
        DateTime::<Utc>::from_timestamp(1_800_000_000, 0).expect("valid timestamp"),
        EventKind::RunStarted,
    )
    .with_detail(json!({"summary": run_id}))
}

#[test]
fn lease_blocks_second_live_holder() {
    let fixture = Fixture::new();
    let first = fixture.store("first");
    first.sync().expect("bootstrap the ledger branch");

    let lease = Lease::acquire(&first, "run-a", LEASE_TTL)
        .expect("acquire")
        .expect("the first holder gets the lease");
    assert_eq!(lease.holder().run_id, "run-a");
    assert!(lease.holder().expires_at > Utc::now());
    assert!(fixture.lease_oid().is_some(), "the lease is on its own ref");
    assert!(
        fixture.remote_lease().is_some(),
        "acquiring clones the ledger branch on demand"
    );

    let second = fixture.store("second");
    match Lease::acquire(&second, "run-b", LEASE_TTL) {
        Err(LeaseError::Busy { holder }) => {
            assert_eq!(holder.run_id, "run-a");
            assert!(holder.expires_at > Utc::now());
        }
        other => panic!("expected Busy, got {other:?}"),
    }

    lease.release().expect("release");
    let lease = Lease::acquire(&second, "run-b", LEASE_TTL)
        .expect("acquire after release")
        .expect("the lease is free again");
    assert_eq!(lease.holder().run_id, "run-b");
    lease.release().expect("release again");
}

#[test]
fn expired_lease_is_stolen_and_logged() {
    let fixture = Fixture::new();
    let first = fixture.store("first");
    first.sync().expect("bootstrap the ledger branch");

    let stale = Lease::acquire(&first, "run-a", Duration::from_millis(1))
        .expect("acquire")
        .expect("the first holder gets the lease");
    thread::sleep(Duration::from_millis(20));

    let second = fixture.store("second");
    let mut lease = Lease::acquire(&second, "run-b", LEASE_TTL)
        .expect("acquire")
        .expect("an expired lease is stolen");
    assert_eq!(lease.holder().run_id, "run-b");
    assert_eq!(
        lease.taken_over().map(|holder| holder.run_id.as_str()),
        Some("run-a"),
        "the takeover names the previous holder"
    );

    let takeover = lease
        .takeover_event(1)
        .expect("a takeover is recorded as an event");
    assert_eq!(takeover.kind, EventKind::LeaseTakenOver);
    assert_eq!(takeover.run_id, "run-b");
    assert_eq!(takeover.detail["previous_run_id"], "run-a");

    let remote = fixture.remote_lease().expect("lease on the remote");
    assert_eq!(remote["run_id"], "run-b");

    // Releasing the stale holder must not delete the new holder's lease.
    stale.release().expect("best-effort release");
    assert_eq!(
        fixture
            .remote_lease()
            .expect("the thief's lease survives")
            .get("run_id")
            .and_then(Value::as_str),
        Some("run-b")
    );

    assert!(lease.refresh().expect("refresh"));
    lease.release().expect("release");
    assert!(fixture.lease_oid().is_none(), "release deletes the ref");
}

#[test]
fn lease_push_race_returns_busy() {
    let fixture = Fixture::new();
    let first = fixture.store("first");
    first.sync().expect("bootstrap the ledger branch");

    // A competitor wins the lease between our read and our push: the push is
    // rejected and the re-read must see the competitor instead of retrying.
    let racer = format!(
        r#"#!/bin/sh
set -e
blob=$(printf '%s' '{{"run_id":"racer","host":"racer","pid":1,"acquired_at":"2026-11-25T00:00:00Z","expires_at":"2099-01-01T00:00:00Z","note":""}}' | git --git-dir="{remote}" hash-object -w --stdin)
tree=$(printf '100644 blob %s\tlease.json\n' "$blob" | git --git-dir="{remote}" mktree)
commit=$(git --git-dir="{remote}" -c user.name=racer -c user.email=racer@localhost commit-tree "$tree" -m racer)
git --git-dir="{remote}" update-ref refs/heads/ledger-lease "$commit"
echo "the lease was taken by a racer" >&2
exit 1
"#,
        remote = fixture.remote.display()
    );

    let second = fixture.store("second");
    second.sync().expect("clone the ledger branch");
    install_hook(
        &fixture.workdir("second").join(".git/hooks"),
        "pre-push",
        &racer,
    );

    match Lease::acquire(&second, "run-b", LEASE_TTL) {
        Err(LeaseError::Busy { holder }) => {
            assert_eq!(
                holder.run_id, "racer",
                "the rejected push re-reads the ref and sees the racer"
            );
        }
        other => panic!("expected Busy, got {other:?}"),
    }
    assert_eq!(
        fixture.remote_lease().expect("racer lease")["run_id"],
        "racer"
    );
}

#[test]
fn refresh_extends_the_lease_and_failures_only_warn() {
    let fixture = Fixture::new();
    let store = fixture.store("first");
    store.sync().expect("bootstrap the ledger branch");

    let mut lease = Lease::acquire(&store, "run-a", Duration::from_millis(300))
        .expect("acquire")
        .expect("lease granted");
    let acquired = lease.holder().expires_at;
    thread::sleep(Duration::from_millis(10));
    assert!(
        lease.refresh().expect("refresh"),
        "refresh rewrites the lease"
    );

    let refreshed = lease.holder().expires_at;
    assert!(refreshed > acquired, "refresh moves the expiry forward");
    assert!(refreshed > Utc::now());
    let remote = fixture.remote_lease().expect("lease on the remote");
    let remote_expiry = DateTime::parse_from_rfc3339(
        remote["expires_at"]
            .as_str()
            .expect("expires_at is a string"),
    )
    .expect("parse expires_at")
    .with_timezone(&Utc);
    assert_eq!(remote_expiry, refreshed);

    // An unreachable remote is a warning: the run keeps going unleased.
    fs::remove_dir_all(&fixture.remote).expect("remove the remote");
    assert!(!lease.refresh().expect("refresh never fails the run"));
    lease.release().expect("release is best effort");
}

#[test]
fn release_deletes_the_lease_ref() {
    let fixture = Fixture::new();
    let store = fixture.store("first");
    store.sync().expect("bootstrap the ledger branch");

    let lease = Lease::acquire(&store, "run-a", LEASE_TTL)
        .expect("acquire")
        .expect("lease granted");
    assert!(fixture.lease_oid().is_some());

    lease.release().expect("release");
    assert!(fixture.lease_oid().is_none());
    assert!(
        fixture.remote_lease().is_none(),
        "the blob is gone with the ref"
    );
}

#[test]
fn push_rejection_pulls_and_retries() {
    let fixture = Fixture::new();
    let first = fixture.store("first");
    first.sync().expect("bootstrap the ledger branch");
    let second = fixture.store("second");
    second.sync().expect("clone the ledger branch");

    // The second writer commits locally but does not push yet.
    let path = second
        .write_run(&[event("run-second")])
        .expect("write the run");
    git(&fixture.workdir("second"), &["add", "-A"]);
    commit(&fixture.workdir("second"), "run second");

    // A third writer wins the race and advances the branch first.
    let third = fixture.store("third");
    third.sync().expect("clone the ledger branch");
    let third_path = third
        .write_run(&[event("run-third")])
        .expect("write the run");
    third
        .commit_and_push(&third_path, "run third")
        .expect("push the third run");

    // The second push is rejected, rebased onto the third run and retried.
    second
        .commit_and_push(&path, "run second")
        .expect("retry the rejected push");
    let workdir = fixture.workdir("second");
    assert!(workdir.join("runs/run-second.ndjson").is_file());
    assert!(
        workdir.join("runs/run-third.ndjson").is_file(),
        "the rebase brought the competing run"
    );
    assert_eq!(git(&workdir, &["status", "--porcelain"]), "");

    let tracked = git(
        &fixture.remote,
        &["ls-tree", "--name-only", "refs/heads/ledger", "runs/"],
    );
    assert!(tracked.contains("run-second.ndjson"), "tracked: {tracked}");
    assert!(tracked.contains("run-third.ndjson"), "tracked: {tracked}");
}

#[test]
fn persistent_push_rejection_is_reported_after_three_attempts() {
    const REJECT: &str = r#"#!/bin/sh
while read -r old new ref; do
  if [ "$ref" = "refs/heads/ledger" ]; then
    echo "ledger pushes are rejected here" >&2
    exit 1
  fi
done
exit 0
"#;

    let fixture = Fixture::new();
    let store = fixture.store("first");
    store.sync().expect("bootstrap the ledger branch");
    install_hook(&fixture.remote.join("hooks"), "pre-receive", REJECT);

    let path = store.write_run(&[event("run-a")]).expect("write the run");
    match store.commit_and_push(&path, "run a") {
        Err(LedgerGitError::PushRejected { attempts, .. }) => assert_eq!(attempts, 3),
        other => panic!("expected PushRejected, got {other:?}"),
    }
}
