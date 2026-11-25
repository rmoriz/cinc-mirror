//! Ledger segment files: NDJSON committed to the ledger branch.
//!
//! Every test runs against a real bare repository reached over a `file://` URL,
//! so the fixtures behave like the remote a run pushes to: clone, commit, push,
//! fetch. Git is a hard requirement here; a host without it fails loudly instead
//! of skipping the durability checks.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::{DateTime, Duration, TimeZone, Utc};
use cinc_mirror::artifact::Artifact;
use cinc_mirror::ledger::{
    Event, EventKind, Ledger, LedgerFilesError, LedgerGitError, LedgerStore,
};
use serde_json::{json, Value};

const BRANCH: &str = "ledger";

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

    fn head(&self) -> String {
        git(&self.remote, &["rev-parse", "refs/heads/ledger"])
    }
}

fn commit(dir: &Path, message: &str) {
    let output = Command::new("git")
        .arg("-C")
        .arg(dir)
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

fn ts_at(seq: u64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 25, 12, 0, 0)
        .single()
        .expect("valid timestamp")
        + Duration::seconds(i64::try_from(seq).expect("small seq"))
}

fn artifact(version: &str, sha_byte: char) -> Artifact {
    Artifact {
        channel: "stable".to_string(),
        project: "cinc".to_string(),
        version: version.to_string(),
        platform: "debian".to_string(),
        platform_version: "13".to_string(),
        arch: "amd64".to_string(),
        raw_arch: "x86_64".to_string(),
        basename: format!("cinc-{version}-debian-13-x86_64.pkg.tar.zst"),
        sha256: sha_byte.to_string().repeat(64),
        iteration: None,
    }
}

fn artifact_detail(artifact: &Artifact) -> Value {
    json!({
        "channel": artifact.channel,
        "project": artifact.project,
        "version": artifact.version,
        "platform": artifact.platform,
        "platform_version": artifact.platform_version,
        "arch": artifact.arch,
        "raw_arch": artifact.raw_arch,
        "basename": artifact.basename,
        "sha256": artifact.sha256,
        "iteration": artifact.iteration,
    })
}

fn seen(run_id: &str, seq: u64, artifact: &Artifact, size: u64) -> Event {
    Event::new(run_id, seq, ts_at(seq), EventKind::ArtifactSeen)
        .with_artifact(artifact.key())
        .with_detail(json!({
            "artifact": artifact_detail(artifact),
            "size": size,
            "upstream_path": artifact.rsync_relpath(),
        }))
}

fn published(run_id: &str, seq: u64, artifact: &Artifact, target: &str) -> Event {
    Event::new(run_id, seq, ts_at(seq), EventKind::Published)
        .with_artifact(artifact.key())
        .with_target(target)
        .with_detail(json!({
            "remote_ref": format!("ghcr.example/{}:tag", artifact.key()),
            "remote_digest": artifact.sha256,
        }))
}

fn counts(ledger: &Ledger) -> (u64, usize, usize) {
    (
        ledger.event_count().expect("event count"),
        ledger.artifacts().expect("artifacts").len(),
        ledger.publications("ghcr").expect("publications").len(),
    )
}

fn remove_database(state: &Path) {
    for name in ["ledger.db", "ledger.db-wal", "ledger.db-shm"] {
        let path = state.join(name);
        if path.exists() {
            fs::remove_file(&path).expect("remove database file");
        }
    }
}

#[test]
fn write_run_produces_sorted_ndjson() {
    let fixture = Fixture::new();
    let store = fixture.store("state");
    store.sync().expect("bootstrap the ledger branch");

    let events = vec![
        Event::new("run-1", 3, ts_at(3), EventKind::DownloadStarted).with_artifact("late"),
        Event::new("run-1", 1, ts_at(1), EventKind::RunStarted),
        Event::new("run-1", 2, ts_at(2), EventKind::RunFinished),
    ];
    let path = store.write_run(&events).expect("write the run file");
    assert!(
        path.ends_with("runs/run-1.ndjson"),
        "path: {}",
        path.display()
    );

    let body = fs::read_to_string(&path).expect("read the run file");
    assert!(body.ends_with('\n'), "lines must be newline terminated");
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 3, "one event per line");

    let parsed: Vec<Event> = lines
        .iter()
        .map(|line| serde_json::from_str(line).expect("every line is one event"))
        .collect();
    assert_eq!(
        parsed.iter().map(|event| event.seq).collect::<Vec<_>>(),
        vec![1, 2, 3],
        "events are sorted by seq"
    );
    assert_eq!(parsed[0].kind, EventKind::RunStarted);
    assert_eq!(parsed[2].artifact_key.as_deref(), Some("late"));
}

#[test]
fn write_run_refuses_mixed_runs_and_escaping_ids() {
    let fixture = Fixture::new();
    let store = fixture.store("state");
    store.sync().expect("bootstrap the ledger branch");

    let mixed = [
        Event::new("run-a", 1, ts_at(1), EventKind::RunStarted),
        Event::new("run-b", 2, ts_at(2), EventKind::RunStarted),
    ];
    assert!(matches!(
        store.write_run(&mixed),
        Err(LedgerFilesError::MixedRuns)
    ));
    assert!(matches!(
        store.write_run(&[]),
        Err(LedgerFilesError::EmptyRun)
    ));

    for run_id in ["../escape", "a/b", ".hidden", ""] {
        let events = [Event::new(run_id, 1, ts_at(1), EventKind::DownloadStarted)];
        assert!(
            matches!(
                store.write_run(&events),
                Err(LedgerFilesError::InvalidRunId { .. })
            ),
            "run id {run_id:?} must be rejected"
        );
    }
    assert!(!fixture
        .state("state")
        .join("ledger-repo")
        .join("escape.ndjson")
        .exists());
}

#[test]
fn sync_bootstraps_an_orphan_branch() {
    let fixture = Fixture::new();
    let store = fixture.store("state");
    store.sync().expect("bootstrap the ledger branch");

    let workdir = fixture.state("state").join("ledger-repo");
    assert_eq!(
        fs::read_to_string(workdir.join("README.md")).expect("readme"),
        "ledger for cinc-mirror\n"
    );
    assert_eq!(
        git(&workdir, &["symbolic-ref", "--short", "HEAD"]),
        "ledger"
    );
    assert_eq!(
        git(
            &fixture.remote,
            &["rev-list", "--count", "refs/heads/ledger"]
        ),
        "1",
        "the bootstrap is one readme commit"
    );

    store
        .sync()
        .expect("syncing the own branch again is harmless");
    assert_eq!(git(&workdir, &["status", "--porcelain"]), "");
}

#[test]
fn load_all_is_idempotent() {
    let fixture = Fixture::new();
    let store = fixture.store("state");
    store.sync().expect("bootstrap the ledger branch");

    let first = artifact("19.1.0", 'a');
    let second = artifact("19.2.0", 'b');
    store
        .write_run(&[
            seen("run-1", 1, &first, 1024),
            published("run-1", 2, &first, "ghcr"),
        ])
        .expect("write the first run");
    store
        .write_run(&[seen("run-2", 1, &second, 2048)])
        .expect("write the second run");

    let state = fixture.state("state");
    let mut ledger = Ledger::open(&state).expect("open the ledger");
    assert_eq!(store.load_all(&mut ledger).expect("first load"), 3);
    assert_eq!(counts(&ledger), (3, 2, 1));
    assert_eq!(ledger.satisfied_keys("ghcr").expect("satisfied").len(), 1);

    // Unchanged files are skipped through the high-water mark, and the cache
    // keeps them: every later load is a no-op too instead of alternating
    // between replaying everything and writing an empty cache.
    assert_eq!(store.load_all(&mut ledger).expect("second load"), 0);
    assert_eq!(store.load_all(&mut ledger).expect("third load"), 0);
    assert_eq!(counts(&ledger), (3, 2, 1));

    // Correctness does not depend on that cache: drop it and replay everything.
    fs::remove_file(state.join("ledger.hwm")).expect("remove the high-water mark");
    assert_eq!(store.load_all(&mut ledger).expect("third load"), 3);
    assert_eq!(counts(&ledger), (3, 2, 1));

    let row = ledger
        .artifact(&first.key())
        .expect("query the artifact")
        .expect("artifact row");
    assert_eq!(row.size, Some(1024), "replay keeps the recorded size");
}

#[test]
fn load_all_reloads_when_the_database_was_deleted() {
    let fixture = Fixture::new();
    let store = fixture.store("state");
    store.sync().expect("bootstrap the ledger branch");

    let only = artifact("19.4.0", 'c');
    store
        .write_run(&[seen("run-1", 1, &only, 4096)])
        .expect("write the run");

    let state = fixture.state("state");
    let mut ledger = Ledger::open(&state).expect("open the ledger");
    assert_eq!(store.load_all(&mut ledger).expect("first load"), 1);
    assert!(
        state.join("ledger.hwm").is_file(),
        "a high-water mark is kept"
    );
    drop(ledger);

    // A disposable database is a promise: the branch alone must rebuild it even
    // though the cache still says every file was already applied.
    remove_database(&state);
    let mut rebuilt = Ledger::open(&state).expect("reopen the ledger");
    assert_eq!(store.load_all(&mut rebuilt).expect("reload"), 1);
    assert_eq!(counts(&rebuilt), (1, 1, 0));
}

#[test]
fn load_all_reports_the_offending_line() {
    let fixture = Fixture::new();
    let store = fixture.store("state");
    store.sync().expect("bootstrap the ledger branch");

    let path = store
        .write_run(&[Event::new(
            "run-bad",
            1,
            ts_at(1),
            EventKind::DownloadStarted,
        )])
        .expect("write the run");
    let mut body = fs::read_to_string(&path).expect("read the run");
    body.push_str("this is not an event\n");
    fs::write(&path, body).expect("corrupt the run file");

    let mut ledger = Ledger::open(&fixture.state("state")).expect("open the ledger");
    match store.load_all(&mut ledger) {
        Err(LedgerFilesError::Parse { line, path, .. }) => {
            assert_eq!(line, 2);
            assert!(path.ends_with("run-bad.ndjson"), "path: {}", path.display());
        }
        other => panic!("expected a parse error, got {other:?}"),
    }
}

#[test]
fn sync_fetches_a_branch_advanced_by_another_writer() {
    let fixture = Fixture::new();
    let first = fixture.store("first");
    first.sync().expect("bootstrap the ledger branch");
    let second = fixture.store("second");
    second.sync().expect("clone the ledger branch");
    assert_eq!(
        git(
            &fixture.state("second").join("ledger-repo"),
            &["rev-parse", "HEAD"]
        ),
        fixture.head()
    );

    let shared = artifact("19.3.0", 'd');
    let path = first
        .write_run(&[seen("run-first", 1, &shared, 10)])
        .expect("write the run");
    first
        .commit_and_push(&path, "run first")
        .expect("push the run");

    second.sync().expect("follow the advanced remote");
    let workdir = fixture.state("second").join("ledger-repo");
    assert!(
        workdir.join("runs/run-first.ndjson").is_file(),
        "sync must bring the other writer's run"
    );
    assert_eq!(git(&workdir, &["rev-parse", "HEAD"]), fixture.head());
    assert_eq!(git(&workdir, &["status", "--porcelain"]), "");

    // A dirty worktree is refused rather than reset over.
    let scratch = workdir.join("scratch.txt");
    fs::write(&scratch, "uncommitted\n").expect("write scratch file");
    match second.sync() {
        Err(LedgerGitError::Dirty { .. }) => {}
        other => panic!("expected Dirty, got {other:?}"),
    }
    assert!(scratch.is_file(), "sync must not discard local work");
    fs::remove_file(&scratch).expect("remove scratch file");
    second.sync().expect("a clean worktree syncs again");
}

#[test]
fn sync_pushes_unpushed_commits() {
    let fixture = Fixture::new();
    let first = fixture.store("first");
    first.sync().expect("bootstrap the ledger branch");
    let second = fixture.store("second");
    second.sync().expect("clone the ledger branch");

    let local = artifact("19.9.0", 'e');
    let path = second
        .write_run(&[seen("run-local", 1, &local, 99)])
        .expect("write the run");
    let workdir = fixture.state("second").join("ledger-repo");
    git(&workdir, &["add", "-A"]);
    commit(&workdir, "run local");

    second
        .sync()
        .expect("a local commit is published instead of dropped");
    assert!(
        path.is_file(),
        "the run file survives the sync: {}",
        path.display()
    );
    assert_eq!(git(&workdir, &["status", "--porcelain"]), "");
    assert_eq!(git(&workdir, &["rev-parse", "HEAD"]), fixture.head());
    assert_eq!(
        git(
            &fixture.remote,
            &["ls-tree", "--name-only", "refs/heads/ledger", "runs/"]
        ),
        "runs/run-local.ndjson",
        "the unpushed run reached the remote"
    );
}

#[test]
fn sync_refuses_to_discard_unpushed_commits() {
    let fixture = Fixture::new();
    let first = fixture.store("first");
    first.sync().expect("bootstrap the ledger branch");
    let second = fixture.store("second");
    second.sync().expect("clone the ledger branch");

    let local = artifact("19.8.0", 'f');
    let path = second
        .write_run(&[seen("run-local", 1, &local, 98)])
        .expect("write the run");
    let workdir = fixture.state("second").join("ledger-repo");
    git(&workdir, &["add", "-A"]);
    commit(&workdir, "run local");
    let local_head = git(&workdir, &["rev-parse", "HEAD"]);

    // Another writer advances the remote, so the local commit cannot be pushed
    // without a rebase. `sync` must refuse instead of resetting it away.
    let competing = artifact("19.9.0", 'a');
    let competing_path = first
        .write_run(&[seen("run-remote", 1, &competing, 97)])
        .expect("write the competing run");
    first
        .commit_and_push(&competing_path, "run remote")
        .expect("push the competing run");

    match second.sync() {
        Err(LedgerGitError::UnpushedCommits { count, .. }) => assert_eq!(count, 1),
        other => panic!("expected UnpushedCommits, got {other:?}"),
    }
    assert_eq!(
        git(&workdir, &["rev-parse", "HEAD"]),
        local_head,
        "the local commit survives"
    );
    assert!(
        path.is_file(),
        "the local run file survives: {}",
        path.display()
    );
    assert!(
        !git(
            &fixture.remote,
            &["ls-tree", "--name-only", "refs/heads/ledger", "runs/"]
        )
        .contains("run-local"),
        "the refused run was not pushed"
    );

    // Once the local work is committed no further sync may sneak it away.
    match second.sync() {
        Err(LedgerGitError::UnpushedCommits { count, .. }) => assert_eq!(count, 1),
        other => panic!("expected UnpushedCommits again, got {other:?}"),
    }
    assert!(path.is_file());
}

#[test]
fn snapshot_compaction_keeps_history() {
    let fixture = Fixture::new();
    let store = fixture.store("state");
    store.sync().expect("bootstrap the ledger branch");

    let state = fixture.state("state");
    let mut ledger = Ledger::open(&state).expect("open the ledger");
    let runs = 25_u64;
    for index in 0..runs {
        let artifact = artifact(
            &format!("19.{index}.0"),
            char::from(b'a' + u8::try_from(index % 26).expect("small index")),
        );
        let run_id = format!("run-{index:03}");
        let path = store
            .write_run(&[seen(&run_id, 1, &artifact, index)])
            .expect("write the run");
        store
            .commit_and_push(&path, &format!("run {run_id}"))
            .expect("push the run");
    }
    assert_eq!(store.load_all(&mut ledger).expect("load the runs"), runs);
    assert_eq!(
        ledger.artifacts().expect("artifacts").len(),
        usize::try_from(runs).expect("small run count")
    );

    let snapshot = store.compact(&ledger).expect("compact the ledger");
    assert!(
        snapshot.ends_with("snapshot-1.ndjson"),
        "path: {}",
        snapshot.display()
    );
    let body = fs::read_to_string(&snapshot).expect("read the snapshot");
    assert_eq!(body.lines().count(), 25);
    let first: Event =
        serde_json::from_str(body.lines().next().expect("a line")).expect("parse the first event");
    assert_eq!(first.run_id, "run-000", "snapshot follows append order");

    let removed = store.gc().expect("garbage-collect covered runs");
    assert_eq!(removed.len(), 5, "gc keeps the last 20 run files");
    let runs_dir = state.join("ledger-repo/runs");
    assert_eq!(fs::read_dir(&runs_dir).expect("runs dir").count(), 20);
    assert!(!runs_dir.join("run-000.ndjson").exists());
    assert!(runs_dir.join("run-024.ndjson").exists());

    // The snapshot alone must be enough: throw the database and the remaining
    // run files away and rebuild from the branch.
    drop(ledger);
    remove_database(&state);
    fs::remove_dir_all(&runs_dir).expect("delete the remaining run files");
    let mut rebuilt = Ledger::open(&state).expect("reopen the ledger");
    assert_eq!(store.load_all(&mut rebuilt).expect("load the snapshot"), 25);
    assert_eq!(
        rebuilt.artifacts().expect("artifacts").len(),
        usize::try_from(runs).expect("small run count")
    );
    assert_eq!(rebuilt.event_count().expect("event count"), runs);
}
