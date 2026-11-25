//! CLI-level tests: the process boundary and its exit codes.
//!
//! Every test runs the real binary from a temporary directory. Ledger-accessing
//! tests point the configuration at a local bare repository, so nothing leaves
//! the machine and no credentials are needed.

mod common;

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command as Process;
use std::time::Duration;

use assert_cmd::Command;
use chrono::Utc;
use cinc_mirror::artifact::Artifact;
use cinc_mirror::ledger::{Event, EventKind, Lease, Ledger, LedgerStore};
use common::mirror::package_artifact;
use predicates::prelude::*;
use serde_json::json;

/// A bare git repository plus its `file://` URL.
fn bare_remote(root: &Path) -> String {
    let remote = root.join("ledger.git");
    let status = Process::new("git")
        .args(["init", "--bare", "--quiet"])
        .arg(&remote)
        .status()
        .expect("run git init --bare");
    assert!(status.success(), "git init --bare failed");
    format!("file://{}", remote.display())
}

/// Write a `mirror.toml` pointing at `state` and `remote`, plus any targets.
fn write_config(root: &Path, state: &Path, remote: &str, extra: &str) -> PathBuf {
    let path = root.join("mirror.toml");
    let body = format!(
        r#"state_dir = {state:?}

[ledger]
branch = "ledger"
remote = {remote:?}

{extra}
"#
    );
    std::fs::write(&path, body).expect("write mirror.toml");
    path
}

/// A ledger store configuration for the state directory of `config`.
fn store_for(state: &Path, remote: &str) -> LedgerStore {
    LedgerStore::new(
        state.join("ledger-repo"),
        remote.to_string(),
        "ledger".to_string(),
    )
}

/// The binary under test, with CI/credential variables removed so a developer
/// environment cannot change the lease policy or probe the network.
fn binary() -> Command {
    let mut command = assert_cmd::cargo::cargo_bin_cmd!("cinc-mirror");
    command
        .env_remove("CI")
        .env_remove("GITHUB_ACTIONS")
        .env_remove("GITHUB_TOKEN")
        .env_remove("GHCR_TOKEN");
    command
}

/// Seed `events` into the ledger, commit one run file per run id and push.
fn seed_ledger(state: &Path, remote: &str, events: &[Event]) {
    let store = store_for(state, remote);
    store.sync().expect("sync the ledger remote");
    let mut ledger = Ledger::open(state).expect("ledger");
    for event in events {
        ledger.append(event).expect("append the seed event");
    }
    let run_ids: BTreeSet<&str> = events.iter().map(|event| event.run_id.as_str()).collect();
    for run_id in run_ids {
        let events = ledger
            .events()
            .expect("events")
            .into_iter()
            .filter(|event| event.run_id == run_id)
            .collect::<Vec<_>>();
        let path = store.write_run(&events).expect("write the run file");
        store.commit_and_push(&path, "seed").expect("push the seed");
    }
}

#[test]
fn help_lists_every_subcommand() {
    let mut command = binary();
    command
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("mirror"))
        .stdout(predicate::str::contains("plan"))
        .stdout(predicate::str::contains("backfill"))
        .stdout(predicate::str::contains("verify"))
        .stdout(predicate::str::contains("repair"))
        .stdout(predicate::str::contains("incidents"))
        .stdout(predicate::str::contains("ledger"))
        .stdout(predicate::str::contains("targets"))
        .stdout(predicate::str::contains("config"));
}

#[test]
fn config_check_prints_redacted_summary() {
    let root = tempfile::tempdir().expect("root");
    let state = root.path().join("state");
    let config = write_config(
        root.path(),
        &state,
        "git@example.invalid:ledger.git",
        r#"[[targets]]
name = "ghcr"
kind = "oci"
registry = "ghcr.io"
namespace = "rmoriz/cinc-mirror"
auth = "docker"

[[targets]]
name = "rsync"
kind = "rsync"
url = "ssh://mirror:hunter2@backup.example.org/srv/cinc-mirror"
auth = "ssh-key"
"#,
    );

    binary()
        .arg("--config")
        .arg(&config)
        .args(["config", "check"])
        .env("GHCR_TOKEN", "ghcr-secret-token-value")
        .assert()
        .success()
        .stdout(predicate::str::contains("config OK"))
        .stdout(predicate::str::contains("ghcr"))
        .stdout(predicate::str::contains("hunter2").not())
        .stdout(predicate::str::contains("ghcr-secret-token-value").not());
}

#[test]
fn config_check_probe_checks_targets() {
    let root = tempfile::tempdir().expect("root");
    let state = root.path().join("state");
    let target_root = root.path().join("rsync");
    let config = write_config(
        root.path(),
        &state,
        "git@example.invalid:ledger.git",
        &format!(
            r#"[[targets]]
name = "rsync"
kind = "rsync"
url = {target_root:?}
auth = "anonymous"
"#
        ),
    );

    binary()
        .arg("--config")
        .arg(&config)
        .args(["config", "check", "--probe"])
        .assert()
        .success()
        .stdout(predicate::str::contains("probe rsync"))
        .stdout(predicate::str::contains("config OK"));
}

#[test]
fn usage_errors_exit_64() {
    let root = tempfile::tempdir().expect("root");
    let state = root.path().join("state");
    let config = write_config(root.path(), &state, "git@example.invalid:ledger.git", "");

    binary()
        .arg("--config")
        .arg(&config)
        .args(["mirror", "--everything", "--project", "cinc"])
        .assert()
        .code(64);

    binary()
        .arg("--config")
        .arg(&config)
        .args(["mirror", "--limit", "0"])
        .assert()
        .code(64);
}

#[test]
fn zero_byte_limit_is_a_usage_error() {
    let root = tempfile::tempdir().expect("root");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("state dir");
    let remote = bare_remote(root.path());
    let config = write_config(root.path(), &state, &remote, "");

    // `--limit-bytes 0` parses; the runner refuses it as a usage error.
    binary()
        .arg("--config")
        .arg(&config)
        .args(["mirror", "--everything", "--limit-bytes", "0"])
        .assert()
        .code(64)
        .stderr(predicate::str::contains("greater than zero"));
}

#[test]
fn a_failed_mirror_still_writes_its_run_file() {
    let root = tempfile::tempdir().expect("root");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("state dir");
    let target_root = root.path().join("rsync");
    std::fs::create_dir_all(&target_root).expect("target root");
    let remote = bare_remote(root.path());
    // A project name with a traversal segment makes the crawl fail locally,
    // after the runner has appended `run_started` and before any network I/O.
    let config = write_config(
        root.path(),
        &state,
        &remote,
        &format!(
            r#"[[projects]]
id = "broken"
project = ".."
channel = "stable"

[[targets]]
name = "rsync"
kind = "rsync"
url = {target_root:?}
auth = "anonymous"
"#
        ),
    );

    binary()
        .arg("--config")
        .arg(&config)
        .args(["mirror", "--everything"])
        .assert()
        .code(1);

    let runs = state.join("ledger-repo").join("runs");
    let files: Vec<PathBuf> = std::fs::read_dir(&runs)
        .expect("run files directory")
        .map(|entry| entry.expect("entry").path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "ndjson"))
        .collect();
    assert_eq!(files.len(), 1, "the failed run must leave one event file");
    let body = std::fs::read_to_string(&files[0]).expect("run file");
    assert!(
        body.contains("\"run_started\""),
        "the events appended before the failure are kept: {body}"
    );
    assert!(
        !body.contains("\"run_finished\""),
        "a failed run has no finished event: {body}"
    );
}

#[test]
fn lease_busy_exits_4() {
    let root = tempfile::tempdir().expect("root");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("state dir");
    let remote = bare_remote(root.path());
    let config = write_config(root.path(), &state, &remote, "");

    let store = store_for(&state, &remote);
    store.sync().expect("sync");
    let held = Lease::acquire(&store, "other-run-1", Duration::from_secs(600))
        .expect("acquire the live lease")
        .expect("a lease");

    binary()
        .arg("--config")
        .arg(&config)
        .args(["mirror", "--everything"])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("busy"));

    // A plain acknowledgement writes events too, so it takes the lease as well.
    binary()
        .arg("--config")
        .arg(&config)
        .args(["incidents", "ack", "tag_conflict-0000000000000000"])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("busy"));

    // `--allow-unleased` only forgives an unreachable ledger remote: a live
    // foreign lease still refuses the run.
    binary()
        .arg("--config")
        .arg(&config)
        .args(["mirror", "--everything", "--allow-unleased"])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("busy"));

    binary()
        .arg("--config")
        .arg(&config)
        .args([
            "incidents",
            "ack",
            "tag_conflict-0000000000000000",
            "--allow-unleased",
        ])
        .assert()
        .code(4)
        .stderr(predicate::str::contains("busy"));

    held.release().expect("release");
}

#[test]
fn allow_unleased_continues_past_an_unreachable_ledger_remote() {
    let root = tempfile::tempdir().expect("root");
    let state = root.path().join("state");
    // A remote path that does not exist: every git operation fails fast and
    // nothing leaves the machine.
    let missing = root.path().join("no-such-ledger.git");
    let config = write_config(root.path(), &state, &missing.to_string_lossy(), "");

    // Without the flag, the unreachable remote is a configuration failure.
    binary()
        .arg("--config")
        .arg(&config)
        .args(["mirror", "--everything"])
        .assert()
        .code(5)
        .stderr(predicate::str::contains("cannot sync the ledger branch"));

    // With the flag the run proceeds unleased and says so; it only fails on
    // the missing targets, proving the remote failure was downgraded.
    binary()
        .arg("--config")
        .arg(&config)
        .args(["mirror", "--everything", "--allow-unleased"])
        .assert()
        .code(5)
        .stderr(predicate::str::contains(
            "continuing without the ledger remote",
        ))
        .stderr(predicate::str::contains(
            "no publication targets are enabled",
        ));
}

#[test]
fn incidents_open_exit_3_only_when_new() {
    let root = tempfile::tempdir().expect("root");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("state dir");
    let remote = bare_remote(root.path());
    let config = write_config(root.path(), &state, &remote, "");
    let incident = "tag_conflict-0123456789abcdef";

    let artifact: Artifact = package_artifact(b"the contested bytes", "19.4.46");
    seed_ledger(
        &state,
        &remote,
        &[
            Event::new("seed-incident-1", 1, Utc::now(), EventKind::ArtifactSeen)
                .with_artifact(artifact.key())
                .with_detail(json!({
                    "artifact": cinc_mirror::ledger::artifact_detail(&artifact),
                    "upstream_path": artifact.rsync_relpath(),
                })),
            Event::new("seed-incident-1", 2, Utc::now(), EventKind::IncidentOpened)
                .with_artifact(artifact.key())
                .with_detail(json!({
                    "id": incident,
                    "kind": "tag_conflict",
                    "artifact_key": artifact.key(),
                })),
        ],
    );

    binary()
        .arg("--config")
        .arg(&config)
        .args(["incidents", "list"])
        .assert()
        .code(3)
        .stdout(predicate::str::contains(incident));

    binary()
        .arg("--config")
        .arg(&config)
        .args(["incidents", "ack", incident, "-m", "checked upstream"])
        .assert()
        .success();

    // The incident is now acknowledged, not new: the list exits zero and the
    // summary still names it.
    binary()
        .arg("--config")
        .arg(&config)
        .args(["incidents", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains(incident))
        .stdout(predicate::str::contains("acked"));
}

#[test]
fn partial_target_failure_exits_2() {
    let root = tempfile::tempdir().expect("root");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("state dir");
    let remote = bare_remote(root.path());
    let target_root = root.path().join("rsync");
    std::fs::create_dir_all(&target_root).expect("target root");
    let config = write_config(
        root.path(),
        &state,
        &remote,
        &format!(
            r#"[[targets]]
name = "rsync"
kind = "rsync"
url = {target_root:?}
auth = "anonymous"
"#
        ),
    );

    let artifact: Artifact = package_artifact(b"a package that never reached rsync", "19.4.46");
    seed_ledger(
        &state,
        &remote,
        &[
            Event::new("seed-artifact-1", 1, Utc::now(), EventKind::ArtifactSeen)
                .with_artifact(artifact.key())
                .with_detail(json!({
                    "artifact": cinc_mirror::ledger::artifact_detail(&artifact),
                    "upstream_path": artifact.rsync_relpath(),
                })),
            Event::new("seed-artifact-1", 2, Utc::now(), EventKind::Published)
                .with_artifact(artifact.key())
                .with_target("rsync")
                .with_detail(json!({"remote_digest": artifact.sha256})),
        ],
    );

    binary()
        .arg("--config")
        .arg(&config)
        .args(["verify"])
        .assert()
        .code(2)
        .stdout(predicate::str::contains("remote"));
}

#[test]
fn targets_list_reports_name_kind_and_state() {
    let root = tempfile::tempdir().expect("root");
    let state = root.path().join("state");
    let config = write_config(
        root.path(),
        &state,
        "git@example.invalid:ledger.git",
        r#"[[targets]]
name = "ghcr"
kind = "oci"
registry = "ghcr.io"
namespace = "rmoriz/cinc-mirror"
auth = "anonymous"

[[targets]]
name = "backup"
kind = "rsync"
url = "/srv/cinc-mirror"
auth = "anonymous"
enabled = false
"#,
    );

    binary()
        .arg("--config")
        .arg(&config)
        .args(["targets", "list"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ghcr oci enabled"))
        .stdout(predicate::str::contains("backup rsync disabled"));
}

#[test]
fn ledger_export_prints_ndjson() {
    let root = tempfile::tempdir().expect("root");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("state dir");
    let remote = bare_remote(root.path());
    let config = write_config(root.path(), &state, &remote, "");

    let artifact: Artifact = package_artifact(b"exported bytes", "19.4.46");
    seed_ledger(
        &state,
        &remote,
        &[
            Event::new("seed-export-1", 1, Utc::now(), EventKind::ArtifactSeen)
                .with_artifact(artifact.key())
                .with_detail(json!({
                    "artifact": cinc_mirror::ledger::artifact_detail(&artifact),
                    "upstream_path": artifact.rsync_relpath(),
                })),
        ],
    );

    let output = binary()
        .arg("--config")
        .arg(&config)
        .args(["ledger", "export"])
        .assert()
        .success()
        .get_output()
        .stdout
        .clone();
    let body = String::from_utf8(output).expect("utf-8 export");
    let first = body.lines().next().expect("one event line");
    let event: serde_json::Value = serde_json::from_str(first).expect("NDJSON event");
    assert_eq!(event["kind"], "artifact_seen");
}
