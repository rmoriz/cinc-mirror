//! Repair tests.
//!
//! Every test drives a real ledger in a temporary state directory and a real
//! rsync target on a local directory. The payload ladder is injected so a test
//! can prove whether repair downloaded at all, and the assertions look at the
//! bytes that ended up in the store and on the target, the derived publication
//! rows and the incidents a human will see.

mod common;

use std::fs;
use std::path::Path;
use std::sync::Arc;

use chrono::Utc;
use cinc_mirror::artifact::Artifact;
use cinc_mirror::ledger::{
    Event, EventKind, IncidentFilter, IncidentKind, IncidentState, Ledger, PublicationStatus,
};
use cinc_mirror::repair::{self, RepairOpts, RepairOutcome};
use cinc_mirror::store::Store;
use cinc_mirror::targets::TargetSet;
use common::mirror::{
    context, package_artifact, publish, rsync_target, seed_artifact, seed_published, sha256_hex,
    source_with, store_blob, FakeTransport,
};
use serde_json::json;

/// Incidents may reach GitHub when a token is in the environment; the tests that
/// open one serialise and clear those variables first.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn clean_incident_env() -> tokio::sync::MutexGuard<'static, ()> {
    let guard = ENV_LOCK.lock().await;
    std::env::remove_var("GITHUB_TOKEN");
    std::env::remove_var("GITHUB_REPOSITORY");
    std::env::remove_var("GITHUB_ENV");
    guard
}

/// Remove every file the rsync target writes for `artifact`.
fn remove_remote(root: &Path, artifact: &Artifact) {
    let relpath = artifact.rsync_relpath();
    let path = root.join(&relpath);
    fs::remove_file(&path).expect("remove remote package");
    fs::remove_file(root.join(format!("{relpath}.sha256"))).expect("remove remote sidecar");
    let directory = path.parent().expect("canonical directory");
    fs::remove_file(directory.join("metadata.json")).expect("remove remote metadata");
}

/// Commit `bytes` and record it as the local blob of `artifact`.
fn local_blob(ledger: &mut Ledger, state: &Path, artifact: &Artifact, bytes: &[u8]) {
    store_blob(state, bytes);
    seed_artifact(ledger, artifact, Some(bytes.len() as u64));
}

/// Record a deliberate local gc so the ledger agrees the blob is gone.
async fn record_local_gc(ctx: &cinc_mirror::Ctx, artifact: &Artifact) {
    ctx.ledger
        .lock()
        .await
        .append(
            &Event::new("gc-run".to_string(), 1, Utc::now(), EventKind::LocalGc)
                .with_artifact(artifact.key())
                .with_detail(json!({"sha256": artifact.sha256})),
        )
        .expect("record local_gc");
}

#[tokio::test]
async fn repair_repushes_from_store_without_download() {
    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let root = tempfile::tempdir().expect("rsync root");
    let targets = TargetSet::from_targets(vec![Arc::new(rsync_target("rsync", root.path()))]);

    let package = b"a package that is still in the store".to_vec();
    let artifact = package_artifact(&package, "19.4.46");
    publish(targets.all()[0].as_ref(), &artifact, &package).await;
    local_blob(&mut ledger, state.path(), &artifact, &package);
    seed_published(&mut ledger, &artifact, "rsync", 1);
    remove_remote(root.path(), &artifact);
    assert!(
        targets.all()[0].verify(&artifact).await.is_err(),
        "the remote publication is broken before the repair"
    );

    let transport = FakeTransport::serving(b"upstream must not be asked".to_vec());
    let ctx = context(
        state.path(),
        ledger,
        targets,
        source_with(vec![transport.clone()]),
    );

    let report = repair::run(&ctx, RepairOpts::default())
        .await
        .expect("repair");

    assert_eq!(report.examined, 1, "{report}");
    assert_eq!(report.repaired, 1, "{report}");
    assert_eq!(report.failed, 0);
    assert_eq!(report.exit_code(), 0);
    assert_eq!(
        transport.calls(),
        0,
        "the store copy makes a download unnecessary"
    );

    ctx.targets.all()[0]
        .verify(&artifact)
        .await
        .expect("the publication is restored and verified");
    assert_eq!(
        fs::read(root.path().join(artifact.rsync_relpath())).expect("remote package"),
        package
    );
    let publication = ctx
        .ledger
        .lock()
        .await
        .publication(&artifact.key(), "rsync")
        .expect("publication")
        .expect("row");
    assert_eq!(publication.status, PublicationStatus::Published);
}

#[tokio::test]
async fn repair_refetches_when_store_missing() {
    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let root = tempfile::tempdir().expect("rsync root");
    let targets = TargetSet::from_targets(vec![Arc::new(rsync_target("rsync", root.path()))]);

    let package = b"a package whose local blob was collected".to_vec();
    let artifact = package_artifact(&package, "19.4.46");
    publish(targets.all()[0].as_ref(), &artifact, &package).await;
    local_blob(&mut ledger, state.path(), &artifact, &package);
    seed_published(&mut ledger, &artifact, "rsync", 1);
    Store::open(state.path())
        .expect("store")
        .gc(&artifact.sha256)
        .expect("drop the local blob");
    remove_remote(root.path(), &artifact);

    let transport = FakeTransport::serving(package.clone());
    let ctx = context(
        state.path(),
        ledger,
        targets,
        source_with(vec![transport.clone()]),
    );
    record_local_gc(&ctx, &artifact).await;
    assert!(!ctx.store.has(&artifact.sha256));

    let report = repair::run(&ctx, RepairOpts::default())
        .await
        .expect("repair");

    assert_eq!(report.repaired, 1, "{report}");
    assert_eq!(report.exit_code(), 0);
    assert_eq!(transport.calls(), 1, "the missing blob is fetched once");
    assert!(
        ctx.store.verify(&artifact.sha256).expect("verify blob"),
        "the fetched bytes are committed under their digest"
    );
    ctx.targets.all()[0]
        .verify(&artifact)
        .await
        .expect("the publication is restored");
    assert_eq!(
        fs::read(root.path().join(artifact.rsync_relpath())).expect("remote package"),
        package
    );
}

#[tokio::test]
async fn repair_marks_unrecoverable_and_incident_when_upstream_gone() {
    let _env = clean_incident_env().await;

    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let root = tempfile::tempdir().expect("rsync root");
    let targets = TargetSet::from_targets(vec![Arc::new(rsync_target("rsync", root.path()))]);

    let package = b"bytes that no longer exist anywhere".to_vec();
    let artifact = package_artifact(&package, "19.4.46");
    publish(targets.all()[0].as_ref(), &artifact, &package).await;
    local_blob(&mut ledger, state.path(), &artifact, &package);
    seed_published(&mut ledger, &artifact, "rsync", 1);
    Store::open(state.path())
        .expect("store")
        .gc(&artifact.sha256)
        .expect("drop the local blob");
    remove_remote(root.path(), &artifact);

    let transport = FakeTransport::gone();
    let ctx = context(
        state.path(),
        ledger,
        targets,
        source_with(vec![transport.clone()]),
    );
    record_local_gc(&ctx, &artifact).await;

    let report = repair::run(&ctx, RepairOpts::default())
        .await
        .expect("repair");

    assert_eq!(report.examined, 1, "{report}");
    assert_eq!(report.unrecoverable, 1, "{report}");
    assert_eq!(report.repaired, 0);
    assert_eq!(
        report.exit_code(),
        2,
        "an unrecoverable publication stays broken"
    );
    assert!(matches!(
        report.actions[0].outcome,
        RepairOutcome::Unrecoverable
    ));
    assert!(
        report.actions[0].detail.contains("incident"),
        "the action points at the incident: {report}"
    );

    let publication = ctx
        .ledger
        .lock()
        .await
        .publication(&artifact.key(), "rsync")
        .expect("publication")
        .expect("row");
    assert_eq!(
        publication.status,
        PublicationStatus::Unrecoverable,
        "the loss is visible in the ledger"
    );

    let incidents = ctx
        .ledger
        .lock()
        .await
        .incidents(IncidentFilter {
            state: Some(IncidentState::Open),
            kind: Some(IncidentKind::Unrecoverable),
            artifact_key: None,
        })
        .expect("incidents");
    assert_eq!(incidents.len(), 1, "exactly one incident records the loss");

    // A second repair is deduplicated: the incident is not opened again.
    let again = repair::run(&ctx, RepairOpts::default())
        .await
        .expect("second repair");
    assert_eq!(again.unrecoverable, 1);
    let incidents = ctx
        .ledger
        .lock()
        .await
        .incidents(IncidentFilter {
            state: Some(IncidentState::Open),
            kind: Some(IncidentKind::Unrecoverable),
            artifact_key: None,
        })
        .expect("incidents after a second repair");
    assert_eq!(incidents.len(), 1);
    assert_eq!(transport.calls(), 2, "each repair asks upstream once");
}

#[tokio::test]
async fn repair_skips_a_tag_conflict_and_points_at_the_incident() {
    let _env = clean_incident_env().await;

    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let root = tempfile::tempdir().expect("rsync root");
    let targets = TargetSet::from_targets(vec![Arc::new(rsync_target("rsync", root.path()))]);

    let published_bytes = b"bytes that own the canonical path".to_vec();
    let incoming_bytes = b"different bytes with the same canonical path".to_vec();
    let published = package_artifact(&published_bytes, "19.4.46");
    let incoming = package_artifact(&incoming_bytes, "19.4.46");
    assert_eq!(published.rsync_relpath(), incoming.rsync_relpath());
    assert_ne!(published.sha256, incoming.sha256);

    publish(targets.all()[0].as_ref(), &published, &published_bytes).await;
    local_blob(&mut ledger, state.path(), &incoming, &incoming_bytes);

    let transport = FakeTransport::serving(b"upstream must not be asked".to_vec());
    let ctx = context(
        state.path(),
        ledger,
        targets,
        source_with(vec![transport.clone()]),
    );

    let report = repair::run(&ctx, RepairOpts::default())
        .await
        .expect("repair");

    assert_eq!(report.examined, 1, "{report}");
    assert_eq!(report.skipped, 1, "{report}");
    assert_eq!(
        report.actions[0].outcome,
        RepairOutcome::Skipped,
        "a tag conflict is never overwritten"
    );
    assert!(report.actions[0].detail.contains("incident"));
    assert_eq!(report.exit_code(), 2);
    assert_eq!(transport.calls(), 0);

    assert_eq!(
        fs::read(root.path().join(published.rsync_relpath())).expect("canonical package"),
        published_bytes,
        "the canonical path still serves its original bytes"
    );

    let incidents = ctx
        .ledger
        .lock()
        .await
        .incidents(IncidentFilter {
            state: Some(IncidentState::Open),
            kind: Some(IncidentKind::TagConflict),
            artifact_key: None,
        })
        .expect("incidents");
    assert_eq!(
        incidents.len(),
        1,
        "the conflict is an incident, not a retry"
    );
}

#[tokio::test]
async fn repair_limit_stops_and_still_exits_two() {
    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let root = tempfile::tempdir().expect("rsync root");
    let targets = TargetSet::from_targets(vec![Arc::new(rsync_target("rsync", root.path()))]);

    let mut artifacts = Vec::new();
    for version in ["19.4.46", "19.4.47"] {
        let package = format!("package {version}").into_bytes();
        let artifact = package_artifact(&package, version);
        publish(targets.all()[0].as_ref(), &artifact, &package).await;
        local_blob(&mut ledger, state.path(), &artifact, &package);
        seed_published(&mut ledger, &artifact, "rsync", 1);
        remove_remote(root.path(), &artifact);
        artifacts.push((artifact, package));
    }

    let transport = FakeTransport::serving(b"upstream must not be asked".to_vec());
    let ctx = context(
        state.path(),
        ledger,
        targets,
        source_with(vec![transport.clone()]),
    );

    let report = repair::run(
        &ctx,
        RepairOpts {
            limit: Some(1),
            ..RepairOpts::default()
        },
    )
    .await
    .expect("repair");

    assert_eq!(report.repaired, 1, "{report}");
    assert!(
        report.limit_reached,
        "the second broken artifact is deferred"
    );
    assert_eq!(report.exit_code(), 2, "a truncated run cannot claim clean");

    let repaired = artifacts
        .iter()
        .filter(|(artifact, _)| root.path().join(artifact.rsync_relpath()).is_file())
        .count();
    assert_eq!(
        repaired, 1,
        "exactly one artifact was re-published before the cap"
    );
    assert_eq!(transport.calls(), 0);
}

#[test]
fn the_fixture_digests_differ_for_the_conflict_case() {
    assert_ne!(
        sha256_hex(b"bytes that own the canonical path"),
        sha256_hex(b"different bytes with the same canonical path")
    );
}
