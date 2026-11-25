//! Deep verification and coverage tests.
//!
//! Every test drives a real ledger in a temporary state directory, a real rsync
//! target on a local directory, and the shared in-memory OCI registry where a
//! remote probe is needed. The assertions look at the findings that came back,
//! the artifacts that were actually probed and the process exit code.

mod common;

use std::sync::Arc;

use chrono::Utc;
use cinc_mirror::config::ProjectPolicy;
use cinc_mirror::ledger::{Event, EventKind, Ledger, PublicationStatus};
use cinc_mirror::scope::ScopeArgs;
use cinc_mirror::store::Store;
use cinc_mirror::targets::TargetSet;
use cinc_mirror::verify::{self, FindingKind, VerifyOpts};
use common::mirror::{
    config_with, context, context_with, mock_registry, package_artifact, publish, rsync_target,
    seed_artifact, seed_published, sha256_hex, source_with, store_blob, RecordingTarget,
};
use serde_json::json;

#[tokio::test]
async fn deep_verify_hashes_local_blobs() {
    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let root = tempfile::tempdir().expect("rsync root");
    let targets = TargetSet::from_targets(vec![Arc::new(rsync_target("rsync", root.path()))]);

    let package = b"the verified package bytes".to_vec();
    let artifact = package_artifact(&package, "19.4.46");
    publish(targets.all()[0].as_ref(), &artifact, &package).await;
    seed_artifact(&mut ledger, &artifact, Some(package.len() as u64));
    seed_published(&mut ledger, &artifact, "rsync", 1);

    let blob = store_blob(state.path(), &package);
    let mut corrupt = package.clone();
    corrupt[0] ^= 0xff;
    std::fs::write(&blob, &corrupt).expect("corrupt the blob in place");

    let ctx = context(state.path(), ledger, targets, source_with(Vec::new()));
    let report = verify::run(
        &ctx,
        VerifyOpts {
            deep: true,
            ..VerifyOpts::default()
        },
    )
    .await
    .expect("verify");

    assert_eq!(report.exit_code(), 2);
    assert_eq!(report.findings.len(), 1, "{report}");
    let finding = &report.findings[0];
    assert_eq!(finding.kind, FindingKind::LocalCorrupt);
    assert_eq!(finding.artifact_key, artifact.key());
    assert!(finding.target.is_none());
    assert!(
        report.to_string().contains("local_corrupt"),
        "the human report names the kind: {report}"
    );
}

#[tokio::test]
async fn deep_verify_skips_local_gc_rows() {
    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let root = tempfile::tempdir().expect("rsync root");
    let targets = TargetSet::from_targets(vec![Arc::new(rsync_target("rsync", root.path()))]);

    let package = b"a package that was published and then collected".to_vec();
    let artifact = package_artifact(&package, "19.4.46");
    publish(targets.all()[0].as_ref(), &artifact, &package).await;
    seed_artifact(&mut ledger, &artifact, Some(package.len() as u64));
    seed_published(&mut ledger, &artifact, "rsync", 1);

    let blob = store_blob(state.path(), &package);
    Store::open(state.path())
        .expect("store")
        .gc(&artifact.sha256)
        .expect("gc the blob");
    assert!(!blob.exists());

    let ctx = context(state.path(), ledger, targets, source_with(Vec::new()));

    // Without the `local_gc` event the ledger still says the blob is present,
    // so a deep verify must report the absence.
    let before = verify::run(
        &ctx,
        VerifyOpts {
            deep: true,
            ..VerifyOpts::default()
        },
    )
    .await
    .expect("verify before the gc is recorded");
    assert_eq!(before.findings.len(), 1, "{before}");
    assert_eq!(before.findings[0].kind, FindingKind::LocalMissing);

    ctx.ledger
        .lock()
        .await
        .append(
            &Event::new("gc-run".to_string(), 1, Utc::now(), EventKind::LocalGc)
                .with_artifact(artifact.key())
                .with_detail(json!({"sha256": artifact.sha256})),
        )
        .expect("record the gc");

    let after = verify::run(
        &ctx,
        VerifyOpts {
            deep: true,
            ..VerifyOpts::default()
        },
    )
    .await
    .expect("verify after the gc is recorded");
    assert!(
        after.is_clean(),
        "a deliberate local removal is not corruption: {after}"
    );
    assert_eq!(after.exit_code(), 0);
}

#[tokio::test]
async fn verify_checks_every_target_by_default() {
    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let mock = mock_registry().await;
    let root = tempfile::tempdir().expect("rsync root");
    let targets = TargetSet::from_targets(vec![
        Arc::new(common::mirror::oci_target(&mock, "oci")),
        Arc::new(rsync_target("rsync", root.path())),
    ]);

    let package = b"published to rsync only".to_vec();
    let artifact = package_artifact(&package, "19.4.46");
    publish(targets.all()[1].as_ref(), &artifact, &package).await;
    seed_artifact(&mut ledger, &artifact, None);
    seed_published(&mut ledger, &artifact, "rsync", 1);

    let ctx = context(state.path(), ledger, targets, source_with(Vec::new()));

    let all = verify::run(&ctx, VerifyOpts::default())
        .await
        .expect("verify every target");
    assert_eq!(all.publications_checked, 2);
    assert_eq!(all.findings.len(), 1, "{all}");
    assert_eq!(all.findings[0].kind, FindingKind::Remote);
    assert_eq!(all.findings[0].target.as_deref(), Some("oci"));
    assert_eq!(all.exit_code(), 2);

    let rsync_only = verify::run(
        &ctx,
        VerifyOpts {
            targets: Some(vec!["rsync".to_string()]),
            ..VerifyOpts::default()
        },
    )
    .await
    .expect("verify one target");
    assert_eq!(rsync_only.publications_checked, 1);
    assert!(rsync_only.is_clean(), "{rsync_only}");
}

#[tokio::test]
async fn a_pending_artifact_is_not_a_remote_finding() {
    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let root = tempfile::tempdir().expect("rsync root");

    // Seen upstream and verified locally, but never fanned out: there is no
    // publication whose remote state could be compared.
    let package = b"a package the mirror has not published yet".to_vec();
    let artifact = package_artifact(&package, "19.4.46");
    seed_artifact(&mut ledger, &artifact, Some(package.len() as u64));
    store_blob(state.path(), &package);

    let targets = || TargetSet::from_targets(vec![Arc::new(rsync_target("rsync", root.path()))]);
    let ctx = context(state.path(), ledger, targets(), source_with(Vec::new()));

    let report = verify::run(&ctx, VerifyOpts::default())
        .await
        .expect("verify");
    assert!(
        report.is_clean(),
        "a never-published row is not broken: {report}"
    );
    assert_eq!(
        report.publications_checked, 0,
        "nothing is probed without a publication row"
    );

    // A deep verify still re-hashes the local copy the ledger promises.
    let deep = verify::run(
        &ctx,
        VerifyOpts {
            deep: true,
            ..VerifyOpts::default()
        },
    )
    .await
    .expect("deep verify");
    assert!(deep.is_clean(), "{deep}");
    assert_eq!(deep.artifacts_checked, 1);

    // Once the mirror records a publication, the row becomes checkable.
    let mut ledger = ctx.ledger.into_inner();
    seed_published(&mut ledger, &artifact, "rsync", 1);
    let ctx_after = context(state.path(), ledger, targets(), source_with(Vec::new()));
    let after = verify::run(&ctx_after, VerifyOpts::default())
        .await
        .expect("verify after publishing");
    assert_eq!(after.publications_checked, 1, "{after}");
    assert_eq!(after.findings.len(), 1, "{after}");
    assert_eq!(after.findings[0].kind, FindingKind::Remote);
}

#[tokio::test]
async fn verify_ignores_current_policy_narrowing() {
    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let root = tempfile::tempdir().expect("rsync root");
    let targets = TargetSet::from_targets(vec![Arc::new(rsync_target("rsync", root.path()))]);

    let old_bytes = b"the 18.x package".to_vec();
    let new_bytes = b"the 19.x package".to_vec();
    let old = package_artifact(&old_bytes, "18.9.0");
    let new = package_artifact(&new_bytes, "19.4.46");
    for artifact in [&old, &new] {
        let bytes = if artifact.version == "18.9.0" {
            &old_bytes
        } else {
            &new_bytes
        };
        publish(targets.all()[0].as_ref(), artifact, bytes).await;
        seed_artifact(&mut ledger, artifact, None);
        seed_published(&mut ledger, artifact, "rsync", 1);
    }

    // Break only the 18.x publication behind the sidecar's back.
    std::fs::remove_file(root.path().join(old.rsync_relpath())).expect("remove the old package");

    // Today's policy no longer selects 18.x.
    let mut config = config_with(state.path(), "https://api.github.com");
    config.projects = vec![ProjectPolicy::new("cinc")
        .with_project("cinc")
        .with_channel("stable")];
    config.projects[0].min_version = Some("19.0.0".to_string());
    let scope = config
        .resolve(&ScopeArgs::default())
        .expect("resolve scope");
    assert_eq!(scope.policies.len(), 1);

    let ctx = context_with(config, scope, ledger, targets, source_with(Vec::new()));
    let report = verify::run(&ctx, VerifyOpts::default())
        .await
        .expect("verify");

    assert_eq!(report.artifacts_checked, 2, "every ledger row is covered");
    assert_eq!(report.publications_checked, 2);
    assert_eq!(report.findings.len(), 1, "{report}");
    assert_eq!(report.findings[0].artifact_key, old.key());
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.artifact_key == new.key()),
        "the healthy 19.x row must not be reported"
    );
}

#[tokio::test]
async fn sampling_is_deterministic_and_bounded() {
    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let root = tempfile::tempdir().expect("rsync root");
    let recorder = RecordingTarget::new("rsync", root.path());
    let targets = TargetSet::from_targets(vec![recorder.clone()]);

    for index in 1..=6 {
        let version = format!("18.0.{index}");
        let bytes = format!("package {version}").into_bytes();
        let artifact = package_artifact(&bytes, &version);
        publish(targets.all()[0].as_ref(), &artifact, &bytes).await;
        seed_artifact(&mut ledger, &artifact, None);
        seed_published(&mut ledger, &artifact, "rsync", 1);
    }

    let ctx = context(state.path(), ledger, targets, source_with(Vec::new()));
    let opts = VerifyOpts {
        sample: Some(2),
        ..VerifyOpts::default()
    };

    let first = verify::run(&ctx, opts.clone()).await.expect("first sample");
    let first_keys = recorder.verified();
    assert_eq!(first.artifacts_checked, 2);
    assert_eq!(first_keys.len(), 2, "at most two artifacts are probed");
    assert!(first.is_clean(), "{first}");

    recorder.clear();
    let second = verify::run(&ctx, opts).await.expect("second sample");
    let second_keys = recorder.verified();

    assert_eq!(first.artifacts_checked, second.artifacts_checked);
    assert_eq!(
        first_keys, second_keys,
        "the same ledger always samples the same artifacts"
    );
    assert_eq!(
        first_keys
            .iter()
            .collect::<std::collections::HashSet<_>>()
            .len(),
        2,
        "each sampled artifact is probed once"
    );
}

#[test]
fn sha_fixture_matches_the_artifact_digest() {
    let bytes = b"fixture";
    assert_eq!(package_artifact(bytes, "19.4.46").sha256, sha256_hex(bytes));
}

#[test]
fn a_published_row_is_the_ledger_truth_verify_reads() {
    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let artifact = package_artifact(b"fixture", "19.4.46");
    seed_artifact(&mut ledger, &artifact, None);
    seed_published(&mut ledger, &artifact, "rsync", 1);
    let publications = ledger
        .publications_for(&artifact.key())
        .expect("publications");
    assert_eq!(publications.len(), 1);
    assert_eq!(publications[0].status, PublicationStatus::Published);
    assert!(ledger
        .all_artifacts()
        .expect("all")
        .iter()
        .any(|row| row.key() == artifact.key()));
}
