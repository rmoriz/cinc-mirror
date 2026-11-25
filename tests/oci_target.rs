//! OCI target tests.
//!
//! Every test talks to the in-memory registry in `tests/common/registry.rs` and
//! asserts what actually crossed the wire: the manifest bytes, the layer order
//! and digests, the annotations the legacy ORAS push wrote, and the number of
//! manifest `PUT`s a repeated or conflicting publication costs.

mod common;

use std::time::Duration;

use cinc_mirror::artifact::{Artifact, ArtifactContext, ArtifactInput};
use cinc_mirror::config::{Config, TargetAuth, TargetConfig, TargetKind};
use cinc_mirror::ledger::{Event, EventKind, Ledger};
use cinc_mirror::oci::{OciAuth, OciConfig, Registry};
use cinc_mirror::targets::{OciTarget, Target, TargetError, TargetSet};
use common::registry::{MockAuth, MockRegistry};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const NAMESPACE: &str = "cinc-mirror";
const PROJECT: &str = "cinc";
const REPO: &str = "cinc-mirror/cinc";
const BASENAME: &str = "cinc_19.4.46-1_amd64.deb";

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

fn artifact_for(bytes: &[u8]) -> Artifact {
    artifact_for_version(bytes, "19.4.46")
}

/// The upstream document, mirroring the real `*.metadata.json`: numeric
/// `iteration`, the optional cross-check digests and fields the mirror ignores.
fn raw_metadata(bytes: &[u8], version: &str) -> String {
    format!(
        r#"{{
  "basename": "{BASENAME}",
  "md5": "33db1d1be1d5cd535d8b7dcfd2ec7ee0",
  "sha1": "c6d023b4f8fc5097e5a44625e639d1adfa4d1c04",
  "sha256": "{}",
  "sha512": "cdbbdd1d4be7454adc4c819dd5a0cb9d499b46913b7f4eb00910199d880632114006230221acfeea17b8f59da9bf62c00987d444bab3004b3e62914df292992a",
  "platform": "debian",
  "platform_version": "13",
  "arch": "x86_64",
  "name": "cinc",
  "friendly_name": "Cinc Client",
  "homepage": "https://www.cinc.sh",
  "version": "{version}",
  "iteration": 1,
  "license": "Apache-2.0"
}}"#,
        sha256_hex(bytes)
    )
}

fn artifact_for_version(bytes: &[u8], version: &str) -> Artifact {
    Artifact::new(
        &ArtifactContext {
            channel: "stable".to_string(),
            project: PROJECT.to_string(),
            version: version.to_string(),
            platform: "debian".to_string(),
            platform_version: "13".to_string(),
        },
        ArtifactInput {
            basename: BASENAME.to_string(),
            sha256: sha256_hex(bytes),
            metadata_json: raw_metadata(bytes, version),
            platform: "debian".to_string(),
            platform_version: "13".to_string(),
            version: version.to_string(),
            iteration: Some("1".to_string()),
            raw_arch: "x86_64".to_string(),
        },
    )
    .expect("artifact")
}

fn target_for(mock: &MockRegistry) -> OciTarget {
    let registry = Registry::new(OciConfig {
        registry: mock.registry_name(),
        namespace: NAMESPACE.to_string(),
        auth: OciAuth::Anonymous,
        insecure_http: true,
        ..OciConfig::default()
    })
    .expect("mock registry")
    // The production backoff is 0.5/1/2 s; these tests assert outcomes, not
    // waits.
    .with_retry_base(Duration::ZERO);
    OciTarget::new("ghcr", registry)
}

fn write_package(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join(BASENAME);
    std::fs::write(&path, bytes).expect("write package");
    (dir, path)
}

fn target_config(name: &str, kind: TargetKind, enabled: bool, mock: &MockRegistry) -> TargetConfig {
    TargetConfig {
        name: name.to_string(),
        kind,
        enabled,
        registry: Some(mock.registry_name()),
        namespace: Some(NAMESPACE.to_string()),
        url: None,
        auth: TargetAuth::Anonymous,
        max_bandwidth: None,
        identity_file: None,
        password_file: None,
    }
}

fn config_with(targets: Vec<TargetConfig>) -> Config {
    Config {
        targets,
        ..Config::default()
    }
}

fn stored_manifest(mock: &MockRegistry, reference: &str) -> Value {
    let stored = mock
        .manifest(REPO, reference)
        .unwrap_or_else(|| panic!("manifest `{reference}` must be stored"));
    serde_json::from_slice(&stored.bytes).expect("stored manifest is JSON")
}

#[tokio::test]
async fn put_writes_expected_manifest_and_annotations() {
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let target = target_for(&mock);
    let bytes = b"the verified package bytes".as_slice();
    let artifact = artifact_for(bytes);
    let (_dir, path) = write_package(bytes);

    let outcome = target.put(&artifact, &path).await.expect("put");

    assert_eq!(
        outcome.remote_ref,
        format!("{}/{}:{}", mock.registry_name(), REPO, artifact.tag())
    );
    let stored = mock
        .manifest(REPO, &artifact.tag())
        .expect("manifest under the descriptive tag");
    assert_eq!(
        outcome.remote_digest, stored.digest,
        "put must report the manifest digest, not the package digest"
    );

    let manifest = stored_manifest(&mock, &artifact.tag());
    assert_eq!(manifest["schemaVersion"], json!(2));
    assert_eq!(
        manifest["mediaType"],
        json!("application/vnd.oci.image.manifest.v1+json")
    );
    assert_eq!(
        manifest["artifactType"],
        json!("application/vnd.cinc.package.v1+json")
    );

    let config = &manifest["config"];
    assert_eq!(
        config["mediaType"],
        json!("application/vnd.oci.empty.v1+json")
    );
    assert_eq!(config["digest"], json!(sha256_digest(b"{}")));
    assert_eq!(config["size"], json!(2));

    let layers = manifest["layers"].as_array().expect("layers are an array");
    assert_eq!(layers.len(), 2, "package first, metadata second");

    assert_eq!(layers[0]["mediaType"], json!("application/octet-stream"));
    assert_eq!(layers[0]["digest"], json!(sha256_digest(bytes)));
    assert_eq!(layers[0]["size"], json!(bytes.len()));
    assert_eq!(
        layers[0]["annotations"]["org.opencontainers.image.title"],
        json!(BASENAME)
    );

    assert_eq!(layers[1]["mediaType"], json!("application/json"));
    assert_eq!(
        layers[1]["annotations"]["org.opencontainers.image.title"],
        json!("metadata.json")
    );
    let metadata_digest = layers[1]["digest"].as_str().expect("metadata digest");
    let expected_metadata = raw_metadata(bytes, "19.4.46");
    let metadata_bytes = mock
        .blob(REPO, metadata_digest)
        .expect("the metadata layer blob is uploaded");
    assert_eq!(
        metadata_bytes,
        expected_metadata.as_bytes(),
        "the layer must carry the upstream document byte for byte"
    );
    assert_eq!(
        layers[1]["digest"],
        json!(sha256_digest(expected_metadata.as_bytes()))
    );
    assert_eq!(layers[1]["size"], json!(expected_metadata.len()));
    let metadata: Value = serde_json::from_slice(&metadata_bytes).expect("metadata is JSON");
    assert_eq!(metadata["basename"], json!(BASENAME));
    assert_eq!(metadata["sha256"], json!(sha256_hex(bytes)));
    assert_eq!(metadata["sha512"], json!("cdbbdd1d4be7454adc4c819dd5a0cb9d499b46913b7f4eb00910199d880632114006230221acfeea17b8f59da9bf62c00987d444bab3004b3e62914df292992a"));
    assert_eq!(metadata["arch"], json!("x86_64"));
    assert_eq!(metadata["platform"], json!("debian"));
    assert_eq!(metadata["platform_version"], json!("13"));
    assert_eq!(metadata["version"], json!("19.4.46"));
    assert_eq!(metadata["iteration"], json!(1), "numeric, not null");
    assert_eq!(metadata["license"], json!("Apache-2.0"));

    let annotations = &manifest["annotations"];
    assert_eq!(
        annotations["org.opencontainers.artifact.title"],
        json!(BASENAME)
    );
    assert_eq!(
        annotations["org.opencontainers.artifact.description.platform"],
        json!("debian")
    );
    assert_eq!(
        annotations["org.opencontainers.artifact.description.platform-version"],
        json!("13")
    );
    assert_eq!(
        annotations["org.opencontainers.artifact.description.machine"],
        json!("amd64")
    );
    assert_eq!(
        annotations["org.opencontainers.artifact.description.version"],
        json!("19.4.46")
    );

    assert_eq!(
        mock.blob(REPO, &sha256_digest(b"{}")),
        Some(b"{}".to_vec()),
        "the empty config blob must exist before the manifest"
    );
}

#[tokio::test]
async fn exists_returns_none_when_tag_missing() {
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let target = target_for(&mock);
    let artifact = artifact_for(b"never published");

    assert_eq!(target.exists(&artifact).await.expect("exists"), None);
    assert_eq!(
        mock.manifest_put_count(),
        0,
        "resolution must not write anything"
    );
}

#[tokio::test]
async fn exists_returns_digest_when_same_package() {
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let target = target_for(&mock);
    let bytes = b"the verified package bytes".as_slice();
    let artifact = artifact_for(bytes);
    let (_dir, path) = write_package(bytes);

    target.put(&artifact, &path).await.expect("put");

    assert_eq!(
        target.exists(&artifact).await.expect("exists"),
        Some(sha256_digest(bytes))
    );
}

#[tokio::test]
async fn put_is_idempotent_for_the_same_package() {
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let target = target_for(&mock);
    let bytes = b"the verified package bytes".as_slice();
    let artifact = artifact_for(bytes);
    let (_dir, path) = write_package(bytes);

    let first = target.put(&artifact, &path).await.expect("first put");
    let second = target.put(&artifact, &path).await.expect("second put");

    assert_eq!(second.remote_ref, first.remote_ref);
    assert_eq!(second.remote_digest, first.remote_digest);
    assert_eq!(
        mock.manifest_put_count(),
        1,
        "an identical package must not be re-pushed"
    );
}

#[tokio::test]
async fn put_refuses_to_overwrite_different_package() {
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let target = target_for(&mock);
    let original = b"the verified package bytes".as_slice();
    let artifact = artifact_for(original);
    let (_first_dir, first_path) = write_package(original);
    target.put(&artifact, &first_path).await.expect("first put");
    let uploads_after_first = mock.upload_starts();

    let replacement = b"different bytes at the same coordinates".as_slice();
    let conflicting = artifact_for(replacement);
    let (_second_dir, second_path) = write_package(replacement);

    let error = target
        .put(&conflicting, &second_path)
        .await
        .expect_err("a different package under the same tag must be refused");
    match error {
        TargetError::TagConflict {
            tag,
            existing,
            incoming,
        } => {
            assert_eq!(tag, artifact.tag());
            assert_eq!(existing, sha256_digest(original));
            assert_eq!(incoming, sha256_digest(replacement));
        }
        other => panic!("expected TagConflict, got {other:?}"),
    }

    assert_eq!(
        mock.manifest_put_count(),
        1,
        "a conflict must not write a manifest"
    );
    assert_eq!(
        mock.upload_starts(),
        uploads_after_first,
        "a conflict must be detected before any blob upload"
    );
    let manifest = stored_manifest(&mock, &artifact.tag());
    assert_eq!(
        manifest["layers"][0]["digest"],
        json!(sha256_digest(original)),
        "the canonical tag still holds the original bytes"
    );
}

#[tokio::test]
async fn verify_detects_missing_metadata_layer() {
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let target = target_for(&mock);
    let bytes = b"the verified package bytes".as_slice();
    let artifact = artifact_for(bytes);

    let package_only = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.cinc.package.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.empty.v1+json",
            "digest": sha256_digest(b"{}"),
            "size": 2
        },
        "layers": [{
            "mediaType": "application/octet-stream",
            "digest": sha256_digest(bytes),
            "size": bytes.len(),
            "annotations": {"org.opencontainers.image.title": BASENAME}
        }]
    });
    mock.store_manifest(
        REPO,
        &artifact.tag(),
        &serde_json::to_vec(&package_only).expect("manifest bytes"),
    );

    let error = target
        .verify(&artifact)
        .await
        .expect_err("a manifest without the metadata layer is incomplete");
    match error {
        TargetError::MissingLayer { tag, title } => {
            assert_eq!(tag, artifact.tag());
            assert_eq!(title, "metadata.json");
        }
        other => panic!("expected MissingLayer, got {other:?}"),
    }

    assert!(
        matches!(
            target
                .verify(&artifact_for_version(b"never published", "19.4.47"))
                .await
                .expect_err("missing tag is not published"),
            TargetError::NotPublished { .. }
        ),
        "an absent tag must report NotPublished"
    );
}

#[tokio::test]
async fn verify_accepts_the_manifest_that_put_wrote() {
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let target = target_for(&mock);
    let bytes = b"the verified package bytes".as_slice();
    let artifact = artifact_for(bytes);
    let (_dir, path) = write_package(bytes);

    target.put(&artifact, &path).await.expect("put");
    target.verify(&artifact).await.expect("verify");
}

#[tokio::test]
async fn superseded_artifact_uses_suffixed_tag() {
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let target = target_for(&mock);
    let bytes = b"the replacement bytes".as_slice();
    let artifact = artifact_for(bytes).with_superseded(true);
    let (_dir, path) = write_package(bytes);

    let outcome = target.put(&artifact, &path).await.expect("put");

    assert_eq!(
        outcome.remote_ref,
        format!(
            "{}/{}:{}",
            mock.registry_name(),
            REPO,
            artifact.superseded_tag()
        )
    );
    assert!(
        mock.manifest(REPO, &artifact.superseded_tag()).is_some(),
        "the replacement is stored under the suffixed tag"
    );
    assert!(
        mock.manifest(REPO, &artifact.tag()).is_none(),
        "the descriptive tag is left untouched"
    );
    assert_eq!(
        target.exists(&artifact).await.expect("exists"),
        Some(sha256_digest(bytes))
    );
}

#[tokio::test]
async fn ledger_round_trip_keeps_the_metadata_layer_digest() {
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let target = target_for(&mock);
    let bytes = b"the verified package bytes".as_slice();
    let fresh = artifact_for(bytes);
    let (_dir, path) = write_package(bytes);

    target.put(&fresh, &path).await.expect("fresh put");
    let fresh_digest = stored_manifest(&mock, &fresh.tag())["layers"][1]["digest"].clone();

    // Reconstruct the artifact the way a later run does: through the ledger,
    // which persists both the exact metadata text and the raw architecture.
    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    ledger
        .append(&Event {
            run_id: "run-1".to_string(),
            seq: 1,
            ts: chrono::Utc::now(),
            kind: EventKind::ArtifactSeen,
            artifact_key: Some(fresh.key()),
            target: None,
            detail: json!({
                "artifact": {
                    "channel": fresh.channel,
                    "project": fresh.project,
                    "version": fresh.version,
                    "platform": fresh.platform,
                    "platform_version": fresh.platform_version,
                    "arch": fresh.arch,
                    "raw_arch": fresh.raw_arch,
                    "basename": fresh.basename,
                    "sha256": fresh.sha256,
                    "metadata_json": fresh.metadata_json,
                    "iteration": fresh.iteration,
                },
                "size": bytes.len(),
            }),
        })
        .expect("artifact_seen");
    let reconstructed = ledger
        .artifact(&fresh.key())
        .expect("artifact query")
        .expect("artifact row")
        .artifact;

    assert_eq!(
        reconstructed, fresh,
        "the round trip must be field-identical"
    );

    let superseded = reconstructed.with_superseded(true);
    target
        .put(&superseded, &path)
        .await
        .expect("reconstructed put");
    let rebuilt_digest =
        stored_manifest(&mock, &superseded.superseded_tag())["layers"][1]["digest"].clone();
    assert_eq!(
        rebuilt_digest, fresh_digest,
        "a ledger-reconstructed artifact publishes the same metadata layer"
    );
}

#[tokio::test]
async fn put_skips_blobs_the_registry_already_has() {
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let target = target_for(&mock);
    let bytes = b"the verified package bytes".as_slice();
    let canonical = artifact_for(bytes);
    let superseded = artifact_for(bytes).with_superseded(true);
    let (_dir, path) = write_package(bytes);

    target.put(&canonical, &path).await.expect("canonical put");
    let uploads_after_canonical = mock.upload_starts();
    let heads_after_canonical = mock.blob_head_count();

    target
        .put(&superseded, &path)
        .await
        .expect("superseded put");

    assert_eq!(
        mock.upload_starts(),
        uploads_after_canonical,
        "the config, package and metadata blobs are already present"
    );
    assert!(
        mock.blob_head_count() >= heads_after_canonical + 3,
        "every layer is checked with HEAD before the manifest"
    );
    assert_eq!(mock.manifest_put_count(), 2);
}

#[tokio::test]
async fn verify_reports_a_conflict_for_a_different_package() {
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let target = target_for(&mock);
    let published = b"the published bytes".as_slice();
    let artifact = artifact_for(published);
    let (_dir, path) = write_package(published);
    target.put(&artifact, &path).await.expect("put");

    let different = artifact_for(b"different bytes at the same coordinates");
    let error = target
        .verify(&different)
        .await
        .expect_err("the tag holds a different package");
    assert!(matches!(
        error,
        TargetError::TagConflict {
            existing,
            incoming,
            ..
        } if existing == sha256_digest(published) && incoming == sha256_digest(b"different bytes at the same coordinates")
    ));
}

#[tokio::test]
async fn probe_checks_the_registry_without_writing() {
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let target = target_for(&mock);

    target.probe().await.expect("probe");

    let log = mock.request_log();
    assert!(
        log.iter()
            .any(|(method, path)| method == "GET" && (path == "/v2" || path == "/v2/")),
        "probe must ask the registry endpoint: {log:?}"
    );
    assert_eq!(mock.manifest_put_count(), 0);
    assert_eq!(mock.upload_starts(), 0);
}

#[tokio::test]
async fn target_set_builds_enabled_targets_in_config_order() {
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let config = config_with(vec![
        target_config("first", TargetKind::Oci, true, &mock),
        target_config("disabled", TargetKind::Oci, false, &mock),
        target_config("second", TargetKind::Oci, true, &mock),
    ]);

    let set = TargetSet::from_config(&config).expect("target set");
    let names: Vec<&str> = set.all().iter().map(|target| target.name()).collect();
    assert_eq!(names, vec!["first", "second"]);
}

#[tokio::test]
async fn target_set_builds_rsync_targets_too() {
    let root = tempfile::tempdir().expect("rsync root");
    let rsync = TargetConfig {
        name: "legacy".to_string(),
        kind: TargetKind::Rsync,
        enabled: true,
        registry: None,
        namespace: None,
        url: Some(root.path().to_string_lossy().into_owned()),
        auth: TargetAuth::Anonymous,
        max_bandwidth: None,
        identity_file: None,
        password_file: None,
    };

    let set = TargetSet::from_config(&config_with(vec![rsync])).expect("rsync target builds");
    let names: Vec<&str> = set.all().iter().map(|target| target.name()).collect();
    assert_eq!(names, vec!["legacy"]);
}
