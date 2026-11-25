//! Incident flow tests.
//!
//! Every test drives a real ledger in a temporary state directory, the shared
//! in-memory OCI registry, a local rsync directory and, where the GitHub issue
//! path is exercised, a wiremock server. The assertions look at what actually
//! happened: the bytes behind a tag or sidecar, the derived ledger rows, the
//! alert file and the requests that reached the issue API.

mod common;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{SecondsFormat, TimeZone, Utc};
use cinc_mirror::artifact::{Artifact, ArtifactContext, ArtifactInput};
use cinc_mirror::config::{Config, IncidentConfig, TargetAuth};
use cinc_mirror::incident::{self, IncidentError, IncidentKind, IncidentState};
use cinc_mirror::ledger::{self, Event, EventKind, Incident, Ledger, PublicationStatus};
use cinc_mirror::oci::{OciAuth, OciConfig, Registry};
use cinc_mirror::store::Store;
use cinc_mirror::targets::{
    OciTarget, PutOutcome, RsyncConfig, RsyncTarget, Target, TargetError, TargetSet,
};
use common::registry::{MockAuth, MockRegistry};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const NAMESPACE: &str = "cinc-mirror";
const PROJECT: &str = "cinc";
const REPO: &str = "cinc-mirror/cinc";
const BASENAME: &str = "cinc_19.4.46-1_amd64.deb";
const GITHUB_TOKEN: &str = "test-token-not-a-real-secret";

/// Environment variables are process-global; the tests that let `open` reach
/// the GitHub path hold this lock so one test cannot see another's token.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn env_lock() -> tokio::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().await
}

fn clear_github_env() {
    std::env::remove_var("GITHUB_TOKEN");
    std::env::remove_var("GITHUB_REPOSITORY");
    std::env::remove_var("GITHUB_ENV");
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The upstream document, mirroring the real `*.metadata.json`.
fn raw_metadata(bytes: &[u8], version: &str) -> String {
    format!(
        r#"{{
  "basename": "{BASENAME}",
  "sha256": "{}",
  "platform": "debian",
  "platform_version": "13",
  "arch": "x86_64",
  "name": "cinc",
  "version": "{version}",
  "iteration": 1
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

fn artifact_for(bytes: &[u8]) -> Artifact {
    artifact_for_version(bytes, "19.4.46")
}

fn config_with(state_dir: &Path, api_base: &str) -> Config {
    Config {
        state_dir: state_dir.to_path_buf(),
        incident: IncidentConfig {
            api_base: api_base.to_string(),
        },
        ..Config::default()
    }
}

fn oci_target(mock: &MockRegistry, name: &str) -> OciTarget {
    let registry = Registry::new(OciConfig {
        registry: mock.base_url().to_string(),
        namespace: NAMESPACE.to_string(),
        auth: OciAuth::Anonymous,
        insecure_http: true,
        ..OciConfig::default()
    })
    .expect("mock registry")
    .with_retry_base(Duration::ZERO);
    OciTarget::new(name, registry)
}

fn rsync_target(name: &str, root: &Path) -> RsyncTarget {
    RsyncTarget::new(RsyncConfig {
        name: name.to_string(),
        url: root.to_string_lossy().into_owned(),
        auth: TargetAuth::Anonymous,
        identity_file: None,
        password_file: None,
    })
    .expect("rsync target")
}

fn write_package(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("package dir");
    let path = dir.path().join(BASENAME);
    std::fs::write(&path, bytes).expect("write package");
    (dir, path)
}

fn store_blob(state_dir: &Path, bytes: &[u8]) -> (String, PathBuf) {
    let sha256 = sha256_hex(bytes);
    let store = Store::open(state_dir).expect("store");
    let partial = store.partial_path(&sha256).expect("partial path");
    std::fs::write(&partial, bytes).expect("write partial");
    let path = store.commit(&sha256, &partial).expect("commit blob");
    (sha256, path)
}

fn seen_event(run_id: &str, seq: u64, artifact: &Artifact) -> Event {
    Event {
        run_id: run_id.to_string(),
        seq,
        ts: Utc::now(),
        kind: EventKind::ArtifactSeen,
        artifact_key: Some(artifact.key()),
        target: None,
        detail: json!({
            "artifact": ledger::artifact_detail(artifact),
            "upstream_path": artifact.rsync_relpath(),
            "size": 1,
        }),
    }
}

/// Make `artifact` known to the ledger; incidents reference an artifact row.
fn seed_artifact(ledger: &mut Ledger, artifact: &Artifact) {
    let run_id = format!("seed-{}", artifact.key());
    ledger
        .append(&seen_event(&run_id, 1, artifact))
        .expect("artifact_seen");
}

fn published_event(
    run_id: &str,
    seq: u64,
    artifact: &Artifact,
    target: &str,
    outcome: &PutOutcome,
) -> Event {
    Event {
        run_id: run_id.to_string(),
        seq,
        ts: Utc::now(),
        kind: EventKind::Published,
        artifact_key: Some(artifact.key()),
        target: Some(target.to_string()),
        detail: json!({
            "remote_ref": outcome.remote_ref,
            "remote_digest": outcome.remote_digest,
        }),
    }
}

/// Publish `artifact` to `target` and record the publication in the ledger.
///
/// `seen` adds the `artifact_seen` row a hash-change detection needs; the
/// caller passes a gap-free sequence for one run.
async fn publish_and_record(
    ledger: &mut Ledger,
    target: &dyn Target,
    artifact: &Artifact,
    package: &Path,
    run_id: &str,
    seq: u64,
    seen: bool,
) -> PutOutcome {
    let outcome = target.put(artifact, package).await.expect("target put");
    if seen {
        ledger
            .append(&seen_event(run_id, seq, artifact))
            .expect("artifact_seen");
    }
    ledger
        .append(&published_event(
            run_id,
            if seen { seq + 1 } else { seq },
            artifact,
            target.name(),
            &outcome,
        ))
        .expect("published");
    outcome
}

fn package_digest_from_manifest(bytes: &[u8]) -> String {
    let manifest: Value = serde_json::from_slice(bytes).expect("manifest is JSON");
    manifest["layers"][0]["digest"]
        .as_str()
        .expect("package layer digest")
        .to_string()
}

fn sidecar(state_dir: &Path, artifact: &Artifact) -> String {
    let path = state_dir.join(format!("{}.sha256", artifact.rsync_relpath()));
    std::fs::read_to_string(path).expect("rsync sidecar")
}

async fn wiremock_github(server: &MockServer, status: u16) {
    let response = if status == 201 {
        ResponseTemplate::new(201).set_body_json(json!({
            "html_url": "https://github.example/owner/repo/issues/1"
        }))
    } else {
        ResponseTemplate::new(status)
    };
    Mock::given(method("POST"))
        .and(path("/repos/owner/repo/issues"))
        .and(header("authorization", format!("Bearer {GITHUB_TOKEN}")))
        .respond_with(response)
        .mount(server)
        .await;
}

/// A target that publishes normally but always fails the acknowledged
/// republish, so a test can prove the old canonical tag is restored.
struct FailingRepublish {
    inner: OciTarget,
}

#[async_trait]
impl Target for FailingRepublish {
    fn name(&self) -> &str {
        self.inner.name()
    }

    async fn probe(&self) -> Result<(), TargetError> {
        self.inner.probe().await
    }

    async fn exists(&self, artifact: &Artifact) -> Result<Option<String>, TargetError> {
        self.inner.exists(artifact).await
    }

    async fn put(&self, artifact: &Artifact, package: &Path) -> Result<PutOutcome, TargetError> {
        self.inner.put(artifact, package).await
    }

    async fn verify(&self, artifact: &Artifact) -> Result<(), TargetError> {
        self.inner.verify(artifact).await
    }

    async fn republish(
        &self,
        _artifact: &Artifact,
        _package: &Path,
    ) -> Result<PutOutcome, TargetError> {
        Err(TargetError::Command {
            command: "republish".to_string(),
            status: Some(1),
            stderr: "injected republish failure".to_string(),
        })
    }
}

async fn open_hash_change(
    ledger: &mut Ledger,
    config: &Config,
    old: &Artifact,
    new: &Artifact,
) -> Incident {
    incident::open(ledger, config, new, &old.sha256, IncidentKind::HashChanged)
        .await
        .expect("open incident")
}

#[tokio::test]
async fn hash_change_opens_incident_and_keeps_old_tag() {
    let _env = env_lock().await;
    clear_github_env();

    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let rsync_root = tempfile::tempdir().expect("rsync root");
    let targets = TargetSet::from_targets(vec![
        Arc::new(oci_target(&mock, "oci")),
        Arc::new(rsync_target("rsync", rsync_root.path())),
    ]);
    let config = config_with(state.path(), "https://api.github.com");

    let old_bytes = b"the old published package".as_slice();
    let new_bytes = b"the replacement package".as_slice();
    let old = artifact_for(old_bytes);
    let new = artifact_for(new_bytes);
    let (_old_dir, old_path) = write_package(old_bytes);

    publish_and_record(
        &mut ledger,
        targets.all()[0].as_ref(),
        &old,
        &old_path,
        "run-1",
        1,
        true,
    )
    .await;
    publish_and_record(
        &mut ledger,
        targets.all()[1].as_ref(),
        &old,
        &old_path,
        "run-1",
        3,
        false,
    )
    .await;

    let incident = open_hash_change(&mut ledger, &config, &old, &new).await;

    assert_eq!(incident.kind, IncidentKind::HashChanged);
    assert_eq!(incident.state, IncidentState::Open);
    assert_eq!(incident.old_sha256.as_deref(), Some(old.sha256.as_str()));
    assert_eq!(incident.new_sha256.as_deref(), Some(new.sha256.as_str()));
    assert_eq!(incident.artifact_key.as_deref(), Some(new.key().as_str()));

    let manifest = mock.manifest(REPO, &old.tag()).expect("old manifest");
    assert_eq!(
        package_digest_from_manifest(&manifest.bytes),
        format!("sha256:{}", old.sha256),
        "the canonical tag keeps the old bytes"
    );
    assert!(
        sidecar(rsync_root.path(), &old).starts_with(&old.sha256),
        "the canonical rsync sidecar keeps the old bytes"
    );

    assert_eq!(
        ledger
            .publication(&old.key(), "oci")
            .expect("old oci publication")
            .expect("row")
            .status,
        PublicationStatus::Published
    );
    assert_eq!(
        ledger
            .publication(&old.key(), "rsync")
            .expect("old rsync publication")
            .expect("row")
            .status,
        PublicationStatus::Published
    );
    assert_eq!(
        ledger
            .publication(&new.key(), "oci")
            .expect("new oci publication")
            .expect("row")
            .status,
        PublicationStatus::Pending,
        "the replacement is queued for its superseded publication"
    );
    assert_eq!(
        ledger
            .artifact(&old.key())
            .expect("old artifact")
            .expect("row")
            .superseded_by
            .as_deref(),
        Some(new.key().as_str())
    );

    let alert = state
        .path()
        .join("alerts")
        .join(format!("{}.json", incident.id));
    assert!(alert.is_file(), "a newly opened incident writes an alert");
}

#[tokio::test]
async fn new_bytes_are_published_only_under_the_superseded_tag() {
    let _env = env_lock().await;
    clear_github_env();

    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let targets = TargetSet::from_targets(vec![Arc::new(oci_target(&mock, "oci"))]);
    let config = config_with(state.path(), "https://api.github.com");

    let old_bytes = b"the old published package".as_slice();
    let new_bytes = b"the replacement package".as_slice();
    let old = artifact_for(old_bytes);
    let new = artifact_for(new_bytes);
    let (_old_dir, old_path) = write_package(old_bytes);
    let (_new_dir, new_path) = write_package(new_bytes);

    publish_and_record(
        &mut ledger,
        targets.all()[0].as_ref(),
        &old,
        &old_path,
        "run-1",
        1,
        true,
    )
    .await;
    open_hash_change(&mut ledger, &config, &old, &new).await;

    let superseded = new.clone().with_superseded(true);
    let outcome = targets.all()[0]
        .put(&superseded, &new_path)
        .await
        .expect("superseded put");
    assert_eq!(
        outcome.remote_ref,
        format!(
            "{}/{}:{}",
            mock.registry_name(),
            REPO,
            superseded.superseded_tag()
        )
    );

    let canonical = mock.manifest(REPO, &old.tag()).expect("old manifest");
    assert_eq!(
        package_digest_from_manifest(&canonical.bytes),
        format!("sha256:{}", old.sha256),
        "publishing the replacement must not move the canonical tag"
    );
    let replacement = mock
        .manifest(REPO, &superseded.superseded_tag())
        .expect("superseded manifest");
    assert_eq!(
        package_digest_from_manifest(&replacement.bytes),
        format!("sha256:{}", new.sha256)
    );
}

#[tokio::test]
async fn ack_without_republish_leaves_the_canonical_tag() {
    let _env = env_lock().await;
    clear_github_env();

    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let rsync_root = tempfile::tempdir().expect("rsync root");
    let targets = TargetSet::from_targets(vec![
        Arc::new(oci_target(&mock, "oci")),
        Arc::new(rsync_target("rsync", rsync_root.path())),
    ]);
    let config = config_with(state.path(), "https://api.github.com");

    let old_bytes = b"the old published package".as_slice();
    let new_bytes = b"the replacement package".as_slice();
    let old = artifact_for(old_bytes);
    let new = artifact_for(new_bytes);
    let (_old_dir, old_path) = write_package(old_bytes);

    publish_and_record(
        &mut ledger,
        targets.all()[0].as_ref(),
        &old,
        &old_path,
        "run-1",
        1,
        true,
    )
    .await;
    publish_and_record(
        &mut ledger,
        targets.all()[1].as_ref(),
        &old,
        &old_path,
        "run-1",
        3,
        false,
    )
    .await;
    let incident = open_hash_change(&mut ledger, &config, &old, &new).await;

    incident::ack(
        &mut ledger,
        &targets,
        &config,
        &incident.id,
        Some("checked upstream"),
        false,
    )
    .await
    .expect("ack without republish");

    let acked = incident::show(&ledger, &incident.id).expect("incident");
    assert_eq!(acked.state, IncidentState::Acked);
    assert_eq!(acked.ack_note.as_deref(), Some("checked upstream"));

    let manifest = mock.manifest(REPO, &old.tag()).expect("old manifest");
    assert_eq!(
        package_digest_from_manifest(&manifest.bytes),
        format!("sha256:{}", old.sha256),
        "ack without --republish keeps serving the old bytes"
    );
    assert!(sidecar(rsync_root.path(), &old).starts_with(&old.sha256));

    assert_eq!(
        ledger
            .publication(&old.key(), "oci")
            .expect("old oci publication")
            .expect("row")
            .status,
        PublicationStatus::Published,
        "without republish the old publication stays satisfied"
    );
    assert_eq!(
        ledger
            .publication(&new.key(), "oci")
            .expect("new oci publication")
            .expect("row")
            .status,
        PublicationStatus::Pending
    );
}

#[tokio::test]
async fn ack_with_republish_moves_tag_and_marks_old_publications_superseded() {
    let _env = env_lock().await;
    clear_github_env();

    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let rsync_root = tempfile::tempdir().expect("rsync root");
    let targets = TargetSet::from_targets(vec![
        Arc::new(oci_target(&mock, "oci")),
        Arc::new(rsync_target("rsync", rsync_root.path())),
    ]);
    let config = config_with(state.path(), "https://api.github.com");

    let old_bytes = b"the old published package".as_slice();
    let new_bytes = b"the replacement package".as_slice();
    let old = artifact_for(old_bytes);
    let new = artifact_for(new_bytes);
    let (_old_dir, old_path) = write_package(old_bytes);
    store_blob(state.path(), new_bytes);

    publish_and_record(
        &mut ledger,
        targets.all()[0].as_ref(),
        &old,
        &old_path,
        "run-1",
        1,
        true,
    )
    .await;
    publish_and_record(
        &mut ledger,
        targets.all()[1].as_ref(),
        &old,
        &old_path,
        "run-1",
        3,
        false,
    )
    .await;
    let incident = open_hash_change(&mut ledger, &config, &old, &new).await;

    incident::ack(
        &mut ledger,
        &targets,
        &config,
        &incident.id,
        Some("new bytes verified"),
        true,
    )
    .await
    .expect("ack with republish");

    let acked = incident::show(&ledger, &incident.id).expect("incident");
    assert_eq!(acked.state, IncidentState::Acked);
    assert_eq!(acked.ack_note.as_deref(), Some("new bytes verified"));

    let manifest = mock.manifest(REPO, &old.tag()).expect("canonical manifest");
    assert_eq!(
        package_digest_from_manifest(&manifest.bytes),
        format!("sha256:{}", new.sha256),
        "the canonical OCI tag moves to the replacement"
    );
    assert!(
        sidecar(rsync_root.path(), &new).starts_with(&new.sha256),
        "the canonical rsync sidecar moves to the replacement"
    );

    for target in ["oci", "rsync"] {
        assert_eq!(
            ledger
                .publication(&old.key(), target)
                .expect("old publication")
                .expect("row")
                .status,
            PublicationStatus::Superseded,
            "{target} must retire the old publication"
        );
        assert_eq!(
            ledger
                .publication(&new.key(), target)
                .expect("new publication")
                .expect("row")
                .status,
            PublicationStatus::Published,
            "{target} must record the acknowledged publication"
        );
    }

    assert!(!ledger
        .satisfied_keys("oci")
        .expect("satisfied keys")
        .contains(&old.key()));
    assert!(ledger
        .satisfied_keys("oci")
        .expect("satisfied keys")
        .contains(&new.key()));
    assert!(
        ledger.pending("oci").expect("pending").is_empty(),
        "repair and the next run have nothing left to publish"
    );
}

#[tokio::test]
async fn republish_failure_leaves_every_canonical_tag_and_publication_untouched() {
    let _env = env_lock().await;
    clear_github_env();

    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let targets = TargetSet::from_targets(vec![
        Arc::new(oci_target(&mock, "oci-good")),
        Arc::new(FailingRepublish {
            inner: oci_target(&mock, "oci-failing"),
        }),
    ]);
    let config = config_with(state.path(), "https://api.github.com");

    let old_bytes = b"the old published package".as_slice();
    let new_bytes = b"the replacement package".as_slice();
    let old = artifact_for(old_bytes);
    let new = artifact_for(new_bytes);
    let (_old_dir, old_path) = write_package(old_bytes);
    store_blob(state.path(), old_bytes);
    store_blob(state.path(), new_bytes);

    publish_and_record(
        &mut ledger,
        targets.all()[0].as_ref(),
        &old,
        &old_path,
        "run-1",
        1,
        true,
    )
    .await;
    publish_and_record(
        &mut ledger,
        targets.all()[1].as_ref(),
        &old,
        &old_path,
        "run-1",
        3,
        false,
    )
    .await;
    let incident = open_hash_change(&mut ledger, &config, &old, &new).await;

    let error = incident::ack(&mut ledger, &targets, &config, &incident.id, None, true)
        .await
        .expect_err("the failing target must abort the republish");
    assert!(matches!(error, IncidentError::RepublishFailed { .. }));

    let manifest = mock.manifest(REPO, &old.tag()).expect("canonical manifest");
    assert_eq!(
        package_digest_from_manifest(&manifest.bytes),
        format!("sha256:{}", old.sha256),
        "the old canonical tag is restored after a partial failure"
    );
    for target in ["oci-good", "oci-failing"] {
        assert_eq!(
            ledger
                .publication(&old.key(), target)
                .expect("old publication")
                .expect("row")
                .status,
            PublicationStatus::Published,
            "{target} keeps its old publication"
        );
    }
    assert_eq!(
        incident::show(&ledger, &incident.id)
            .expect("incident")
            .state,
        IncidentState::Open,
        "a failed republish does not acknowledge the incident"
    );
}

#[tokio::test]
async fn duplicate_detection_is_suppressed_and_the_issue_is_created_once() {
    let _env = env_lock().await;
    std::env::set_var("GITHUB_TOKEN", GITHUB_TOKEN);
    std::env::set_var("GITHUB_REPOSITORY", "owner/repo");
    std::env::remove_var("GITHUB_ENV");

    let server = MockServer::start().await;
    wiremock_github(&server, 201).await;

    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let targets = TargetSet::from_targets(vec![Arc::new(oci_target(&mock, "oci"))]);
    let config = config_with(state.path(), &server.uri());

    let old_bytes = b"the old published package".as_slice();
    let new_bytes = b"the replacement package".as_slice();
    let old = artifact_for(old_bytes);
    let new = artifact_for(new_bytes);
    let (_old_dir, old_path) = write_package(old_bytes);

    publish_and_record(
        &mut ledger,
        targets.all()[0].as_ref(),
        &old,
        &old_path,
        "run-1",
        1,
        true,
    )
    .await;

    let first = open_hash_change(&mut ledger, &config, &old, &new).await;
    assert_eq!(
        first.issue_url.as_deref(),
        Some("https://github.example/owner/repo/issues/1")
    );
    let events_after_first = ledger.event_count().expect("event count");
    let alert = state
        .path()
        .join("alerts")
        .join(format!("{}.json", first.id));
    assert!(alert.is_file());

    let second = open_hash_change(&mut ledger, &config, &old, &new).await;

    assert_eq!(second.id, first.id, "the detection triple dedupes");
    assert_eq!(
        ledger.event_count().expect("event count"),
        events_after_first,
        "a duplicate detection writes no event"
    );
    assert_eq!(
        std::fs::read_dir(state.path().join("alerts"))
            .expect("alerts dir")
            .count(),
        1,
        "a duplicate detection writes no second alert"
    );
    let requests = server.received_requests().await.expect("recorded requests");
    assert_eq!(
        requests.len(),
        1,
        "a duplicate detection creates no second issue"
    );
    let issue: Value = serde_json::from_slice(&requests[0].body).expect("issue payload is JSON");
    assert_eq!(
        issue["title"],
        format!("cinc-mirror: hash_changed for {}", old.rsync_relpath())
    );
    let body = issue["body"].as_str().expect("issue body");
    assert!(
        body.contains(&first.id),
        "the body names the ledger incident"
    );
    assert!(
        body.contains(&old.sha256),
        "the body carries the old digest"
    );
    assert!(
        body.contains(&new.sha256),
        "the body carries the new digest"
    );
    assert!(
        body.contains(
            &first
                .detected_at
                .to_rfc3339_opts(SecondsFormat::Millis, true)
        ),
        "the body carries the detection time"
    );
    assert_eq!(issue["labels"], json!(["security-incident"]));
}

#[tokio::test]
async fn security_alert_is_written_to_github_env_only_for_a_new_incident() {
    let _env = env_lock().await;
    clear_github_env();
    let env_file = tempfile::NamedTempFile::new().expect("github env file");
    std::env::set_var("GITHUB_ENV", env_file.path());

    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let config = config_with(state.path(), "https://api.github.com");
    let artifact = artifact_for_version(b"first", "19.4.46");
    seed_artifact(&mut ledger, &artifact);

    incident::open(
        &mut ledger,
        &config,
        &artifact,
        &"a".repeat(64),
        IncidentKind::TagConflict,
    )
    .await
    .expect("first detection");
    let after_first = std::fs::read_to_string(env_file.path()).expect("github env");
    assert_eq!(after_first.trim(), "SECURITY_ALERT=true");

    incident::open(
        &mut ledger,
        &config,
        &artifact,
        &"a".repeat(64),
        IncidentKind::TagConflict,
    )
    .await
    .expect("duplicate detection");
    assert_eq!(
        std::fs::read_to_string(env_file.path())
            .expect("github env")
            .matches("SECURITY_ALERT=true")
            .count(),
        1,
        "a duplicate detection does not append the alert again"
    );
}

#[tokio::test]
async fn github_issue_failure_does_not_fail_the_run() {
    let _env = env_lock().await;
    std::env::set_var("GITHUB_TOKEN", GITHUB_TOKEN);
    std::env::set_var("GITHUB_REPOSITORY", "owner/repo");
    std::env::remove_var("GITHUB_ENV");

    let server = MockServer::start().await;
    wiremock_github(&server, 500).await;

    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let targets = TargetSet::from_targets(vec![Arc::new(oci_target(&mock, "oci"))]);
    let config = config_with(state.path(), &server.uri());

    let old_bytes = b"the old published package".as_slice();
    let new_bytes = b"the replacement package".as_slice();
    let old = artifact_for(old_bytes);
    let new = artifact_for(new_bytes);
    let (_old_dir, old_path) = write_package(old_bytes);

    publish_and_record(
        &mut ledger,
        targets.all()[0].as_ref(),
        &old,
        &old_path,
        "run-1",
        1,
        true,
    )
    .await;

    let incident = open_hash_change(&mut ledger, &config, &old, &new).await;

    assert_eq!(incident.state, IncidentState::Open);
    assert!(
        incident.issue_url.is_none(),
        "a failed issue call is swallowed, not recorded"
    );
    assert!(
        state
            .path()
            .join("alerts")
            .join(format!("{}.json", incident.id))
            .is_file(),
        "the local alert is still written"
    );
}

#[tokio::test]
async fn github_issue_is_skipped_without_a_token_or_repo_and_uses_the_config_repo() {
    let _env = env_lock().await;
    let server = MockServer::start().await;
    wiremock_github(&server, 201).await;

    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let mut config = config_with(state.path(), &server.uri());

    // No token, even with a configured repo: skip.
    std::env::remove_var("GITHUB_TOKEN");
    std::env::set_var("GITHUB_REPOSITORY", "owner/repo");
    std::env::remove_var("GITHUB_ENV");
    let first = artifact_for_version(b"first", "19.4.46");
    seed_artifact(&mut ledger, &first);
    let no_token = incident::open(
        &mut ledger,
        &config,
        &first,
        &"a".repeat(64),
        IncidentKind::TagConflict,
    )
    .await
    .expect("open without token");
    assert!(no_token.issue_url.is_none());

    // Token but neither GITHUB_REPOSITORY nor issue_repo: skip.
    std::env::set_var("GITHUB_TOKEN", GITHUB_TOKEN);
    std::env::remove_var("GITHUB_REPOSITORY");
    config.issue_repo = None;
    let second = artifact_for_version(b"second", "19.4.47");
    seed_artifact(&mut ledger, &second);
    let no_repo = incident::open(
        &mut ledger,
        &config,
        &second,
        &"b".repeat(64),
        IncidentKind::TagConflict,
    )
    .await
    .expect("open without repo");
    assert!(no_repo.issue_url.is_none());

    // The configured repo is the fallback when the environment has none.
    config.issue_repo = Some("owner/repo".to_string());
    let third = artifact_for_version(b"third", "19.4.48");
    seed_artifact(&mut ledger, &third);
    let configured = incident::open(
        &mut ledger,
        &config,
        &third,
        &"c".repeat(64),
        IncidentKind::TagConflict,
    )
    .await
    .expect("open with configured repo");
    assert_eq!(
        configured.issue_url.as_deref(),
        Some("https://github.example/owner/repo/issues/1")
    );
    assert_eq!(
        server
            .received_requests()
            .await
            .expect("recorded requests")
            .len(),
        1,
        "only the incident with a token and a repo calls GitHub"
    );
}

#[test]
fn alert_file_is_json_and_redacted() {
    let state = tempfile::tempdir().expect("state dir");
    let old_sha = "a".repeat(64);
    let new_sha = "b".repeat(64);
    let incident = Incident {
        id: "hash_changed-0123456789abcdef".to_string(),
        artifact_key: Some(format!(
            "stable/{PROJECT}/19.4.46/debian/13/amd64/{new_sha}"
        )),
        kind: IncidentKind::HashChanged,
        old_sha256: Some(old_sha.clone()),
        new_sha256: Some(new_sha.clone()),
        detected_at: Utc
            .with_ymd_and_hms(2026, 11, 24, 12, 0, 0)
            .single()
            .expect("timestamp"),
        detail: json!({
            "upstream_path": format!("stable/{PROJECT}/19.4.46/debian/13/{BASENAME}"),
            "token": "ghp_this_must_not_be_written",
            "authorization": format!("Bearer {GITHUB_TOKEN}"),
        }),
        state: IncidentState::Open,
        issue_url: Some("https://github.example/owner/repo/issues/7".to_string()),
        ack_note: None,
    };

    let path = incident::write_alert(state.path(), &incident).expect("write alert");
    assert_eq!(
        path,
        state
            .path()
            .join("alerts")
            .join(format!("{}.json", incident.id))
    );

    let text = std::fs::read_to_string(&path).expect("alert file");
    let value: Value = serde_json::from_str(&text).expect("alert is JSON");
    assert_eq!(value["kind"], "hash_changed");
    assert_eq!(
        value["artifact_key"],
        incident.artifact_key.clone().unwrap()
    );
    assert_eq!(value["old_sha256"], old_sha);
    assert_eq!(value["new_sha256"], new_sha);
    assert_eq!(
        value["upstream_path"],
        format!("stable/{PROJECT}/19.4.46/debian/13/{BASENAME}")
    );
    assert_eq!(
        value["issue_url"],
        "https://github.example/owner/repo/issues/7"
    );
    assert!(value["detected_at"].as_str().is_some());

    assert!(!text.contains("ghp_this_must_not_be_written"));
    assert!(!text.contains(GITHUB_TOKEN));
    assert!(!text.to_ascii_lowercase().contains("token"));
    assert!(!text.to_ascii_lowercase().contains("authorization"));

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path)
            .expect("alert metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "alerts are private to the mirror user");
    }
}

#[tokio::test]
async fn incidents_list_shows_open_first_then_acked_newest_first() {
    let _env = env_lock().await;
    clear_github_env();

    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let config = config_with(state.path(), "https://api.github.com");
    let no_targets = TargetSet::from_targets(Vec::new());

    let first_artifact = artifact_for_version(b"first", "19.4.46");
    seed_artifact(&mut ledger, &first_artifact);
    let first = incident::open(
        &mut ledger,
        &config,
        &first_artifact,
        &"a".repeat(64),
        IncidentKind::TagConflict,
    )
    .await
    .expect("first incident");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let second_artifact = artifact_for_version(b"second", "19.4.47");
    seed_artifact(&mut ledger, &second_artifact);
    let second = incident::open(
        &mut ledger,
        &config,
        &second_artifact,
        &"b".repeat(64),
        IncidentKind::TagConflict,
    )
    .await
    .expect("second incident");
    incident::ack(
        &mut ledger,
        &no_targets,
        &config,
        &second.id,
        Some("expected"),
        false,
    )
    .await
    .expect("ack");
    tokio::time::sleep(Duration::from_millis(20)).await;
    let third_artifact = artifact_for_version(b"third", "19.4.48");
    seed_artifact(&mut ledger, &third_artifact);
    let third = incident::open(
        &mut ledger,
        &config,
        &third_artifact,
        &"c".repeat(64),
        IncidentKind::TagConflict,
    )
    .await
    .expect("third incident");

    let listed = incident::list(&ledger).expect("list");
    assert_eq!(
        listed
            .iter()
            .map(|item| item.id.as_str())
            .collect::<Vec<_>>(),
        vec![third.id.as_str(), first.id.as_str(), second.id.as_str()],
        "open incidents come first, newest first, then acknowledged ones"
    );

    assert_eq!(
        incident::show(&ledger, &first.id).expect("show").id,
        first.id
    );
    assert!(matches!(
        incident::show(&ledger, "missing"),
        Err(IncidentError::UnknownIncident { .. })
    ));
}
