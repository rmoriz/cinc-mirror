//! Bootstrap tests: import artifacts that predate the ledger.
//!
//! Every test drives a real ledger, a fake upstream (listings and metadata) and
//! the shared OCI registry mock. Nothing here downloads a package or writes to
//! the registry: bootstrap only reads the tag's package layer and records what
//! it found.

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use cinc_mirror::artifact::Artifact;
use cinc_mirror::bootstrap::{self, BootstrapError, BootstrapReport};
use cinc_mirror::config::{TargetAuth, TargetConfig, TargetKind};
use cinc_mirror::ctx::Ctx;
use cinc_mirror::ledger::{
    Event, EventKind, Incident, IncidentFilter, IncidentKind, IncidentState, Ledger, Publication,
    PublicationStatus,
};
use cinc_mirror::scope::{ResolvedPolicy, ResolvedScope};
use cinc_mirror::source::{Fetched, Fetcher, Source, SourceError};
use cinc_mirror::targets::TargetSet;
use common::mirror::{
    config_with, context_with, mock_registry, oci_target, package_artifact, rsync_target,
    sha256_hex,
};
use common::registry::MockRegistry;
use serde_json::json;
use tempfile::TempDir;
use url::Url;

const VERSION: &str = "19.4.46";
const BASE: &str = "https://downloads.cinc.sh/files";
const REPO: &str = "cinc-mirror/cinc";
const OCI: &str = "oci";
const RSYNC: &str = "rsync";

/// Environment variables are process-global; the conflict test clears them so a
/// developer's `GITHUB_TOKEN` cannot make the incident flow reach the network.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Clears the GitHub variables for the duration of one test and restores them
/// afterwards, so a developer's real values survive the suite.
struct GithubEnvGuard {
    token: Option<String>,
    repository: Option<String>,
    env_file: Option<String>,
}

impl GithubEnvGuard {
    fn clear() -> Self {
        let saved = Self {
            token: std::env::var("GITHUB_TOKEN").ok(),
            repository: std::env::var("GITHUB_REPOSITORY").ok(),
            env_file: std::env::var("GITHUB_ENV").ok(),
        };
        std::env::remove_var("GITHUB_TOKEN");
        std::env::remove_var("GITHUB_REPOSITORY");
        std::env::remove_var("GITHUB_ENV");
        saved
    }
}

impl Drop for GithubEnvGuard {
    fn drop(&mut self) {
        restore_env("GITHUB_TOKEN", self.token.as_deref());
        restore_env("GITHUB_REPOSITORY", self.repository.as_deref());
        restore_env("GITHUB_ENV", self.env_file.as_deref());
    }
}

fn restore_env(name: &str, value: Option<&str>) {
    match value {
        Some(value) => std::env::set_var(name, value),
        None => std::env::remove_var(name),
    }
}

/// `sha256:<hex>` of `bytes`.
fn digest(bytes: &[u8]) -> String {
    format!("sha256:{}", sha256_hex(bytes))
}

/// The upstream index pages and metadata document for one artifact.
fn upstream_pages(artifact: &Artifact) -> HashMap<String, String> {
    let root = format!("files/{}/{}", artifact.channel, artifact.project);
    let version_dir = format!("{root}/{}", artifact.version);
    let platform_dir = format!("{version_dir}/{}", artifact.platform);
    let release_dir = format!("{platform_dir}/{}", artifact.platform_version);
    let metadata_name = format!("{}.metadata.json", artifact.basename);

    let mut pages = HashMap::new();
    pages.insert(
        format!("{root}/"),
        listing(&[format!("{}/", artifact.version)]),
    );
    pages.insert(
        format!("{version_dir}/"),
        listing(&[format!("{}/", artifact.platform)]),
    );
    pages.insert(
        format!("{platform_dir}/"),
        listing(&[format!("{}/", artifact.platform_version)]),
    );
    pages.insert(
        format!("{release_dir}/"),
        listing(std::slice::from_ref(&metadata_name)),
    );
    pages.insert(
        format!("{release_dir}/{metadata_name}"),
        artifact.metadata_json.clone(),
    );
    pages
}

/// An Apache-style directory listing.
fn listing(names: &[String]) -> String {
    let mut body = String::from("<html><body>");
    for name in names {
        body.push_str(&format!(r#"<a href="{name}">{name}</a>"#));
    }
    body.push_str("</body></html>");
    body
}

/// A fake downstream upstream: pages and metadata by URL path.
struct FakeUpstream {
    pages: HashMap<String, String>,
}

#[async_trait]
impl Fetcher for FakeUpstream {
    async fn get(&self, url: &Url) -> Result<Fetched, SourceError> {
        let key = url.path().trim_start_matches('/').to_string();
        match self.pages.get(&key) {
            Some(body) => Ok(Fetched {
                body: body.clone(),
                final_url: url.clone(),
            }),
            None => Err(SourceError::HttpStatus {
                url: url.to_string(),
                status: 404,
            }),
        }
    }

    async fn head_len(&self, _url: &Url) -> Result<Option<u64>, SourceError> {
        Ok(None)
    }
}

fn source_for(artifact: &Artifact) -> Source {
    Source::with_fetcher(
        Arc::new(FakeUpstream {
            pages: upstream_pages(artifact),
        }),
        Url::parse(BASE).expect("base url"),
    )
}

fn scope() -> ResolvedScope {
    ResolvedScope {
        policies: vec![ResolvedPolicy {
            id: "cinc".to_string(),
            project: "cinc".to_string(),
            channel: "stable".to_string(),
            min_version: None,
            max_version: None,
            versions: Vec::new(),
            cli_versions: Vec::new(),
            platforms: cinc_mirror::config::Selection::All,
            platform_versions: Default::default(),
            cli_platform_versions: Vec::new(),
            arches: cinc_mirror::config::Selection::All,
            all_versions: false,
        }],
    }
}

fn target_config(name: &str, kind: TargetKind) -> TargetConfig {
    TargetConfig {
        name: name.to_string(),
        kind,
        enabled: true,
        registry: None,
        namespace: None,
        url: None,
        auth: TargetAuth::Anonymous,
        max_bandwidth: None,
        identity_file: None,
        password_file: None,
    }
}

/// A manifest shaped like the ones this mirror writes.
fn matching_manifest(artifact: &Artifact, bytes: &[u8]) -> Vec<u8> {
    json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "artifactType": "application/vnd.cinc.package.v1+json",
        "config": {
            "mediaType": "application/vnd.oci.empty.v1+json",
            "digest": digest(b"{}"),
            "size": 2,
        },
        "layers": [
            {
                "mediaType": "application/octet-stream",
                "digest": digest(bytes),
                "size": bytes.len(),
                "annotations": {"org.opencontainers.image.title": artifact.basename},
            },
            {
                "mediaType": "application/json",
                "digest": digest(artifact.metadata_json.as_bytes()),
                "size": artifact.metadata_json.len(),
                "annotations": {"org.opencontainers.image.title": "metadata.json"},
            },
        ],
        "annotations": {
            "org.opencontainers.artifact.title": artifact.basename,
            "org.opencontainers.artifact.description.platform": artifact.platform,
        },
    })
    .to_string()
    .into_bytes()
}

/// A legacy manifest: different media types, a different config descriptor,
/// different annotations and the metadata layer first.
fn legacy_manifest(artifact: &Artifact, package_digest: &str, package_size: usize) -> Vec<u8> {
    json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "digest": digest(b"legacy-config-document"),
            "size": 23,
        },
        "layers": [
            {
                "mediaType": "text/plain; charset=utf-8",
                "digest": digest(b"legacy-metadata-layer"),
                "size": 21,
                "annotations": {
                    "org.opencontainers.image.title": "metadata.json",
                    "com.example.legacy.layer": "yes",
                },
            },
            {
                "mediaType": "application/vnd.cinc.package.v1+json",
                "digest": package_digest,
                "size": package_size,
                "annotations": {
                    "org.opencontainers.image.title": artifact.basename,
                    "com.example.legacy.layer": "yes",
                },
            },
        ],
        "annotations": {
            "org.opencontainers.image.created": "2024-01-01T00:00:00Z",
            "com.example.legacy.manifest": "yes",
        },
    })
    .to_string()
    .into_bytes()
}

struct Fixture {
    ctx: Ctx,
    mock: MockRegistry,
    artifact: Artifact,
    bytes: Vec<u8>,
    _state: TempDir,
}

async fn fixture() -> Fixture {
    let state = tempfile::tempdir().expect("state dir");
    let bytes = b"the legacy package bytes".to_vec();
    let artifact = package_artifact(&bytes, VERSION);
    let mock = mock_registry().await;

    let rsync_root = state.path().join("rsync-target");
    std::fs::create_dir_all(&rsync_root).expect("rsync root");

    let mut config = config_with(state.path(), "http://127.0.0.1:9");
    config.targets = vec![
        target_config(OCI, TargetKind::Oci),
        target_config(RSYNC, TargetKind::Rsync),
    ];
    let targets = TargetSet::from_targets(vec![
        Arc::new(oci_target(&mock, OCI)),
        Arc::new(rsync_target(RSYNC, &rsync_root)),
    ]);
    let source = source_for(&artifact);
    let ledger = Ledger::open(state.path()).expect("ledger");
    let ctx = context_with(config, scope(), ledger, targets, source);

    Fixture {
        ctx,
        mock,
        artifact,
        bytes,
        _state: state,
    }
}

async fn event_list(ctx: &Ctx) -> Vec<Event> {
    ctx.ledger.lock().await.events().expect("events")
}

fn count_kind(events: &[Event], kind: EventKind) -> usize {
    events.iter().filter(|event| event.kind == kind).count()
}

async fn publication(ctx: &Ctx, key: &str, target: &str) -> Option<Publication> {
    ctx.ledger
        .lock()
        .await
        .publication(key, target)
        .expect("publication")
}

async fn incidents(ctx: &Ctx, kind: IncidentKind) -> Vec<Incident> {
    ctx.ledger
        .lock()
        .await
        .incidents(IncidentFilter {
            kind: Some(kind),
            ..IncidentFilter::default()
        })
        .expect("incidents")
}

#[tokio::test]
async fn imports_tag_when_layer_digest_matches_upstream_sha() {
    let fixture = fixture().await;
    let manifest = matching_manifest(&fixture.artifact, &fixture.bytes);
    fixture
        .mock
        .store_manifest(REPO, &fixture.artifact.tag(), &manifest);

    let report = bootstrap::run(&fixture.ctx).await.expect("bootstrap");

    assert_eq!(
        report,
        BootstrapReport {
            imported: 1,
            skipped: 0,
            conflicts: 0,
        }
    );
    assert!(report.to_string().contains("1 imported"));

    let key = fixture.artifact.key();
    let publication = publication(&fixture.ctx, &key, OCI)
        .await
        .expect("the import records a publication");
    assert_eq!(publication.status, PublicationStatus::Published);

    let events = event_list(&fixture.ctx).await;
    assert_eq!(count_kind(&events, EventKind::ArtifactSeen), 1);
    assert_eq!(count_kind(&events, EventKind::Imported), 1);

    assert_eq!(
        fixture.mock.manifest_put_count(),
        0,
        "bootstrap never pushes"
    );
    assert_eq!(
        fixture
            .mock
            .manifest(REPO, &fixture.artifact.tag())
            .expect("manifest")
            .bytes,
        manifest,
        "the existing manifest is untouched"
    );
}

#[tokio::test]
async fn skips_already_imported_rows() {
    let mut fixture = fixture().await;
    let manifest = matching_manifest(&fixture.artifact, &fixture.bytes);
    fixture
        .mock
        .store_manifest(REPO, &fixture.artifact.tag(), &manifest);

    let first = bootstrap::run(&fixture.ctx).await.expect("first bootstrap");
    assert_eq!(first.imported, 1);

    // Idempotence is across runs: each run must use its own event namespace.
    fixture.ctx.run_id = "bootstrap-second-run".to_string();
    let second = bootstrap::run(&fixture.ctx)
        .await
        .expect("second bootstrap");

    assert_eq!(
        second,
        BootstrapReport::default(),
        "an imported row is skipped silently"
    );
    assert_eq!(
        count_kind(&event_list(&fixture.ctx).await, EventKind::Imported),
        1,
        "the second run appends no imported event"
    );
    assert_eq!(fixture.mock.manifest_put_count(), 0);
}

#[tokio::test]
async fn a_reused_run_id_is_refused_before_writing_anything() {
    let fixture = fixture().await;
    let manifest = matching_manifest(&fixture.artifact, &fixture.bytes);
    fixture
        .mock
        .store_manifest(REPO, &fixture.artifact.tag(), &manifest);

    let first = bootstrap::run(&fixture.ctx).await.expect("first bootstrap");
    assert_eq!(first.imported, 1);
    let events_before = event_list(&fixture.ctx).await.len();

    let error = bootstrap::run(&fixture.ctx)
        .await
        .expect_err("a reused run id must not be accepted");
    match error {
        BootstrapError::RunIdReused { run_id } => {
            assert_eq!(run_id, fixture.ctx.run_id);
        }
        other => panic!("expected RunIdReused, got {other:?}"),
    }

    assert_eq!(
        event_list(&fixture.ctx).await.len(),
        events_before,
        "the refused run appended nothing"
    );
    assert_eq!(
        count_kind(&event_list(&fixture.ctx).await, EventKind::Imported),
        1,
        "no duplicate import was recorded"
    );
    assert_eq!(fixture.mock.manifest_put_count(), 0);
}

#[tokio::test]
async fn reports_conflict_when_layer_differs() {
    let _env = ENV_LOCK.lock().await;
    let _github = GithubEnvGuard::clear();

    let mut fixture = fixture().await;
    let other = digest(b"some other package published under the tag");
    let manifest = legacy_manifest(&fixture.artifact, &other, 42);
    fixture
        .mock
        .store_manifest(REPO, &fixture.artifact.tag(), &manifest);

    let report = bootstrap::run(&fixture.ctx).await.expect("bootstrap");

    assert_eq!(
        report,
        BootstrapReport {
            imported: 0,
            skipped: 0,
            conflicts: 1,
        }
    );

    let found = incidents(&fixture.ctx, IncidentKind::TagConflict).await;
    assert_eq!(found.len(), 1, "one deduplicated incident");
    assert_eq!(found[0].state, IncidentState::Open);
    assert_eq!(found[0].old_sha256.as_deref(), Some(other.as_str()));
    assert_eq!(
        found[0].new_sha256.as_deref(),
        Some(fixture.artifact.sha256.as_str())
    );

    assert!(
        publication(&fixture.ctx, &fixture.artifact.key(), OCI)
            .await
            .is_none(),
        "a conflict records no publication"
    );
    assert_eq!(
        fixture
            .mock
            .manifest(REPO, &fixture.artifact.tag())
            .expect("manifest")
            .bytes,
        manifest,
        "nothing is overwritten"
    );
    assert_eq!(fixture.mock.manifest_put_count(), 0);
    assert_eq!(
        count_kind(&event_list(&fixture.ctx).await, EventKind::Imported),
        0
    );

    // A rerun of the conflict uses a fresh event namespace.
    fixture.ctx.run_id = "bootstrap-conflict-rerun".to_string();
    let again = bootstrap::run(&fixture.ctx)
        .await
        .expect("second bootstrap");
    assert_eq!(again.conflicts, 1, "the conflict is reported again");
    assert_eq!(
        incidents(&fixture.ctx, IncidentKind::TagConflict)
            .await
            .len(),
        1,
        "the incident is deduplicated"
    );
}

#[tokio::test]
async fn missing_tag_is_not_an_error() {
    let fixture = fixture().await;

    let report = bootstrap::run(&fixture.ctx).await.expect("bootstrap");

    assert_eq!(
        report,
        BootstrapReport {
            imported: 0,
            skipped: 1,
            conflicts: 0,
        }
    );
    assert!(
        fixture
            .ctx
            .ledger
            .lock()
            .await
            .artifacts()
            .unwrap()
            .is_empty(),
        "a missing tag records no artifact row"
    );
    assert!(fixture
        .ctx
        .ledger
        .lock()
        .await
        .publications(OCI)
        .unwrap()
        .is_empty());
    assert_eq!(fixture.mock.manifest_put_count(), 0);
}

#[tokio::test]
async fn legacy_manifest_with_other_annotations_is_compatible() {
    let fixture = fixture().await;
    let package_digest = digest(&fixture.bytes);
    let manifest = legacy_manifest(&fixture.artifact, &package_digest, fixture.bytes.len());
    fixture
        .mock
        .store_manifest(REPO, &fixture.artifact.tag(), &manifest);

    let report = bootstrap::run(&fixture.ctx).await.expect("bootstrap");

    assert_eq!(report.imported, 1);
    assert_eq!(report.skipped, 0);
    assert_eq!(report.conflicts, 0);

    let key = fixture.artifact.key();
    let publication = publication(&fixture.ctx, &key, OCI)
        .await
        .expect("publication");
    assert_eq!(publication.status, PublicationStatus::Published);
    assert_eq!(
        fixture
            .mock
            .manifest(REPO, &fixture.artifact.tag())
            .expect("manifest")
            .bytes,
        manifest,
        "the legacy manifest stays as it was"
    );
    assert_eq!(fixture.mock.manifest_put_count(), 0);
}

#[tokio::test]
async fn rsync_targets_are_ignored() {
    let fixture = fixture().await;

    let report = bootstrap::run(&fixture.ctx).await.expect("bootstrap");

    assert_eq!(
        report,
        BootstrapReport {
            imported: 0,
            skipped: 1,
            conflicts: 0,
        },
        "only the OCI target is resolved"
    );
    assert!(fixture
        .ctx
        .ledger
        .lock()
        .await
        .publications(RSYNC)
        .unwrap()
        .is_empty());
    let events = event_list(&fixture.ctx).await;
    assert_eq!(
        events.len(),
        2,
        "an ignored rsync target records only the run pair"
    );
    assert_eq!(count_kind(&events, EventKind::RunStarted), 1);
    assert_eq!(count_kind(&events, EventKind::RunFinished), 1);
    assert_eq!(count_kind(&events, EventKind::Imported), 0);
    assert_eq!(count_kind(&events, EventKind::IncidentOpened), 0);
}
