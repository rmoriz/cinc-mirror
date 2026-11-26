//! Fixtures shared by the verification and repair integration tests.
//!
//! Every test drives a real ledger in a temporary state directory, the shared
//! OCI registry mock, a real rsync target on a local directory, and an injected
//! payload ladder for the cases where repair must (or must not) fetch bytes.
//! The helpers build the same [`crate::Ctx`] a command would build, so the test
//! exercises the production wiring rather than a parallel one.

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use cinc_mirror::artifact::{Artifact, ArtifactContext, ArtifactInput};
use cinc_mirror::config::{
    Config, IncidentConfig, RetentionConfig, TargetAuth, TargetConfig, TargetKind, TransportKind,
};
use cinc_mirror::ctx::Ctx;
use cinc_mirror::ledger::{Event, EventKind, Ledger};
use cinc_mirror::net::RateLimiter;
use cinc_mirror::oci::{OciAuth, OciConfig, Registry};
use cinc_mirror::scope::ResolvedScope;
use cinc_mirror::source::transport::{PayloadTransport, RetryPolicy, TransportError};
use cinc_mirror::source::{Fetched, Fetcher, Source, SourceError};
use cinc_mirror::store::Store;
use cinc_mirror::targets::{
    OciTarget, PutOutcome, RsyncConfig, RsyncTarget, Target, TargetError, TargetSet,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;
use url::Url;

use super::registry::{MockAuth, MockRegistry};

/// Namespace the mock registry serves.
pub const NAMESPACE: &str = "cinc-mirror";
/// Upstream project used by every fixture.
pub const PROJECT: &str = "cinc";

/// Lowercase hex SHA-256 of `bytes`.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// The upstream `*.metadata.json` document matching `bytes`.
pub fn raw_metadata(bytes: &[u8], version: &str) -> String {
    format!(
        r#"{{
  "basename": "cinc_{version}-1_amd64.deb",
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

/// A validated artifact for `bytes` at `version`.
pub fn package_artifact(bytes: &[u8], version: &str) -> Artifact {
    Artifact::new(
        &ArtifactContext {
            channel: "stable".to_string(),
            project: PROJECT.to_string(),
            version: version.to_string(),
            platform: "debian".to_string(),
            platform_version: "13".to_string(),
        },
        ArtifactInput {
            basename: format!("cinc_{version}-1_amd64.deb"),
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

/// Write `bytes` to a temporary package file.
pub fn write_package(bytes: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("package dir");
    let path = dir
        .path()
        .join(format!("cinc_{}-1_amd64.deb", sha256_hex(bytes)));
    std::fs::write(&path, bytes).expect("write package");
    (dir, path)
}

/// Commit `bytes` into the store and return the blob address.
pub fn store_blob(state_dir: &Path, bytes: &[u8]) -> PathBuf {
    let sha256 = sha256_hex(bytes);
    let store = Store::open(state_dir).expect("store");
    let partial = store.partial_path(&sha256).expect("partial path");
    std::fs::write(&partial, bytes).expect("write partial");
    store.commit(&sha256, &partial).expect("commit blob")
}

/// Seed an `artifact_seen` event and, when `size` is given, a `verified` event
/// that records the local blob as present.
pub fn seed_artifact(ledger: &mut Ledger, artifact: &Artifact, size: Option<u64>) {
    let run_id = format!("seed-{}", artifact.key());
    ledger
        .append(
            &Event::new(run_id.clone(), 1, Utc::now(), EventKind::ArtifactSeen)
                .with_artifact(artifact.key())
                .with_detail(json!({
                    "artifact": cinc_mirror::ledger::artifact_detail(artifact),
                    "upstream_path": artifact.rsync_relpath(),
                    "size": size,
                })),
        )
        .expect("artifact_seen");
    if let Some(size) = size {
        ledger
            .append(
                &Event::new(run_id, 2, Utc::now(), EventKind::Verified)
                    .with_artifact(artifact.key())
                    .with_detail(json!({"size": size})),
            )
            .expect("verified");
    }
}

/// Seed a `published` event for `artifact` on `target`.
pub fn seed_published(ledger: &mut Ledger, artifact: &Artifact, target: &str, seq: u64) {
    ledger
        .append(
            &Event::new(
                format!("publish-{}", artifact.key()),
                seq,
                Utc::now(),
                EventKind::Published,
            )
            .with_artifact(artifact.key())
            .with_target(target)
            .with_detail(json!({
                "remote_ref": format!("{target}:{}", artifact.tag()),
                "remote_digest": artifact.sha256,
            })),
        )
        .expect("published");
}

/// Configuration with the temporary state directory and an issue API override.
pub fn config_with(state_dir: &Path, api_base: &str) -> Config {
    Config {
        state_dir: state_dir.to_path_buf(),
        incident: IncidentConfig {
            api_base: api_base.to_string(),
            ..IncidentConfig::default()
        },
        ..Config::default()
    }
}

/// A [`TargetConfig`] for `mock`, pointing at its namespace [`NAMESPACE`].
pub fn oci_target_config(mock: &MockRegistry, name: &str) -> TargetConfig {
    TargetConfig {
        name: name.to_string(),
        kind: TargetKind::Oci,
        enabled: true,
        registry: Some(mock.base_url().to_string()),
        namespace: Some(NAMESPACE.to_string()),
        url: None,
        auth: TargetAuth::Anonymous,
        max_bandwidth: None,
        identity_file: None,
        password_file: None,
    }
}

/// A [`TargetConfig`] for the GitHub Packages API on `ghcr.io`.
///
/// The registry name is the real GHCR host, so the delete mode resolves to the
/// packages backend; the API root comes from the test configuration, which
/// points at the packages mock.
pub fn packages_target_config(name: &str, namespace: &str) -> TargetConfig {
    TargetConfig {
        name: name.to_string(),
        kind: TargetKind::Oci,
        enabled: true,
        registry: Some("ghcr.io".to_string()),
        namespace: Some(namespace.to_string()),
        url: None,
        auth: TargetAuth::Anonymous,
        max_bandwidth: None,
        identity_file: None,
        password_file: None,
    }
}

/// Configuration with retention enabled against `api_base` and one target.
pub fn config_with_retention(state_dir: &Path, api_base: &str, target: TargetConfig) -> Config {
    Config {
        targets: vec![target],
        retention: RetentionConfig {
            prune: true,
            api_base: api_base.to_string(),
            ..RetentionConfig::default()
        },
        ..config_with(state_dir, "https://api.github.com")
    }
}

/// An OCI target backed by the shared in-memory registry.
pub fn oci_target(mock: &MockRegistry, name: &str) -> OciTarget {
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

/// An rsync target rooted at a local directory.
pub fn rsync_target(name: &str, root: &Path) -> RsyncTarget {
    RsyncTarget::new(RsyncConfig {
        name: name.to_string(),
        url: root.to_string_lossy().into_owned(),
        auth: TargetAuth::Anonymous,
        identity_file: None,
        password_file: None,
    })
    .expect("rsync target")
}

/// Publish `artifact` to `target` from a fresh package file.
pub async fn publish(target: &dyn Target, artifact: &Artifact, bytes: &[u8]) -> PutOutcome {
    let (_dir, path) = write_package(bytes);
    target.put(artifact, &path).await.expect("target put")
}

/// Build the [`Ctx`] a command would build, with default config and scope.
pub fn context(state_dir: &Path, ledger: Ledger, targets: TargetSet, source: Source) -> Ctx {
    context_with(
        config_with(state_dir, "https://api.github.com"),
        ResolvedScope::default(),
        ledger,
        targets,
        source,
    )
}

/// Build a [`Ctx`] with an explicit configuration and resolved scope.
pub fn context_with(
    config: Config,
    scope: ResolvedScope,
    ledger: Ledger,
    targets: TargetSet,
    source: Source,
) -> Ctx {
    let state_dir = config.state_dir.clone();
    Ctx {
        config: Arc::new(config),
        scope,
        source,
        store: Store::open(&state_dir).expect("store"),
        ledger: AsyncMutex::new(ledger),
        targets,
        rate: RateLimiter::new(None),
        run_id: "verify-repair-test".to_string(),
        state_dir,
    }
}

/// A fetcher that must never be used: verification and repair use the payload
/// ladder directly.
pub struct UnusedFetcher;

#[async_trait]
impl Fetcher for UnusedFetcher {
    async fn get(&self, url: &Url) -> Result<Fetched, SourceError> {
        Err(SourceError::Config {
            reason: format!("tests must not fetch {url}"),
        })
    }

    async fn head_len(&self, _url: &Url) -> Result<Option<u64>, SourceError> {
        Ok(None)
    }
}

/// A source whose payload ladder is exactly `transports`.
pub fn source_with(transports: Vec<Arc<dyn PayloadTransport>>) -> Source {
    Source::with_fetcher(
        Arc::new(UnusedFetcher),
        Url::parse("https://downloads.cinc.sh/files").expect("base url"),
    )
    .with_payload_transports(transports)
    .with_retry_policy(RetryPolicy::new(1, Duration::ZERO))
}

/// What an injected payload rung does.
enum TransportMode {
    /// Serve these bytes, honouring the resume offset.
    Serve(Vec<u8>),
    /// Report the object as permanently gone.
    Gone,
    /// Fail every attempt with a retryable transport error.
    Failing,
}

/// An injected payload rung that records how often it was asked for bytes.
pub struct FakeTransport {
    mode: TransportMode,
    calls: AtomicUsize,
}

impl FakeTransport {
    /// A rung that serves `bytes`.
    #[must_use]
    pub fn serving(bytes: Vec<u8>) -> Arc<Self> {
        Arc::new(Self {
            mode: TransportMode::Serve(bytes),
            calls: AtomicUsize::new(0),
        })
    }

    /// A rung that answers `Not Found` for every request.
    #[must_use]
    pub fn gone() -> Arc<Self> {
        Arc::new(Self {
            mode: TransportMode::Gone,
            calls: AtomicUsize::new(0),
        })
    }

    /// A rung that fails every attempt with a retryable error.
    #[must_use]
    pub fn failing() -> Arc<Self> {
        Arc::new(Self {
            mode: TransportMode::Failing,
            calls: AtomicUsize::new(0),
        })
    }

    /// How many transfers were attempted.
    #[must_use]
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl PayloadTransport for FakeTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Https
    }

    async fn fetch(
        &self,
        remote_path: &str,
        dest: &Path,
        resume_from: u64,
    ) -> Result<u64, TransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.mode {
            TransportMode::Serve(body) => {
                let start = usize::try_from(resume_from)
                    .expect("resume offset")
                    .min(body.len());
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(dest)
                    .map_err(|source| TransportError::Local {
                        path: dest.display().to_string(),
                        source,
                    })?;
                file.write_all(&body[start..])
                    .map_err(|source| TransportError::Local {
                        path: dest.display().to_string(),
                        source,
                    })?;
                Ok((body.len() - start) as u64)
            }
            TransportMode::Gone => Err(TransportError::NotFound {
                path: remote_path.to_string(),
            }),
            TransportMode::Failing => Err(TransportError::Retryable {
                path: remote_path.to_string(),
                reason: "injected transport failure".to_string(),
            }),
        }
    }
}

/// An rsync target that records the artifacts it was asked to verify.
///
/// Sampling asserts which artifacts were checked, which is observable only at
/// the target boundary; everything else is the real rsync target.
pub struct RecordingTarget {
    inner: RsyncTarget,
    verified: Mutex<Vec<String>>,
    puts: AtomicUsize,
}

impl RecordingTarget {
    /// Wrap a local rsync target.
    pub fn new(name: &str, root: &Path) -> Arc<Self> {
        Arc::new(Self {
            inner: rsync_target(name, root),
            verified: Mutex::new(Vec::new()),
            puts: AtomicUsize::new(0),
        })
    }

    /// Artifact keys verified since the last [`RecordingTarget::clear`].
    #[must_use]
    pub fn verified(&self) -> Vec<String> {
        self.verified.lock().expect("verified lock").clone()
    }

    /// How many `put` calls were attempted since the last
    /// [`RecordingTarget::clear`].
    #[must_use]
    pub fn puts(&self) -> usize {
        self.puts.load(Ordering::SeqCst)
    }

    /// Forget the recorded verifications and puts.
    pub fn clear(&self) {
        self.verified.lock().expect("verified lock").clear();
        self.puts.store(0, Ordering::SeqCst);
    }
}

#[async_trait]
impl Target for RecordingTarget {
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
        self.puts.fetch_add(1, Ordering::SeqCst);
        self.inner.put(artifact, package).await
    }

    async fn republish(
        &self,
        artifact: &Artifact,
        package: &Path,
    ) -> Result<PutOutcome, TargetError> {
        self.inner.republish(artifact, package).await
    }

    async fn preserve_superseded(&self, artifact: &Artifact) -> Result<(), TargetError> {
        self.inner.preserve_superseded(artifact).await
    }

    async fn verify(&self, artifact: &Artifact) -> Result<(), TargetError> {
        let result = self.inner.verify(artifact).await;
        self.verified
            .lock()
            .expect("verified lock")
            .push(artifact.key());
        result
    }
}

/// Start the shared OCI registry mock with anonymous access.
pub async fn mock_registry() -> MockRegistry {
    MockRegistry::start(MockAuth::Anonymous).await
}
