//! Runner tests: queue ordering, limits, fan-out, resume and pacing.
//!
//! Nothing here reaches upstream. Listings and metadata come from a fake
//! `Fetcher`, package bytes from an instrumented fake transport, and the
//! fan-out test drives the shared OCI mock and a local rsync directory. Every
//! assertion looks at observable state: the queue order, the bytes that reached
//! a target, the ledger rows and the events the run appended.

mod common;

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use cinc_mirror::artifact::{Artifact, ArtifactContext, ArtifactInput};
use cinc_mirror::config::{Config, Selection, TargetAuth};
use cinc_mirror::ctx::Ctx;
use cinc_mirror::hash::{hash_file, hash_reader};
use cinc_mirror::ledger::{
    self, Event, EventKind, IncidentFilter, IncidentKind, Ledger, PublicationStatus,
};
use cinc_mirror::net::RateLimiter;
use cinc_mirror::oci::{OciAuth, OciConfig, OciError, Registry};
use cinc_mirror::runner::{run, Order, RunError, RunOpts};
use cinc_mirror::scope::{ResolvedPolicy, ResolvedScope};
use cinc_mirror::source::transport::{PayloadTransport, RetryPolicy, TransportError};
use cinc_mirror::source::{Fetched, Fetcher, Source, SourceError};
use cinc_mirror::store::Store;
use cinc_mirror::targets::{
    OciTarget, PutOutcome, RsyncConfig, RsyncTarget, Target, TargetError, TargetSet,
};
use common::registry::{MockAuth, MockRegistry};
use serde_json::json;
use tempfile::TempDir;
use url::Url;

const BASE: &str = "https://downloads.cinc.sh/files";
const NAMESPACE: &str = "cinc-mirror";
const REPO: &str = "cinc-mirror/cinc";

/// One package the fake upstream publishes.
#[derive(Debug, Clone)]
struct Spec {
    version: String,
    platform: String,
    platform_version: String,
    basename: String,
    arch: String,
    body: Vec<u8>,
}

impl Spec {
    fn new(version: &str, basename: &str, body: &[u8]) -> Self {
        Self {
            version: version.to_string(),
            platform: "debian".to_string(),
            platform_version: "13".to_string(),
            basename: basename.to_string(),
            arch: "x86_64".to_string(),
            body: body.to_vec(),
        }
    }

    /// Publish this package under a different raw architecture, so two specs
    /// can share a directory (the arch collision case).
    fn with_raw_arch(mut self, arch: &str) -> Self {
        self.arch = arch.to_string();
        self
    }

    fn upstream_path(&self) -> String {
        format!(
            "stable/cinc/{}/{}/{}/{}",
            self.version, self.platform, self.platform_version, self.basename
        )
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    hash_reader(bytes).expect("hash fixture").sha256
}

fn metadata_json(spec: &Spec) -> String {
    json!({
        "basename": spec.basename,
        "sha256": sha256_hex(&spec.body),
        "platform": spec.platform,
        "platform_version": spec.platform_version,
        "arch": spec.arch,
        "version": spec.version,
        "iteration": 1,
        "unknown_field": "tolerated",
    })
    .to_string()
}

/// The ledger row a crawl of `spec` produces.
fn artifact_of(spec: &Spec) -> Artifact {
    Artifact::new(
        &ArtifactContext {
            channel: "stable".to_string(),
            project: "cinc".to_string(),
            version: spec.version.clone(),
            platform: spec.platform.clone(),
            platform_version: spec.platform_version.clone(),
        },
        ArtifactInput {
            basename: spec.basename.clone(),
            sha256: sha256_hex(&spec.body),
            metadata_json: metadata_json(spec),
            platform: spec.platform.clone(),
            platform_version: spec.platform_version.clone(),
            version: spec.version.clone(),
            iteration: Some("1".to_string()),
            raw_arch: spec.arch.clone(),
        },
    )
    .expect("artifact")
}

fn listing(entries: impl IntoIterator<Item = String>) -> String {
    let mut body = String::from("<html><body><table>");
    for entry in entries {
        body.push_str(&format!(
            r#"<tr><td><a href="{entry}">{entry}</a></td></tr>"#
        ));
    }
    body.push_str("</table></body></html>");
    body
}

/// Build the Apache index pages and payload map for `specs`.
fn build_upstream(specs: &[Spec]) -> (HashMap<String, String>, HashMap<String, Vec<u8>>) {
    let mut pages = HashMap::new();
    let mut payloads = HashMap::new();
    let mut tree: BTreeMap<String, BTreeMap<String, BTreeMap<String, Vec<String>>>> =
        BTreeMap::new();

    for spec in specs {
        tree.entry(spec.version.clone())
            .or_default()
            .entry(spec.platform.clone())
            .or_default()
            .entry(spec.platform_version.clone())
            .or_default()
            .push(spec.basename.clone());

        let dir = format!(
            "files/stable/cinc/{}/{}/{}",
            spec.version, spec.platform, spec.platform_version
        );
        pages.insert(
            format!("{dir}/{}.metadata.json", spec.basename),
            metadata_json(spec),
        );
        payloads.insert(spec.upstream_path(), spec.body.clone());
    }

    pages.insert(
        "files/stable/cinc/".to_string(),
        listing(tree.keys().map(|version| format!("{version}/"))),
    );
    for (version, platforms) in &tree {
        pages.insert(
            format!("files/stable/cinc/{version}/"),
            listing(platforms.keys().map(|platform| format!("{platform}/"))),
        );
        for (platform, versions) in platforms {
            pages.insert(
                format!("files/stable/cinc/{version}/{platform}/"),
                listing(versions.keys().map(|value| format!("{value}/"))),
            );
            for (platform_version, basenames) in versions {
                pages.insert(
                    format!("files/stable/cinc/{version}/{platform}/{platform_version}/"),
                    listing(basenames.iter().map(|name| format!("{name}.metadata.json"))),
                );
            }
        }
    }

    (pages, payloads)
}

/// A fake HTTPS upstream: index pages and metadata documents by URL path.
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

/// Counts concurrent entries and the high-water mark.
struct InFlight<'a>(&'a AtomicUsize);

impl<'a> Drop for InFlight<'a> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A payload rung that serves fixture bytes and records every call.
struct FakePayload {
    payloads: Mutex<HashMap<String, Vec<u8>>>,
    calls: AtomicUsize,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
    fail_next: AtomicUsize,
    corrupt: AtomicBool,
    delay_millis: AtomicUsize,
}

impl FakePayload {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn fail_next(&self, count: usize) {
        self.fail_next.store(count, Ordering::SeqCst);
    }

    fn set_corrupt(&self, corrupt: bool) {
        self.corrupt.store(corrupt, Ordering::SeqCst);
    }

    fn set_delay(&self, delay: Duration) {
        self.delay_millis
            .store(delay.as_millis() as usize, Ordering::SeqCst);
    }

    fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::SeqCst)
    }

    fn enter(&self) -> InFlight<'_> {
        let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(current, Ordering::SeqCst);
        InFlight(&self.in_flight)
    }
}

#[async_trait]
impl PayloadTransport for FakePayload {
    fn kind(&self) -> cinc_mirror::config::TransportKind {
        cinc_mirror::config::TransportKind::Https
    }

    async fn fetch(
        &self,
        remote_path: &str,
        dest: &Path,
        resume_from: u64,
    ) -> Result<u64, TransportError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let _flight = self.enter();
        let delay = self.delay_millis.load(Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay as u64)).await;
        }

        if self.fail_next.load(Ordering::SeqCst) > 0 {
            self.fail_next.fetch_sub(1, Ordering::SeqCst);
            return Err(TransportError::Retryable {
                path: remote_path.to_string(),
                reason: "injected transport failure".to_string(),
            });
        }

        let body = {
            let payloads = self.payloads.lock().expect("payload lock");
            payloads
                .get(remote_path)
                .cloned()
                .ok_or_else(|| TransportError::NotFound {
                    path: remote_path.to_string(),
                })?
        };
        let bytes = if self.corrupt.load(Ordering::SeqCst) {
            vec![0_u8; body.len()]
        } else {
            body
        };

        let start = usize::try_from(resume_from).unwrap_or(0).min(bytes.len());
        let mut file = if resume_from == 0 {
            tokio::fs::File::create(dest).await
        } else {
            tokio::fs::OpenOptions::new().append(true).open(dest).await
        }
        .map_err(|source| TransportError::Local {
            path: dest.display().to_string(),
            source,
        })?;
        tokio::io::AsyncWriteExt::write_all(&mut file, &bytes[start..])
            .await
            .map_err(|source| TransportError::Local {
                path: dest.display().to_string(),
                source,
            })?;
        // `tokio::fs::File` buffers writes and schedules the actual write in the
        // background, so the final chunk can still sit in memory when the caller
        // hashes the file right away. The real transports flush for the same
        // reason; without it a fast fake download reads as an empty file.
        tokio::io::AsyncWriteExt::flush(&mut file)
            .await
            .map_err(|source| TransportError::Local {
                path: dest.display().to_string(),
                source,
            })?;
        Ok((bytes.len() - start) as u64)
    }
}

#[derive(Debug, Clone)]
struct PutRecord {
    key: String,
    reference: String,
    superseded: bool,
    sha256: String,
}

/// A target that records what it was asked to publish and can fail on demand.
struct FakeTarget {
    name: String,
    owners: Mutex<HashMap<String, String>>,
    published: Mutex<HashMap<String, String>>,
    puts: Mutex<Vec<PutRecord>>,
    attempts: AtomicUsize,
    fail_puts: AtomicUsize,
    fail_probe: AtomicBool,
    fail_exists: AtomicBool,
    delay_millis: AtomicUsize,
    in_flight: AtomicUsize,
    max_in_flight: AtomicUsize,
}

impl FakeTarget {
    fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            owners: Mutex::new(HashMap::new()),
            published: Mutex::new(HashMap::new()),
            puts: Mutex::new(Vec::new()),
            attempts: AtomicUsize::new(0),
            fail_puts: AtomicUsize::new(0),
            fail_probe: AtomicBool::new(false),
            fail_exists: AtomicBool::new(false),
            delay_millis: AtomicUsize::new(0),
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
        }
    }

    fn set_delay(&self, delay: Duration) {
        self.delay_millis
            .store(delay.as_millis() as usize, Ordering::SeqCst);
    }

    fn fail_next_puts(&self, count: usize) {
        self.fail_puts.store(count, Ordering::SeqCst);
    }

    fn fail_probe(&self) {
        self.fail_probe.store(true, Ordering::SeqCst);
    }

    fn fail_exists(&self) {
        self.fail_exists.store(true, Ordering::SeqCst);
    }

    fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }

    fn max_in_flight(&self) -> usize {
        self.max_in_flight.load(Ordering::SeqCst)
    }

    fn puts(&self) -> Vec<PutRecord> {
        self.puts.lock().expect("puts lock").clone()
    }

    /// Pretend a reference already holds `sha256`, as a previous run would.
    fn own(&self, reference: &str, sha256: &str) {
        self.owners
            .lock()
            .expect("owners lock")
            .insert(reference.to_string(), sha256.to_string());
    }

    fn owner(&self, reference: &str) -> Option<String> {
        self.owners
            .lock()
            .expect("owners lock")
            .get(reference)
            .cloned()
    }

    fn enter(&self) -> InFlight<'_> {
        let current = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
        self.max_in_flight.fetch_max(current, Ordering::SeqCst);
        InFlight(&self.in_flight)
    }

    fn reference(artifact: &Artifact) -> String {
        if artifact.superseded {
            artifact.superseded_tag()
        } else {
            artifact.tag()
        }
    }
}

#[async_trait]
impl Target for FakeTarget {
    fn name(&self) -> &str {
        &self.name
    }

    async fn probe(&self) -> Result<(), TargetError> {
        if self.fail_probe.load(Ordering::SeqCst) {
            return Err(TargetError::Oci(OciError::Config {
                reason: "unusable test credentials".to_string(),
            }));
        }
        Ok(())
    }

    async fn exists(&self, artifact: &Artifact) -> Result<Option<String>, TargetError> {
        if self.fail_exists.load(Ordering::SeqCst) {
            return Err(TargetError::Oci(OciError::Config {
                reason: "unusable test credentials".to_string(),
            }));
        }
        Ok(self.owner(&Self::reference(artifact)))
    }

    async fn put(&self, artifact: &Artifact, package: &Path) -> Result<PutOutcome, TargetError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        let _flight = self.enter();
        let delay = self.delay_millis.load(Ordering::SeqCst);
        if delay > 0 {
            tokio::time::sleep(Duration::from_millis(delay as u64)).await;
        }
        if self.fail_puts.load(Ordering::SeqCst) > 0 {
            self.fail_puts.fetch_sub(1, Ordering::SeqCst);
            return Err(TargetError::Command {
                command: format!("put {}", artifact.basename),
                status: Some(1),
                stderr: "injected upload failure".to_string(),
            });
        }

        let hashes = hash_file(package).map_err(|source| TargetError::Io {
            path: package.to_path_buf(),
            source,
        })?;
        if hashes.sha256 != artifact.sha256 {
            return Err(TargetError::Command {
                command: format!("put {}", artifact.basename),
                status: Some(2),
                stderr: "package bytes do not match the artifact digest".to_string(),
            });
        }

        let reference = Self::reference(artifact);
        self.owners
            .lock()
            .expect("owners lock")
            .insert(reference.clone(), artifact.sha256.clone());
        self.published
            .lock()
            .expect("published lock")
            .insert(artifact.key(), artifact.sha256.clone());
        self.puts.lock().expect("puts lock").push(PutRecord {
            key: artifact.key(),
            reference: reference.clone(),
            superseded: artifact.superseded,
            sha256: artifact.sha256.clone(),
        });

        Ok(PutOutcome {
            remote_ref: format!("{}:{reference}", self.name),
            remote_digest: artifact.sha256.clone(),
        })
    }

    async fn verify(&self, artifact: &Artifact) -> Result<(), TargetError> {
        match self
            .published
            .lock()
            .expect("published lock")
            .get(&artifact.key())
        {
            Some(sha256) if *sha256 == artifact.sha256 => Ok(()),
            _ => Err(TargetError::NotPublished {
                tag: Self::reference(artifact),
            }),
        }
    }
}

/// Everything one run needs, plus seeding helpers for a previous run's state.
struct Fixture {
    state_dir: PathBuf,
    config: Arc<Config>,
    scope: ResolvedScope,
    source: Source,
    store: Store,
    ledger: Ledger,
    targets: Vec<Arc<FakeTarget>>,
    payload: Arc<FakePayload>,
}

impl Fixture {
    fn new(
        state_dir: &Path,
        specs: &[Spec],
        target_names: &[&str],
        concurrency: u32,
        upload_concurrency: u32,
    ) -> Self {
        let (pages, payloads) = build_upstream(specs);
        let upstream = Arc::new(FakeUpstream { pages });
        let payload = Arc::new(FakePayload {
            payloads: Mutex::new(payloads),
            calls: AtomicUsize::new(0),
            in_flight: AtomicUsize::new(0),
            max_in_flight: AtomicUsize::new(0),
            fail_next: AtomicUsize::new(0),
            corrupt: AtomicBool::new(false),
            delay_millis: AtomicUsize::new(0),
        });

        let source = Source::with_fetcher(Arc::clone(&upstream) as Arc<dyn Fetcher>, base_url())
            .with_payload_transports(vec![Arc::clone(&payload) as Arc<dyn PayloadTransport>])
            .with_retry_policy(RetryPolicy::new(1, Duration::ZERO));

        Self {
            state_dir: state_dir.to_path_buf(),
            config: Arc::new(Config {
                state_dir: state_dir.to_path_buf(),
                concurrency,
                upload_concurrency,
                ..Config::default()
            }),
            scope: ResolvedScope {
                policies: vec![policy()],
            },
            source,
            store: Store::open(state_dir).expect("store"),
            ledger: Ledger::open(state_dir).expect("ledger"),
            targets: target_names
                .iter()
                .map(|name| Arc::new(FakeTarget::new(name)))
                .collect(),
            payload,
        }
    }

    fn ignore_arch_collisions(mut self, project: &str) -> Self {
        let mut config = (*self.config).clone();
        config
            .incident
            .ignore_arch_collisions
            .push(project.to_string());
        self.config = Arc::new(config);
        self
    }

    fn seed_blob(&self, spec: &Spec) -> String {
        let sha256 = sha256_hex(&spec.body);
        let partial = self.store.partial_path(&sha256).expect("partial path");
        std::fs::write(&partial, &spec.body).expect("write partial");
        self.store.commit(&sha256, &partial).expect("commit blob");
        sha256
    }

    fn seed_seen(&mut self, spec: &Spec, size: Option<u64>) {
        let artifact = artifact_of(spec);
        let mut detail = json!({
            "artifact": ledger::artifact_detail(&artifact),
            "upstream_path": artifact.rsync_relpath(),
        });
        if let Some(size) = size {
            detail["size"] = json!(size);
        }
        let event = Event::new(
            format!("seed-seen-{}", artifact.key()),
            1,
            Utc::now(),
            EventKind::ArtifactSeen,
        )
        .with_artifact(artifact.key())
        .with_detail(detail);
        self.ledger.append(&event).expect("artifact_seen");
    }

    fn seed_verified(&mut self, spec: &Spec) {
        let artifact = artifact_of(spec);
        let event = Event::new(
            format!("seed-verified-{}", artifact.key()),
            1,
            Utc::now(),
            EventKind::Verified,
        )
        .with_artifact(artifact.key())
        .with_detail(json!({"size": spec.body.len()}));
        self.ledger.append(&event).expect("verified");
    }

    fn seed_published(&mut self, spec: &Spec, target: &str) {
        let artifact = artifact_of(spec);
        let event = Event::new(
            format!("seed-published-{}-{target}", artifact.key()),
            1,
            Utc::now(),
            EventKind::Published,
        )
        .with_artifact(artifact.key())
        .with_target(target)
        .with_detail(json!({"remote_digest": artifact.sha256}));
        self.ledger.append(&event).expect("published");
    }

    fn seed_uploading(&mut self, spec: &Spec, target: &str) {
        let artifact = artifact_of(spec);
        let event = Event::new(
            format!("seed-uploading-{}-{target}", artifact.key()),
            1,
            Utc::now(),
            EventKind::PublicationStarted,
        )
        .with_artifact(artifact.key())
        .with_target(target);
        self.ledger.append(&event).expect("publication_started");
    }

    fn seed_satisfied(&mut self, spec: &Spec, targets: &[&str]) {
        self.seed_seen(spec, Some(spec.body.len() as u64));
        self.seed_verified(spec);
        for target in targets {
            self.seed_published(spec, target);
        }
        self.seed_blob(spec);
    }

    fn ctx_with(self, run_id: &str, targets: TargetSet) -> Ctx {
        let state_dir = self.state_dir.clone();
        Ctx {
            config: self.config,
            scope: self.scope,
            source: self.source,
            store: self.store,
            ledger: tokio::sync::Mutex::new(self.ledger),
            targets,
            rate: RateLimiter::new(None),
            run_id: run_id.to_string(),
            state_dir,
        }
    }

    fn ctx(self, run_id: &str) -> Ctx {
        let targets = self.targets.clone();
        self.ctx_with(
            run_id,
            TargetSet::from_targets(
                targets
                    .into_iter()
                    .map(|target| target as Arc<dyn Target>)
                    .collect(),
            ),
        )
    }
}

fn base_url() -> Url {
    Url::parse(BASE).expect("base url")
}

fn policy() -> ResolvedPolicy {
    ResolvedPolicy {
        id: "cinc".to_string(),
        project: "cinc".to_string(),
        channel: "stable".to_string(),
        min_version: None,
        max_version: None,
        versions: Vec::new(),
        cli_versions: Vec::new(),
        platforms: Selection::All,
        platform_versions: BTreeMap::new(),
        cli_platform_versions: Vec::new(),
        arches: Selection::All,
        all_versions: false,
    }
}

async fn ledger_events(ctx: &Ctx, run_id: &str) -> Vec<Event> {
    ctx.ledger
        .lock()
        .await
        .events()
        .expect("events")
        .into_iter()
        .filter(|event| event.run_id == run_id)
        .collect()
}

fn kinds(events: &[Event]) -> Vec<EventKind> {
    events.iter().map(|event| event.kind).collect()
}

fn one_package() -> Spec {
    Spec::new(
        "19.4.46",
        "cinc_19.4.46-1_amd64.deb",
        b"the package bytes for 19.4.46",
    )
}

/// Keep the incident tests off the network and out of the CI environment file.
///
/// `incident::open` files a GitHub issue when a token and repository are in the
/// environment and appends `SECURITY_ALERT` to `$GITHUB_ENV`. A test run must
/// do neither.
fn clear_security_env() {
    std::env::remove_var("GITHUB_TOKEN");
    std::env::remove_var("GITHUB_REPOSITORY");
    std::env::remove_var("GITHUB_ENV");
}

// Queue order and limits ------------------------------------------------------

#[tokio::test]
async fn queue_order_is_deterministic_and_skips_satisfied() {
    let dir = TempDir::new().expect("state dir");
    let older = Spec::new("19.3.14", "cinc_19.3.14-1_amd64.deb", b"older package");
    let newer = Spec::new("19.4.46", "cinc_19.4.46-1_amd64.deb", b"newer package");
    let satisfied = Spec::new("19.10.0", "cinc_19.10.0-1_amd64.deb", b"satisfied package");

    let mut fixture = Fixture::new(
        dir.path(),
        &[older.clone(), newer.clone(), satisfied.clone()],
        &["t1"],
        1,
        1,
    );
    fixture.seed_satisfied(&satisfied, &["t1"]);
    let target = Arc::clone(&fixture.targets[0]);
    let ctx = fixture.ctx("run-1");

    let summary = run(&ctx, RunOpts::default()).await.expect("run");

    assert_eq!(summary.discovered, 3);
    assert_eq!(summary.satisfied, 1);
    assert_eq!(summary.downloaded, 2);
    assert_eq!(summary.published, 2);
    assert_eq!(summary.failed, 0);
    assert_eq!(summary.exit_code, 0);

    let puts = target.puts();
    let order: Vec<String> = puts.iter().map(|record| record.key.clone()).collect();
    assert_eq!(
        order,
        vec![artifact_of(&newer).key(), artifact_of(&older).key()],
        "versions sort numerically descending"
    );
    assert!(
        !order.contains(&artifact_of(&satisfied).key()),
        "a row published everywhere is dropped before ordering"
    );
}

#[tokio::test]
async fn size_orders_put_known_sizes_first_and_unknown_last() {
    let large = Spec::new("19.4.46", "cinc_19.4.46-1_amd64.deb", b"large body");
    let small = Spec::new("19.3.14", "cinc_19.3.14-1_amd64.deb", b"small");
    let unknown = Spec::new("19.10.0", "cinc_19.10.0-1_amd64.deb", b"unknown size");
    let small_key = artifact_of(&small).key();
    let large_key = artifact_of(&large).key();
    let unknown_key = artifact_of(&unknown).key();

    for (order, expected) in [
        (
            Order::SmallestFirst,
            vec![small_key.clone(), large_key.clone()],
        ),
        (Order::LargestFirst, vec![large_key, small_key]),
    ] {
        let dir = TempDir::new().expect("state dir");
        let mut fixture = Fixture::new(
            dir.path(),
            &[large.clone(), small.clone(), unknown.clone()],
            &["t1"],
            1,
            1,
        );
        fixture.seed_seen(&large, Some(300));
        fixture.seed_verified(&large);
        fixture.seed_blob(&large);
        fixture.seed_seen(&small, Some(100));
        fixture.seed_verified(&small);
        fixture.seed_blob(&small);

        let target = Arc::clone(&fixture.targets[0]);
        let ctx = fixture.ctx(if order == Order::SmallestFirst {
            "run-smallest"
        } else {
            "run-largest"
        });
        run(
            &ctx,
            RunOpts {
                order,
                ..RunOpts::default()
            },
        )
        .await
        .expect("run");

        let keys: Vec<String> = target
            .puts()
            .iter()
            .map(|record| record.key.clone())
            .collect();
        assert_eq!(
            &keys[..2],
            expected.as_slice(),
            "known sizes sort before an unknown one"
        );
        assert_eq!(keys[2], unknown_key, "an unknown size sorts last");
    }
}

#[tokio::test]
async fn limit_bytes_finishes_the_crossing_artifact_and_stops() {
    let dir = TempDir::new().expect("state dir");
    let first = Spec::new("19.4.46", "cinc_19.4.46-1_amd64.deb", b"first package");
    let second = Spec::new("19.3.14", "cinc_19.3.14-1_amd64.deb", b"second package");

    let fixture = Fixture::new(dir.path(), &[first.clone(), second.clone()], &["t1"], 2, 1);
    let target = Arc::clone(&fixture.targets[0]);
    let payload = Arc::clone(&fixture.payload);
    let ctx = fixture.ctx("run-1");

    let summary = run(
        &ctx,
        RunOpts {
            max_bytes: Some(1),
            ..RunOpts::default()
        },
    )
    .await
    .expect("run");

    assert_eq!(summary.downloaded, 1, "the crossing artifact is finished");
    assert_eq!(summary.published, 1);
    assert!(
        summary.bytes_downloaded >= 1,
        "the crossing artifact's bytes are counted in full"
    );
    assert_eq!(payload.calls(), 1, "the second artifact is never fetched");
    assert_eq!(target.puts().len(), 1);
    let row = ctx
        .ledger
        .lock()
        .await
        .run("run-1")
        .expect("run row query")
        .expect("run row");
    assert_eq!(row.max_bytes, Some(1), "the cap is recorded in the run row");
}

#[tokio::test]
async fn limit_bytes_zero_fails_with_usage_error() {
    let dir = TempDir::new().expect("state dir");
    let fixture = Fixture::new(dir.path(), &[one_package()], &["t1"], 1, 1);
    let payload = Arc::clone(&fixture.payload);
    let ctx = fixture.ctx("run-1");

    let error = run(
        &ctx,
        RunOpts {
            max_bytes: Some(0),
            ..RunOpts::default()
        },
    )
    .await
    .expect_err("a zero byte cap is a usage error");

    assert!(matches!(error, RunError::Usage { .. }), "{error:?}");
    assert_eq!(error.exit_code(), 64);
    assert_eq!(payload.calls(), 0);
    assert_eq!(ctx.ledger.lock().await.event_count().expect("events"), 0);
}

#[tokio::test]
async fn limit_artifacts_stops_after_the_requested_count() {
    let dir = TempDir::new().expect("state dir");
    let first = Spec::new("19.4.46", "cinc_19.4.46-1_amd64.deb", b"first package");
    let second = Spec::new("19.3.14", "cinc_19.3.14-1_amd64.deb", b"second package");

    let fixture = Fixture::new(dir.path(), &[first, second], &["t1"], 1, 1);
    let payload = Arc::clone(&fixture.payload);
    let ctx = fixture.ctx("run-1");

    let summary = run(
        &ctx,
        RunOpts {
            max_artifacts: Some(1),
            ..RunOpts::default()
        },
    )
    .await
    .expect("run");

    assert_eq!(summary.downloaded, 1);
    assert_eq!(summary.published, 1);
    assert_eq!(payload.calls(), 1);
}

// Fan-out, retries and recovery ----------------------------------------------

#[tokio::test]
async fn partial_target_failure_is_retried_only_for_the_missing_target() {
    let dir = TempDir::new().expect("state dir");
    let package = one_package();
    let first_fixture = Fixture::new(
        dir.path(),
        std::slice::from_ref(&package),
        &["t1", "t2"],
        1,
        1,
    );
    let first_payload = Arc::clone(&first_fixture.payload);
    let bad = Arc::clone(&first_fixture.targets[1]);
    bad.fail_next_puts(1);
    let first_ctx = first_fixture.ctx("run-1");

    let first = run(&first_ctx, RunOpts::default())
        .await
        .expect("first run");
    assert_eq!(first.published, 1);
    assert_eq!(first.failed, 1);
    assert_eq!(first.exit_code, 2);
    assert_eq!(first_payload.calls(), 1);

    let second_fixture = Fixture::new(
        dir.path(),
        std::slice::from_ref(&package),
        &["t1", "t2"],
        1,
        1,
    );
    let second_payload = Arc::clone(&second_fixture.payload);
    let good = Arc::clone(&second_fixture.targets[0]);
    let retried = Arc::clone(&second_fixture.targets[1]);
    let second_ctx = second_fixture.ctx("run-2");
    let second = run(&second_ctx, RunOpts::default())
        .await
        .expect("second run");

    let artifact = artifact_of(&package);
    assert_eq!(second.downloaded, 0, "the verified blob is reused");
    assert_eq!(second.published, 1, "only the failed target is published");
    assert_eq!(second.failed, 0);
    assert_eq!(second.exit_code, 0);
    assert_eq!(
        first_payload.calls() + second_payload.calls(),
        1,
        "one download across both runs"
    );
    assert_eq!(good.attempts(), 0, "the published target is not touched");
    assert_eq!(retried.attempts(), 1);
    let ledger = second_ctx.ledger.lock().await;
    assert_eq!(
        ledger
            .publication(&artifact.key(), "t1")
            .expect("publication")
            .expect("t1 row")
            .status,
        PublicationStatus::Published
    );
    assert_eq!(
        ledger
            .publication(&artifact.key(), "t2")
            .expect("publication")
            .expect("t2 row")
            .status,
        PublicationStatus::Published
    );
}

#[tokio::test]
async fn interrupted_upload_is_requeued_and_downloads_nothing() {
    let dir = TempDir::new().expect("state dir");
    let package = one_package();
    let mut fixture = Fixture::new(dir.path(), std::slice::from_ref(&package), &["t1"], 1, 1);
    fixture.seed_seen(&package, Some(package.body.len() as u64));
    fixture.seed_verified(&package);
    fixture.seed_uploading(&package, "t1");
    fixture.seed_blob(&package);

    let target = Arc::clone(&fixture.targets[0]);
    let payload = Arc::clone(&fixture.payload);
    let ctx = fixture.ctx("run-2");

    let summary = run(&ctx, RunOpts::default()).await.expect("run");

    assert_eq!(summary.downloaded, 0);
    assert_eq!(summary.published, 1);
    assert_eq!(payload.calls(), 0);
    let events = ledger_events(&ctx, "run-2").await;
    assert!(
        kinds(&events).contains(&EventKind::PublicationInterrupted),
        "the stale uploading row is requeued"
    );
    assert!(kinds(&events).contains(&EventKind::Published));
    assert_eq!(target.puts().len(), 1);
}

#[tokio::test]
async fn corrupt_payload_fails_the_run_then_recovers() {
    let dir = TempDir::new().expect("state dir");
    let package = one_package();
    let first_fixture = Fixture::new(dir.path(), std::slice::from_ref(&package), &["t1"], 1, 1);
    first_fixture.payload.set_corrupt(true);
    let first_target = Arc::clone(&first_fixture.targets[0]);
    let first_ctx = first_fixture.ctx("run-1");

    let first = run(&first_ctx, RunOpts::default())
        .await
        .expect("first run");
    assert_eq!(first.downloaded, 0);
    assert_eq!(first.failed, 1);
    assert_eq!(first.published, 0);
    assert_eq!(first.exit_code, 2);
    assert!(!first_ctx.store.has(&sha256_hex(&package.body)));
    assert!(first_target.puts().is_empty());

    let second_fixture = Fixture::new(dir.path(), std::slice::from_ref(&package), &["t1"], 1, 1);
    let second_ctx = second_fixture.ctx("run-2");
    let second = run(&second_ctx, RunOpts::default())
        .await
        .expect("second run");
    assert_eq!(second.downloaded, 1);
    assert_eq!(second.published, 1);
    assert_eq!(second.exit_code, 0);
    assert!(second_ctx.store.has(&sha256_hex(&package.body)));
}

#[tokio::test]
async fn transport_failure_counts_as_a_failed_download() {
    let dir = TempDir::new().expect("state dir");
    let package = one_package();
    let fixture = Fixture::new(dir.path(), std::slice::from_ref(&package), &["t1"], 1, 1);
    fixture.payload.fail_next(1);
    let target = Arc::clone(&fixture.targets[0]);
    let ctx = fixture.ctx("run-1");

    let summary = run(&ctx, RunOpts::default()).await.expect("run");

    assert_eq!(summary.downloaded, 0);
    assert_eq!(summary.failed, 1);
    assert_eq!(summary.published, 0);
    assert_eq!(summary.exit_code, 2);
    assert!(target.puts().is_empty());
    let events = kinds(&ledger_events(&ctx, "run-1").await);
    assert!(events.contains(&EventKind::DownloadStarted));
    assert!(events.contains(&EventKind::RunFinished));
    assert!(
        !events.contains(&EventKind::Verified),
        "a failed download is never recorded as verified"
    );
}

// Hash changes and superseded publications ------------------------------------

#[tokio::test]
async fn hash_change_opens_one_incident_and_publishes_only_the_superseded_ref() {
    clear_security_env();
    let dir = TempDir::new().expect("state dir");
    let first = one_package();
    let second = Spec::new(
        "19.4.46",
        &first.basename,
        b"replacement bytes for the same upstream path",
    );

    let first_fixture = Fixture::new(dir.path(), std::slice::from_ref(&first), &["t1"], 1, 1);
    let first_target = Arc::clone(&first_fixture.targets[0]);
    let first_ctx = first_fixture.ctx("run-1");

    run(&first_ctx, RunOpts::default())
        .await
        .expect("first run");

    let old = artifact_of(&first);
    let new = artifact_of(&second);
    assert_eq!(first_target.owner(&old.tag()), Some(old.sha256.clone()));

    // Upstream replaces the bytes behind the same path.
    let change_fixture = Fixture::new(dir.path(), std::slice::from_ref(&second), &["t1"], 1, 1);
    let change_target = Arc::clone(&change_fixture.targets[0]);
    let change_ctx = change_fixture.ctx("run-2");

    let change = run(&change_ctx, RunOpts::default())
        .await
        .expect("change run");
    assert_eq!(change.incidents_opened, 1);
    assert_eq!(change.exit_code, 3);
    assert_eq!(change.downloaded, 1);
    assert_eq!(change.published, 1);

    let superseded_puts: Vec<PutRecord> = change_target
        .puts()
        .into_iter()
        .filter(|record| record.sha256 == new.sha256)
        .collect();
    assert_eq!(superseded_puts.len(), 1);
    assert!(superseded_puts[0].superseded);
    assert_eq!(superseded_puts[0].reference, new.superseded_tag());
    assert_eq!(
        first_target.owner(&old.tag()),
        Some(old.sha256.clone()),
        "the canonical reference still serves the old bytes"
    );
    assert_eq!(
        change_target.owner(&old.tag()),
        None,
        "the change run never writes the canonical reference"
    );
    assert_eq!(
        change_target.owner(&new.superseded_tag()),
        Some(new.sha256.clone())
    );

    {
        let ledger = change_ctx.ledger.lock().await;
        let incidents = ledger.incidents(IncidentFilter::open()).expect("incidents");
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].kind, IncidentKind::HashChanged);
        let old_row = ledger.artifact(&old.key()).expect("old row").expect("old");
        assert_eq!(old_row.superseded_by.as_deref(), Some(new.key().as_str()));
        let new_row = ledger.artifact(&new.key()).expect("new row").expect("new");
        assert_eq!(new_row.supersedes.as_deref(), Some(old.key().as_str()));
    }

    let repeat_fixture = Fixture::new(dir.path(), std::slice::from_ref(&second), &["t1"], 1, 1);
    let repeat_target = Arc::clone(&repeat_fixture.targets[0]);
    let repeat_ctx = repeat_fixture.ctx("run-3");
    let repeat = run(&repeat_ctx, RunOpts::default())
        .await
        .expect("repeat run");
    assert_eq!(repeat.incidents_opened, 0, "detection is deduplicated");
    assert_eq!(repeat.published, 0);
    assert_eq!(repeat.downloaded, 0);
    assert_eq!(repeat.exit_code, 0);
    assert!(repeat_target.puts().is_empty());
    assert_eq!(first_target.owner(&old.tag()), Some(old.sha256));
}

#[tokio::test]
async fn a_tag_that_already_holds_other_bytes_opens_a_conflict_incident() {
    clear_security_env();
    let dir = TempDir::new().expect("state dir");
    let package = one_package();
    let fixture = Fixture::new(dir.path(), std::slice::from_ref(&package), &["t1"], 1, 1);
    let artifact = artifact_of(&package);
    let other = "1".repeat(64);
    fixture.targets[0].own(&artifact.tag(), &other);
    let target = Arc::clone(&fixture.targets[0]);
    let ctx = fixture.ctx("run-1");

    let summary = run(&ctx, RunOpts::default()).await.expect("run");

    assert_eq!(summary.incidents_opened, 1);
    assert_eq!(summary.exit_code, 3);
    assert_eq!(summary.published, 0);
    assert_eq!(
        target.owner(&artifact.tag()),
        Some(other),
        "nothing overwrote the tag"
    );
    let incidents = ctx
        .ledger
        .lock()
        .await
        .incidents(IncidentFilter::open())
        .expect("incidents");
    assert_eq!(incidents.len(), 1);
    assert_eq!(incidents[0].kind, IncidentKind::TagConflict);
}

#[tokio::test]
async fn an_arch_collision_opens_one_incident_and_the_run_continues() {
    clear_security_env();
    let dir = TempDir::new().expect("state dir");
    // Two raw arches mapping to one public arm64 with different bytes, plus an
    // unrelated package that must still be processed.
    let kept = Spec::new(
        "19.4.46",
        "cinc_19.4.46-1_aarch64.deb",
        b"the aarch64 build",
    )
    .with_raw_arch("aarch64");
    let conflicting = Spec::new(
        "19.4.46",
        "cinc_19.4.46-1_arm64.deb",
        b"the arm64 build with different bytes",
    )
    .with_raw_arch("arm64");
    let other = Spec::new(
        "19.3.14",
        "cinc_19.3.14-1_amd64.deb",
        b"an unrelated package",
    );

    let specs = [kept.clone(), conflicting.clone(), other.clone()];
    let fixture = Fixture::new(dir.path(), &specs, &["t1"], 1, 1);
    let target = Arc::clone(&fixture.targets[0]);
    let payload = Arc::clone(&fixture.payload);
    let ctx = fixture.ctx("run-1");

    let summary = run(&ctx, RunOpts::default()).await.expect("run");

    let kept_artifact = artifact_of(&kept);
    let conflicting_artifact = artifact_of(&conflicting);
    let other_artifact = artifact_of(&other);

    // One newly opened incident drives exit code 3; the kept artifact and the
    // unrelated one are still published.
    assert_eq!(summary.incidents_opened, 1, "{summary:?}");
    assert_eq!(summary.exit_code, 3, "{summary:?}");
    assert_eq!(summary.skipped, 1, "the conflicting artifact is excluded");
    assert_eq!(summary.discovered, 2, "{summary:?}");
    assert_eq!(summary.downloaded, 2, "{summary:?}");
    assert_eq!(summary.published, 2, "{summary:?}");
    assert_eq!(summary.open_incidents, 1, "{summary:?}");
    assert_eq!(
        target.owner(&kept_artifact.tag()),
        Some(kept_artifact.sha256.clone()),
        "the first artifact owns the descriptive tag"
    );
    assert_eq!(
        target.owner(&other_artifact.tag()),
        Some(other_artifact.sha256.clone()),
        "other artifacts are still processed"
    );
    assert!(
        target
            .puts()
            .iter()
            .all(|record| record.sha256 != conflicting_artifact.sha256),
        "the conflicting artifact is never published: {:?}",
        target.puts()
    );
    assert_eq!(
        payload.calls(),
        2,
        "the conflicting artifact is never downloaded either"
    );

    {
        let ledger = ctx.ledger.lock().await;
        let incidents = ledger.incidents(IncidentFilter::open()).expect("incidents");
        assert_eq!(incidents.len(), 1);
        let incident = &incidents[0];
        assert_eq!(incident.kind, IncidentKind::ArchCollision);
        assert_eq!(
            incident.artifact_key.as_deref(),
            Some(conflicting_artifact.key().as_str()),
            "the incident names the excluded artifact"
        );
        assert_eq!(
            incident.old_sha256.as_deref(),
            Some(kept_artifact.sha256.as_str()),
            "the kept artifact's digest is the old value"
        );
        assert_eq!(
            incident.new_sha256.as_deref(),
            Some(conflicting_artifact.sha256.as_str())
        );
        // The excluded artifact is recorded as seen so the incident can name
        // it, but it never reaches a publication row.
        assert!(ledger
            .artifact(&conflicting_artifact.key())
            .expect("row")
            .is_some());
        assert!(ledger
            .publications_for(&conflicting_artifact.key())
            .expect("publications")
            .is_empty());
    }

    // A later run sees the same collision but the incident is deduplicated:
    // no new incident, exit 0, and no bytes move.
    let repeat_fixture = Fixture::new(dir.path(), &specs, &["t1"], 1, 1);
    let repeat_payload = Arc::clone(&repeat_fixture.payload);
    let repeat_target = Arc::clone(&repeat_fixture.targets[0]);
    let repeat_ctx = repeat_fixture.ctx("run-2");
    let repeat = run(&repeat_ctx, RunOpts::default())
        .await
        .expect("repeat run");

    assert_eq!(repeat.incidents_opened, 0, "{repeat:?}");
    assert_eq!(repeat.exit_code, 0, "{repeat:?}");
    assert_eq!(repeat.satisfied, 2, "{repeat:?}");
    assert_eq!(repeat.skipped, 1, "{repeat:?}");
    assert_eq!(
        repeat.open_incidents, 1,
        "the still-open incident stays visible without failing the run"
    );
    assert_eq!(
        repeat_payload.calls(),
        0,
        "a satisfied queue downloads nothing"
    );
    assert!(repeat_target.puts().is_empty());
}

#[tokio::test]
async fn an_arch_collision_for_an_ignored_project_opens_no_incident() {
    clear_security_env();
    let dir = TempDir::new().expect("state dir");
    let kept = Spec::new(
        "19.4.46",
        "cinc_19.4.46-1_aarch64.deb",
        b"the aarch64 build",
    )
    .with_raw_arch("aarch64");
    let conflicting = Spec::new(
        "19.4.46",
        "cinc_19.4.46-1_arm64.deb",
        b"the arm64 build with different bytes",
    )
    .with_raw_arch("arm64");
    let other = Spec::new(
        "19.3.14",
        "cinc_19.3.14-1_amd64.deb",
        b"an unrelated package",
    );

    let specs = [kept.clone(), conflicting.clone(), other.clone()];
    let fixture = Fixture::new(dir.path(), &specs, &["t1"], 1, 1).ignore_arch_collisions("cinc");
    let target = Arc::clone(&fixture.targets[0]);
    let ctx = fixture.ctx("run-1");

    let summary = run(&ctx, RunOpts::default()).await.expect("run");

    let conflicting_artifact = artifact_of(&conflicting);
    assert_eq!(summary.incidents_opened, 0, "{summary:?}");
    assert_eq!(summary.open_incidents, 0, "{summary:?}");
    assert_eq!(summary.exit_code, 0, "{summary:?}");
    assert_eq!(summary.skipped, 1, "the conflicting artifact is excluded");
    assert_eq!(summary.discovered, 2, "{summary:?}");
    assert_eq!(summary.published, 2, "{summary:?}");
    assert!(
        target
            .puts()
            .iter()
            .all(|record| record.sha256 != conflicting_artifact.sha256),
        "the conflicting artifact is never published: {:?}",
        target.puts()
    );

    let ledger = ctx.ledger.lock().await;
    assert!(
        ledger
            .incidents(IncidentFilter::open())
            .expect("incidents")
            .is_empty(),
        "an ignored project opens no incident"
    );
}

// Concurrency, pacing and dry runs --------------------------------------------

#[tokio::test]
async fn concurrency_never_exceeds_the_configured_maximum() {
    let dir = TempDir::new().expect("state dir");
    let specs: Vec<Spec> = (1..=4)
        .map(|index| {
            Spec::new(
                &format!("19.4.{index}"),
                &format!("cinc_19.4.{index}-1_amd64.deb"),
                format!("package number {index}").as_bytes(),
            )
        })
        .collect();

    let fixture = Fixture::new(dir.path(), &specs, &["t1", "t2"], 2, 1);
    fixture.payload.set_delay(Duration::from_millis(25));
    for target in &fixture.targets {
        target.set_delay(Duration::from_millis(25));
    }
    let payload = Arc::clone(&fixture.payload);
    let first = Arc::clone(&fixture.targets[0]);
    let second = Arc::clone(&fixture.targets[1]);
    let ctx = fixture.ctx("run-1");

    let summary = run(&ctx, RunOpts::default()).await.expect("run");

    assert_eq!(summary.downloaded, 4);
    assert_eq!(summary.published, 8);
    assert_eq!(
        payload.max_in_flight(),
        2,
        "downloads are bounded by concurrency and do run in parallel"
    );
    for target in [&first, &second] {
        assert_eq!(
            target.max_in_flight(),
            1,
            "uploads per target are bounded by upload_concurrency"
        );
    }
}

#[tokio::test]
async fn a_single_unusable_target_aborts_after_the_first_download() {
    let dir = TempDir::new().expect("state dir");
    let specs: Vec<Spec> = (1..=3)
        .map(|index| {
            Spec::new(
                &format!("19.4.{index}"),
                &format!("cinc_19.4.{index}-1_amd64.deb"),
                format!("package {index}").as_bytes(),
            )
        })
        .collect();
    let fixture = Fixture::new(dir.path(), &specs, &["t1"], 1, 1);
    fixture.targets[0].fail_exists();
    let payload = Arc::clone(&fixture.payload);
    let ctx = fixture.ctx("run-1");

    let error = run(&ctx, RunOpts::default())
        .await
        .expect_err("the only target is unusable");

    assert!(
        matches!(error, RunError::TargetUnusable { .. }),
        "expected an unusable-target error, got {error:?}"
    );
    assert_eq!(
        payload.calls(),
        1,
        "the run aborts after the first artifact instead of downloading the queue"
    );
}

#[tokio::test]
async fn a_single_target_probe_failure_aborts_before_publication() {
    let dir = TempDir::new().expect("state dir");
    let specs = vec![Spec::new(
        "19.4.1",
        "cinc_19.4.1-1_amd64.deb",
        b"package one",
    )];
    let fixture = Fixture::new(dir.path(), &specs, &["t1"], 1, 1);
    fixture.targets[0].fail_probe();
    let target = Arc::clone(&fixture.targets[0]);
    let payload = Arc::clone(&fixture.payload);
    let ctx = fixture.ctx("run-1");

    let error = run(&ctx, RunOpts::default())
        .await
        .expect_err("the only target cannot be probed");

    assert!(
        matches!(error, RunError::TargetUnusable { .. }),
        "expected an unusable-target error, got {error:?}"
    );
    assert_eq!(payload.calls(), 1);
    assert!(target.puts().is_empty());
}

#[tokio::test]
async fn a_second_target_keeps_the_run_going_when_one_is_unusable() {
    let dir = TempDir::new().expect("state dir");
    let specs = vec![Spec::new(
        "19.4.1",
        "cinc_19.4.1-1_amd64.deb",
        b"package one",
    )];
    let fixture = Fixture::new(dir.path(), &specs, &["t1", "t2"], 1, 1);
    fixture.targets[0].fail_exists();
    let second = Arc::clone(&fixture.targets[1]);
    let ctx = fixture.ctx("run-1");

    let summary = run(&ctx, RunOpts::default())
        .await
        .expect("a second target keeps the run alive");

    assert_eq!(summary.published, 1, "the working target still publishes");
    assert_eq!(summary.failed, 1, "the unusable target is reported");
    assert_eq!(second.puts().len(), 1);
}

#[tokio::test]
async fn rate_limiter_stretches_transfer_time() {
    let limited = RateLimiter::new(Some(1_048_576));
    let started = Instant::now();
    for _ in 0..16 {
        limited.consume(65_536).await;
    }
    assert!(
        started.elapsed() >= Duration::from_millis(900),
        "1 MiB at 1 MiB/s must take about a second, took {:?}",
        started.elapsed()
    );

    let unlimited = RateLimiter::new(None);
    let started = Instant::now();
    for _ in 0..16 {
        unlimited.consume(65_536).await;
    }
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "an unlimited limiter must not sleep"
    );

    let first = RateLimiter::new(Some(1024));
    let started = Instant::now();
    first.consume(1024).await;
    assert!(
        started.elapsed() < Duration::from_millis(200),
        "the first call is immediate"
    );
}

#[tokio::test]
async fn dry_run_publishes_nothing_and_writes_no_events() {
    let dir = TempDir::new().expect("state dir");
    let package = one_package();
    let fixture = Fixture::new(dir.path(), std::slice::from_ref(&package), &["t1"], 2, 1);
    let target = Arc::clone(&fixture.targets[0]);
    let payload = Arc::clone(&fixture.payload);
    let ctx = fixture.ctx("run-1");

    let summary = run(
        &ctx,
        RunOpts {
            dry_run: true,
            ..RunOpts::default()
        },
    )
    .await
    .expect("dry run");

    assert_eq!(summary.discovered, 1);
    assert_eq!(summary.downloaded, 0);
    assert_eq!(summary.published, 0);
    assert_eq!(summary.bytes_downloaded, 0);
    assert_eq!(summary.exit_code, 0);
    assert_eq!(payload.calls(), 0);
    assert!(target.puts().is_empty());
    assert!(!ctx.store.has(&sha256_hex(&package.body)));
    assert_eq!(ctx.ledger.lock().await.event_count().expect("events"), 0);
}

// Garbage collection ----------------------------------------------------------

#[tokio::test]
async fn gc_after_removes_the_blob_and_marks_local_gc() {
    let dir = TempDir::new().expect("state dir");
    let package = one_package();
    let fixture = Fixture::new(dir.path(), std::slice::from_ref(&package), &["t1"], 1, 1);
    let artifact = artifact_of(&package);
    let ctx = fixture.ctx("run-1");

    let summary = run(
        &ctx,
        RunOpts {
            gc_after: true,
            ..RunOpts::default()
        },
    )
    .await
    .expect("run");

    assert_eq!(summary.published, 1);
    assert!(
        !ctx.store.has(&artifact.sha256),
        "the published blob is deleted"
    );
    let row = ctx
        .ledger
        .lock()
        .await
        .artifact(&artifact.key())
        .expect("row")
        .expect("row");
    assert!(!row.local);
    let events = ledger_events(&ctx, "run-1").await;
    assert_eq!(
        kinds(&events)
            .iter()
            .filter(|kind| **kind == EventKind::LocalGc)
            .count(),
        1
    );
}

#[tokio::test]
async fn gc_after_also_collects_a_row_that_is_already_satisfied() {
    let dir = TempDir::new().expect("state dir");
    let package = one_package();
    let artifact = artifact_of(&package);

    let first_fixture = Fixture::new(dir.path(), std::slice::from_ref(&package), &["t1"], 1, 1);
    let first_ctx = first_fixture.ctx("run-1");
    run(&first_ctx, RunOpts::default())
        .await
        .expect("first run");
    assert!(first_ctx.store.has(&artifact.sha256));

    let second_fixture = Fixture::new(dir.path(), std::slice::from_ref(&package), &["t1"], 1, 1);
    let second_payload = Arc::clone(&second_fixture.payload);
    let second_ctx = second_fixture.ctx("run-2");
    let summary = run(
        &second_ctx,
        RunOpts {
            gc_after: true,
            ..RunOpts::default()
        },
    )
    .await
    .expect("second run");

    assert_eq!(summary.discovered, 1);
    assert_eq!(summary.satisfied, 1);
    assert_eq!(summary.published, 0);
    assert_eq!(second_payload.calls(), 0);
    assert!(
        !second_ctx.store.has(&artifact.sha256),
        "a satisfied row is collected too"
    );
    let events = kinds(&ledger_events(&second_ctx, "run-2").await);
    assert_eq!(
        events
            .iter()
            .filter(|kind| **kind == EventKind::LocalGc)
            .count(),
        1
    );
}

#[tokio::test]
async fn gc_after_keeps_the_blob_when_a_target_failed() {
    let dir = TempDir::new().expect("state dir");
    let package = one_package();
    let fixture = Fixture::new(
        dir.path(),
        std::slice::from_ref(&package),
        &["t1", "t2"],
        1,
        1,
    );
    fixture.targets[1].fail_next_puts(1);
    let artifact = artifact_of(&package);
    let ctx = fixture.ctx("run-1");

    let summary = run(
        &ctx,
        RunOpts {
            gc_after: true,
            ..RunOpts::default()
        },
    )
    .await
    .expect("run");

    assert_eq!(summary.failed, 1);
    assert!(
        ctx.store.has(&artifact.sha256),
        "an unfinished fan-out keeps the blob"
    );
    let events = ledger_events(&ctx, "run-1").await;
    assert!(
        !kinds(&events).contains(&EventKind::LocalGc),
        "no local_gc event for an incomplete publication"
    );
}

#[tokio::test]
async fn gc_after_keeps_the_replacement_blob_until_the_incident_is_acked() {
    clear_security_env();
    let dir = TempDir::new().expect("state dir");
    let first = one_package();
    let second = Spec::new(
        "19.4.46",
        &first.basename,
        b"replacement bytes for the same upstream path",
    );

    // Run 1 publishes the original bytes everywhere.
    let first_fixture = Fixture::new(dir.path(), std::slice::from_ref(&first), &["t1"], 1, 1);
    let first_ctx = first_fixture.ctx("run-1");
    run(&first_ctx, RunOpts::default())
        .await
        .expect("first run");

    // Upstream replaces the bytes; the run opens a hash-change incident,
    // publishes the replacement under the superseded name and runs gc.
    let change_fixture = Fixture::new(dir.path(), std::slice::from_ref(&second), &["t1"], 1, 1);
    let change_config = Arc::clone(&change_fixture.config);
    let change_targets = change_fixture.targets.clone();
    let change_ctx = change_fixture.ctx("run-2");
    let change = run(
        &change_ctx,
        RunOpts {
            gc_after: true,
            ..RunOpts::default()
        },
    )
    .await
    .expect("change run");

    let old = artifact_of(&first);
    let new = artifact_of(&second);
    assert_eq!(change.incidents_opened, 1);
    assert!(change_ctx.store.has(&new.sha256));

    let incident = {
        let ledger = change_ctx.ledger.lock().await;
        let incidents = ledger.incidents(IncidentFilter::open()).expect("incidents");
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].kind, IncidentKind::HashChanged);
        incidents[0].id.clone()
    };

    // The replacement blob survives --gc-after precisely so that the
    // acknowledgement can republish it; without it the incident would dead-end.
    assert!(
        change_ctx.store.has(&old.sha256),
        "the superseded blob stays for the acknowledged republish"
    );
    assert!(
        change_ctx.store.has(&new.sha256),
        "the replacement blob survives --gc-after while the incident is open"
    );

    // `ack --republish` needs the replacement locally and succeeds.
    let mut ledger = change_ctx.ledger.into_inner();
    let targets = TargetSet::from_targets(
        change_targets
            .into_iter()
            .map(|target| target as Arc<dyn Target>)
            .collect(),
    );
    cinc_mirror::incident::ack(
        &mut ledger,
        &targets,
        &change_config,
        &incident,
        Some("replacement verified"),
        true,
    )
    .await
    .expect("ack --republish");

    let acked = cinc_mirror::incident::show(&ledger, &incident).expect("incident");
    assert_eq!(acked.state, cinc_mirror::ledger::IncidentState::Acked);
    assert_eq!(
        ledger
            .publication(&old.key(), "t1")
            .expect("old publication")
            .expect("row")
            .status,
        PublicationStatus::Superseded
    );
    assert_eq!(
        ledger
            .publication(&new.key(), "t1")
            .expect("new publication")
            .expect("row")
            .status,
        PublicationStatus::Published
    );
}

// Real targets ----------------------------------------------------------------

#[tokio::test]
async fn fans_out_to_the_oci_registry_and_a_local_rsync_directory() {
    let dir = TempDir::new().expect("state dir");
    let package = one_package();
    let fixture = Fixture::new(dir.path(), std::slice::from_ref(&package), &[], 2, 1);

    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    let oci = OciTarget::new(
        "oci",
        Registry::new(OciConfig {
            registry: mock.base_url().to_string(),
            namespace: NAMESPACE.to_string(),
            auth: OciAuth::Anonymous,
            insecure_http: true,
            ..OciConfig::default()
        })
        .expect("mock registry"),
    );
    let rsync_root = dir.path().join("rsync");
    let rsync = RsyncTarget::new(RsyncConfig {
        name: "rsync".to_string(),
        url: rsync_root.to_string_lossy().into_owned(),
        auth: TargetAuth::Anonymous,
        identity_file: None,
        password_file: None,
    })
    .expect("rsync target");
    let targets = TargetSet::from_targets(vec![
        Arc::new(oci) as Arc<dyn Target>,
        Arc::new(rsync) as Arc<dyn Target>,
    ]);
    let ctx = fixture.ctx_with("run-1", targets);

    let summary = run(&ctx, RunOpts::default()).await.expect("run");

    assert_eq!(summary.published, 2);
    assert_eq!(summary.downloaded, 1);
    assert_eq!(summary.exit_code, 0);

    let artifact = artifact_of(&package);
    let sha256 = sha256_hex(&package.body);
    let tag = artifact.tag();
    assert!(
        mock.manifest(REPO, &tag).is_some(),
        "the OCI target wrote the descriptive tag"
    );
    let blob = mock
        .blob(REPO, &format!("sha256:{sha256}"))
        .expect("the package layer is in the registry");
    assert_eq!(blob, package.body);

    let published = rsync_root.join(artifact.rsync_relpath());
    assert_eq!(
        std::fs::read(&published).expect("rsync package"),
        package.body
    );
    let metadata = rsync_root.join(format!("{}.metadata.json", artifact.rsync_relpath()));
    assert_eq!(
        std::fs::read_to_string(&metadata).expect("rsync metadata"),
        metadata_json(&package)
    );
    let sidecar = rsync_root.join(format!("{}.sha256", artifact.rsync_relpath()));
    assert_eq!(
        std::fs::read_to_string(&sidecar).expect("sidecar"),
        format!("{sha256}  {}\n", package.body.len())
    );
}

#[tokio::test]
async fn reusing_a_run_id_is_a_usage_error() {
    let dir = TempDir::new().expect("state dir");
    let fixture = Fixture::new(dir.path(), &[one_package()], &["t1"], 1, 1);
    let ctx = fixture.ctx("run-1");

    run(&ctx, RunOpts::default()).await.expect("first run");
    let events = ctx.ledger.lock().await.event_count().expect("events");

    let error = run(&ctx, RunOpts::default())
        .await
        .expect_err("a reused run id would silently duplicate every event");
    assert!(matches!(error, RunError::Usage { .. }), "{error:?}");
    assert_eq!(error.exit_code(), 64);
    assert_eq!(
        ctx.ledger.lock().await.event_count().expect("events"),
        events
    );
}

#[tokio::test]
async fn run_records_order_and_summary_in_the_run_row() {
    let dir = TempDir::new().expect("state dir");
    let package = one_package();
    let fixture = Fixture::new(dir.path(), std::slice::from_ref(&package), &["t1"], 1, 1);
    let ctx = fixture.ctx("run-1");

    let summary = run(&ctx, RunOpts::default()).await.expect("run");

    let row = ctx
        .ledger
        .lock()
        .await
        .run("run-1")
        .expect("run row query")
        .expect("run row");
    assert_eq!(row.order.as_deref(), Some("version_desc"));
    assert_eq!(row.outcome.as_deref(), Some("success"));
    assert_eq!(row.summary["published"], json!(summary.published));
    assert_eq!(row.summary["exit_code"], json!(0));
    assert_eq!(row.transport_order, vec!["ftp", "ftps", "https"]);
}
