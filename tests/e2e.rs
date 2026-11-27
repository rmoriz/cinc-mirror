//! End-to-end coverage of the production pipeline.
//!
//! One in-process run wires the real ledger, store, runner, verify and repair
//! to a fake HTTPS upstream, an instrumented payload ladder, the shared OCI
//! registry mock and a real rsync target on a local directory. The three runs
//! assert the property the whole design exists for: a second run transfers no
//! bytes, and a broken target is repaired from the local store without
//! downloading anything again.
//!
//! The run's event file is written and pushed to a local bare ledger remote the
//! same way the command layer does it, so the NDJSON contract is covered too.

mod common;

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::Command as Process;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use assert_cmd::Command as Binary;
use async_trait::async_trait;
use chrono::Utc;
use cinc_mirror::artifact::Artifact;
use cinc_mirror::config::{Config, Selection, TransportKind};
use cinc_mirror::ctx::Ctx;
use cinc_mirror::ledger::{EventKind, Ledger, LedgerStore};
use cinc_mirror::net::RateLimiter;
use cinc_mirror::prune;
use cinc_mirror::repair::{self, RepairOpts};
use cinc_mirror::runner::{self, RunOpts};
use cinc_mirror::scope::{ResolvedPolicy, ResolvedScope};
use cinc_mirror::source::transport::{PayloadTransport, TransportError};
use cinc_mirror::source::{Fetched, Fetcher, Source, SourceError};
use cinc_mirror::store::Store;
use cinc_mirror::targets::TargetSet;
use cinc_mirror::verify::{self, VerifyOpts};
use common::mirror::{
    mock_registry, oci_target, package_artifact, raw_metadata, rsync_target, sha256_hex,
};
use common::packages::MockPackages;
use serde_json::json;
use url::Url;

const BASE: &str = "https://downloads.cinc.sh/files";
const LEDGER_BRANCH: &str = "ledger";

/// One package the fake upstream serves.
#[derive(Debug)]
struct Spec {
    version: String,
    body: Vec<u8>,
}

impl Spec {
    fn new(version: &str, body: &[u8]) -> Self {
        Self {
            version: version.to_string(),
            body: body.to_vec(),
        }
    }

    fn basename(&self) -> String {
        format!("cinc_{}-1_amd64.deb", self.version)
    }

    fn upstream_path(&self) -> String {
        format!("stable/cinc/{}/debian/13/{}", self.version, self.basename())
    }
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

/// A fake HTTPS upstream holding the index pages and metadata documents.
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

/// Build the index tree and the metadata pages for `specs`.
fn upstream(specs: &[Spec]) -> (FakeUpstream, HashMap<String, Vec<u8>>) {
    let mut pages = HashMap::new();
    let mut payloads = HashMap::new();
    let mut versions: BTreeMap<String, Vec<String>> = BTreeMap::new();

    for spec in specs {
        versions
            .entry(spec.version.clone())
            .or_default()
            .push(spec.basename());
        let dir = format!("files/stable/cinc/{}/debian/13", spec.version);
        pages.insert(
            format!("{dir}/{}.metadata.json", spec.basename()),
            raw_metadata(&spec.body, &spec.version),
        );
        payloads.insert(spec.upstream_path(), spec.body.clone());
    }

    pages.insert(
        "files/stable/cinc/".to_string(),
        listing(versions.keys().map(|version| format!("{version}/"))),
    );
    for (version, basenames) in &versions {
        pages.insert(
            format!("files/stable/cinc/{version}/"),
            listing(["debian/".to_string()]),
        );
        pages.insert(
            format!("files/stable/cinc/{version}/debian/"),
            listing(["13/".to_string()]),
        );
        pages.insert(
            format!("files/stable/cinc/{version}/debian/13/"),
            listing(basenames.iter().map(|name| format!("{name}.metadata.json"))),
        );
    }

    (FakeUpstream { pages }, payloads)
}

/// A payload rung that serves fixture bytes and counts transfers.
#[derive(Debug)]
struct CountingPayload {
    payloads: Mutex<HashMap<String, Vec<u8>>>,
    calls: AtomicUsize,
    failing: Mutex<HashSet<String>>,
}

impl CountingPayload {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    /// Fail every attempt for `remote_path`, as an unreachable object.
    fn fail(&self, remote_path: &str) {
        self.failing
            .lock()
            .expect("failing lock")
            .insert(remote_path.to_string());
    }

    /// Serve `remote_path` again.
    fn heal(&self, remote_path: &str) {
        self.failing
            .lock()
            .expect("failing lock")
            .remove(remote_path);
    }

    fn is_failing(&self, remote_path: &str) -> bool {
        self.failing
            .lock()
            .expect("failing lock")
            .contains(remote_path)
    }
}

#[async_trait]
impl PayloadTransport for CountingPayload {
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
        if self.is_failing(remote_path) {
            return Err(TransportError::Retryable {
                path: remote_path.to_string(),
                reason: "injected transfer failure".to_string(),
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
        let start = usize::try_from(resume_from).unwrap_or(0).min(body.len());
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dest)
            .map_err(|source| TransportError::Local {
                path: dest.display().to_string(),
                source,
            })?;
        std::io::Write::write_all(&mut file, &body[start..]).map_err(|source| {
            TransportError::Local {
                path: dest.display().to_string(),
                source,
            }
        })?;
        Ok((body.len() - start) as u64)
    }
}

struct Fixture {
    ctx: Ctx,
    payload: Arc<CountingPayload>,
    mock: common::registry::MockRegistry,
    specs: Vec<Spec>,
    state: tempfile::TempDir,
    rsync_root: PathBuf,
    store: LedgerStore,
}

impl Fixture {
    fn artifact(&self, spec: &Spec) -> Artifact {
        package_artifact(&spec.body, &spec.version)
    }

    /// Start a new run id on the same context, as the command layer does.
    fn start_run(&mut self, run_id: &str) {
        self.ctx.run_id = run_id.to_string();
    }

    /// Write and push the run's event file, exactly as the CLI does.
    fn persist(&self, run_id: &str) {
        let events = self
            .ctx
            .ledger
            .try_lock()
            .expect("the run is finished")
            .events()
            .expect("events")
            .into_iter()
            .filter(|event| event.run_id == run_id)
            .collect::<Vec<_>>();
        assert!(
            !events.is_empty(),
            "run {run_id} appended no events to commit"
        );
        let path = self.store.write_run(&events).expect("write the run file");
        self.store
            .commit_and_push(&path, &format!("run {run_id}"))
            .expect("push the run file");
    }
}

async fn fixture() -> Fixture {
    let specs = vec![
        Spec::new("19.4.46", b"the package bytes of 19.4.46"),
        Spec::new("19.4.47", b"the package bytes of 19.4.47"),
    ];
    let (upstream, payloads) = upstream(&specs);
    let payload = Arc::new(CountingPayload {
        payloads: Mutex::new(payloads),
        calls: AtomicUsize::new(0),
        failing: Mutex::new(HashSet::new()),
    });
    let source = Source::with_fetcher(Arc::new(upstream), Url::parse(BASE).expect("base url"))
        .with_payload_transports(vec![Arc::clone(&payload) as Arc<dyn PayloadTransport>])
        .with_retry_policy(cinc_mirror::source::transport::RetryPolicy::new(
            1,
            Duration::ZERO,
        ));

    let state = tempfile::tempdir().expect("state dir");
    let rsync_root = state.path().join("rsync-target");
    let mock = mock_registry().await;

    let targets = TargetSet::from_targets(vec![
        Arc::new(oci_target(&mock, "oci")),
        Arc::new(rsync_target("rsync", &rsync_root)),
    ]);

    let config = Config {
        state_dir: state.path().to_path_buf(),
        concurrency: 2,
        upload_concurrency: 2,
        // `prune_targets` walks `config.targets`; the publishing `TargetSet`
        // below is built separately.
        targets: vec![common::mirror::oci_target_config(&mock, "oci")],
        retention: cinc_mirror::config::RetentionConfig {
            prune: true,
            ..cinc_mirror::config::RetentionConfig::default()
        },
        ..Config::default()
    };
    let scope = ResolvedScope {
        policies: vec![ResolvedPolicy {
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
            all_versions: true,
        }],
    };

    let ledger = Ledger::open(state.path()).expect("ledger");
    let ctx = Ctx {
        config: Arc::new(config),
        scope,
        source,
        store: Store::open(state.path()).expect("store"),
        ledger: tokio::sync::Mutex::new(ledger),
        targets,
        rate: RateLimiter::new(None),
        run_id: "e2e-run-1".to_string(),
        state_dir: state.path().to_path_buf(),
    };

    // A local bare remote, so the run file is really committed and pushed.
    let remote = state.path().join("ledger.git");
    let status = Process::new("git")
        .args(["init", "--bare", "--quiet"])
        .arg(&remote)
        .status()
        .expect("run git init --bare");
    assert!(status.success(), "git init --bare failed");
    let store = LedgerStore::new(
        state.path().join("ledger-repo"),
        format!("file://{}", remote.display()),
        LEDGER_BRANCH.to_string(),
    );
    store.sync().expect("sync the fresh ledger remote");

    Fixture {
        ctx,
        payload,
        mock,
        specs,
        state,
        rsync_root,
        store,
    }
}

#[tokio::test]
async fn e2e_mirror_then_noop_then_repair() {
    let mut fixture = fixture().await;

    // Run 1: both artifacts are downloaded and published to both targets.
    let first = runner::run(&fixture.ctx, RunOpts::default())
        .await
        .expect("first mirror run");
    assert_eq!(first.discovered, 2, "{first:?}");
    assert_eq!(first.downloaded, 2, "{first:?}");
    assert_eq!(first.published, 4, "{first:?}");
    assert_eq!(first.failed, 0, "{first:?}");
    assert_eq!(first.incidents_opened, 0, "{first:?}");
    assert_eq!(first.exit_code, 0, "{first:?}");
    assert_eq!(fixture.payload.calls(), 2);
    assert_eq!(fixture.mock.manifest_put_count(), 2);

    let run_file = fixture
        .store
        .workdir()
        .join("runs")
        .join("e2e-run-1.ndjson");
    assert!(
        !run_file.exists(),
        "the run file is written by the command layer"
    );
    fixture.persist("e2e-run-1");
    let events = std::fs::read_to_string(&run_file).expect("run file");
    assert!(events.contains("\"run_started\""), "{events}");
    assert!(events.contains("\"run_finished\""), "{events}");

    // Run 2: everything is satisfied; not one package byte moves.
    fixture.start_run("e2e-run-2");
    let second = runner::run(&fixture.ctx, RunOpts::default())
        .await
        .expect("second mirror run");
    assert_eq!(second.discovered, 2, "{second:?}");
    assert_eq!(second.satisfied, 2, "{second:?}");
    assert_eq!(second.downloaded, 0, "{second:?}");
    assert_eq!(second.bytes_downloaded, 0, "{second:?}");
    assert_eq!(second.published, 0, "{second:?}");
    assert_eq!(second.exit_code, 0, "{second:?}");
    assert_eq!(fixture.payload.calls(), 2, "a no-op run must not download");
    assert_eq!(fixture.mock.manifest_put_count(), 2);

    // Break exactly one target: the rsync publication disappears entirely.
    let broken = fixture.artifact(&fixture.specs[0]);
    let package = fixture.rsync_root.join(broken.rsync_relpath());
    assert!(package.is_file(), "run 1 published {}", package.display());
    std::fs::remove_dir_all(package.parent().expect("published directory"))
        .expect("break the rsync publication");

    let before = verify::run(&fixture.ctx, VerifyOpts::default())
        .await
        .expect("verify before repair");
    assert_eq!(before.findings.len(), 1, "{before}");
    assert_eq!(before.findings[0].target.as_deref(), Some("rsync"));

    // Run 3: repair restores that one publication from the local store.
    fixture.start_run("e2e-run-3");
    let repair = repair::run(&fixture.ctx, RepairOpts::default())
        .await
        .expect("repair run");
    assert_eq!(repair.repaired, 1, "{repair}");
    assert_eq!(repair.failed, 0, "{repair}");
    assert_eq!(repair.actions.len(), 1, "{repair}");
    assert_eq!(repair.actions[0].target, "rsync", "{repair}");
    assert_eq!(repair.actions[0].artifact_key, broken.key(), "{repair}");
    assert_eq!(
        fixture.payload.calls(),
        2,
        "repair must reuse the verified local blob"
    );
    assert_eq!(
        fixture.mock.manifest_put_count(),
        2,
        "repair must not re-publish the healthy OCI target"
    );
    assert!(package.is_file(), "repair restored {}", package.display());

    let after = verify::run(&fixture.ctx, VerifyOpts::default())
        .await
        .expect("verify after repair");
    assert!(after.is_clean(), "{after}");
    assert_eq!(after.exit_code(), 0);

    // The repair's events are the run's NDJSON record.
    fixture.persist("e2e-run-3");
    let repair_file = std::fs::read_to_string(
        fixture
            .store
            .workdir()
            .join("runs")
            .join("e2e-run-3.ndjson"),
    )
    .expect("repair run file");
    assert!(repair_file.contains("\"published\""), "{repair_file}");

    // Keep the unused helpers honest: the state directory is the fixture's.
    assert!(fixture.state.path().is_dir());
    let keys: HashSet<String> = fixture
        .specs
        .iter()
        .map(|spec| sha256_hex(&spec.body))
        .collect();
    assert_eq!(keys.len(), 2);
    let _ = json!({ "ok": true });
}

#[tokio::test]
async fn e2e_prune_removes_a_stale_publication_a_denied_prune_exits_two() {
    let mut fixture = fixture().await;
    let repo = format!("{}/{}", common::mirror::NAMESPACE, common::mirror::PROJECT);

    // A reference no policy selects any more: an old major line.
    fixture
        .mock
        .store_manifest(&repo, "19.4.1", b"the package bytes of 19.4.1");

    // The mirror run publishes both wanted artifacts and prunes the stale one.
    let first = runner::run(&fixture.ctx, RunOpts::default())
        .await
        .expect("mirror run with prune");
    assert_eq!(first.published, 4, "{first:?}");
    assert_eq!(first.pruned, 1, "{first:?}");
    assert_eq!(first.exit_code, 0, "{first:?}");
    assert_eq!(fixture.mock.delete_count(), 1);
    assert!(
        fixture.mock.manifest(&repo, "19.4.1").is_none(),
        "the stale reference is gone"
    );
    for spec in &fixture.specs {
        let artifact = fixture.artifact(spec);
        assert!(
            fixture.mock.manifest(&repo, &artifact.tag()).is_some(),
            "the wanted tag {} survives",
            artifact.tag()
        );
    }

    // A prune on its own, with the registry refusing deletes: one failure and
    // exit code 2, and the stale reference stays.
    fixture
        .mock
        .store_manifest(&repo, "19.4.1", b"the package bytes of 19.4.1");
    fixture.mock.deny_deletes(&repo);

    let artifacts: Vec<Artifact> = fixture
        .specs
        .iter()
        .map(|spec| fixture.artifact(spec))
        .collect();
    let wanted = prune::wanted(&artifacts.iter().collect::<Vec<_>>());
    let crawled = BTreeMap::from([(common::mirror::PROJECT.to_string(), artifacts.len())]);
    let hold_back: HashSet<String> = HashSet::new();
    let configured = HashSet::from([common::mirror::PROJECT.to_string()]);
    let projects = vec![common::mirror::PROJECT];
    let pass = prune::Pass {
        projects: &projects,
        wanted: &wanted,
        crawled: &crawled,
        hold_back: &hold_back,
        configured: &configured,
        sweep_orphans: false,
        dry_run: false,
        budget: 10,
        seq: None,
    };

    fixture.start_run("e2e-prune-denied");
    let denied = prune::prune_targets(&fixture.ctx, &pass).await;
    assert_eq!(denied.pruned, 0, "{denied:?}");
    assert!(denied.failed > 0, "{denied:?}");
    assert_eq!(denied.exit_code, 2, "{denied:?}");
    assert!(
        fixture.mock.manifest(&repo, "19.4.1").is_some(),
        "a denied prune leaves the reference alone"
    );
}

/// A state directory with a bare ledger remote and a configuration for the
/// binary `prune` command against `api_base`.
///
/// The configuration has no policies on purpose: the packages sweep then empties
/// every package the mock holds and the command needs no upstream crawl, so the
/// test stays offline. Returns the state directory (kept alive by the caller)
/// and the configuration path.
fn prune_layout(api_base: &str) -> (tempfile::TempDir, std::path::PathBuf) {
    let state = tempfile::tempdir().expect("state dir");
    let remote = state.path().join("ledger.git");
    let status = Process::new("git")
        .args(["init", "--bare", "--quiet"])
        .arg(&remote)
        .status()
        .expect("run git init --bare");
    assert!(status.success(), "git init --bare failed");

    let config = state.path().join("mirror.toml");
    std::fs::write(
        &config,
        format!(
            r#"state_dir = {state:?}

[ledger]
branch = "{LEDGER_BRANCH}"
remote = "file://{remote}"

[retention]
delete = "packages-api"
api_base = "{api_base}"

[[targets]]
name = "ghcr"
kind = "oci"
registry = "ghcr.io"
namespace = "acme/mirror"
auth = "anonymous"
"#,
            state = state.path(),
            remote = remote.display(),
        ),
    )
    .expect("write config");
    (state, config)
}

/// Invoke the built binary on `config` and return its output.
///
/// The mock needs the runtime, so the tests use the multi-thread flavour: the
/// blocking `output()` must not stop the only worker. Without `token` both
/// credential variables are removed, so the target is ineligible.
fn prune_binary(config: &Path, extra: &[&str], token: bool) -> std::process::Output {
    let mut command = Binary::new(env!("CARGO_BIN_EXE_cinc-mirror"));
    command
        .arg("--config")
        .arg(config)
        .arg("--allow-unleased")
        .arg("prune")
        .args(extra);
    if token {
        command.env("GHCR_TOKEN", "ghcr-e2e-token");
    } else {
        command
            .env_remove("GHCR_TOKEN")
            .env_remove("GITHUB_TOKEN")
            .env_remove("CINC_MIRROR_GHCR_API_TOKEN");
    }
    command.output().expect("run prune")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_binary_prune_reports_a_denied_delete_and_exits_two() {
    let mock = MockPackages::start().await;
    mock.seed_version("mirror/cinc", &["19.4.46"], Utc::now());
    mock.seed_version("mirror/cinc", &["19.4.45"], Utc::now());
    mock.fail_deletes_with(403);
    let (state, config) = prune_layout(mock.base_url());

    let output = prune_binary(&config, &[], true);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert_eq!(output.status.code(), Some(2), "{stdout}{stderr}");
    assert!(stdout.contains("pruned=0"), "{stdout}");
    assert!(stdout.contains("failed=1"), "{stdout}");
    assert!(
        stdout.contains("skipped targets: ghcr"),
        "a refused target is named:\n{stdout}"
    );
    assert_eq!(
        mock.versions_for("mirror/cinc").len(),
        2,
        "a denied prune keeps both versions alive"
    );
    assert!(mock.deleted().is_empty());

    // The run is committed and closed, so a denial is visible afterwards. A
    // denied delete appends no per-reference event; the summary carries it.
    let ledger = Ledger::open(state.path()).expect("ledger");
    let events = ledger.events().expect("events");
    let kinds: Vec<EventKind> = events.iter().map(|event| event.kind).collect();
    assert!(kinds.contains(&EventKind::RunStarted), "{kinds:?}");
    assert!(kinds.contains(&EventKind::RunFinished), "{kinds:?}");
    let finished = events
        .iter()
        .find(|event| event.kind == EventKind::RunFinished)
        .expect("a finished event");
    assert_eq!(finished.detail["outcome"], json!("partial"));
    assert_eq!(finished.detail["summary"]["prune_failed"], json!(1));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_binary_prune_dry_run_plans_and_writes_no_event() {
    let mock = MockPackages::start().await;
    mock.seed_version("mirror/cinc", &["19.4.46"], Utc::now());
    mock.seed_version("mirror/cinc", &["19.4.45"], Utc::now());
    let (state, config) = prune_layout(mock.base_url());

    let output = prune_binary(&config, &["--dry-run"], true);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    assert!(
        stdout.contains("dry run: 2 reference(s) would be deleted"),
        "the plan is listed and counted:\n{stdout}"
    );
    assert!(stdout.contains("ghcr.io/acme/mirror/cinc:"), "{stdout}");
    assert_eq!(
        mock.versions_for("mirror/cinc").len(),
        1,
        "the probe really deletes its first reference"
    );

    // Nothing is written: no run file, no event, no ledger row.
    let ledger = Ledger::open(state.path()).expect("ledger");
    assert!(
        ledger.events().expect("events").is_empty(),
        "a dry run writes no event"
    );
    let worktree = state.path().join("ledger-repo");
    assert!(
        worktree.join(".git").exists(),
        "the ledger worktree exists:\n{stderr}"
    );
    assert!(
        !worktree.join("runs").exists(),
        "a dry run writes no run file"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_binary_prune_dry_run_json_carries_the_plan() {
    let mock = MockPackages::start().await;
    mock.seed_version("mirror/cinc", &["19.4.46"], Utc::now());
    mock.seed_version("mirror/cinc", &["19.4.45"], Utc::now());
    let (_state, config) = prune_layout(mock.base_url());

    let output = prune_binary(&config, &["--dry-run", "--json"], true);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    assert_eq!(output.status.code(), Some(0), "{stdout}");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("a JSON report");
    assert_eq!(report["pruned"], json!(2), "{stdout}");
    let references = report["references"].as_array().expect("the reference list");
    assert_eq!(references.len(), 2, "{stdout}");
    assert!(references.len() as u64 == report["pruned"].as_u64().unwrap_or(0));
    assert!(
        references.iter().all(|line| line
            .as_str()
            .is_some_and(|line| line.contains("mirror/cinc:"))),
        "{stdout}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_binary_prune_without_a_token_stays_green_and_prunes_nothing() {
    let mock = MockPackages::start().await;
    mock.seed_version("mirror/cinc", &["19.4.46"], Utc::now());
    let (_state, config) = prune_layout(mock.base_url());

    let output = prune_binary(&config, &[], false);

    let stdout = String::from_utf8_lossy(&output.stdout).to_string();
    let stderr = String::from_utf8_lossy(&output.stderr).to_string();
    assert_eq!(output.status.code(), Some(0), "{stdout}{stderr}");
    assert!(
        stdout.contains("pruned=0 failed=0 deferred=0 skipped=0 exit=0"),
        "an ineligible target counts nowhere:\n{stdout}"
    );
    // Only the warning distinguishes it from a reconciled, empty target.
    assert!(
        stderr.contains(
            "packages deletes need CINC_MIRROR_<TARGET>_API_TOKEN, GHCR_TOKEN or GITHUB_TOKEN"
        ),
        "{stderr}"
    );
    assert!(mock.versions_for("mirror/cinc").len() == 1);
}

#[tokio::test]
async fn e2e_backfill_cursor_rotates_a_capped_queue() {
    let mut fixture = fixture().await;
    // Version descending: 19.4.47 is first, 19.4.46 second.
    let first_processed = fixture.artifact(&fixture.specs[1]);
    let second_processed = fixture.artifact(&fixture.specs[0]);
    let fingerprint = "policy-fingerprint-e2e";

    // Make the newest artifact undownloadable so it stays in the queue; that is
    // the case in which the cursor has to rotate instead of restarting.
    fixture.payload.fail(&first_processed.rsync_relpath());

    let first = runner::run(
        &fixture.ctx,
        RunOpts {
            max_artifacts: Some(1),
            cursor_fingerprint: Some(fingerprint.to_string()),
            ..RunOpts::default()
        },
    )
    .await
    .expect("first capped backfill run");
    assert_eq!(first.downloaded, 0, "{first:?}");
    assert!(first.capped, "a limit with work left must report capped");
    assert_eq!(
        first.last_artifact_key.as_deref(),
        Some(first_processed.key().as_str())
    );

    let cursor = fixture
        .ctx
        .ledger
        .lock()
        .await
        .cursor(fingerprint)
        .expect("cursor query")
        .expect("cursor row");
    assert_eq!(
        cursor.last_artifact_key.as_deref(),
        Some(first_processed.key().as_str())
    );
    assert_eq!(
        cursor.last_version.as_deref(),
        Some(first_processed.version.as_str())
    );

    // The next capped run starts just after the cursor: the still-queued first
    // artifact is not retried before the second one is reached.
    fixture.start_run("e2e-backfill-2");
    let second = runner::run(
        &fixture.ctx,
        RunOpts {
            max_artifacts: Some(1),
            start_after: cursor.last_artifact_key.clone(),
            cursor_fingerprint: Some(fingerprint.to_string()),
            ..RunOpts::default()
        },
    )
    .await
    .expect("resumed capped backfill run");
    assert_eq!(second.downloaded, 1, "{second:?}");
    assert_eq!(
        second.last_artifact_key.as_deref(),
        Some(second_processed.key().as_str()),
        "the queue starts after the stored key instead of restarting"
    );

    // The healed artifact is picked up by an uncapped run, which clears the
    // cursor because the queue is now empty.
    fixture.payload.heal(&first_processed.rsync_relpath());
    fixture.start_run("e2e-backfill-3");
    let third = runner::run(
        &fixture.ctx,
        RunOpts {
            cursor_fingerprint: Some(fingerprint.to_string()),
            ..RunOpts::default()
        },
    )
    .await
    .expect("uncapped backfill run");
    assert!(!third.capped, "{third:?}");
    let cleared = fixture
        .ctx
        .ledger
        .lock()
        .await
        .cursor(fingerprint)
        .expect("cursor query")
        .expect("cursor row");
    assert_eq!(
        cleared.last_artifact_key, None,
        "an uncapped run clears the cursor"
    );
    assert_eq!(cleared.last_version, None);
}
