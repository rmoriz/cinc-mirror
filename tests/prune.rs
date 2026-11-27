//! Prune execution tests.
//!
//! Every test drives a real ledger and one of the two delete backends: the
//! shared in-memory registry or the packages API mock. The assertions look at
//! what actually disappeared, at the events the pass appended and at the counts
//! and lines the report came back with.

mod common;

use std::collections::{BTreeMap, HashSet};
use std::ffi::OsString;
use std::sync::{Arc, Mutex, Once};

use chrono::{Duration as ChronoDuration, Utc};
use cinc_mirror::artifact::Artifact;
use cinc_mirror::config::TargetKind;
use cinc_mirror::ctx::Ctx;
use cinc_mirror::ledger::{Event, EventKind, Ledger, PublicationStatus};
use cinc_mirror::prune::{backend_for, prune_targets, Pass, PruneReport, Wanted};
use cinc_mirror::report::{EXIT_OK, EXIT_PARTIAL};
use cinc_mirror::runner::Seq;
use cinc_mirror::scope::ResolvedScope;
use cinc_mirror::targets::TargetSet;
use common::mirror::{
    config_with_retention, context_with, mock_registry, oci_target, oci_target_config,
    package_artifact, packages_target_config, source_with, NAMESPACE, PROJECT,
};
use common::packages::MockPackages;
use common::registry::MockRegistry;
use serde_json::json;

/// Serialises tests that change process-wide environment variables.
static ENV_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

/// Serialises the tests that assert captured warnings.
static LOG_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn lock_env() -> tokio::sync::MutexGuard<'static, ()> {
    ENV_LOCK.lock().await
}

/// Sets an environment variable and restores the previous value on drop.
struct EnvVar {
    key: &'static str,
    previous: Option<OsString>,
}

impl EnvVar {
    fn set(key: &'static str, value: &str) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, previous }
    }

    fn remove(key: &'static str) -> Self {
        let previous = std::env::var_os(key);
        std::env::remove_var(key);
        Self { key, previous }
    }
}

impl Drop for EnvVar {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

/// Everything captured from the `WARN` level of the pass.
static LOGS: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// A writer that appends to [`LOGS`].
struct Capture;

impl std::io::Write for Capture {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        LOGS.lock()
            .unwrap_or_else(|error| error.into_inner())
            .extend_from_slice(buffer);
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Hands out [`Capture`] writers.
struct MakeCapture;

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for MakeCapture {
    type Writer = Capture;

    fn make_writer(&self) -> Capture {
        Capture
    }
}

/// Install the warning capture once per test binary.
fn capture_warnings() {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .without_time()
            .with_ansi(false)
            .with_writer(MakeCapture)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    });
}

/// Clear the capture and hold the log lock for the duration of a test.
async fn log_guard() -> tokio::sync::MutexGuard<'static, ()> {
    capture_warnings();
    let guard = LOG_LOCK.lock().await;
    clear_warnings();
    guard
}

/// Everything warned since the last [`log_guard`].
fn warnings() -> String {
    String::from_utf8_lossy(&LOGS.lock().unwrap_or_else(|error| error.into_inner())).into_owned()
}

fn clear_warnings() {
    LOGS.lock()
        .unwrap_or_else(|error| error.into_inner())
        .clear();
}

/// The registry repository of a project.
fn repo(project: &str) -> String {
    format!("{NAMESPACE}/{project}")
}

/// Opt-in inputs of a pass; everything unset is filled sensibly.
#[derive(Default)]
struct Opts {
    crawled: BTreeMap<String, usize>,
    hold_back: HashSet<String>,
    configured: HashSet<String>,
    sweep_orphans: bool,
    dry_run: bool,
    /// `None` leaves the budget wide open; `Some(0)` deletes nothing.
    budget: Option<usize>,
}

impl Opts {
    fn budget(mut self, budget: usize) -> Self {
        self.budget = Some(budget);
        self
    }

    fn crawled(mut self, project: &str, count: usize) -> Self {
        self.crawled.insert(project.to_string(), count);
        self
    }

    fn hold_back(mut self, project: &str) -> Self {
        self.hold_back.insert(project.to_string());
        self
    }

    fn configured(mut self, projects: &[&str]) -> Self {
        self.configured
            .extend(projects.iter().map(|project| (*project).to_string()));
        self
    }

    fn sweep_orphans(mut self) -> Self {
        self.sweep_orphans = true;
        self
    }

    fn dry_run(mut self) -> Self {
        self.dry_run = true;
        self
    }
}

/// Run one pass over `projects`; each project counts as crawled once unless
/// [`Opts::crawled`] says otherwise.
async fn prune(ctx: &Ctx, projects: &[&str], wanted: &Wanted, opts: Opts) -> PruneReport {
    let crawled = if opts.crawled.is_empty() {
        projects
            .iter()
            .map(|project| ((*project).to_string(), 1))
            .collect()
    } else {
        opts.crawled
    };
    let configured = if opts.configured.is_empty() {
        projects
            .iter()
            .map(|project| (*project).to_string())
            .collect()
    } else {
        opts.configured
    };
    let seq = Seq::new(1);
    let seq = if opts.dry_run { None } else { Some(&seq) };
    prune_targets(
        ctx,
        &Pass {
            projects,
            wanted,
            crawled: &crawled,
            hold_back: &opts.hold_back,
            configured: &configured,
            sweep_orphans: opts.sweep_orphans,
            dry_run: opts.dry_run,
            budget: opts.budget.unwrap_or(usize::MAX),
            seq,
        },
    )
    .await
}

/// A [`Ctx`] for a registry target backed by `mock`.
fn registry_context(state: &std::path::Path, ledger: Ledger, mock: &MockRegistry) -> Ctx {
    context_with(
        config_with_retention(
            state,
            "https://api.github.com",
            oci_target_config(mock, "ghcr"),
        ),
        ResolvedScope::default(),
        ledger,
        TargetSet::from_targets(vec![Arc::new(oci_target(mock, "ghcr"))]),
        source_with(Vec::new()),
    )
}

/// A [`Ctx`] for a packages target against `mock`.
fn packages_context(state: &std::path::Path, ledger: Ledger, mock: &MockPackages) -> Ctx {
    context_with(
        config_with_retention(
            state,
            mock.base_url(),
            packages_target_config("ghcr", "acme/mirror"),
        ),
        ResolvedScope::default(),
        ledger,
        TargetSet::from_targets(Vec::new()),
        source_with(Vec::new()),
    )
}

/// Seed an `artifact_seen` event for `artifact`.
fn seed_artifact(ledger: &mut Ledger, artifact: &Artifact) {
    ledger
        .append(
            &Event::new(
                format!("seed-{}", artifact.key()),
                1,
                Utc::now(),
                EventKind::ArtifactSeen,
            )
            .with_artifact(artifact.key())
            .with_detail(json!({
                "artifact": cinc_mirror::ledger::artifact_detail(artifact),
                "upstream_path": artifact.rsync_relpath(),
                "size": null,
            })),
        )
        .expect("artifact_seen");
}

/// Seed a `published` event naming `remote_ref` as the target wrote it.
fn seed_publication(ledger: &mut Ledger, artifact: &Artifact, target: &str, remote_ref: &str) {
    ledger
        .append(
            &Event::new(
                format!("seed-{}", artifact.key()),
                3,
                Utc::now(),
                EventKind::Published,
            )
            .with_artifact(artifact.key())
            .with_target(target)
            .with_detail(json!({
                "remote_ref": remote_ref,
                "remote_digest": format!("sha256:{}", artifact.sha256),
            })),
        )
        .expect("publication");
}

/// Seed an open incident on `artifact`, which protects all its publications.
fn seed_incident(ledger: &mut Ledger, artifact: &Artifact) {
    ledger
        .append(
            &Event::new(
                format!("seed-incident-{}", artifact.key()),
                2,
                Utc::now(),
                EventKind::IncidentOpened,
            )
            .with_artifact(artifact.key())
            .with_detail(json!({
                "kind": "hash_changed",
                "artifact_key": artifact.key(),
            })),
        )
        .expect("incident_opened");
}

async fn events(ctx: &Ctx) -> Vec<Event> {
    ctx.ledger.lock().await.events().expect("events")
}

#[tokio::test]
async fn a_stale_tag_is_deleted_and_a_pruned_event_is_appended() {
    let mock = mock_registry().await;
    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    let artifact = package_artifact(b"stale bytes", "19.4.46");
    let digest = mock.store_manifest(&repo(PROJECT), &artifact.tag(), b"stale bytes");
    seed_artifact(&mut ledger, &artifact);
    let remote_ref = format!(
        "{}/{}:{}",
        mock.registry_name(),
        repo(PROJECT),
        artifact.tag()
    );
    seed_publication(&mut ledger, &artifact, "ghcr", &remote_ref);

    let ctx = registry_context(state.path(), ledger, &mock);
    let report = prune(&ctx, &[PROJECT], &Wanted::default(), Opts::default()).await;

    assert_eq!(report.pruned, 1, "{report:?}");
    assert!(mock.manifest(&repo(PROJECT), &artifact.tag()).is_none());
    assert_eq!(mock.delete_count(), 1);
    let events = events(&ctx).await;
    let pruned: Vec<&Event> = events
        .iter()
        .filter(|event| event.kind == EventKind::Pruned)
        .collect();
    assert_eq!(pruned.len(), 1);
    assert_eq!(
        pruned[0].artifact_key.as_deref(),
        Some(artifact.key().as_str())
    );
    assert_eq!(pruned[0].target.as_deref(), Some("ghcr"));
    assert_eq!(pruned[0].detail["remote_ref"], json!(remote_ref));
    assert_eq!(pruned[0].detail["remote_digest"], json!(digest));
}

#[tokio::test]
async fn a_stale_tag_without_a_ledger_row_still_deletes() {
    let mock = mock_registry().await;
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");
    mock.store_manifest(&repo(PROJECT), "19.4.46-debian-13-amd64", b"stale");

    let ctx = registry_context(state.path(), ledger, &mock);
    let report = prune(&ctx, &[PROJECT], &Wanted::default(), Opts::default()).await;

    assert_eq!(report.pruned, 1);
    assert!(mock
        .manifest(&repo(PROJECT), "19.4.46-debian-13-amd64")
        .is_none());
    let events = events(&ctx).await;
    let pruned: Vec<&Event> = events
        .iter()
        .filter(|event| event.kind == EventKind::Pruned)
        .collect();
    assert_eq!(pruned.len(), 1);
    assert_eq!(pruned[0].artifact_key, None);
}

#[tokio::test]
async fn a_version_created_after_the_cutoff_survives() {
    let _guard = lock_env().await;
    let _token = EnvVar::set("GHCR_TOKEN", "test-token");
    let mock = MockPackages::start().await;
    mock.owner_is_org("acme");
    let stale = mock.seed_version(
        "mirror/cinc",
        &["19.4.46-debian-13-amd64"],
        Utc::now() - ChronoDuration::hours(2),
    );
    mock.seed_version("mirror/cinc", &[], Utc::now() + ChronoDuration::hours(2));
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");

    let ctx = packages_context(state.path(), ledger, &mock);
    let report = prune(&ctx, &[PROJECT], &Wanted::default(), Opts::default()).await;

    assert_eq!(report.pruned, 1, "{report:?}");
    assert_eq!(mock.deleted(), vec![stale]);
}

#[tokio::test]
async fn a_project_without_crawled_artifacts_is_emptied_and_warned_about_once() {
    let _log = log_guard().await;
    let _guard = lock_env().await;
    let _token = EnvVar::set("GHCR_TOKEN", "test-token");
    let mock = MockPackages::start().await;
    mock.owner_is_org("acme");
    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");

    // Both would survive under the normal rules: `19.4.46` is wanted and the
    // artifact of `19.4.45` has an open incident. Emptying must ignore both.
    let wanted_artifact = package_artifact(b"wanted bytes", "19.4.46");
    seed_artifact(&mut ledger, &wanted_artifact);
    let protected_artifact = package_artifact(b"protected bytes", "19.4.45");
    seed_artifact(&mut ledger, &protected_artifact);
    seed_publication(
        &mut ledger,
        &protected_artifact,
        "ghcr",
        &format!("ghcr.io/acme/mirror/cinc:{}", protected_artifact.tag()),
    );
    seed_incident(&mut ledger, &protected_artifact);
    // The listed tag is the one `protection` derives from the publication, so
    // the incident alone would protect this version.
    let wanted_version = mock.seed_version("mirror/cinc", &["19.4.46"], Utc::now());
    let protected = mock.seed_version("mirror/cinc", &[&protected_artifact.tag()], Utc::now());
    let wanted = Wanted {
        tags: ["19.4.46".to_string()].into_iter().collect(),
    };

    let ctx = packages_context(state.path(), ledger, &mock);
    let report = prune(
        &ctx,
        &[PROJECT],
        &wanted,
        Opts::default().crawled(PROJECT, 0),
    )
    .await;

    assert_eq!(report.pruned, 2, "{report:?}");
    let mut deleted = mock.deleted();
    deleted.sort_unstable();
    let mut expected = vec![wanted_version, protected];
    expected.sort_unstable();
    assert_eq!(
        deleted, expected,
        "the wanted and the protected version die"
    );
    assert!(mock.versions_for("mirror/cinc").is_empty());
    assert_eq!(
        warnings().matches("has no crawled artifacts").count(),
        1,
        "{}",
        warnings()
    );
}

#[tokio::test]
async fn a_held_back_project_is_untouched() {
    let _guard = lock_env().await;
    let _token = EnvVar::set("GHCR_TOKEN", "test-token");
    let mock = MockPackages::start().await;
    mock.owner_is_org("acme");
    mock.seed_version("mirror/cinc", &["19.4.46"], Utc::now());
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");

    let ctx = packages_context(state.path(), ledger, &mock);
    let report = prune(
        &ctx,
        &[PROJECT],
        &Wanted::default(),
        Opts::default().hold_back(PROJECT),
    )
    .await;

    assert_eq!(report.pruned, 0);
    assert!(mock.deleted().is_empty());
}

#[tokio::test]
async fn a_405_skips_the_target_without_counting_a_failure() {
    let mock = mock_registry().await;
    mock.answer_405();
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");
    mock.store_manifest(&repo(PROJECT), "19.4.46-debian-13-amd64", b"stale");

    let ctx = registry_context(state.path(), ledger, &mock);
    let report = prune(&ctx, &[PROJECT], &Wanted::default(), Opts::default()).await;

    assert_eq!(report.targets_skipped, vec!["ghcr".to_string()]);
    assert_eq!(report.failed, 0);
    assert_eq!(report.pruned, 0);
    assert_eq!(report.exit_code, EXIT_PARTIAL);
    assert!(mock
        .manifest(&repo(PROJECT), "19.4.46-debian-13-amd64")
        .is_some());
}

#[tokio::test]
async fn a_403_aborts_the_project_and_leaves_the_budget_unspent() {
    let _log = log_guard().await;
    let _guard = lock_env().await;
    let _token = EnvVar::set("GHCR_TOKEN", "test-token");
    let mock = MockPackages::start().await;
    mock.owner_is_org("acme");
    mock.seed_version("mirror/cinc", &["19.4.46"], Utc::now());
    mock.deny();
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");

    let ctx = packages_context(state.path(), ledger, &mock);
    let report = prune(
        &ctx,
        &[PROJECT],
        &Wanted::default(),
        Opts::default().budget(1),
    )
    .await;

    assert_eq!(report.failed, 1, "{report:?}");
    assert_eq!(report.deferred, 0);
    assert_eq!(report.pruned, 0);
    assert_eq!(report.exit_code, EXIT_PARTIAL);
    assert_eq!(
        report.targets_skipped,
        vec!["ghcr".to_string()],
        "the refused listing names its target"
    );
    assert!(mock.deleted().is_empty());
    assert_eq!(
        warnings().matches("abandoning the project").count(),
        1,
        "{}",
        warnings()
    );
}

#[tokio::test]
async fn a_registry_403_abandons_the_project_and_leaves_the_budget_unspent() {
    let _log = log_guard().await;
    let mock = mock_registry().await;
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");
    mock.store_manifest(&repo(PROJECT), "19.4.46-debian-13-amd64", b"first");
    mock.store_manifest(&repo(PROJECT), "19.4.45-debian-13-amd64", b"second");
    mock.store_manifest(&repo(PROJECT), "19.4.44-debian-13-amd64", b"third");
    mock.store_manifest(&repo("cinc-auditor"), "4.18.100-debian-13-amd64", b"other");
    mock.deny_deletes(&repo(PROJECT));

    let ctx = registry_context(state.path(), ledger, &mock);
    let report = prune(
        &ctx,
        &[PROJECT, "cinc-auditor"],
        &Wanted::default(),
        Opts::default(),
    )
    .await;

    assert_eq!(report.failed, 1, "{report:?}");
    assert_eq!(report.pruned, 1, "the other project still deletes");
    assert_eq!(report.exit_code, EXIT_PARTIAL);
    assert_eq!(mock.delete_count(), 1);
    assert_eq!(
        mock.delete_attempts(),
        2,
        "one refused request for the denied project, one delete elsewhere"
    );
    let denied_prefix = format!("/v2/{}/manifests/", repo(PROJECT));
    let denied_attempts = mock
        .request_log()
        .iter()
        .filter(|(method, path)| method == "DELETE" && path.starts_with(&denied_prefix))
        .count();
    assert_eq!(
        denied_attempts, 1,
        "the denied project stops after its first reference"
    );
    assert!(
        mock.manifest(&repo(PROJECT), "19.4.45-debian-13-amd64")
            .is_some(),
        "the denied tail is left behind"
    );
    assert!(mock
        .manifest(&repo("cinc-auditor"), "4.18.100-debian-13-amd64")
        .is_none());
    assert_eq!(
        warnings().matches("abandoning the project").count(),
        1,
        "{}",
        warnings()
    );
}

#[tokio::test]
async fn a_failed_delete_spends_its_budget_slot() {
    let mock = mock_registry().await;
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");
    mock.store_manifest(&repo(PROJECT), "19.4.46-debian-13-amd64", b"first");
    mock.store_manifest(&repo(PROJECT), "19.4.45-debian-13-amd64", b"second");
    mock.store_manifest(&repo(PROJECT), "19.4.44-debian-13-amd64", b"third");
    mock.fail_all_deletes_with(422);

    let ctx = registry_context(state.path(), ledger, &mock);
    let report = prune(
        &ctx,
        &[PROJECT],
        &Wanted::default(),
        Opts::default().budget(1),
    )
    .await;

    assert_eq!(report.failed, 1, "{report:?}");
    assert_eq!(report.pruned, 0, "{report:?}");
    assert_eq!(report.deferred, 2, "the tail of the spent slot waits");
    assert_eq!(
        mock.delete_attempts(),
        1,
        "the budget caps the attempts, so the failure does not retry"
    );
}

#[tokio::test]
async fn a_failed_registry_delete_records_prune_failed_and_carries_on() {
    let mock = mock_registry().await;
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");
    mock.store_manifest(&repo(PROJECT), "19.4.46-debian-13-amd64", b"first");
    mock.store_manifest(&repo(PROJECT), "19.4.45-debian-13-amd64", b"second");
    mock.fail_deletes_with(422);

    let ctx = registry_context(state.path(), ledger, &mock);
    let report = prune(&ctx, &[PROJECT], &Wanted::default(), Opts::default()).await;

    assert_eq!(report.failed, 1, "{report:?}");
    assert_eq!(report.pruned, 1, "{report:?}");
    assert_eq!(report.exit_code, EXIT_PARTIAL);
    let events = events(&ctx).await;
    let failed: Vec<&Event> = events
        .iter()
        .filter(|event| event.kind == EventKind::PruneFailed)
        .collect();
    assert_eq!(failed.len(), 1);
    let remote_ref = failed[0].detail["remote_ref"].as_str().expect("remote_ref");
    assert!(
        remote_ref.starts_with(&format!("{}/{}:", mock.registry_name(), repo(PROJECT))),
        "{remote_ref}"
    );
    assert!(remote_ref.ends_with("-debian-13-amd64"), "{remote_ref}");
    assert!(
        failed[0].detail["error"]
            .as_str()
            .is_some_and(|error| !error.is_empty()),
        "{:?}",
        failed[0].detail
    );
    assert_eq!(mock.delete_count(), 1, "the next reference still deleted");
    let left = ["19.4.46-debian-13-amd64", "19.4.45-debian-13-amd64"]
        .iter()
        .filter(|tag| mock.manifest(&repo(PROJECT), tag).is_some())
        .count();
    assert_eq!(left, 1, "exactly the failed manifest is left behind");
}

#[tokio::test]
async fn a_failed_packages_delete_records_prune_failed_and_carries_on() {
    let _guard = lock_env().await;
    let _token = EnvVar::set("GHCR_TOKEN", "test-token");
    let mock = MockPackages::start().await;
    mock.owner_is_org("acme");
    mock.seed_version("mirror/cinc", &["19.4.46"], Utc::now());
    mock.seed_version("mirror/cinc", &["19.4.45"], Utc::now());
    mock.fail_deletes_with(422);
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");

    let ctx = packages_context(state.path(), ledger, &mock);
    let report = prune(&ctx, &[PROJECT], &Wanted::default(), Opts::default()).await;

    assert_eq!(report.failed, 1, "{report:?}");
    assert_eq!(report.pruned, 1, "{report:?}");
    assert_eq!(report.exit_code, EXIT_PARTIAL);
    let events = events(&ctx).await;
    let failed: Vec<&Event> = events
        .iter()
        .filter(|event| event.kind == EventKind::PruneFailed)
        .collect();
    assert_eq!(failed.len(), 1);
    let mut remaining = mock.versions_for("mirror/cinc");
    assert_eq!(remaining.len(), 1, "the next version still deleted");
    let kept = remaining.pop().expect("one version left");
    assert_eq!(
        failed[0].detail["remote_ref"],
        json!(format!("ghcr.io/acme/mirror/cinc:{kept}"))
    );
    assert!(
        failed[0].detail["error"]
            .as_str()
            .is_some_and(|error| !error.is_empty()),
        "{:?}",
        failed[0].detail
    );
    assert_eq!(mock.deleted().len(), 1);
}

#[tokio::test]
async fn a_denied_project_stops_after_one_request_and_frees_its_slot() {
    let _log = log_guard().await;
    let _guard = lock_env().await;
    let _token = EnvVar::set("GHCR_TOKEN", "test-token");
    let mock = MockPackages::start().await;
    mock.owner_is_org("acme");
    mock.seed_version("mirror/cinc", &["19.4.46"], Utc::now());
    mock.seed_version("mirror/cinc", &["19.4.45"], Utc::now());
    mock.seed_version("mirror/cinc", &["19.4.44"], Utc::now());
    mock.seed_version("mirror/cinc-auditor", &["4.18.100"], Utc::now());
    mock.fail_deletes_with(403);
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");
    let projects = [PROJECT, "cinc-auditor"];

    let ctx = packages_context(state.path(), ledger, &mock);
    let report = prune(
        &ctx,
        &projects,
        &Wanted::default(),
        Opts::default().budget(1),
    )
    .await;

    assert_eq!(report.failed, 1, "{report:?}");
    assert_eq!(report.pruned, 1, "the freed slot goes to the other project");
    assert_eq!(report.deferred, 2, "the denied project's tail waits");
    assert_eq!(
        warnings().matches("abandoning the project").count(),
        1,
        "{}",
        warnings()
    );
    let deletes = mock
        .request_log()
        .iter()
        .filter(|(method, _)| method == "DELETE")
        .count();
    assert_eq!(deletes, 2, "no doomed requests");
    assert_eq!(mock.versions_for("mirror/cinc").len(), 3);
}

#[tokio::test]
async fn the_budget_defers_the_tail() {
    let _guard = lock_env().await;
    let _token = EnvVar::set("GHCR_TOKEN", "test-token");
    let mock = MockPackages::start().await;
    mock.owner_is_org("acme");
    mock.seed_version("mirror/cinc", &["19.4.46"], Utc::now());
    mock.seed_version("mirror/cinc-auditor", &["4.18.100"], Utc::now());
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");
    let projects = [PROJECT, "cinc-auditor"];

    let ctx = packages_context(state.path(), ledger, &mock);
    let report = prune(
        &ctx,
        &projects,
        &Wanted::default(),
        Opts::default().budget(1),
    )
    .await;

    assert_eq!(report.pruned, 1, "{report:?}");
    assert_eq!(report.deferred, 1);
    assert_eq!(mock.deleted().len(), 1);

    // `budget == 0` is literal: nothing is deleted, the whole tail waits.
    let report = prune(
        &ctx,
        &projects,
        &Wanted::default(),
        Opts::default().budget(0),
    )
    .await;
    assert_eq!(report.pruned, 0, "{report:?}");
    assert_eq!(report.deferred, 1);
    assert_eq!(mock.deleted().len(), 1);
}

#[tokio::test]
async fn a_dry_run_probes_one_delete_and_plans_the_rest() {
    let mock = mock_registry().await;
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");
    let first = "19.4.46-debian-13-amd64";
    let second = "19.4.45-debian-13-amd64";
    mock.store_manifest(&repo(PROJECT), first, b"stale one");
    mock.store_manifest(&repo(PROJECT), second, b"stale two");

    let ctx = registry_context(state.path(), ledger, &mock);
    let report = prune(
        &ctx,
        &[PROJECT],
        &Wanted::default(),
        Opts::default().dry_run(),
    )
    .await;

    // The first candidate probes the capability and is deleted for real; the
    // tail is only planned. The probe is counted and listed like any other
    // deletion, so the count and the lines agree.
    assert_eq!(report.targets_skipped, Vec::<String>::new());
    let remaining = [first, second]
        .into_iter()
        .find(|tag| mock.manifest(&repo(PROJECT), tag).is_some())
        .expect("the probe deleted one of the two");
    let probed = if remaining == first { second } else { first };
    assert_eq!(report.pruned, 2, "{report:?}");
    assert_eq!(
        report.pruned,
        report.lines.len(),
        "the probe counts and is listed: {report:?}"
    );
    assert!(
        report.lines.contains(&format!(
            "{}/{}:{probed}",
            mock.registry_name(),
            repo(PROJECT)
        )),
        "the probed reference is listed: {report:?}"
    );
    assert_eq!(
        report.lines,
        vec![
            format!("{}/{}:{probed}", mock.registry_name(), repo(PROJECT)),
            format!("{}/{}:{remaining}", mock.registry_name(), repo(PROJECT)),
        ]
    );
    assert_eq!(mock.delete_count(), 1);
    assert!(events(&ctx).await.is_empty(), "a dry run writes no events");
}

#[tokio::test]
async fn a_dry_run_on_a_405_endpoint_skips_instead_of_planning() {
    let mock = mock_registry().await;
    mock.answer_405();
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");
    mock.store_manifest(&repo(PROJECT), "19.4.46-debian-13-amd64", b"stale one");
    mock.store_manifest(&repo(PROJECT), "19.4.45-debian-13-amd64", b"stale two");

    let ctx = registry_context(state.path(), ledger, &mock);
    let report = prune(
        &ctx,
        &[PROJECT],
        &Wanted::default(),
        Opts::default().dry_run(),
    )
    .await;

    // The probe is refused, so the two stale tags must not become two plans.
    assert_eq!(report.targets_skipped, vec!["ghcr".to_string()]);
    assert!(report.lines.is_empty(), "{report:?}");
    assert_eq!(report.pruned, 0);
    assert_eq!(report.deferred, 2);
    assert_eq!(mock.delete_attempts(), 1);
    assert_eq!(report.exit_code, EXIT_PARTIAL);
}

#[tokio::test]
async fn a_version_with_one_wanted_tag_survives_the_prune() {
    let _guard = lock_env().await;
    let _token = EnvVar::set("GHCR_TOKEN", "test-token");
    let mock = MockPackages::start().await;
    mock.owner_is_org("acme");
    // A second policy mirrored the same payload, so GitHub stores one version
    // under both tags. Deleting the version would take the wanted tag with it.
    let stale = "19.4.45-debian-13-amd64";
    let wanted_tag = "19.4.46-debian-13-amd64";
    let version = mock.seed_version(
        "mirror/cinc",
        &[stale, wanted_tag],
        Utc::now() - ChronoDuration::hours(2),
    );
    assert!(version > 0);
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");
    let wanted = Wanted {
        tags: [wanted_tag.to_string()].into_iter().collect(),
    };

    let ctx = packages_context(state.path(), ledger, &mock);
    let report = prune(&ctx, &[PROJECT], &wanted, Opts::default()).await;

    assert_eq!(report.pruned, 0, "{report:?}");
    assert!(mock.deleted().is_empty(), "the shared version stays");
    let versions = mock.versions_for("mirror/cinc");
    assert!(
        versions.contains(&wanted_tag.to_string()),
        "the wanted tag still resolves: {versions:?}"
    );
    assert!(versions.contains(&stale.to_string()), "{versions:?}");
    assert_eq!(mock.versions_for("mirror/cinc").len(), 2);
}

#[tokio::test]
async fn a_version_with_two_stale_tags_is_deleted_once() {
    let _guard = lock_env().await;
    let _token = EnvVar::set("GHCR_TOKEN", "test-token");
    let mock = MockPackages::start().await;
    mock.owner_is_org("acme");
    let version = mock.seed_version(
        "mirror/cinc",
        &["19.4.45-debian-13-amd64", "19.4.44-debian-13-amd64"],
        Utc::now() - ChronoDuration::hours(2),
    );
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");

    let ctx = packages_context(state.path(), ledger, &mock);
    let report = prune(&ctx, &[PROJECT], &Wanted::default(), Opts::default()).await;

    assert_eq!(report.pruned, 1, "one version, one deletion: {report:?}");
    assert_eq!(mock.deleted(), vec![version]);
    assert_eq!(report.deferred, 0, "{report:?}");
    assert_eq!(
        mock.request_log()
            .iter()
            .filter(|(method, _)| method == "DELETE")
            .count(),
        1
    );
}

#[tokio::test]
async fn a_pruned_version_marks_the_ledger_row_under_any_of_its_tags() {
    let _guard = lock_env().await;
    let _token = EnvVar::set("GHCR_TOKEN", "test-token");
    let mock = MockPackages::start().await;
    mock.owner_is_org("acme");
    // The ledger recorded the second tag; the version serves both, and the
    // alphabetically first tag is the one the log line names.
    let stale_tag = "19.4.45-debian-13-amd64";
    let artifact = package_artifact(b"stale bytes", "19.4.46");
    let recorded_tag = artifact.tag();
    let version = mock.seed_version(
        "mirror/cinc",
        &[stale_tag, &recorded_tag],
        Utc::now() - ChronoDuration::hours(2),
    );
    let state = tempfile::tempdir().expect("state dir");
    let mut ledger = Ledger::open(state.path()).expect("ledger");
    seed_artifact(&mut ledger, &artifact);
    seed_publication(
        &mut ledger,
        &artifact,
        "ghcr",
        &format!("ghcr.io/acme/mirror/cinc:{recorded_tag}"),
    );

    let ctx = packages_context(state.path(), ledger, &mock);
    let report = prune(&ctx, &[PROJECT], &Wanted::default(), Opts::default()).await;

    assert_eq!(report.pruned, 1, "{report:?}");
    assert_eq!(mock.deleted(), vec![version]);
    let row = ctx
        .ledger
        .lock()
        .await
        .publication(&artifact.key(), "ghcr")
        .expect("publication query")
        .expect("publication row");
    assert_eq!(
        row.status,
        PublicationStatus::Pruned,
        "the row must not stay published for verify to act on"
    );
}

#[tokio::test]
async fn an_unresolved_stale_digest_is_not_deleted() {
    let _guard = log_guard().await;
    let mock = mock_registry().await;
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");
    let wanted_tag = "19.4.46-debian-13-amd64";
    let stale_tag = "19.4.45-debian-13-amd64";
    mock.store_manifest(&repo(PROJECT), wanted_tag, b"shared bytes");
    mock.store_manifest(&repo(PROJECT), stale_tag, b"shared bytes");
    // The registry never sends a digest for the stale tag, so neither the
    // listing nor the delete can tell that the wanted tag serves the same
    // manifest. Deleting it would take both tags down.
    mock.omit_head_digest_for(&repo(PROJECT), stale_tag);
    let wanted = Wanted {
        tags: [wanted_tag.to_string()].into_iter().collect(),
    };

    let ctx = registry_context(state.path(), ledger, &mock);
    let report = prune(&ctx, &[PROJECT], &wanted, Opts::default()).await;

    assert_eq!(report.pruned, 0, "{report:?}");
    assert_eq!(report.deferred, 0, "{report:?}");
    assert_eq!(mock.delete_count(), 0);
    assert!(mock.manifest(&repo(PROJECT), stale_tag).is_some());
    assert!(
        mock.manifest(&repo(PROJECT), wanted_tag).is_some(),
        "the wanted tag still resolves"
    );
    assert!(
        warnings()
            .contains("1 held back: their digest could not be resolved; they are retried next run"),
        "{}",
        warnings()
    );
}

#[tokio::test]
async fn a_stale_tag_sharing_a_manifest_with_a_wanted_tag_survives() {
    let mock = mock_registry().await;
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");
    // Both tags resolve to one manifest, as a second policy's digest-qualified
    // tag does. A delete by digest would drop the wanted tag as well.
    let wanted_tag = "19.4.46-debian-13-amd64";
    let stale_tag = "19.4.45-debian-13-amd64";
    mock.store_manifest(&repo(PROJECT), wanted_tag, b"shared bytes");
    mock.store_manifest(&repo(PROJECT), stale_tag, b"shared bytes");
    let wanted = Wanted {
        tags: [wanted_tag.to_string()].into_iter().collect(),
    };

    let ctx = registry_context(state.path(), ledger, &mock);
    let report = prune(&ctx, &[PROJECT], &wanted, Opts::default()).await;

    assert_eq!(report.pruned, 0, "{report:?}");
    assert_eq!(mock.delete_count(), 0);
    assert!(mock.manifest(&repo(PROJECT), stale_tag).is_some());
    assert!(
        mock.manifest(&repo(PROJECT), wanted_tag).is_some(),
        "the wanted tag still resolves"
    );
}

#[tokio::test]
async fn a_target_api_token_alone_authenticates_the_packages_backend() {
    let _guard = lock_env().await;
    let _ghcr = EnvVar::remove("GHCR_TOKEN");
    let _github = EnvVar::remove("GITHUB_TOKEN");
    let _target = EnvVar::remove("CINC_MIRROR_GHCR_API_TOKEN");
    let _target_set = EnvVar::set("CINC_MIRROR_GHCR_API_TOKEN", "target-token");
    let mock = MockPackages::start().await;
    mock.owner_is_org("acme");
    let version = mock.seed_version(
        "mirror/cinc",
        &["19.4.46"],
        Utc::now() - ChronoDuration::hours(2),
    );
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");

    let ctx = packages_context(state.path(), ledger, &mock);
    let report = prune(&ctx, &[PROJECT], &Wanted::default(), Opts::default()).await;

    assert_eq!(report.pruned, 1, "{report:?}");
    assert_eq!(mock.deleted(), vec![version]);
    assert!(
        mock.authorizations()
            .iter()
            .flatten()
            .any(|header| header == "Bearer target-token"),
        "{:?}",
        mock.authorizations()
    );
}

#[tokio::test]
async fn a_405_keeps_the_whole_round_deferred() {
    let mock = mock_registry().await;
    mock.answer_405();
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");
    mock.store_manifest(&repo(PROJECT), "19.4.46-debian-13-amd64", b"stale one");
    mock.store_manifest(&repo("cinc-auditor"), "4.18.100-debian-13-amd64", b"other");

    let ctx = registry_context(state.path(), ledger, &mock);
    let report = prune(
        &ctx,
        &[PROJECT, "cinc-auditor"],
        &Wanted::default(),
        Opts::default(),
    )
    .await;

    assert_eq!(report.targets_skipped, vec!["ghcr".to_string()]);
    assert_eq!(report.pruned, 0, "{report:?}");
    assert_eq!(
        report.deferred, 2,
        "both refused references wait for the next run: {report:?}"
    );
    assert_eq!(
        mock.delete_attempts(),
        2,
        "both references were already in flight"
    );
}

#[tokio::test]
async fn a_digest_qualified_wanted_tag_survives() {
    let mock = mock_registry().await;
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");
    let tag = "19.4.46-debian-13-amd64-0123456789ab";
    mock.store_manifest(&repo(PROJECT), tag, b"wanted");
    mock.store_manifest(&repo(PROJECT), "19.4.45-debian-13-amd64", b"stale");
    let wanted = Wanted {
        tags: [tag.to_string()].into_iter().collect(),
    };

    let ctx = registry_context(state.path(), ledger, &mock);
    let report = prune(&ctx, &[PROJECT], &wanted, Opts::default()).await;

    assert_eq!(report.pruned, 1);
    assert!(mock.manifest(&repo(PROJECT), tag).is_some());
    assert!(mock
        .manifest(&repo(PROJECT), "19.4.45-debian-13-amd64")
        .is_none());
}

#[tokio::test]
async fn sweep_orphans_empties_unnamed_packages_and_spares_foreign_repositories() {
    let _log = log_guard().await;
    let _guard = lock_env().await;
    let _token = EnvVar::set("GHCR_TOKEN", "test-token");
    let mock = MockPackages::start().await;
    mock.owner_is_org("acme");
    mock.seed_version("mirror/cinc", &["19.4.46"], Utc::now());
    let retired = mock.seed_version("mirror/retired", &["1.0.0"], Utc::now());
    mock.seed_version("other/cinc", &["4.18.100"], Utc::now());
    let state = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(state.path()).expect("ledger");
    let wanted = Wanted {
        tags: ["19.4.46".to_string()].into_iter().collect(),
    };

    let ctx = packages_context(state.path(), ledger, &mock);
    let report = prune(
        &ctx,
        &[PROJECT],
        &wanted,
        Opts::default().configured(&[PROJECT]).sweep_orphans(),
    )
    .await;

    assert_eq!(report.pruned, 1, "{report:?}");
    assert_eq!(mock.deleted(), vec![retired]);
    assert_eq!(mock.versions_for("mirror/retired"), Vec::<String>::new());
    assert_eq!(
        mock.versions_for("other/cinc"),
        vec!["4.18.100".to_string()]
    );
    assert!(mock
        .versions_for("mirror/cinc")
        .contains(&"19.4.46".to_string()));
    assert!(warnings().contains("retired"), "{}", warnings());
}

#[tokio::test]
async fn a_finished_report_fails_only_for_failures_and_skips() {
    assert_eq!(PruneReport::default().finish().exit_code, EXIT_OK);
    assert_eq!(
        PruneReport {
            failed: 1,
            ..PruneReport::default()
        }
        .finish()
        .exit_code,
        EXIT_PARTIAL
    );
    assert_eq!(
        PruneReport {
            targets_skipped: vec!["ghcr".to_string()],
            ..PruneReport::default()
        }
        .finish()
        .exit_code,
        EXIT_PARTIAL
    );
    assert_eq!(
        PruneReport {
            deferred: 5,
            ..PruneReport::default()
        }
        .finish()
        .exit_code,
        EXIT_OK
    );
}

#[tokio::test]
async fn an_ineligible_target_has_no_backend() {
    let _guard = lock_env().await;
    let _ghcr = EnvVar::remove("GHCR_TOKEN");
    let _github = EnvVar::remove("GITHUB_TOKEN");
    let _target = EnvVar::remove("CINC_MIRROR_GHCR_API_TOKEN");
    let mock = mock_registry().await;
    let state = tempfile::tempdir().expect("state dir");
    let config = config_with_retention(
        state.path(),
        "https://api.github.com",
        oci_target_config(&mock, "ghcr"),
    );

    let mut rsync = oci_target_config(&mock, "rsync");
    rsync.kind = TargetKind::Rsync;
    assert!(backend_for(&config, &rsync).is_none(), "rsync is not oci");

    let mut no_namespace = packages_target_config("ghcr", "mirror");
    no_namespace.namespace = Some("mirror".to_string());
    assert!(
        backend_for(&config, &no_namespace).is_none(),
        "the namespace has no owner"
    );

    let with_token = EnvVar::set("GHCR_TOKEN", "test-token");
    assert!(
        backend_for(&config, &no_namespace).is_none(),
        "still no repository below the owner"
    );
    let mut with_repository = packages_target_config("ghcr", "acme/mirror");
    with_repository.namespace = Some("acme/mirror".to_string());
    assert!(backend_for(&config, &with_repository).is_some());
    drop(with_token);

    assert!(
        backend_for(&config, &with_repository).is_none(),
        "without a token the packages path is unusable"
    );

    let registry_target = oci_target_config(&mock, "ghcr");
    assert!(
        backend_for(&config, &registry_target).is_some(),
        "a plain registry needs no token"
    );
}
