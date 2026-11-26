//! The command layer: configuration, ledger session, lease, report and exit
//! codes.
//!
//! Every command follows the same skeleton: load and validate the
//! configuration, resolve its scope, open the ledger (sync and replay the
//! branch), optionally take the lease, build a [`Ctx`], run the library
//! function, print the report, write and push the run's event file, release the
//! lease.
//!
//! Exit codes are the specification's: `0` clean, `2` partial or a failed ledger
//! push, `3` newly opened incidents (also an incident-flow error nested in
//! another error), `4` a live foreign lease, `5` configuration or auth, `64`
//! usage. `1` is the documented internal-error code for anything unclassified.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};
use std::process::{Command as Process, ExitCode};
use std::sync::Arc;
use std::time::Duration;

use anyhow::bail;
use chrono::{SecondsFormat, Utc};
use cinc_mirror::cli::{
    BackfillArgs, Cli, Command, ConfigCommand, IncidentsCommand, LedgerCommand, LogFormat,
    MirrorArgs, PlanArgs, PlanGrouping, RepairArgs, RunArgs, ScopeFilterArgs, TargetsCommand,
    VerifyArgs,
};
use cinc_mirror::config::{
    Config, ConfigError, ProjectPolicy, TargetConfig, TargetKind, DEFAULT_CONFIG_FILE,
};
use cinc_mirror::ctx::Ctx;
use cinc_mirror::fsutil::expand_tilde;
use cinc_mirror::hash::hash_reader;
use cinc_mirror::incident::{self, IncidentError};
use cinc_mirror::ledger::{
    Event, EventKind, Incident, IncidentState, Lease, LeaseError, Ledger, LedgerError,
    LedgerFilesError, LedgerGitError, LedgerStore, RUNS_DIR,
};
use cinc_mirror::net::RateLimiter;
use cinc_mirror::oci::OciError;
use cinc_mirror::plan::{self, Plan};
use cinc_mirror::repair::{self, RepairError, RepairReport};
use cinc_mirror::report::{
    redact_secrets, Summary, EXIT_CONFIG, EXIT_INCIDENTS, EXIT_LEASE_BUSY, EXIT_OK, EXIT_PARTIAL,
    EXIT_USAGE,
};
use cinc_mirror::runner::{self, RunError};
use cinc_mirror::scope::{ResolvedScope, ScopeArgs, ScopeError};
use cinc_mirror::source::{Source, SourceConfig, SourceError};
use cinc_mirror::store::{Store, StoreError};
use cinc_mirror::targets::{TargetError, TargetSet};
use cinc_mirror::verify::{self, VerifyError};
use clap::Parser;
use rand::Rng as _;
use serde_json::json;

/// Directory below the state directory holding the ledger worktree.
const LEDGER_WORKTREE: &str = "ledger-repo";
/// A run holds the ledger lease for this long before another run may steal it.
const LEASE_TTL: Duration = Duration::from_secs(10 * 60);
/// How often the background task extends the lease.
const LEASE_REFRESH: Duration = Duration::from_secs(60);

#[tokio::main]
async fn main() -> ExitCode {
    load_env_file();

    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let informational = matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            );
            let _ = error.print();
            return ExitCode::from(if informational { EXIT_OK } else { EXIT_USAGE } as u8);
        }
    };

    init_tracing(cli.log_format);
    match run(cli).await {
        Ok(code) => ExitCode::from(code as u8),
        Err(error) => {
            eprintln!("error: {}", redact_secrets(&format!("{error:#}")));
            ExitCode::from(exit_code(&error) as u8)
        }
    }
}

/// Load credentials from `.env` (or the legacy `config.env`) before anything
/// reads the environment.
///
/// `CINC_MIRROR_ENV_FILE` names one explicit file. Otherwise the first of
/// `.env` and `config.env` in the working directory wins. `dotenvy` does not
/// override variables already present in the environment.
fn load_env_file() {
    let explicit = std::env::var_os("CINC_MIRROR_ENV_FILE");
    let candidates: Vec<std::ffi::OsString> = match explicit {
        Some(path) => vec![path],
        None => vec![".env".into(), "config.env".into()],
    };

    for candidate in candidates {
        let path = std::path::Path::new(&candidate);
        if !path.is_file() {
            continue;
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            if let Ok(metadata) = path.metadata() {
                if metadata.permissions().mode() & 0o077 != 0 {
                    eprintln!(
                        "warning: {} is readable by other users; run `chmod 600 {}`",
                        path.display(),
                        path.display()
                    );
                }
            }
        }
        if let Err(error) = dotenvy::from_path(path) {
            eprintln!("warning: cannot load {}: {error}", path.display());
        }
        return;
    }
}

/// Render tracing events on stderr; diagnostics never mix with command output.
fn init_tracing(format: LogFormat) {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    let builder = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr);
    match format {
        LogFormat::Text => {
            let _ = builder.try_init();
        }
        LogFormat::Json => {
            let _ = builder.json().try_init();
        }
    }
}

/// Map a typed failure to the specification's exit code.
fn exit_code(error: &anyhow::Error) -> i32 {
    if error.downcast_ref::<ConfigFailure>().is_some()
        || error.downcast_ref::<ConfigError>().is_some()
        || error.downcast_ref::<LedgerGitError>().is_some()
        || error.downcast_ref::<LedgerFilesError>().is_some()
        || error.downcast_ref::<SourceError>().is_some()
        || error.downcast_ref::<TargetError>().is_some()
        || error.downcast_ref::<OciError>().is_some()
    {
        return EXIT_CONFIG;
    }

    if error.downcast_ref::<PushFailure>().is_some() {
        return EXIT_PARTIAL;
    }
    if error.downcast_ref::<ScopeError>().is_some() {
        return EXIT_USAGE;
    }
    if let Some(error) = error.downcast_ref::<RunError>() {
        return match error {
            RunError::Usage { .. } => EXIT_USAGE,
            RunError::NoTargets => EXIT_CONFIG,
            RunError::Incident(_) => EXIT_INCIDENTS,
            _ => 1,
        };
    }
    if let Some(error) = error.downcast_ref::<VerifyError>() {
        return match error {
            VerifyError::Usage { .. } | VerifyError::UnknownTarget { .. } => EXIT_USAGE,
            _ => 1,
        };
    }
    if let Some(error) = error.downcast_ref::<RepairError>() {
        return match error {
            RepairError::UnknownTarget { .. } => EXIT_USAGE,
            _ => 1,
        };
    }
    if let Some(error) = error.downcast_ref::<cinc_mirror::bootstrap::BootstrapError>() {
        return match error {
            cinc_mirror::bootstrap::BootstrapError::RunIdReused { .. } => EXIT_USAGE,
            _ => 1,
        };
    }
    if let Some(error) = error.downcast_ref::<IncidentError>() {
        return match error {
            IncidentError::UnknownIncident { .. } | IncidentError::NotRepublishable { .. } => {
                EXIT_USAGE
            }
            IncidentError::RepublishFailed { .. } => EXIT_PARTIAL,
            _ => 1,
        };
    }
    if let Some(error) = error.downcast_ref::<LeaseError>() {
        return match error {
            LeaseError::Busy { .. } => EXIT_LEASE_BUSY,
            _ => EXIT_CONFIG,
        };
    }
    if error.downcast_ref::<LedgerError>().is_some() || error.downcast_ref::<StoreError>().is_some()
    {
        return 1;
    }
    1
}

/// A configuration or environment problem the user has to fix.
#[derive(Debug, thiserror::Error)]
#[error("{message}")]
struct ConfigFailure {
    message: String,
}

impl ConfigFailure {
    fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

/// The ledger push failed; the run file stays for the next run.
#[derive(Debug, thiserror::Error)]
#[error(
    "the ledger push failed; the run stays in {} for the next run to retry: {source}",
    path.display()
)]
struct PushFailure {
    path: PathBuf,
    #[source]
    source: LedgerGitError,
}

async fn run(cli: Cli) -> anyhow::Result<i32> {
    let config_path = selected_config_path(cli.config.clone());
    let config = Config::load(config_path.as_deref())?;
    let allow_unleased = cli.allow_unleased || ci_environment();

    match cli.cmd {
        Command::Config { action } => config_command(&config, config_path.as_deref(), action).await,
        Command::Targets { action } => targets_command(&config, action).await,
        Command::Mirror(args) => mirror_command(&config, args, allow_unleased).await,
        Command::Backfill(args) => backfill_command(&config, args, allow_unleased).await,
        Command::Plan(args) => plan_command(&config, args, allow_unleased).await,
        Command::Verify(args) => verify_command(&config, args, allow_unleased).await,
        Command::Repair(args) => repair_command(&config, args, allow_unleased).await,
        Command::Incidents { action } => incidents_command(&config, action, allow_unleased).await,
        Command::Ledger { action } => ledger_command(&config, action, allow_unleased).await,
    }
}

/// Whether CI defaults to continuing without the ledger lease.
fn ci_environment() -> bool {
    ["CI", "GITHUB_ACTIONS"].iter().any(|name| {
        std::env::var(name).is_ok_and(|value| !value.trim().is_empty() && value.trim() != "false")
    })
}

/// A fresh run id: `<UTC yyyymmddThhmmssZ>-<8 lowercase hex>`.
///
/// The ledger keys events on `(run_id, seq)` and the run file is named after the
/// run, so an id is never reused: two invocations in the same second still
/// differ in the random suffix.
fn new_run_id() -> String {
    let now = Utc::now();
    let mut random = [0_u8; 4];
    rand::thread_rng().fill(&mut random);
    let suffix: String = random.iter().map(|byte| format!("{byte:02x}")).collect();
    format!("{}-{suffix}", now.format("%Y%m%dT%H%M%SZ"))
}

/// Mirror the discovery [`Config::load`] performs so the check can report which
/// file (if any) was used.
fn selected_config_path(explicit: Option<PathBuf>) -> Option<PathBuf> {
    explicit.or_else(|| {
        let default = PathBuf::from(DEFAULT_CONFIG_FILE);
        default.is_file().then_some(default)
    })
}

// ---------------------------------------------------------------------------
// Ledger session
// ---------------------------------------------------------------------------

/// The local database plus the git worktree that holds the event files.
///
/// `store` is `None` when the ledger remote cannot be resolved or reached and
/// `--allow-unleased` (or CI) permits continuing. Every write then prints a
/// warning: the run is recorded locally but not pushed, never skipped silently.
///
/// The ledger is an `Option` so a command can move it into a [`Ctx`] and take it
/// back afterwards without opening a second SQLite connection.
struct LedgerEnv {
    ledger: Option<Ledger>,
    store: Option<LedgerStore>,
    unavailable: Option<String>,
    state_dir: PathBuf,
}

impl LedgerEnv {
    fn ledger(&self) -> anyhow::Result<&Ledger> {
        self.ledger.as_ref().ok_or_else(|| {
            ConfigFailure::new("internal: the ledger was moved out of the command").into()
        })
    }

    fn ledger_mut(&mut self) -> anyhow::Result<&mut Ledger> {
        self.ledger.as_mut().ok_or_else(|| {
            ConfigFailure::new("internal: the ledger was moved out of the command").into()
        })
    }

    fn take_ledger(&mut self) -> anyhow::Result<Ledger> {
        self.ledger.take().ok_or_else(|| {
            ConfigFailure::new("internal: the ledger was moved out of the command").into()
        })
    }

    fn restore(&mut self, ledger: Ledger) {
        self.ledger = Some(ledger);
    }

    /// Reopen the database after a command moved the connection into a [`Ctx`]
    /// and failed before giving it back.
    ///
    /// The events are already committed to SQLite, so the reopened connection
    /// sees them and the error path can still write the run file.
    fn reopen_if_needed(&mut self) -> anyhow::Result<()> {
        if self.ledger.is_none() {
            self.ledger = Some(Ledger::open(&self.state_dir)?);
        }
        Ok(())
    }

    fn require_store(&self) -> anyhow::Result<&LedgerStore> {
        self.store.as_ref().ok_or_else(|| {
            ConfigFailure::new(format!(
                "the ledger remote is unavailable: {}",
                self.unavailable.as_deref().unwrap_or("unknown reason")
            ))
            .into()
        })
    }
}

/// Open the local ledger and bring it in line with the remote branch.
fn open_ledger(config: &Config, allow_unleased: bool) -> anyhow::Result<LedgerEnv> {
    let state_dir = expand_tilde(&config.state_dir);
    let mut ledger = Ledger::open(&state_dir)?;

    let remote = match resolve_ledger_remote(&config.ledger.remote) {
        Ok(remote) => remote,
        Err(error) if allow_unleased => {
            let reason = format!("{error:#}");
            tracing::warn!(%reason, "continuing without the ledger remote");
            return Ok(LedgerEnv {
                ledger: Some(ledger),
                store: None,
                unavailable: Some(reason),
                state_dir,
            });
        }
        Err(error) => return Err(error),
    };

    let store = LedgerStore::new(
        state_dir.join(LEDGER_WORKTREE),
        remote,
        config.ledger.branch.clone(),
    );
    let synced = store
        .sync()
        .map_err(anyhow::Error::new)
        .and_then(|()| store.load_all(&mut ledger).map_err(anyhow::Error::new));
    match synced {
        Ok(loaded) => {
            tracing::debug!(events = loaded, "ledger synced");
            Ok(LedgerEnv {
                ledger: Some(ledger),
                store: Some(store),
                unavailable: None,
                state_dir,
            })
        }
        Err(error) if allow_unleased => {
            let reason = format!("{error:#}");
            tracing::warn!(%reason, "continuing without the ledger remote");
            Ok(LedgerEnv {
                ledger: Some(ledger),
                store: None,
                unavailable: Some(reason),
                state_dir,
            })
        }
        Err(error) => Err(error.context("cannot sync the ledger branch")),
    }
}

/// Resolve `[ledger].remote`: `origin` names the git repository this process
/// runs in, anything else is a URL or path used verbatim.
fn resolve_ledger_remote(configured: &str) -> anyhow::Result<String> {
    if configured != "origin" {
        return Ok(configured.to_string());
    }

    let output = Process::new("git")
        .args(["remote", "get-url", "origin"])
        .output()
        .map_err(|source| ConfigFailure::new(format!("cannot run git: {source}")))?;
    if !output.status.success() {
        let cwd = std::env::current_dir()
            .map_or_else(|_| ".".to_string(), |dir| dir.display().to_string());
        return Err(ConfigFailure::new(format!(
            "cannot resolve the ledger remote `origin` in {cwd}: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
        .into());
    }
    let url = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if url.is_empty() {
        return Err(ConfigFailure::new("the git remote `origin` has no URL").into());
    }
    Ok(url)
}

/// The lease, with a background heartbeat, released when the command ends.
struct LeaseGuard {
    lease: Arc<tokio::sync::Mutex<Option<Lease>>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl LeaseGuard {
    fn start(lease: Lease) -> Self {
        let lease = Arc::new(tokio::sync::Mutex::new(Some(lease)));
        let shared = Arc::clone(&lease);
        let task = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(LEASE_REFRESH);
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let mut guard = shared.lock().await;
                let Some(lease) = guard.as_mut() else {
                    break;
                };
                if let Err(error) = lease.refresh() {
                    tracing::warn!(%error, "the ledger lease heartbeat failed");
                }
            }
        });
        Self {
            lease,
            task: Some(task),
        }
    }

    /// Stop the heartbeat and delete the lease ref.
    async fn release(mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if let Some(lease) = self.lease.lock().await.take() {
            if let Err(error) = lease.release() {
                tracing::warn!(%error, "releasing the ledger lease failed");
            }
        }
    }
}

impl Drop for LeaseGuard {
    fn drop(&mut self) {
        // Best effort on an error path: drop the heartbeat and the remote ref
        // immediately instead of leaving it to expire.
        if let Some(task) = self.task.take() {
            task.abort();
        }
        if let Ok(mut guard) = self.lease.try_lock() {
            if let Some(lease) = guard.take() {
                let _ = lease.release();
            }
        }
    }
}

/// Take the lease when the command writes.
///
/// `--allow-unleased` only forgives a lease remote that cannot be reached:
/// the run then proceeds unleased and says so. A live foreign lease is never
/// downgraded — the flag cannot bypass the holder, so [`LeaseError::Busy`]
/// always stops the command with exit code `4`.
async fn acquire_lease(
    env: &LedgerEnv,
    run_id: &str,
    allow_unleased: bool,
) -> anyhow::Result<Option<LeaseGuard>> {
    let Some(store) = env.store.as_ref() else {
        return Ok(None);
    };
    match Lease::acquire(store, run_id, LEASE_TTL) {
        Ok(Some(lease)) => Ok(Some(LeaseGuard::start(lease))),
        Ok(None) => Ok(None),
        Err(error @ LeaseError::Busy { .. }) => Err(error.into()),
        Err(error) if allow_unleased => {
            tracing::warn!(%error, "continuing without the ledger lease");
            Ok(None)
        }
        Err(error) => Err(error.into()),
    }
}

/// Write the run's events to `runs/<run_id>.ndjson` and push the branch.
fn persist_run(env: &LedgerEnv, run_id: &str, message: &str) -> anyhow::Result<()> {
    let events = env.ledger()?.events_for_run(run_id)?;
    if events.is_empty() {
        return Ok(());
    }
    persist_group(env, run_id, &events, message)
}

/// Write one run's event file and push it.
fn persist_group(
    env: &LedgerEnv,
    run_id: &str,
    events: &[Event],
    message: &str,
) -> anyhow::Result<()> {
    let Some(store) = env.store.as_ref() else {
        // Never silent: an unleased run cannot commit, and an operator must know
        // the events live only in the local database.
        eprintln!(
            "warning: the ledger remote is unavailable; run `{run_id}` was not pushed \
             (local ledger keeps the events)"
        );
        return Ok(());
    };
    let path = store.write_run(events)?;
    store
        .commit_and_push(&path, message)
        .map_err(|source| PushFailure {
            path: path.clone(),
            source,
        })?;
    // Diagnostics stay on stderr so a `--json` report on stdout stays valid.
    eprintln!("ledger: {}", path.display());
    Ok(())
}

/// Remembers which events existed before a command so its writes are known.
///
/// The incident flow records its events under its own run ids, so one command
/// can produce several run files. The recorder makes sure every event appended
/// during the command reaches the branch, not just the primary run's.
struct RunRecorder {
    cursor: i64,
}

impl RunRecorder {
    fn begin(ledger: &Ledger) -> anyhow::Result<Self> {
        Ok(Self {
            cursor: ledger.event_cursor()?,
        })
    }

    /// Write and push one file per run that appended events.
    ///
    /// The primary run is written from [`Ledger::events_for_run`]; the incident
    /// flow uses its own run ids, and those files are written here as well.
    fn finish(&self, env: &LedgerEnv, primary: &str, message: &str) -> anyhow::Result<()> {
        let mut groups: BTreeMap<String, Vec<Event>> = BTreeMap::new();
        for event in env.ledger()?.events_since(self.cursor)? {
            groups.entry(event.run_id.clone()).or_default().push(event);
        }
        if groups.remove(primary).is_some() {
            persist_run(env, primary, message)?;
        }
        for (run_id, events) in groups {
            persist_group(env, &run_id, &events, &format!("{run_id}: {message}"))?;
        }
        Ok(())
    }

    /// Best-effort variant for an error path: never masks the original error.
    fn finish_or_warn(&self, env: &mut LedgerEnv, primary: &str, message: &str) {
        let result = env
            .reopen_if_needed()
            .and_then(|()| self.finish(env, primary, message));
        if let Err(error) = result {
            tracing::warn!(
                %error,
                run_id = primary,
                "the run's events could not be written and pushed; \
                 they exist only in the local ledger"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Configuration and targets
// ---------------------------------------------------------------------------

fn print_config(path: Option<&Path>, config: &Config) {
    match path {
        Some(path) => println!("config: {}", path.display()),
        None => println!("config: none (built-in defaults)"),
    }
    println!("state_dir: {}", config.state_dir.display());
    println!(
        "concurrency: {} downloads, {} uploads",
        config.concurrency, config.upload_concurrency
    );
    println!("max_bandwidth: {}", config.max_bandwidth);
    println!(
        "transport: {}",
        config
            .transport
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("metadata_transport: {}", config.metadata_transport);
    println!(
        "retention: prune {}, delete {}, max_deletions {}",
        config.retention.prune, config.retention.delete, config.retention.max_deletions
    );
    println!(
        "ledger: {} branch {}",
        redact_url(&config.ledger.remote),
        config.ledger.branch
    );

    println!("policies: {}", config.projects.len());
    for policy in &config.projects {
        println!(
            "  {}",
            describe_policy(policy, config.min_version.as_deref())
        );
    }

    let enabled = config
        .targets
        .iter()
        .filter(|target| target.enabled)
        .count();
    println!("targets: {} ({} enabled)", config.targets.len(), enabled);
    for target in &config.targets {
        println!("  {}", describe_target(target));
    }
}

fn describe_policy(policy: &ProjectPolicy, global_floor: Option<&str>) -> String {
    let floor = policy
        .min_version
        .as_deref()
        .or(global_floor)
        .unwrap_or("-");
    let ceiling = policy.max_version.as_deref().unwrap_or("-");
    let mut versions = format!("{floor}..{ceiling}");
    if policy.all_versions {
        versions.push_str(",all_versions");
    }
    if !policy.versions.is_empty() {
        versions.push_str(&format!(",globs={}", policy.versions.join(",")));
    }

    let state = if policy.enabled { "" } else { " disabled" };
    format!(
        "{} project={} channel={} versions={} platforms={} arches={}{}",
        policy.id, policy.project, policy.channel, versions, policy.platforms, policy.arches, state
    )
}

fn describe_target(target: &TargetConfig) -> String {
    let state = if target.enabled {
        "enabled"
    } else {
        "disabled"
    };

    match target.kind {
        TargetKind::Oci => format!(
            "{} kind={} {} auth={} registry={}/{}",
            target.name,
            target.kind,
            state,
            target.auth,
            target.registry.as_deref().unwrap_or("-"),
            target.namespace.as_deref().unwrap_or("-")
        ),
        TargetKind::Rsync => format!(
            "{} kind={} {} auth={} url={}",
            target.name,
            target.kind,
            state,
            target.auth,
            target
                .url
                .as_deref()
                .map(redact_url)
                .unwrap_or_else(|| "-".to_string())
        ),
    }
}

/// Hide a password embedded in URL userinfo. Configuration never needs one, but
/// a user may paste one, and every report must not echo secrets.
fn redact_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };

    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, Some(path)),
        None => (rest, None),
    };

    let authority = match authority.rsplit_once('@') {
        Some((userinfo, host)) if userinfo.contains(':') => {
            let user = userinfo.split_once(':').map_or(userinfo, |(user, _)| user);
            format!("{user}:***@{host}")
        }
        _ => authority.to_string(),
    };

    match path {
        Some(path) => format!("{scheme}://{authority}/{path}"),
        None => format!("{scheme}://{authority}"),
    }
}

async fn config_command(
    config: &Config,
    path: Option<&Path>,
    action: ConfigCommand,
) -> anyhow::Result<i32> {
    let ConfigCommand::Check { probe } = action;
    config.validate()?;
    print_config(path, config);

    if probe {
        let targets = TargetSet::from_config(config)?;
        let mut failed = 0;
        for target in targets.all() {
            match target.probe().await {
                Ok(()) => println!("probe {}: ok", target.name()),
                Err(error) => {
                    failed += 1;
                    println!(
                        "probe {}: FAILED {}",
                        target.name(),
                        redact_secrets(&error.to_string())
                    );
                }
            }
        }
        if failed > 0 {
            println!("config FAILED: {failed} target(s) unreachable");
            return Ok(EXIT_PARTIAL);
        }
    }

    println!("config OK");
    Ok(EXIT_OK)
}

async fn targets_command(config: &Config, action: TargetsCommand) -> anyhow::Result<i32> {
    config.validate()?;
    match action {
        TargetsCommand::List => {
            for target in &config.targets {
                println!(
                    "{} {} {}",
                    target.name,
                    target.kind,
                    if target.enabled {
                        "enabled"
                    } else {
                        "disabled"
                    }
                );
            }
            Ok(EXIT_OK)
        }
        TargetsCommand::Check => {
            let targets = TargetSet::from_config(config)?;
            let mut failed = 0;
            for target in targets.all() {
                match target.probe().await {
                    Ok(()) => println!("probe {}: ok", target.name()),
                    Err(error) => {
                        failed += 1;
                        println!(
                            "probe {}: FAILED {}",
                            target.name(),
                            redact_secrets(&error.to_string())
                        );
                    }
                }
            }
            if failed > 0 {
                println!("{failed} target(s) unreachable");
                return Ok(EXIT_PARTIAL);
            }
            println!("targets OK");
            Ok(EXIT_OK)
        }
    }
}

// ---------------------------------------------------------------------------
// Context
// ---------------------------------------------------------------------------

/// Resolve `--set` overrides and CLI filters into a validated configuration.
fn prepare_config(
    base: &Config,
    filters: &ScopeFilterArgs,
) -> anyhow::Result<(Config, ResolvedScope)> {
    let mut config = base.clone();
    filters.apply_sets(&mut config)?;
    config.validate()?;
    let scope = config.resolve(&filters.to_scope_args())?;
    Ok((config, scope))
}

/// Build the [`Ctx`] every crawling command shares.
fn build_context(
    config: Config,
    scope: ResolvedScope,
    ledger: Ledger,
    run_id: String,
) -> anyhow::Result<Ctx> {
    let state_dir = expand_tilde(&config.state_dir);
    let source_config = SourceConfig::from_config(&config)?;
    let source = Source::new(&source_config)?;
    let store = Store::open(&state_dir)?;
    let targets = TargetSet::from_config(&config)?;
    let bandwidth = plan::parse_bandwidth(&config.max_bandwidth)
        .map_err(|reason| ConfigFailure::new(format!("invalid max_bandwidth: {reason}")))?;

    Ok(Ctx {
        config: Arc::new(config),
        scope,
        source,
        store,
        ledger: tokio::sync::Mutex::new(ledger),
        targets,
        rate: RateLimiter::new(bandwidth),
        run_id,
        state_dir,
    })
}

/// Take the ledger back out of a finished context.
fn take_ledger(ctx: Ctx) -> Ledger {
    ctx.ledger.into_inner()
}

// ---------------------------------------------------------------------------
// mirror / backfill
// ---------------------------------------------------------------------------

async fn mirror_command(
    config: &Config,
    args: MirrorArgs,
    allow_unleased: bool,
) -> anyhow::Result<i32> {
    run_mirror_like(
        config,
        &args.filters,
        args.run,
        allow_unleased,
        BackfillMode::Mirror,
    )
    .await
}

async fn backfill_command(
    config: &Config,
    args: BackfillArgs,
    allow_unleased: bool,
) -> anyhow::Result<i32> {
    run_mirror_like(
        config,
        &args.filters,
        args.run,
        allow_unleased,
        BackfillMode::Backfill,
    )
    .await
}

/// How the shared mirror implementation records its resume point.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BackfillMode {
    Mirror,
    Backfill,
}

async fn run_mirror_like(
    base: &Config,
    filters: &ScopeFilterArgs,
    run_args: RunArgs,
    allow_unleased: bool,
    mode: BackfillMode,
) -> anyhow::Result<i32> {
    let (config, scope) = prepare_config(base, filters)?;
    let run_id = new_run_id();
    let mut env = open_ledger(&config, allow_unleased)?;
    let guard = acquire_lease(&env, &run_id, allow_unleased).await?;

    let mut opts = run_args.to_run_opts();
    if mode == BackfillMode::Backfill {
        let fingerprint = policy_fingerprint(&scope);
        let cursor = env.ledger()?.cursor(&fingerprint)?;
        opts.start_after = cursor.and_then(|cursor| cursor.last_artifact_key);
        opts.cursor_fingerprint = Some(fingerprint);
    }

    let mode_name = match mode {
        BackfillMode::Mirror => "mirror",
        BackfillMode::Backfill => "backfill",
    };
    let recorder = RunRecorder::begin(env.ledger()?)?;
    let ledger = env.take_ledger()?;

    // The body runs in an inner block so a failure still hands the ledger back
    // to the recorder below.
    let outcome = async {
        let ctx = build_context(config, scope, ledger, run_id.clone())?;
        let summary = runner::run(&ctx, opts).await?;
        env.restore(take_ledger(ctx));
        Ok::<Summary, anyhow::Error>(summary)
    }
    .await;

    let summary = match outcome {
        Ok(summary) => summary,
        Err(error) => {
            // A run that failed after `run_started` has events worth keeping.
            recorder.finish_or_warn(
                &mut env,
                &run_id,
                &format!("{mode_name} {run_id} (incomplete)"),
            );
            return Err(error);
        }
    };

    print_summary(&summary, run_args.json);
    if run_args.dry_run {
        println!("dry run: {} artifact(s) would be queued", summary.queued);
    }
    recorder.finish(
        &env,
        &run_id,
        &format!("{mode_name} {run_id}: {}", summary.to_text()),
    )?;
    if let Some(guard) = guard {
        guard.release().await;
    }
    Ok(summary.exit_code)
}

fn print_summary(summary: &Summary, json: bool) {
    if json {
        println!("{}", summary.to_json());
    } else {
        println!("{}", summary.to_text());
    }
}

/// A stable fingerprint of the resolved policies, for the backfill cursor.
fn policy_fingerprint(scope: &ResolvedScope) -> String {
    let value = plan::policies_json(scope);
    let bytes = serde_json::to_vec(&value).unwrap_or_default();
    hash_reader(bytes.as_slice())
        .map(|hashes| hashes.sha256)
        .unwrap_or_default()
}

// ---------------------------------------------------------------------------
// plan
// ---------------------------------------------------------------------------

async fn plan_command(base: &Config, args: PlanArgs, allow_unleased: bool) -> anyhow::Result<i32> {
    let (config, scope) = prepare_config(base, &args.filters)?;
    let mut env = open_ledger(&config, allow_unleased)?;
    let source_config = SourceConfig::from_config(&config)?;
    let source = Source::new(&source_config)?;
    let (satisfied, overrides) = {
        let ledger = env.ledger()?;
        (satisfied_keys(ledger, &config)?, ledger.tag_overrides()?)
    };
    let estimate = plan::build(&source, &config, &scope, &satisfied, &overrides).await?;

    let run_id = new_run_id();
    let out = args
        .out
        .clone()
        .unwrap_or_else(|| expand_tilde(&config.state_dir).join(format!("plan-{run_id}.json")));
    estimate.write(&out).map_err(|source| {
        ConfigFailure::new(format!("cannot write {}: {source}", out.display()))
    })?;

    if args.json {
        println!("{}", estimate.to_json());
        eprintln!("written: {}", out.display());
    } else {
        print_plan(&estimate, args.by);
        println!("written: {}", out.display());
    }

    if args.record {
        let recorder = RunRecorder::begin(env.ledger()?)?;
        let event =
            Event::new(run_id.clone(), 1, Utc::now(), EventKind::PlanRecorded).with_detail(json!({
                "effective_policy": estimate.effective_policy,
                "order": "plan",
                "transport_order": config
                    .transport
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                "host": cinc_mirror::hostname(),
                "summary": {
                    "artifacts": estimate.artifacts,
                    "total_bytes": estimate.total_bytes,
                    "satisfied_bytes": estimate.satisfied_bytes,
                    "skipped": estimate.skipped,
                },
            }));
        if let Err(error) = env.ledger_mut()?.append(&event) {
            recorder.finish_or_warn(&mut env, &run_id, &format!("plan {run_id} (incomplete)"));
            return Err(error.into());
        }
        recorder.finish(&env, &run_id, &format!("plan {run_id} recorded"))?;
    }

    Ok(EXIT_OK)
}

/// Canonical keys already published on every enabled target.
fn satisfied_keys(ledger: &Ledger, config: &Config) -> anyhow::Result<HashSet<String>> {
    let enabled: Vec<&TargetConfig> = config
        .targets
        .iter()
        .filter(|target| target.enabled)
        .collect();
    if enabled.is_empty() {
        return Ok(HashSet::new());
    }

    let mut common: Option<HashSet<String>> = None;
    for target in enabled {
        let keys = ledger.satisfied_keys(&target.name)?;
        common = Some(match common {
            None => keys,
            Some(previous) => previous.intersection(&keys).cloned().collect(),
        });
    }
    Ok(common.unwrap_or_default())
}

fn print_plan(estimate: &Plan, by: PlanGrouping) {
    let to_fetch = estimate
        .total_bytes
        .saturating_sub(estimate.satisfied_bytes);
    println!(
        "plan: {} artifacts, {} total, {} satisfied, {} to fetch",
        estimate.artifacts,
        human_bytes(estimate.total_bytes),
        human_bytes(estimate.satisfied_bytes),
        human_bytes(to_fetch)
    );

    if estimate.collisions > 0 {
        println!(
            "collisions: {} (excluded above; mirror opens an incident for each)",
            estimate.collisions
        );
        for collision in &estimate.collision_details {
            println!("  tag: {}", collision.tag);
            println!("    kept:        {}", collision.kept);
            println!(
                "    conflicting: {} (upstream {})",
                collision.conflicting, collision.upstream_path
            );
        }
    }

    if estimate.skipped > 0 {
        println!(
            "skipped: {} (metadata does not fit its upstream directory; RUST_LOG=debug shows paths)",
            estimate.skipped
        );
    }

    let (label, groups) = match by {
        PlanGrouping::Project => ("project", &estimate.by_project),
        PlanGrouping::Platform => ("platform", &estimate.by_platform),
        PlanGrouping::Arch => ("arch", &estimate.by_arch),
        PlanGrouping::Target => ("target", &estimate.by_target),
    };
    println!("by {label}:");
    for (name, totals) in groups {
        println!(
            "  {name}: {} artifacts, {} ({} satisfied)",
            totals.artifacts,
            human_bytes(totals.bytes),
            human_bytes(totals.satisfied_bytes)
        );
    }

    if !estimate.largest.is_empty() {
        println!("largest:");
        for (key, bytes) in &estimate.largest {
            println!("  {} {}", human_bytes(*bytes), key);
        }
    }

    match estimate.space.fits {
        Some(true) => println!(
            "space: {} free in {}, needs {}",
            human_bytes(estimate.space.free_bytes.unwrap_or(0)),
            estimate.space.state_dir,
            human_bytes(estimate.space.required_bytes)
        ),
        Some(false) => println!(
            "space: NOT ENOUGH - {} free in {}, needs {}",
            human_bytes(estimate.space.free_bytes.unwrap_or(0)),
            estimate.space.state_dir,
            human_bytes(estimate.space.required_bytes)
        ),
        None => println!("space: unknown"),
    }

    if let Some(seconds) = estimate.projected_seconds {
        println!("duration: about {seconds}s at the configured bandwidth");
    }
}

fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 4] = ["B", "KiB", "MiB", "GiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

// ---------------------------------------------------------------------------
// verify / repair
// ---------------------------------------------------------------------------

async fn verify_command(
    base: &Config,
    args: VerifyArgs,
    allow_unleased: bool,
) -> anyhow::Result<i32> {
    let config = base.clone();
    config.validate()?;
    let run_id = new_run_id();
    let mut env = open_ledger(&config, allow_unleased)?;
    let ledger = env.take_ledger()?;
    let ctx = build_context(config, ResolvedScope::default(), ledger, run_id)?;
    let report = verify::run(&ctx, args.to_opts()).await?;
    if args.json {
        println!("{}", verify_json(&report));
    } else {
        print!("{report}");
    }
    Ok(report.exit_code())
}

fn verify_json(report: &cinc_mirror::verify::VerifyReport) -> String {
    let findings: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|finding| {
            json!({
                "artifact_key": finding.artifact_key,
                "target": finding.target,
                "kind": finding.kind.as_str(),
                "detail": finding.detail,
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({
        "artifacts_checked": report.artifacts_checked,
        "publications_checked": report.publications_checked,
        "findings": findings,
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

async fn repair_command(
    base: &Config,
    args: RepairArgs,
    allow_unleased: bool,
) -> anyhow::Result<i32> {
    let config = base.clone();
    config.validate()?;
    let run_id = new_run_id();
    let mut env = open_ledger(&config, allow_unleased)?;
    let recorder = RunRecorder::begin(env.ledger()?)?;
    let ledger = env.take_ledger()?;

    let outcome = async {
        let ctx = build_context(config, ResolvedScope::default(), ledger, run_id.clone())?;
        let report = repair::run(&ctx, args.to_opts()).await?;
        env.restore(take_ledger(ctx));
        Ok::<RepairReport, anyhow::Error>(report)
    }
    .await;

    let report = match outcome {
        Ok(report) => report,
        Err(error) => {
            recorder.finish_or_warn(&mut env, &run_id, &format!("repair {run_id} (incomplete)"));
            return Err(error);
        }
    };

    if args.json {
        println!("{}", repair_json(&report));
    } else {
        print!("{report}");
    }
    recorder.finish(&env, &run_id, &format!("repair {run_id}"))?;
    Ok(report.exit_code())
}

fn repair_json(report: &RepairReport) -> String {
    let actions: Vec<serde_json::Value> = report
        .actions
        .iter()
        .map(|action| {
            json!({
                "artifact_key": action.artifact_key,
                "target": action.target,
                "outcome": action.outcome.as_str(),
                "detail": action.detail,
            })
        })
        .collect();
    serde_json::to_string_pretty(&json!({
        "examined": report.examined,
        "repaired": report.repaired,
        "skipped": report.skipped,
        "unrecoverable": report.unrecoverable,
        "failed": report.failed,
        "limit_reached": report.limit_reached,
        "actions": actions,
    }))
    .unwrap_or_else(|_| "{}".to_string())
}

// ---------------------------------------------------------------------------
// incidents
// ---------------------------------------------------------------------------

async fn incidents_command(
    config: &Config,
    action: IncidentsCommand,
    allow_unleased: bool,
) -> anyhow::Result<i32> {
    config.validate()?;
    match action {
        IncidentsCommand::List { json } => {
            let env = open_ledger(config, allow_unleased)?;
            let incidents = incident::list(env.ledger()?)?;
            let open = incidents
                .iter()
                .filter(|incident| incident.state == IncidentState::Open)
                .count();
            if json {
                let values: Vec<serde_json::Value> = incidents.iter().map(incident_json).collect();
                println!(
                    "{}",
                    serde_json::to_string_pretty(&values).unwrap_or_else(|_| "[]".to_string())
                );
            } else {
                for incident in &incidents {
                    println!(
                        "{} {} {} {}",
                        incident.id,
                        incident.state,
                        incident.kind,
                        incident.artifact_key.as_deref().unwrap_or("-")
                    );
                }
                println!(
                    "{} incident(s), {} open, {} acknowledged",
                    incidents.len(),
                    open,
                    incidents.len() - open
                );
            }
            Ok(if open > 0 { EXIT_INCIDENTS } else { EXIT_OK })
        }
        IncidentsCommand::Show { id } => {
            let env = open_ledger(config, allow_unleased)?;
            let found = incident::show(env.ledger()?, &id)?;
            println!(
                "{}",
                serde_json::to_string_pretty(&incident_json(&found))
                    .unwrap_or_else(|_| "{}".to_string())
            );
            Ok(EXIT_OK)
        }
        IncidentsCommand::Ack {
            id,
            republish,
            note,
        } => {
            let run_id = new_run_id();
            let mut env = open_ledger(config, allow_unleased)?;
            // An acknowledgement appends events and pushes a run file, so it
            // serialises against mirror and backfill writers like they do.
            let guard = acquire_lease(&env, &run_id, allow_unleased).await?;

            let recorder = RunRecorder::begin(env.ledger()?)?;
            let outcome = async {
                let targets = TargetSet::from_config(config)?;
                incident::ack(
                    env.ledger_mut()?,
                    &targets,
                    config,
                    &id,
                    note.as_deref(),
                    republish,
                )
                .await?;
                Ok::<(), anyhow::Error>(())
            }
            .await;

            if let Err(error) = outcome {
                recorder.finish_or_warn(&mut env, &run_id, &format!("incident {id} (incomplete)"));
                return Err(error);
            }
            recorder.finish(&env, &run_id, &format!("incident {id}: acknowledged"))?;
            if let Some(guard) = guard {
                guard.release().await;
            }
            println!("acknowledged {id}");
            Ok(EXIT_OK)
        }
    }
}

fn incident_json(incident: &Incident) -> serde_json::Value {
    json!({
        "id": incident.id,
        "artifact_key": incident.artifact_key,
        "kind": incident.kind.as_str(),
        "old_sha256": incident.old_sha256,
        "new_sha256": incident.new_sha256,
        "detected_at": incident
            .detected_at
            .to_rfc3339_opts(SecondsFormat::Millis, true),
        "detail": incident.detail,
        "state": incident.state.as_str(),
        "issue_url": incident.issue_url,
        "ack_note": incident.ack_note,
    })
}

// ---------------------------------------------------------------------------
// ledger
// ---------------------------------------------------------------------------

async fn ledger_command(
    config: &Config,
    action: LedgerCommand,
    allow_unleased: bool,
) -> anyhow::Result<i32> {
    config.validate()?;
    match action {
        LedgerCommand::Bootstrap => {
            let run_id = new_run_id();
            let mut env = open_ledger(config, allow_unleased)?;
            let guard = acquire_lease(&env, &run_id, allow_unleased).await?;
            let scope = config.resolve(&ScopeArgs::default())?;
            let recorder = RunRecorder::begin(env.ledger()?)?;
            let ledger = env.take_ledger()?;

            let outcome = async {
                let ctx = build_context(config.clone(), scope, ledger, run_id.clone())?;
                let report = cinc_mirror::bootstrap::run(&ctx).await?;
                env.restore(take_ledger(ctx));
                Ok::<cinc_mirror::BootstrapReport, anyhow::Error>(report)
            }
            .await;

            let report = match outcome {
                Ok(report) => report,
                Err(error) => {
                    recorder.finish_or_warn(
                        &mut env,
                        &run_id,
                        &format!("bootstrap {run_id} (incomplete)"),
                    );
                    return Err(error);
                }
            };

            println!("{report}");
            recorder.finish(&env, &run_id, &format!("bootstrap {run_id}"))?;
            if let Some(guard) = guard {
                guard.release().await;
            }
            Ok(if report.conflicts > 0 {
                EXIT_INCIDENTS
            } else {
                EXIT_OK
            })
        }
        LedgerCommand::Pull => {
            let env = open_ledger(config, allow_unleased)?;
            println!("ledger: {} event(s) loaded", env.ledger()?.event_count()?);
            Ok(EXIT_OK)
        }
        LedgerCommand::Push => {
            let run_id = new_run_id();
            let env = open_ledger(config, allow_unleased)?;
            let guard = acquire_lease(&env, &run_id, allow_unleased).await?;
            let store = env.require_store()?;
            let runs = store.workdir().join(RUNS_DIR);
            if !runs.is_dir() {
                println!("ledger: no run files to push");
                if let Some(guard) = guard {
                    guard.release().await;
                }
                return Ok(EXIT_OK);
            }
            store
                .commit_and_push(&runs, "ledger: push pending run files")
                .map_err(|source| PushFailure {
                    path: runs.clone(),
                    source,
                })?;
            println!("ledger: pushed");
            if let Some(guard) = guard {
                guard.release().await;
            }
            Ok(EXIT_OK)
        }
        LedgerCommand::Compact => {
            let run_id = new_run_id();
            let env = open_ledger(config, allow_unleased)?;
            let guard = acquire_lease(&env, &run_id, allow_unleased).await?;
            let store = env.require_store()?;
            let path = store.compact(env.ledger()?)?;
            println!("ledger: wrote {}", path.display());
            if let Some(guard) = guard {
                guard.release().await;
            }
            Ok(EXIT_OK)
        }
        LedgerCommand::Gc => {
            let run_id = new_run_id();
            let env = open_ledger(config, allow_unleased)?;
            let guard = acquire_lease(&env, &run_id, allow_unleased).await?;
            let store = env.require_store()?;
            let removed = store.gc()?;
            println!("ledger: removed {} covered run file(s)", removed.len());
            if let Some(guard) = guard {
                guard.release().await;
            }
            Ok(EXIT_OK)
        }
        LedgerCommand::Export => {
            let env = open_ledger(config, allow_unleased)?;
            for event in env.ledger()?.events()? {
                match serde_json::to_string(&event) {
                    Ok(line) => println!("{line}"),
                    Err(error) => bail!("cannot encode an event: {error}"),
                }
            }
            Ok(EXIT_OK)
        }
    }
}
