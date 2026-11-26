//! Bootstrap import of artifacts that predate the ledger.
//!
//! The legacy mirror published to GHCR before the ledger existed. `ledger
//! bootstrap` reconciles those publications with the ledger without touching the
//! registry:
//!
//! 1. every selected policy is crawled into the same artifact list the runner
//!    would build (a tag collision's latecomer keeps its digest-qualified tag);
//! 2. for every enabled OCI target the artifact's reference is resolved
//!    through [`Target::exists`];
//! 3. a tag that already holds the artifact's package digest is recorded as an
//!    `imported` event, which materialises the publication as `published` and
//!    the artifact row without a download or an upload;
//! 4. a tag that holds different package bytes opens a deduplicated
//!    [`IncidentKind::TagConflict`] incident and changes neither the registry
//!    nor the publication rows;
//! 5. a missing tag is counted as skipped: `mirror` will create it normally.
//!
//! # Compatibility
//!
//! Existing manifests differ in annotations, media types and layer order. Only
//! the package layer digest decides compatibility: [`Target::exists`] returns
//! that digest, and bootstrap compares it with the upstream `sha256`. Manifest
//! bytes are never compared.
//!
//! # Scope and safety
//!
//! rsync targets are ignored: they carry sidecar metadata and no legacy data
//! predates the ledger there. Bootstrap works without the lease (the command
//! layer takes it) and appends a minimal `run_started`/`run_finished` pair with
//! `mode: bootstrap`, so its run file explains itself. It appends events to the
//! in-memory ledger only, never downloads package bytes and never publishes.

use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::Utc;
use serde_json::json;
use thiserror::Error;

use crate::artifact::Artifact;
use crate::config::TargetKind;
use crate::crawl::{self, CrawlError};
use crate::ctx::Ctx;
use crate::incident::{self, IncidentError};
use crate::ledger::{self, Event, EventKind, IncidentKind, LedgerError, PublicationStatus};
use crate::targets::{Target, TargetError};

/// Counts of one bootstrap run.
///
/// One import, skip or conflict is counted per artifact and OCI target: a run
/// with two OCI targets can record two imports for one artifact.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct BootstrapReport {
    /// Tags that already held the upstream package digest and were imported.
    pub imported: usize,
    /// Tags that do not exist yet.
    pub skipped: usize,
    /// Tags that hold different package bytes and became incidents.
    pub conflicts: usize,
}

impl fmt::Display for BootstrapReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "bootstrap: {} imported, {} skipped, {} conflicts",
            self.imported, self.skipped, self.conflicts
        )
    }
}

/// Why a bootstrap run could not finish.
///
/// Target and crawl failures abort the run: a half-read registry or upstream
/// would make the counts lie about what is already published.
#[derive(Debug, Error)]
pub enum BootstrapError {
    /// The upstream crawl failed.
    #[error(transparent)]
    Crawl(#[from] CrawlError),

    /// The ledger rejected a query or an event.
    #[error(transparent)]
    Ledger(#[from] LedgerError),

    /// A target probe failed.
    #[error(transparent)]
    Target(#[from] TargetError),

    /// The incident flow failed.
    #[error(transparent)]
    Incident(#[from] IncidentError),

    /// A configured OCI target was not built into this run's target set.
    #[error("configured OCI target `{name}` is not part of this run")]
    MissingTarget {
        /// The configured target name.
        name: String,
    },

    /// The run id already has ledger events.
    ///
    /// The ledger keys events on `(run_id, seq)` and silently ignores a
    /// duplicate, so a reused run id would drop imports and incidents without a
    /// trace. The caller must mint a fresh id per invocation.
    #[error("run id `{run_id}` already has ledger events; a bootstrap run needs a fresh run id")]
    RunIdReused {
        /// The reused run id.
        run_id: String,
    },
}

/// Monotonic event sequence for one bootstrap run.
struct Seq(AtomicU64);

impl Seq {
    fn new() -> Self {
        Self(AtomicU64::new(1))
    }

    fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst)
    }
}

/// Import existing OCI publications into the ledger.
///
/// `ctx.run_id` must be fresh: it is the ledger's event namespace, and a run id
/// that already has events makes every later append a duplicate-key no-op, so
/// imports and incidents would disappear silently. The caller (the CLI) mints a
/// new run id per invocation; this function enforces that instead of trusting
/// it.
///
/// # Errors
///
/// Returns [`BootstrapError::RunIdReused`] when `ctx.run_id` already has ledger
/// events, and [`BootstrapError`] when the crawl, the ledger, a target probe or
/// the incident flow fails, or when an enabled OCI target has no constructed
/// target in the context.
pub async fn run(ctx: &Ctx) -> Result<BootstrapReport, BootstrapError> {
    if ctx.ledger.lock().await.has_events_for_run(&ctx.run_id)? {
        return Err(BootstrapError::RunIdReused {
            run_id: ctx.run_id.clone(),
        });
    }

    let seq = Seq::new();
    ctx.ledger.lock().await.append(
        &Event::new(
            ctx.run_id.clone(),
            seq.next(),
            Utc::now(),
            EventKind::RunStarted,
        )
        .with_detail(json!({
            "mode": "bootstrap",
            "host": crate::hostname(),
            "transport_order": ctx
                .config
                .transport
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
        })),
    )?;

    let artifacts = crawl_all(ctx).await?;
    let targets = oci_targets(ctx)?;
    let mut report = BootstrapReport::default();

    for artifact in &artifacts {
        for target in &targets {
            let name = target.name();
            if is_imported(ctx, artifact, name).await? {
                continue;
            }

            let Some(existing) = target.exists(artifact).await? else {
                report.skipped += 1;
                continue;
            };

            if existing == package_digest(artifact) {
                import(ctx, artifact, name, &existing, &seq).await?;
                report.imported += 1;
            } else {
                conflict(ctx, artifact, &existing, &seq).await?;
                report.conflicts += 1;
            }
        }
    }

    let outcome = if report.conflicts > 0 {
        "incidents"
    } else {
        "success"
    };
    ctx.ledger.lock().await.append(
        &Event::new(
            ctx.run_id.clone(),
            seq.next(),
            Utc::now(),
            EventKind::RunFinished,
        )
        .with_detail(json!({
            "mode": "bootstrap",
            "outcome": outcome,
            "summary": {
                "imported": report.imported,
                "skipped": report.skipped,
                "conflicts": report.conflicts,
            },
        })),
    )?;

    Ok(report)
}

/// Crawl every selected policy into one artifact list.
///
/// A tag collision's latecomer keeps its digest-qualified tag, so its own
/// reference is normally missing from the registry and is counted as skipped;
/// `mirror` creates it later.
async fn crawl_all(ctx: &Ctx) -> Result<Vec<Artifact>, BootstrapError> {
    let overrides = {
        let ledger = ctx.ledger.lock().await;
        ledger.tag_overrides()?
    };
    let mut artifacts = Vec::new();
    let mut keys = HashSet::new();
    for policy in &ctx.scope.policies {
        let outcome = crawl::crawl(&ctx.source, policy, &overrides).await?;
        for artifact in outcome.artifacts {
            if keys.insert(artifact.key()) {
                artifacts.push(artifact);
            }
        }
    }
    Ok(artifacts)
}

/// The enabled OCI targets, in configuration order.
fn oci_targets(ctx: &Ctx) -> Result<Vec<&Arc<dyn Target>>, BootstrapError> {
    let mut selected = Vec::new();
    for configured in ctx
        .config
        .targets
        .iter()
        .filter(|target| target.enabled && target.kind == TargetKind::Oci)
    {
        let target = ctx
            .targets
            .all()
            .iter()
            .find(|target| target.name() == configured.name)
            .ok_or_else(|| BootstrapError::MissingTarget {
                name: configured.name.clone(),
            })?;
        selected.push(target);
    }
    Ok(selected)
}

/// Whether the ledger already records a published row for this pair.
async fn is_imported(ctx: &Ctx, artifact: &Artifact, target: &str) -> Result<bool, LedgerError> {
    let publication = ctx
        .ledger
        .lock()
        .await
        .publication(&artifact.key(), target)?;
    Ok(publication.is_some_and(|publication| publication.status == PublicationStatus::Published))
}

/// Record a matching tag as an import.
///
/// The artifact row is added first when the ledger has never seen the artifact,
/// because the `imported` reducer targets it. An existing row is left alone.
async fn import(
    ctx: &Ctx,
    artifact: &Artifact,
    target: &str,
    package_digest: &str,
    seq: &Seq,
) -> Result<(), BootstrapError> {
    let mut ledger = ctx.ledger.lock().await;
    ensure_artifact(&mut ledger, ctx.run_id.as_str(), artifact, seq)?;
    let event = Event::new(
        ctx.run_id.clone(),
        seq.next(),
        Utc::now(),
        EventKind::Imported,
    )
    .with_artifact(artifact.key())
    .with_target(target)
    .with_detail(json!({
        "artifact": ledger::artifact_detail(artifact),
        "upstream_path": artifact.rsync_relpath(),
        "package_digest": package_digest,
    }));
    ledger.append(&event)?;
    Ok(())
}

/// Open (or find) the tag-conflict incident for a tag with different bytes.
///
/// The artifact row must exist for the incident to name it, so a first sighting
/// is recorded as an artifact that was seen upstream. Nothing else changes: no
/// publication row is written and the registry keeps the bytes it has.
async fn conflict(
    ctx: &Ctx,
    artifact: &Artifact,
    existing: &str,
    seq: &Seq,
) -> Result<(), BootstrapError> {
    let mut ledger = ctx.ledger.lock().await;
    ensure_artifact(&mut ledger, ctx.run_id.as_str(), artifact, seq)?;
    incident::open(
        &mut ledger,
        ctx.config.as_ref(),
        artifact,
        existing,
        IncidentKind::TagConflict,
    )
    .await?;
    Ok(())
}

/// Append `artifact_seen` when the ledger has no row for `artifact` yet.
fn ensure_artifact(
    ledger: &mut ledger::Ledger,
    run_id: &str,
    artifact: &Artifact,
    seq: &Seq,
) -> Result<(), LedgerError> {
    if ledger.artifact(&artifact.key())?.is_some() {
        return Ok(());
    }
    let event = Event::new(
        run_id.to_string(),
        seq.next(),
        Utc::now(),
        EventKind::ArtifactSeen,
    )
    .with_artifact(artifact.key())
    .with_detail(json!({
        "artifact": ledger::artifact_detail(artifact),
        "upstream_path": artifact.rsync_relpath(),
        "metadata": serde_json::from_str::<serde_json::Value>(&artifact.metadata_json)
            .unwrap_or(serde_json::Value::Null),
    }));
    ledger.append(&event)
}

/// `sha256:<hex>` of the artifact's verified package digest.
fn package_digest(artifact: &Artifact) -> String {
    format!("sha256:{}", artifact.sha256)
}
