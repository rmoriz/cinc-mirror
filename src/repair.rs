//! Repair: restore publications that verification would report.
//!
//! `repair` is the only command besides `mirror` that downloads package bytes,
//! and it downloads only when the local store copy is gone or corrupt. The
//! order of decisions per artifact is:
//!
//! 1. every selected target is probed with [`Target::verify`]; only failing
//!    publications take part in the repair, and a publication the ledger marks
//!    `superseded` is skipped because its canonical reference was retired
//!    deliberately; a `pruned` publication is skipped too, because the prune
//!    deleted it on purpose, unless `--include-pruned` asks for it back;
//! 2. the local blob is re-hashed. A corrupt blob is replaced; a missing blob
//!    is refilled from upstream into the store's partial file and committed;
//! 3. the verified bytes are re-published with [`Target::put`] to every failing
//!    target and verified again afterwards;
//! 4. when upstream no longer serves the bytes (`NotFound`), the publication is
//!    marked `unrecoverable` and one [`IncidentKind::Unrecoverable`] incident is
//!    opened, so the loss is visible in the ledger and to a human instead of
//!    being retried forever.
//!
//! A tag conflict is never overwritten: the canonical reference may only move
//! through the incident flow (`incidents ack --republish`). Repair records the
//! conflict as skipped with a pointer at the open incident.
//!
//! Local health is checked for every artifact the ledger records as present
//! (`artifacts.local = 1`), independent of the remote probes. A corrupt or
//! unexpectedly missing blob is refilled even when every target still verifies,
//! so `verify --deep` followed by `repair` always has a way back to a good local
//! copy. The corrupt occupant stays on disk until replacement bytes are verified,
//! and is left untouched when the refill fails, so the operator keeps the
//! evidence.
//!
//! # Limits
//!
//! `limit` caps the number of broken items repair examines (a publication or the
//! local blob). The cap is checked before each artifact, so the artifact being
//! worked on can take the count past it; a truncated run exits `2` because the
//! mirror cannot claim the rest is clean. `projects` narrows the walk to the
//! named upstream projects, which matters because the ledger keeps rows of
//! projects that left the configuration.

use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use chrono::Utc;
use serde_json::json;
use thiserror::Error;

use crate::artifact::Artifact;
use crate::ctx::Ctx;
use crate::hash::ExpectedHashes;
use crate::incident::{self, IncidentError};
use crate::ledger::{
    Event, EventKind, IncidentFilter, IncidentKind, IncidentState, LedgerError, PublicationStatus,
};
use crate::report::{EXIT_OK, EXIT_PARTIAL};
use crate::source::metadata::Metadata;
use crate::source::transport::{DownloadError, TransportError};
use crate::store::StoreError;
use crate::targets::{Target, TargetError};

/// Pseudo-target name a [`RepairAction`] carries when it concerns the store
/// rather than a remote publication.
pub const LOCAL_STORE: &str = "local-store";

/// What `repair` may do.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepairOpts {
    /// Repair only these targets; `None` repairs every enabled target.
    pub targets: Option<Vec<String>>,
    /// Repair only these projects; `None` repairs every project in the ledger.
    ///
    /// The ledger keeps rows of projects that left the configuration, so a
    /// repair would otherwise walk and re-fetch those first and bury the
    /// projects an operator cares about behind its `limit`.
    pub projects: Option<Vec<String>>,
    /// Repair at most this many broken items (publications or local blobs).
    pub limit: Option<usize>,
    /// Also restore publications a prune deleted (re-downloads and re-publishes
    /// them).
    pub include_pruned: bool,
}

/// What happened to one broken publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RepairOutcome {
    /// The publication was restored and verified.
    Repaired,
    /// A tag conflict; the incident flow owns the reference.
    Skipped,
    /// The bytes are gone locally and upstream; an incident records the loss.
    Unrecoverable,
    /// The repair was attempted but the publication is still broken.
    Failed,
}

impl RepairOutcome {
    /// The stable spelling used in reports and logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Repaired => "repaired",
            Self::Skipped => "skipped",
            Self::Unrecoverable => "unrecoverable",
            Self::Failed => "failed",
        }
    }
}

impl fmt::Display for RepairOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One decision repair made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepairAction {
    /// The artifact the decision concerns.
    pub artifact_key: String,
    /// The target that is still broken, or [`LOCAL_STORE`] for the local blob.
    pub target: String,
    /// What repair did.
    pub outcome: RepairOutcome,
    /// Why, or which incident owns the case.
    pub detail: String,
}

impl fmt::Display for RepairAction {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "{} {} target={}: {}",
            self.outcome, self.artifact_key, self.target, self.detail
        )
    }
}

/// Counts and decisions of one repair run.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RepairReport {
    /// Broken publications and local blobs examined.
    pub examined: usize,
    /// Publications restored and verified.
    pub repaired: usize,
    /// Tag conflicts left to the incident flow.
    pub skipped: usize,
    /// Publications that cannot be restored.
    pub unrecoverable: usize,
    /// Publications that are still broken after an attempt.
    pub failed: usize,
    /// Whether `limit` stopped the scan with broken publications left.
    pub limit_reached: bool,
    /// One line per examined publication.
    pub actions: Vec<RepairAction>,
}

impl RepairReport {
    /// Whether every examined publication is published again.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.skipped == 0 && self.unrecoverable == 0 && self.failed == 0
    }

    /// Process exit code: `2` while anything remains broken, `0` when clean.
    ///
    /// A run truncated by `limit` also exits `2`: it could not prove the rest is
    /// clean.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if self.is_clean() && !self.limit_reached {
            EXIT_OK
        } else {
            EXIT_PARTIAL
        }
    }

    fn record(&mut self, action: RepairAction) {
        match action.outcome {
            RepairOutcome::Repaired => self.repaired += 1,
            RepairOutcome::Skipped => self.skipped += 1,
            RepairOutcome::Unrecoverable => self.unrecoverable += 1,
            RepairOutcome::Failed => self.failed += 1,
        }
        self.actions.push(action);
    }
}

impl fmt::Display for RepairReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            formatter,
            "repair: {} examined, {} repaired, {} skipped, {} unrecoverable, {} failed{}",
            self.examined,
            self.repaired,
            self.skipped,
            self.unrecoverable,
            self.failed,
            if self.limit_reached {
                " (limit reached)"
            } else {
                ""
            }
        )?;
        for action in &self.actions {
            writeln!(formatter, "  {action}")?;
        }
        Ok(())
    }
}

/// Why a repair could not run.
#[derive(Debug, Error)]
pub enum RepairError {
    /// A target filter names a target the configuration does not have.
    #[error("unknown target `{name}`")]
    UnknownTarget {
        /// The requested target name.
        name: String,
    },

    /// The ledger rejected a query or an event.
    #[error(transparent)]
    Ledger(#[from] LedgerError),

    /// The local store failed.
    #[error(transparent)]
    Store(#[from] StoreError),

    /// The incident flow failed.
    #[error(transparent)]
    Incident(#[from] IncidentError),
}

/// Monotonic event sequence for one repair run.
struct Seq(AtomicU64);

impl Seq {
    fn new() -> Self {
        Self(AtomicU64::new(1))
    }

    fn next(&self) -> u64 {
        self.0.fetch_add(1, Ordering::SeqCst)
    }
}

/// Repair every broken publication or local blob verification would report.
///
/// # Errors
///
/// Returns [`RepairError::UnknownTarget`] for a filter that names no configured
/// target, and the ledger, store or incident error that prevented the run.
/// Download and target failures are decisions in the report, not errors.
pub async fn run(ctx: &Ctx, opts: RepairOpts) -> Result<RepairReport, RepairError> {
    let targets = selected_targets(ctx, opts.targets.as_deref())?;
    let rows = {
        let ledger = ctx.ledger.lock().await;
        ledger.artifacts()?
    }
    .into_iter()
    .filter(|row| {
        opts.projects.as_ref().is_none_or(|projects| {
            projects
                .iter()
                .any(|project| project == &row.artifact.project)
        })
    });
    let seq = Seq::new();
    let mut report = RepairReport::default();

    for row in rows {
        let artifact = row.artifact;
        let publications = {
            let ledger = ctx.ledger.lock().await;
            ledger.publications_for(&artifact.key())?
        };
        let superseded: HashSet<&str> = publications
            .iter()
            .filter(|publication| publication.status == PublicationStatus::Superseded)
            .map(|publication| publication.target.as_str())
            .collect();
        let pruned: HashSet<&str> = publications
            .iter()
            .filter(|publication| publication.status == PublicationStatus::Pruned)
            .map(|publication| publication.target.as_str())
            .collect();

        let mut broken: Vec<&Arc<dyn Target>> = Vec::new();
        for target in &targets {
            if target.verify(&artifact).await.is_ok() {
                continue;
            }
            if superseded.contains(target.name()) {
                // The canonical reference was retired by an acknowledged hash
                // change; it is not broken, so it is neither reported nor fixed.
                continue;
            }
            if !opts.include_pruned && pruned.contains(target.name()) {
                // A prune deleted the reference on purpose, so it is not broken
                // either; re-publishing it would undo the retention. The flag is
                // the deliberate way back.
                continue;
            }
            broken.push(target);
        }

        // The local copy is checked even when every remote is healthy: a deep
        // verification finding must be repairable on its own.
        let check = local_check(ctx, &artifact, row.local)?;
        let local_repair = if check.problem != LocalProblem::None {
            check.problem
        } else if !broken.is_empty() && !check.usable {
            // A publication the ledger voluntarily gc'd still needs a blob when
            // a target has to be re-pushed.
            if ctx.store.has(&artifact.sha256) {
                LocalProblem::Corrupt
            } else {
                LocalProblem::Missing
            }
        } else {
            LocalProblem::None
        };
        if broken.is_empty() && local_repair == LocalProblem::None {
            continue;
        }

        if opts.limit.is_some_and(|limit| report.examined >= limit) {
            report.limit_reached = true;
            break;
        }

        match local_repair {
            LocalProblem::None => {}
            LocalProblem::Corrupt | LocalProblem::Missing => {
                let description = if local_repair == LocalProblem::Corrupt {
                    "replaced a corrupt local blob"
                } else {
                    "refetched a missing local blob"
                };
                match repair_local(ctx, &artifact, &seq).await? {
                    LocalState::Ready => {
                        report.examined += 1;
                        report.record(local_action(
                            &artifact,
                            RepairOutcome::Repaired,
                            description,
                        ));
                    }
                    LocalState::Unrecoverable { incident, reason } => {
                        report.examined += 1;
                        report.record(local_action(
                            &artifact,
                            RepairOutcome::Unrecoverable,
                            &format!("{reason}; incident {incident}"),
                        ));
                        for target in broken {
                            append_unrecoverable(
                                ctx,
                                &artifact,
                                target.as_ref(),
                                &reason,
                                &incident,
                                &seq,
                            )
                            .await?;
                            report.examined += 1;
                            report.record(RepairAction {
                                artifact_key: artifact.key(),
                                target: target.name().to_string(),
                                outcome: RepairOutcome::Unrecoverable,
                                detail: format!("{reason}; incident {incident}"),
                            });
                        }
                        continue;
                    }
                    LocalState::Failed { reason } => {
                        report.examined += 1;
                        report.record(local_action(&artifact, RepairOutcome::Failed, &reason));
                        for target in broken {
                            report.examined += 1;
                            report.record(RepairAction {
                                artifact_key: artifact.key(),
                                target: target.name().to_string(),
                                outcome: RepairOutcome::Failed,
                                detail: reason.clone(),
                            });
                        }
                        continue;
                    }
                }
            }
        }

        if broken.is_empty() {
            continue;
        }

        let blob = ctx.store.path(&artifact.sha256)?;
        for target in broken {
            let action = repair_publication(ctx, &artifact, target.as_ref(), &blob, &seq).await?;
            report.examined += 1;
            report.record(action);
        }
    }

    Ok(report)
}

/// What, if anything, is wrong with the local blob the ledger records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LocalProblem {
    /// The blob is present and hashes to its name, or the ledger recorded a
    /// deliberate `local_gc` and no local copy is expected.
    None,
    /// The blob is present but does not hash to its name.
    Corrupt,
    /// The ledger records a local blob that the store does not have.
    Missing,
}

/// The local copy, as the ledger and the store see it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LocalCheck {
    /// Whether a blob that hashes to its name is present.
    usable: bool,
    /// The problem the ledger's `local` flag promises, if any.
    problem: LocalProblem,
}

/// Check the local copy `local` promises.
fn local_check(ctx: &Ctx, artifact: &Artifact, local: bool) -> Result<LocalCheck, RepairError> {
    let usable = ctx.store.verify(&artifact.sha256)?;
    let problem = if !local || usable {
        LocalProblem::None
    } else if ctx.store.has(&artifact.sha256) {
        LocalProblem::Corrupt
    } else {
        LocalProblem::Missing
    };
    Ok(LocalCheck { usable, problem })
}

/// A report action scoped to the local store.
fn local_action(artifact: &Artifact, outcome: RepairOutcome, detail: &str) -> RepairAction {
    RepairAction {
        artifact_key: artifact.key(),
        target: LOCAL_STORE.to_string(),
        outcome,
        detail: detail.to_string(),
    }
}

/// Record that a publication cannot be restored.
async fn append_unrecoverable(
    ctx: &Ctx,
    artifact: &Artifact,
    target: &dyn Target,
    reason: &str,
    incident: &str,
    seq: &Seq,
) -> Result<(), RepairError> {
    append_event(
        ctx,
        Event::new(
            ctx.run_id.clone(),
            seq.next(),
            Utc::now(),
            EventKind::PublicationUnrecoverable,
        )
        .with_artifact(artifact.key())
        .with_target(target.name())
        .with_detail(json!({"error": reason, "incident": incident})),
    )
    .await
}

/// What the local refill produced.
enum LocalState {
    /// Verified replacement bytes are in the store.
    Ready,
    /// Neither upstream nor the store can produce the bytes.
    Unrecoverable { incident: String, reason: String },
    /// A download or store operation failed; the case can be retried.
    Failed { reason: String },
}

/// Refill the local blob from upstream.
///
/// The caller has already established that the blob is missing or corrupt.
async fn repair_local(
    ctx: &Ctx,
    artifact: &Artifact,
    seq: &Seq,
) -> Result<LocalState, RepairError> {
    let partial = ctx.store.partial_path(&artifact.sha256)?;
    let result = ctx
        .source
        .download_with_rate(
            &artifact.rsync_relpath(),
            &partial,
            &expected_hashes(artifact),
            Some(ctx.rate.as_ref()),
        )
        .await;

    match result {
        Ok(outcome) => {
            // A corrupt blob can occupy the digest's address. Remove it only
            // now that replacement bytes are verified on disk, so a failed
            // download never destroys the only local copy.
            if ctx.store.has(&artifact.sha256) {
                ctx.store.gc(&artifact.sha256)?;
            }
            ctx.store.commit(&artifact.sha256, &partial)?;
            append_event(
                ctx,
                Event::new(
                    ctx.run_id.clone(),
                    seq.next(),
                    Utc::now(),
                    EventKind::Verified,
                )
                .with_artifact(artifact.key())
                .with_detail(json!({"size": outcome.hashes.size})),
            )
            .await?;
            Ok(LocalState::Ready)
        }
        Err(error) if upstream_gone(&error) => {
            let reason = error.to_string();
            let id = open_unrecoverable(ctx, artifact, &reason).await?;
            Ok(LocalState::Unrecoverable {
                incident: id,
                reason,
            })
        }
        Err(error) => Ok(LocalState::Failed {
            reason: error.to_string(),
        }),
    }
}

/// Re-publish one broken publication and verify the result.
async fn repair_publication(
    ctx: &Ctx,
    artifact: &Artifact,
    target: &dyn Target,
    blob: &std::path::Path,
    seq: &Seq,
) -> Result<RepairAction, RepairError> {
    let action = |outcome, detail: String| RepairAction {
        artifact_key: artifact.key(),
        target: target.name().to_string(),
        outcome,
        detail,
    };

    match target.put(artifact, blob).await {
        Ok(outcome) => match target.verify(artifact).await {
            Ok(()) => {
                append_event(
                    ctx,
                    Event::new(
                        ctx.run_id.clone(),
                        seq.next(),
                        Utc::now(),
                        EventKind::Published,
                    )
                    .with_artifact(artifact.key())
                    .with_target(target.name())
                    .with_detail(json!({
                        "remote_ref": outcome.remote_ref,
                        "remote_digest": outcome.remote_digest,
                    })),
                )
                .await?;
                Ok(action(
                    RepairOutcome::Repaired,
                    "published and verified".to_string(),
                ))
            }
            Err(error) => {
                let reason = format!("published but verification failed: {error}");
                append_failure(ctx, artifact, target.name(), &reason, seq).await?;
                Ok(action(RepairOutcome::Failed, reason))
            }
        },
        Err(TargetError::TagConflict { existing, .. }) => {
            let reason = format!("tag conflict: the reference already holds {existing}");
            let incident = tag_conflict_incident(ctx, artifact, &existing).await?;
            append_failure(ctx, artifact, target.name(), &reason, seq).await?;
            Ok(action(
                RepairOutcome::Skipped,
                format!("{reason}; incident {incident}"),
            ))
        }
        Err(error) => {
            let reason = error.to_string();
            append_failure(ctx, artifact, target.name(), &reason, seq).await?;
            Ok(action(RepairOutcome::Failed, reason))
        }
    }
}

/// Find the open tag-conflict incident for `artifact`, opening one if needed.
async fn tag_conflict_incident(
    ctx: &Ctx,
    artifact: &Artifact,
    existing: &str,
) -> Result<String, RepairError> {
    let mut ledger = ctx.ledger.lock().await;
    let incidents = ledger.incidents(IncidentFilter {
        state: None,
        kind: Some(IncidentKind::TagConflict),
        artifact_key: Some(artifact.key()),
    })?;
    if let Some(incident) = incidents
        .iter()
        .find(|incident| incident.state == IncidentState::Open)
        .or_else(|| incidents.first())
    {
        return Ok(incident.id.clone());
    }

    let incident = incident::open(
        &mut ledger,
        ctx.config.as_ref(),
        artifact,
        existing,
        IncidentKind::TagConflict,
    )
    .await?;
    Ok(incident.id)
}

/// Open (or find) the incident that records an unrecoverable artifact.
async fn open_unrecoverable(
    ctx: &Ctx,
    artifact: &Artifact,
    reason: &str,
) -> Result<String, RepairError> {
    let mut ledger = ctx.ledger.lock().await;
    let incident = incident::open(
        &mut ledger,
        ctx.config.as_ref(),
        artifact,
        &artifact.sha256,
        IncidentKind::Unrecoverable,
    )
    .await?;
    tracing::warn!(
        artifact = %artifact.key(),
        incident = %incident.id,
        reason,
        "artifact is unrecoverable"
    );
    Ok(incident.id)
}

/// Whether upstream has permanently lost the payload.
fn upstream_gone(error: &DownloadError) -> bool {
    matches!(
        error,
        DownloadError::Rejected {
            source: TransportError::NotFound { .. },
            ..
        }
    )
}

/// Charge `artifact`'s own metadata for the cross-checks the transport verifies.
fn expected_hashes(artifact: &Artifact) -> ExpectedHashes {
    match Metadata::from_json(&artifact.metadata_json) {
        Ok(metadata) => ExpectedHashes::from_metadata(&metadata),
        Err(_) => ExpectedHashes {
            sha256: artifact.sha256.clone(),
            sha512: None,
            sha1: None,
            md5: None,
            size: None,
        },
    }
}

/// The targets a filter selects, in configuration order.
fn selected_targets<'a>(
    ctx: &'a Ctx,
    requested: Option<&[String]>,
) -> Result<Vec<&'a Arc<dyn Target>>, RepairError> {
    let all = ctx.targets.all();
    let Some(names) = requested else {
        return Ok(all.iter().collect());
    };

    let mut selected: Vec<&Arc<dyn Target>> = Vec::new();
    for name in names {
        let target = all
            .iter()
            .find(|target| target.name() == name)
            .ok_or_else(|| RepairError::UnknownTarget { name: name.clone() })?;
        if !selected.iter().any(|seen| seen.name() == name) {
            selected.push(target);
        }
    }
    Ok(selected)
}

async fn append_failure(
    ctx: &Ctx,
    artifact: &Artifact,
    target: &str,
    error: &str,
    seq: &Seq,
) -> Result<(), RepairError> {
    append_event(
        ctx,
        Event::new(
            ctx.run_id.clone(),
            seq.next(),
            Utc::now(),
            EventKind::PublicationFailed,
        )
        .with_artifact(artifact.key())
        .with_target(target)
        .with_detail(json!({"error": error})),
    )
    .await
}

async fn append_event(ctx: &Ctx, event: Event) -> Result<(), RepairError> {
    ctx.ledger.lock().await.append(&event)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_report_with_any_remaining_failure_exits_two() {
        assert_eq!(RepairReport::default().exit_code(), EXIT_OK);
        for outcome in [
            RepairOutcome::Skipped,
            RepairOutcome::Unrecoverable,
            RepairOutcome::Failed,
        ] {
            let mut report = RepairReport::default();
            report.record(RepairAction {
                artifact_key: "stable/cinc/19.4.46/debian/13/amd64/aa".to_string(),
                target: "oci".to_string(),
                outcome,
                detail: "test".to_string(),
            });
            assert_eq!(report.exit_code(), EXIT_PARTIAL, "outcome {outcome}");
        }
    }

    #[test]
    fn a_truncated_report_exits_two() {
        let report = RepairReport {
            limit_reached: true,
            ..RepairReport::default()
        };
        assert_eq!(report.exit_code(), EXIT_PARTIAL);
    }

    #[test]
    fn only_upstream_not_found_counts_as_gone() {
        let not_found = DownloadError::Rejected {
            remote_path: "x".to_string(),
            transport: crate::config::TransportKind::Https,
            source: TransportError::NotFound {
                path: "x".to_string(),
            },
        };
        assert!(upstream_gone(&not_found));

        let forbidden = DownloadError::Rejected {
            remote_path: "x".to_string(),
            transport: crate::config::TransportKind::Https,
            source: TransportError::Forbidden {
                path: "x".to_string(),
                status: 403,
            },
        };
        assert!(!upstream_gone(&forbidden));
    }
}
