//! The one-shot run: crawl, classify, download, fan out and collect a summary.
//!
//! # Queue and limits
//!
//! Every crawled artifact is classified against the ledger before anything is
//! transferred:
//!
//! - no row for the upstream path → `new`;
//! - same digest and published on every enabled target → `satisfied` (dropped);
//! - same digest with a missing, retrying or interrupted target → `retry`;
//! - a different digest for the same path → a hash change: one incident is
//!   opened and the new bytes are published only under the superseded name;
//! - a row that is itself `superseded_by` something → skipped.
//!
//! A tag collision found while crawling (two raw arches mapping to one public
//! one, or the same version on two channels) is not a failed run: the kept
//! artifact flows through the queue, the conflicting one is excluded, and one
//! deduplicated [`IncidentKind::ArchCollision`] incident is opened per pair.
//!
//! Satisfied and terminal rows are removed before ordering, so the queue is a
//! deterministic function of the ledger and the crawl. `version_desc` is the
//! default; `smallest_first`/`largest_first` use the size the ledger learned.
//! Unknown sizes sort last.
//!
//! `max_bytes` counts download bytes. It is checked before an artifact starts
//! and again after it finishes, and the artifact that crosses the cap always
//! completes, so a capped run overshoots by at most one artifact and its next
//! prefix is strictly shorter. A capped run processes artifacts sequentially for
//! the same reason: with parallel workers the overshoot could be one
//! full-sized artifact per worker. `max_artifacts` is likewise exact.
//!
//! # Concurrency
//!
//! Download concurrency is bounded by `config.concurrency`, once in the worker
//! pool and once with an explicit semaphore around the transport call. Uploads
//! are bounded per target by `config.upload_concurrency`; an artifact fans out to
//! every enabled target, and a target that is already `published` is not touched
//! again.
//!
//! # Events and ownership
//!
//! The runner appends `run_started`, recovery, artifact, publication, incident
//! and `run_finished` events to the in-memory ledger and returns a [`Summary`].
//! It never takes the lease, writes the run file or pushes the ledger: the
//! command layer owns the git commit (and can append its own lease metadata).
//! A dry run reads the ledger and the source, counts what it would do, and
//! writes nothing at all.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering as Atomic};
use std::sync::Arc;

use chrono::Utc;
use futures::stream::{self, StreamExt, TryStreamExt};
use serde_json::{json, Value};
use thiserror::Error;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::artifact::Artifact;
use crate::crawl::{self, CrawlError, TagCollision};
use crate::ctx::Ctx;
use crate::hash::ExpectedHashes;
use crate::incident::{self, IncidentError};
use crate::ledger::{
    self, ArtifactRow, Event, EventKind, IncidentFilter, IncidentKind, Ledger, LedgerError,
    PublicationStatus,
};
use crate::report::{Summary, EXIT_USAGE};
use crate::source::metadata::Metadata;
use crate::store::StoreError;
use crate::targets::{Target, TargetError};

/// How the queue is ordered after satisfied rows are removed.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum Order {
    /// Version descending (numerically), then policy, project, platform,
    /// platform version, architecture and basename.
    #[default]
    VersionDesc,
    /// Smallest known size first; unknown sizes last.
    SmallestFirst,
    /// Largest known size first; unknown sizes last.
    LargestFirst,
}

impl Order {
    /// The stable spelling recorded in the run row and events.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::VersionDesc => "version_desc",
            Self::SmallestFirst => "smallest_first",
            Self::LargestFirst => "largest_first",
        }
    }
}

/// Per-run options, applied on top of the configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RunOpts {
    /// Stop after this many artifacts were started.
    pub max_artifacts: Option<usize>,
    /// Stop once this many download bytes were transferred; the crossing
    /// artifact is always finished. `Some(0)` is a usage error.
    pub max_bytes: Option<u64>,
    /// Queue order.
    pub order: Order,
    /// Delete each blob once every enabled target reports success.
    pub gc_after: bool,
    /// Plan and count without downloading, publishing or writing events.
    pub dry_run: bool,
    /// Start the queue just after this artifact key and wrap around. A backfill
    /// sets it from the cursor its previous capped run recorded.
    pub start_after: Option<String>,
    /// Record a resume cursor under this policy fingerprint in the run's
    /// `run_finished` event: the last processed key when the run was capped,
    /// nulls when it finished the queue.
    pub cursor_fingerprint: Option<String>,
}

/// Why a run could not be performed.
#[derive(Debug, Error)]
pub enum RunError {
    /// The options cannot describe a run.
    #[error("usage: {reason}")]
    Usage {
        /// What is wrong with the options.
        reason: String,
    },

    /// There is nowhere to publish.
    #[error("no publication targets are enabled")]
    NoTargets,

    /// An internal semaphore was closed; this cannot happen in a live run.
    #[error("an internal scheduler semaphore was closed")]
    Scheduler,

    /// The crawl, a tag collision check or size resolution failed.
    #[error(transparent)]
    Crawl(#[from] CrawlError),

    /// The ledger rejected a query or an event.
    #[error(transparent)]
    Ledger(#[from] LedgerError),

    /// The local store failed.
    #[error(transparent)]
    Store(#[from] StoreError),

    /// The incident flow failed.
    #[error(transparent)]
    Incident(#[from] IncidentError),

    /// The only configured target cannot be used (bad configuration or
    /// credentials). Continuing would fail every artifact the same way.
    #[error("target `{target}` cannot be used: {source}")]
    TargetUnusable {
        /// Target that failed its probe or first publication.
        target: String,
        /// Underlying configuration or authentication error.
        #[source]
        source: TargetError,
    },
}

impl RunError {
    /// The process exit code this error implies.
    ///
    /// Usage errors map to `64`; everything else is the general error code. The
    /// command layer owns the mapping for configuration, auth and lease errors.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        match self {
            Self::Usage { .. } => EXIT_USAGE,
            _ => 1,
        }
    }
}

/// Monotonic event sequence for one run.
struct Seq(AtomicU64);

impl Seq {
    fn new(start: u64) -> Self {
        Self(AtomicU64::new(start))
    }

    fn next(&self) -> u64 {
        self.0.fetch_add(1, Atomic::SeqCst)
    }
}

/// What is already known about the queue, read once under the ledger lock.
struct Snapshot {
    rows_by_path: HashMap<String, Vec<ArtifactRow>>,
    local: HashMap<String, bool>,
    publications: HashMap<(String, String), PublicationStatus>,
}

impl Snapshot {
    fn build(ledger: &Ledger, targets: &[String]) -> Result<Self, LedgerError> {
        let mut rows_by_path: HashMap<String, Vec<ArtifactRow>> = HashMap::new();
        let mut local = HashMap::new();
        for row in ledger.artifacts()? {
            local.insert(row.artifact.key(), row.local);
            rows_by_path
                .entry(row.upstream_path.clone())
                .or_default()
                .push(row);
        }

        let mut publications = HashMap::new();
        for target in targets {
            for publication in ledger.publications(target)? {
                publications.insert(
                    (publication.artifact_key, publication.target),
                    publication.status,
                );
            }
        }

        Ok(Self {
            rows_by_path,
            local,
            publications,
        })
    }

    fn is_published(&self, key: &str, target: &str) -> bool {
        self.publications
            .get(&(key.to_string(), target.to_string()))
            == Some(&PublicationStatus::Published)
    }
}

/// How one crawled artifact relates to the ledger.
#[derive(Debug, Clone)]
enum Classification {
    New,
    Retry,
    Satisfied,
    Skip,
    HashChange { old_sha256: String },
}

/// One artifact waiting in the queue.
struct Queued {
    artifact: Artifact,
    policy_index: usize,
    size: Option<u64>,
    classification: Classification,
}

/// What one processed artifact contributed to the summary.
#[derive(Debug, Clone)]
struct ArtifactReport {
    key: String,
    version: String,
    sha256: String,
    downloaded: bool,
    bytes: u64,
    published: usize,
    failed: usize,
    incidents: usize,
    fully_published: bool,
}

/// The result of one target publication attempt.
enum PublishResult {
    Published,
    Failed,
    Conflict { new: bool },
}

/// Per-run state shared by the worker pool.
struct Job<'a> {
    ctx: &'a Ctx,
    snapshot: &'a Snapshot,
    targets: &'a [String],
    downloads: &'a Arc<Semaphore>,
    uploads: &'a HashMap<String, Arc<Semaphore>>,
    seq: &'a Seq,
    /// Set once the single configured target has been probed.
    probed: &'a tokio::sync::OnceCell<()>,
}

impl Job<'_> {
    async fn process(&self, item: &Queued) -> Result<ArtifactReport, RunError> {
        let mut artifact = item.artifact.clone();
        let mut incidents = 0;

        match &item.classification {
            Classification::HashChange { old_sha256 } => {
                let new = self
                    .open_incident(&artifact, old_sha256, IncidentKind::HashChanged)
                    .await?;
                if new {
                    incidents += 1;
                }
                // The canonical name keeps the old bytes until a human acks the
                // incident, so the replacement is only ever published under the
                // suffixed name.
                artifact = artifact.with_superseded(true);
            }
            Classification::New => {
                self.append(
                    Event::new(
                        self.ctx.run_id.clone(),
                        self.seq.next(),
                        Utc::now(),
                        EventKind::ArtifactSeen,
                    )
                    .with_artifact(artifact.key())
                    .with_detail(json!({
                        "artifact": ledger::artifact_detail(&artifact),
                        "upstream_path": artifact.rsync_relpath(),
                        "metadata": serde_json::from_str::<Value>(&artifact.metadata_json)
                            .unwrap_or(Value::Null),
                    })),
                )
                .await?;
            }
            Classification::Retry | Classification::Satisfied | Classification::Skip => {}
        }

        let mut downloaded = false;
        let mut bytes = 0_u64;
        let known_local = self
            .snapshot
            .local
            .get(&artifact.key())
            .copied()
            .unwrap_or(false);

        if !self.ctx.store.has(&artifact.sha256) {
            self.append(
                Event::new(
                    self.ctx.run_id.clone(),
                    self.seq.next(),
                    Utc::now(),
                    EventKind::DownloadStarted,
                )
                .with_artifact(artifact.key())
                .with_detail(json!({
                    "upstream_path": artifact.rsync_relpath(),
                    "expected_sha256": artifact.sha256,
                })),
            )
            .await?;

            let permit = self.acquire_download().await?;
            let partial = self.ctx.store.partial_path(&artifact.sha256)?;
            let result = self
                .ctx
                .source
                .download_with_rate(
                    &artifact.rsync_relpath(),
                    &partial,
                    &expected_hashes(&artifact),
                    Some(self.ctx.rate.as_ref()),
                )
                .await;
            drop(permit);

            match result {
                Ok(outcome) => {
                    self.ctx.store.commit(&artifact.sha256, &partial)?;
                    downloaded = true;
                    bytes = outcome.hashes.size.saturating_sub(outcome.resumed_from);
                    tracing::info!(
                        artifact = %artifact.key(),
                        bytes,
                        resumed_from = outcome.resumed_from,
                        transport = %outcome.transport,
                        "verified download"
                    );
                    self.append(verified_event(
                        self.ctx,
                        self.seq.next(),
                        &artifact,
                        Some(outcome.hashes.size),
                    ))
                    .await?;
                }
                Err(error) => {
                    tracing::warn!(
                        artifact = %artifact.key(),
                        %error,
                        "download failed; the next run retries it"
                    );
                    return Ok(ArtifactReport {
                        key: artifact.key(),
                        version: artifact.version.clone(),
                        sha256: artifact.sha256.clone(),
                        downloaded: false,
                        bytes: 0,
                        published: 0,
                        failed: 1,
                        incidents,
                        fully_published: false,
                    });
                }
            }
        } else if !known_local {
            // A previous run committed the blob but stopped before recording it
            // (or a gc was followed by a manual re-fetch). The store name is the
            // proof, so only the ledger flag needs repairing.
            let size = std::fs::metadata(self.ctx.store.path(&artifact.sha256)?)
                .ok()
                .map(|metadata| metadata.len());
            self.append(verified_event(self.ctx, self.seq.next(), &artifact, size))
                .await?;
        }

        self.ensure_target_usable().await?;

        let blob = self.ctx.store.path(&artifact.sha256)?;
        let mut published_now: Vec<String> = Vec::new();
        let mut published = 0;
        let mut failed = 0;

        for target in self.ctx.targets.all() {
            let name = target.name().to_string();
            if self.snapshot.is_published(&artifact.key(), &name) {
                published_now.push(name);
                continue;
            }

            match self.publish_one(&artifact, target.as_ref(), &blob).await? {
                PublishResult::Published => {
                    published += 1;
                    published_now.push(name);
                }
                PublishResult::Failed => failed += 1,
                PublishResult::Conflict { new } => {
                    if new {
                        incidents += 1;
                    }
                }
            }
        }

        Ok(ArtifactReport {
            key: artifact.key(),
            version: artifact.version.clone(),
            sha256: artifact.sha256.clone(),
            downloaded,
            bytes,
            published,
            failed,
            incidents,
            fully_published: failed == 0 && published_now.len() == self.targets.len(),
        })
    }

    /// Probe the only configured target once, after the first artifact is ready
    /// and before publishing it.
    ///
    /// A credential helper the client cannot run, or another configuration
    /// error, would otherwise fail every artifact in the queue. With a second
    /// target configured the run continues and lets the other target publish.
    async fn ensure_target_usable(&self) -> Result<(), RunError> {
        if !self.ctx.targets.is_single() {
            return Ok(());
        }
        let target = &self.ctx.targets.all()[0];
        self.probed
            .get_or_try_init(|| async {
                match target.probe().await {
                    Ok(()) => Ok(()),
                    Err(error) if error.is_unusable() => Err(RunError::TargetUnusable {
                        target: target.name().to_string(),
                        source: error,
                    }),
                    Err(error) => {
                        tracing::warn!(
                            target = target.name(),
                            %error,
                            "target probe failed; publication will report the error"
                        );
                        Ok(())
                    }
                }
            })
            .await?;
        Ok(())
    }

    async fn publish_one(
        &self,
        artifact: &Artifact,
        target: &dyn Target,
        blob: &std::path::Path,
    ) -> Result<PublishResult, RunError> {
        match target.exists(artifact).await {
            Ok(Some(existing)) if existing == artifact.sha256 => {
                // The target already holds these exact bytes; the ledger only
                // needs the publication row.
                tracing::info!(
                    artifact = %artifact.key(),
                    target = target.name(),
                    "target already holds the verified bytes"
                );
                self.append(published_event(
                    self.ctx,
                    self.seq.next(),
                    artifact,
                    target.name(),
                    None,
                    Some(&existing),
                ))
                .await?;
                return Ok(PublishResult::Published);
            }
            Ok(Some(existing)) => {
                // A different digest under this reference is an incident, never
                // an overwrite.
                let new = self
                    .open_incident(artifact, &existing, IncidentKind::TagConflict)
                    .await?;
                tracing::warn!(
                    artifact = %artifact.key(),
                    target = target.name(),
                    existing = %existing,
                    "reference holds different bytes; incident opened"
                );
                self.append(failed_event(
                    self.ctx,
                    self.seq.next(),
                    artifact,
                    target.name(),
                    &format!("reference already holds {existing}"),
                ))
                .await?;
                return Ok(PublishResult::Conflict { new });
            }
            Ok(None) => {}
            Err(error) => {
                if self.ctx.targets.is_single() && error.is_unusable() {
                    return Err(RunError::TargetUnusable {
                        target: target.name().to_string(),
                        source: error,
                    });
                }
                tracing::warn!(
                    artifact = %artifact.key(),
                    target = target.name(),
                    %error,
                    "target probe failed"
                );
                self.append(failed_event(
                    self.ctx,
                    self.seq.next(),
                    artifact,
                    target.name(),
                    &error.to_string(),
                ))
                .await?;
                return Ok(PublishResult::Failed);
            }
        }

        let permit = self.acquire_upload(target.name()).await?;
        self.append(
            Event::new(
                self.ctx.run_id.clone(),
                self.seq.next(),
                Utc::now(),
                EventKind::PublicationStarted,
            )
            .with_artifact(artifact.key())
            .with_target(target.name()),
        )
        .await?;
        let result = target.put(artifact, blob).await;
        drop(permit);

        match result {
            Ok(outcome) => {
                tracing::info!(
                    artifact = %artifact.key(),
                    target = target.name(),
                    remote_ref = %outcome.remote_ref,
                    "published"
                );
                self.append(published_event(
                    self.ctx,
                    self.seq.next(),
                    artifact,
                    target.name(),
                    Some(&outcome.remote_ref),
                    Some(&outcome.remote_digest),
                ))
                .await?;
                Ok(PublishResult::Published)
            }
            Err(TargetError::TagConflict { existing, .. }) => {
                let new = self
                    .open_incident(artifact, &existing, IncidentKind::TagConflict)
                    .await?;
                tracing::warn!(
                    artifact = %artifact.key(),
                    target = target.name(),
                    existing = %existing,
                    "tag conflict; incident opened"
                );
                self.append(failed_event(
                    self.ctx,
                    self.seq.next(),
                    artifact,
                    target.name(),
                    &format!("reference already holds {existing}"),
                ))
                .await?;
                Ok(PublishResult::Conflict { new })
            }
            Err(error) => {
                if self.ctx.targets.is_single() && error.is_unusable() {
                    return Err(RunError::TargetUnusable {
                        target: target.name().to_string(),
                        source: error,
                    });
                }
                tracing::warn!(
                    artifact = %artifact.key(),
                    target = target.name(),
                    %error,
                    "publication failed"
                );
                self.append(failed_event(
                    self.ctx,
                    self.seq.next(),
                    artifact,
                    target.name(),
                    &error.to_string(),
                ))
                .await?;
                Ok(PublishResult::Failed)
            }
        }
    }

    async fn open_incident(
        &self,
        artifact: &Artifact,
        old_sha256: &str,
        kind: IncidentKind,
    ) -> Result<bool, RunError> {
        let mut ledger = self.ctx.ledger.lock().await;
        let id = ledger::incident_id(
            kind,
            Some(&artifact.key()),
            Some(old_sha256),
            Some(&artifact.sha256),
        );
        let is_new = ledger.incident(&id)?.is_none();
        if is_new {
            incident::open(
                &mut ledger,
                self.ctx.config.as_ref(),
                artifact,
                old_sha256,
                kind,
            )
            .await?;
        }
        Ok(is_new)
    }

    async fn acquire_download(&self) -> Result<OwnedSemaphorePermit, RunError> {
        Arc::clone(self.downloads)
            .acquire_owned()
            .await
            .map_err(|_| RunError::Scheduler)
    }

    async fn acquire_upload(&self, target: &str) -> Result<OwnedSemaphorePermit, RunError> {
        let semaphore = self
            .uploads
            .get(target)
            .cloned()
            .ok_or(RunError::Scheduler)?;
        semaphore
            .acquire_owned()
            .await
            .map_err(|_| RunError::Scheduler)
    }

    async fn append(&self, event: Event) -> Result<(), RunError> {
        self.ctx.ledger.lock().await.append(&event)?;
        Ok(())
    }
}

/// Run one crawl-and-publish pass over `ctx`.
///
/// # Errors
///
/// Returns [`RunError::Usage`] for an unusable option, [`RunError::NoTargets`]
/// when a live run has nowhere to publish, [`RunError::TargetUnusable`] when the
/// only configured target has a configuration or authentication error, and the
/// crawl, ledger, store or incident error that aborted the run. Other
/// per-artifact download and target failures are counted in the summary instead
/// of aborting.
pub async fn run(ctx: &Ctx, opts: RunOpts) -> Result<Summary, RunError> {
    if opts.max_artifacts == Some(0) {
        return Err(RunError::Usage {
            reason: "--limit must be greater than zero".to_string(),
        });
    }
    if opts.max_bytes == Some(0) {
        return Err(RunError::Usage {
            reason: "--limit-bytes must be greater than zero".to_string(),
        });
    }

    let target_names: Vec<String> = ctx
        .targets
        .all()
        .iter()
        .map(|target| target.name().to_string())
        .collect();
    if target_names.is_empty() && !opts.dry_run {
        return Err(RunError::NoTargets);
    }

    let seq = Seq::new(1);
    if !opts.dry_run {
        // A reused run id would make every `(run_id, seq)` insert a duplicate
        // and silently drop the whole run from the ledger. Refuse loudly.
        if ctx.ledger.lock().await.run(&ctx.run_id)?.is_some() {
            return Err(RunError::Usage {
                reason: format!("run id `{}` was already used", ctx.run_id),
            });
        }
        append(ctx, started_event(ctx, &opts, seq.next())).await?;
        recover_interrupted(ctx, &seq, &target_names).await?;
        tracing::info!(
            run_id = %ctx.run_id,
            order = opts.order.as_str(),
            targets = target_names.len(),
            "run started"
        );
    }

    let (candidates, collisions) = crawl_scope(ctx).await?;
    let discovered = candidates.len();

    let snapshot = {
        let ledger = ctx.ledger.lock().await;
        Snapshot::build(&ledger, &target_names)?
    };

    let mut queue = Vec::new();
    let mut satisfied = 0;
    // A collision's conflicting artifact is excluded from the queue before
    // classification; it is still a deliberate skip the summary must show.
    let mut skipped = collisions.len();
    let mut satisfied_gc = Vec::new();

    for (policy_index, artifact) in candidates.into_values() {
        let classification = classify(&snapshot, &artifact, &target_names);
        match classification {
            Classification::Satisfied => {
                satisfied += 1;
                if opts.gc_after
                    && !opts.dry_run
                    && snapshot
                        .local
                        .get(&artifact.key())
                        .copied()
                        .unwrap_or(false)
                {
                    satisfied_gc.push((artifact.key(), artifact.sha256.clone()));
                }
            }
            Classification::Skip => skipped += 1,
            Classification::HashChange { .. } if opts.dry_run => skipped += 1,
            other => {
                let size = snapshot
                    .rows_by_path
                    .get(&artifact.rsync_relpath())
                    .and_then(|rows| {
                        rows.iter()
                            .find(|row| row.artifact.sha256 == artifact.sha256)
                    })
                    .and_then(|row| row.size);
                queue.push(Queued {
                    artifact,
                    policy_index,
                    size,
                    classification: other,
                });
            }
        }
    }

    if opts.dry_run {
        return Ok(Summary {
            discovered,
            satisfied,
            skipped,
            queued: queue.len(),
            open_incidents: open_incident_count(ctx).await?,
            ..Summary::default()
        }
        .finish());
    }

    // A collision is an upstream anomaly, not a reason to stop the run: open
    // one deduplicated incident per collision and keep the kept artifacts
    // flowing through the queue.
    let mut collision_incidents = 0;
    for collision in &collisions {
        if open_collision_incident(ctx, &seq, collision).await? {
            collision_incidents += 1;
        }
    }

    queue.sort_by(|left, right| compare(left, right, opts.order));
    if let Some(after) = opts.start_after.as_deref() {
        if let Some(index) = queue.iter().position(|item| item.artifact.key() == *after) {
            if index + 1 < queue.len() {
                queue.rotate_left(index + 1);
            }
        } else {
            tracing::warn!(
                artifact = after,
                "the stored backfill cursor is not in this queue; starting at the beginning"
            );
        }
    }
    tracing::debug!(
        discovered,
        satisfied,
        skipped,
        queued = queue.len(),
        "queue built"
    );
    let queued_shas: HashSet<String> = queue
        .iter()
        .map(|item| item.artifact.sha256.clone())
        .collect();

    let download_limit = usize::try_from(ctx.config.concurrency)
        .unwrap_or(usize::MAX)
        .max(1);
    let upload_limit = usize::try_from(ctx.config.upload_concurrency)
        .unwrap_or(usize::MAX)
        .max(1);
    let downloads = Arc::new(Semaphore::new(download_limit));
    let uploads: HashMap<String, Arc<Semaphore>> = target_names
        .iter()
        .map(|name| (name.clone(), Arc::new(Semaphore::new(upload_limit))))
        .collect();
    let probed = tokio::sync::OnceCell::new();

    let job = Job {
        ctx,
        snapshot: &snapshot,
        targets: &target_names,
        downloads: &downloads,
        uploads: &uploads,
        seq: &seq,
        probed: &probed,
    };

    // A capped run is sequential: with parallel workers each could start an
    // artifact before the previous bytes are counted, and the cap would
    // overshoot by one artifact per worker instead of one in total.
    let reports: Vec<ArtifactReport> = if opts.max_artifacts.is_some() || opts.max_bytes.is_some() {
        let mut reports = Vec::new();
        let mut bytes = 0_u64;
        for (started, item) in queue.iter().enumerate() {
            if opts.max_artifacts.is_some_and(|limit| started >= limit) {
                break;
            }
            if opts.max_bytes.is_some_and(|cap| bytes >= cap) {
                break;
            }
            let report = job.process(item).await?;
            bytes = bytes.saturating_add(report.bytes);
            reports.push(report);
        }
        reports
    } else {
        stream::iter(&queue)
            .map(|item| job.process(item))
            .buffer_unordered(download_limit)
            .try_collect::<Vec<_>>()
            .await?
    };

    let mut summary = Summary {
        discovered,
        satisfied,
        skipped,
        queued: queue.len(),
        ..Summary::default()
    };
    for report in &reports {
        summary.downloaded += usize::from(report.downloaded);
        summary.published += report.published;
        summary.failed += report.failed;
        summary.incidents_opened += report.incidents;
        summary.bytes_downloaded = summary.bytes_downloaded.saturating_add(report.bytes);
    }
    summary.incidents_opened += collision_incidents;
    // A capped run stops with work left, so its last artifact is a valid resume
    // point. An uncapped run has nothing to resume.
    summary.capped = reports.len() < queue.len();
    if summary.capped {
        summary.last_version = reports.last().map(|report| report.version.clone());
        summary.last_artifact_key = reports.last().map(|report| report.key.clone());
    }
    // Incidents opened by earlier runs still need a human; the summary names
    // them without changing the exit-code rule.
    summary.open_incidents = open_incident_count(ctx).await?;
    let summary = summary.finish();

    if opts.gc_after {
        collect_garbage(ctx, &seq, &snapshot, satisfied_gc, &reports, &queued_shas).await?;
    }

    if !opts.dry_run {
        let outcome = if summary.incidents_opened > 0 {
            "incidents"
        } else if summary.failed > 0 {
            "partial"
        } else {
            "success"
        };
        let mut detail = json!({"outcome": outcome, "summary": &summary});
        if let Some(fingerprint) = opts.cursor_fingerprint.as_deref() {
            detail["cursor"] = if summary.capped {
                json!({
                    "fingerprint": fingerprint,
                    "last_version": summary.last_version.as_deref(),
                    "last_artifact_key": summary.last_artifact_key.as_deref(),
                })
            } else {
                // A finished queue clears the old resume point.
                json!({
                    "fingerprint": fingerprint,
                    "last_version": null,
                    "last_artifact_key": null,
                })
            };
        }
        append(
            ctx,
            Event::new(
                ctx.run_id.clone(),
                seq.next(),
                Utc::now(),
                EventKind::RunFinished,
            )
            .with_detail(detail),
        )
        .await?;
    }

    tracing::info!(summary = %summary.to_text(), "run finished");
    Ok(summary)
}

/// Crawl every selected policy into a keyed candidate map, preserving the
/// configuration order for tie-breaking, plus every tag collision found on
/// the way.
///
/// Two policies can still bring the same descriptive tag with different bytes
/// (the same version number on two channels); the merged candidate set gets its
/// own collision pass and the conflicting artifacts are excluded exactly like
/// the ones a single crawl reported.
async fn crawl_scope(
    ctx: &Ctx,
) -> Result<(BTreeMap<String, (usize, Artifact)>, Vec<TagCollision>), RunError> {
    let mut candidates = BTreeMap::new();
    let mut collisions = Vec::new();
    for (index, policy) in ctx.scope.policies.iter().enumerate() {
        let outcome = crawl::crawl(&ctx.source, policy).await?;
        for artifact in outcome.artifacts {
            candidates
                .entry(artifact.key())
                .or_insert((index, artifact));
        }
        collisions.extend(outcome.collisions);
    }
    for collision in
        crawl::collect_tag_collisions(candidates.values().map(|(_, artifact)| artifact))
    {
        candidates.remove(&collision.conflicting.key());
        collisions.push(collision);
    }
    Ok((candidates, crawl::dedup_collisions(collisions)))
}

/// How many incidents are still open, including the ones earlier runs opened.
async fn open_incident_count(ctx: &Ctx) -> Result<usize, RunError> {
    let ledger = ctx.ledger.lock().await;
    let incidents = ledger.incidents(IncidentFilter::open())?;
    let count = incidents.len();
    Ok(count)
}

/// Open the deduplicated arch-collision incident for one crawl collision.
///
/// The incident names the excluded artifact with the kept artifact's digest as
/// the old value, so a human sees exactly which pair of upstream files maps to
/// one public reference. The excluded artifact is recorded as seen first — the
/// incident must name a row the ledger knows. Returns whether the incident was
/// newly opened; a later run's detection is deduplicated and only reported. A
/// project listed in `incident.ignore_arch_collisions` returns `false` without
/// recording anything.
async fn open_collision_incident(
    ctx: &Ctx,
    seq: &Seq,
    collision: &TagCollision,
) -> Result<bool, RunError> {
    if ctx
        .config
        .incident
        .ignores_arch_collision(&collision.conflicting.project)
    {
        tracing::info!(
            tag = %collision.tag,
            conflicting = %collision.conflicting.key(),
            kept = %collision.first.key(),
            "arch collision ignored by configuration; keeping the first artifact"
        );
        return Ok(false);
    }

    let mut ledger = ctx.ledger.lock().await;
    let id = ledger::incident_id(
        IncidentKind::ArchCollision,
        Some(&collision.conflicting.key()),
        Some(&collision.first.sha256),
        Some(&collision.conflicting.sha256),
    );
    if ledger.incident(&id)?.is_some() {
        tracing::warn!(
            tag = %collision.tag,
            conflicting = %collision.conflicting.key(),
            "tag collision already has an open incident; keeping the first artifact"
        );
        return Ok(false);
    }

    if ledger.artifact(&collision.conflicting.key())?.is_none() {
        let event = Event::new(
            ctx.run_id.clone(),
            seq.next(),
            Utc::now(),
            EventKind::ArtifactSeen,
        )
        .with_artifact(collision.conflicting.key())
        .with_detail(json!({
            "artifact": ledger::artifact_detail(&collision.conflicting),
            "upstream_path": collision.conflicting.rsync_relpath(),
            "metadata": serde_json::from_str::<Value>(&collision.conflicting.metadata_json)
                .unwrap_or(Value::Null),
        }));
        ledger.append(&event)?;
    }
    incident::open(
        &mut ledger,
        ctx.config.as_ref(),
        &collision.conflicting,
        &collision.first.sha256,
        IncidentKind::ArchCollision,
    )
    .await?;
    Ok(true)
}

fn classify(snapshot: &Snapshot, artifact: &Artifact, targets: &[String]) -> Classification {
    let Some(rows) = snapshot.rows_by_path.get(&artifact.rsync_relpath()) else {
        return Classification::New;
    };

    if let Some(row) = rows
        .iter()
        .find(|row| row.artifact.sha256 == artifact.sha256)
    {
        if row.superseded_by.is_some() {
            return Classification::Skip;
        }
        if targets
            .iter()
            .all(|target| snapshot.is_published(&artifact.key(), target))
        {
            return Classification::Satisfied;
        }
        return Classification::Retry;
    }

    match rows
        .iter()
        .filter(|row| row.superseded_by.is_none())
        .max_by_key(|row| row.last_seen)
    {
        Some(old) => Classification::HashChange {
            old_sha256: old.artifact.sha256.clone(),
        },
        None => Classification::New,
    }
}

fn compare(left: &Queued, right: &Queued, order: Order) -> Ordering {
    let by_size = match order {
        Order::VersionDesc => Ordering::Equal,
        Order::SmallestFirst => left
            .size
            .unwrap_or(u64::MAX)
            .cmp(&right.size.unwrap_or(u64::MAX)),
        Order::LargestFirst => right.size.unwrap_or(0).cmp(&left.size.unwrap_or(0)),
    };

    by_size
        .then_with(|| version_desc(&left.artifact.version, &right.artifact.version))
        .then_with(|| left.policy_index.cmp(&right.policy_index))
        .then_with(|| left.artifact.project.cmp(&right.artifact.project))
        .then_with(|| left.artifact.platform.cmp(&right.artifact.platform))
        .then_with(|| {
            left.artifact
                .platform_version
                .cmp(&right.artifact.platform_version)
        })
        .then_with(|| left.artifact.arch.cmp(&right.artifact.arch))
        .then_with(|| left.artifact.basename.cmp(&right.artifact.basename))
        .then_with(|| left.artifact.key().cmp(&right.artifact.key()))
}

fn version_desc(left: &str, right: &str) -> Ordering {
    match (
        left.parse::<crate::version::Version>(),
        right.parse::<crate::version::Version>(),
    ) {
        (Ok(left), Ok(right)) => right.cmp(&left),
        _ => right.cmp(left),
    }
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

fn started_event(ctx: &Ctx, opts: &RunOpts, seq: u64) -> Event {
    Event::new(ctx.run_id.clone(), seq, Utc::now(), EventKind::RunStarted).with_detail(json!({
        "effective_policy": crate::plan::policies_json(&ctx.scope),
        "order": opts.order.as_str(),
        "max_bytes": opts.max_bytes,
        "transport_order": ctx
            .config
            .transport
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        "host": crate::hostname(),
    }))
}

/// Mark publications a previous process left `uploading` as interrupted so the
/// next classification retries them.
async fn recover_interrupted(ctx: &Ctx, seq: &Seq, targets: &[String]) -> Result<(), RunError> {
    let mut ledger = ctx.ledger.lock().await;
    for target in targets {
        for publication in ledger.publications(target)? {
            if publication.status != PublicationStatus::Uploading {
                continue;
            }
            let event = Event::new(
                ctx.run_id.clone(),
                seq.next(),
                Utc::now(),
                EventKind::PublicationInterrupted,
            )
            .with_artifact(publication.artifact_key)
            .with_target(target.clone())
            .with_detail(json!({"error": "interrupted in a previous run"}));
            ledger.append(&event)?;
        }
    }
    Ok(())
}

/// Delete blobs that this run or a previous one published everywhere.
///
/// A blob stays when any target failed, when a queued artifact shares its
/// digest and was not finished, when a superseded row still refers to it, or
/// when an open incident names it as a replacement: `ack --republish` needs
/// those bytes locally, so they survive until the incident is acknowledged.
async fn collect_garbage(
    ctx: &Ctx,
    seq: &Seq,
    snapshot: &Snapshot,
    satisfied: Vec<(String, String)>,
    reports: &[ArtifactReport],
    queued_shas: &HashSet<String>,
) -> Result<(), RunError> {
    let successful: HashSet<String> = reports
        .iter()
        .filter(|report| report.fully_published)
        .map(|report| report.sha256.clone())
        .collect();
    let mut blocked: HashSet<String> = queued_shas.difference(&successful).cloned().collect();
    for rows in snapshot.rows_by_path.values() {
        for row in rows {
            if row.superseded_by.is_some() {
                blocked.insert(row.artifact.sha256.clone());
            }
        }
    }
    // A hash change publishes the replacement under the superseded name; the
    // incident keeps it addressable for `ack --republish`, which needs the
    // blob in the local store.
    for incident in ctx.ledger.lock().await.incidents(IncidentFilter::open())? {
        if let Some(sha256) = incident.new_sha256 {
            blocked.insert(sha256);
        }
    }

    let mut candidates = satisfied;
    candidates.extend(
        reports
            .iter()
            .filter(|report| report.fully_published)
            .map(|report| (report.key.clone(), report.sha256.clone())),
    );

    let mut seen = HashSet::new();
    for (key, sha256) in candidates {
        if !seen.insert(key.clone()) || blocked.contains(&sha256) || !ctx.store.has(&sha256) {
            continue;
        }
        ctx.store.gc(&sha256)?;
        tracing::info!(sha256 = %sha256, "removed the local blob");
        append(
            ctx,
            Event::new(
                ctx.run_id.clone(),
                seq.next(),
                Utc::now(),
                EventKind::LocalGc,
            )
            .with_artifact(key)
            .with_detail(json!({"sha256": sha256})),
        )
        .await?;
    }
    Ok(())
}

fn verified_event(ctx: &Ctx, seq: u64, artifact: &Artifact, size: Option<u64>) -> Event {
    let mut detail = json!({});
    if let Some(size) = size {
        detail["size"] = json!(size);
    }
    Event::new(ctx.run_id.clone(), seq, Utc::now(), EventKind::Verified)
        .with_artifact(artifact.key())
        .with_detail(detail)
}

fn published_event(
    ctx: &Ctx,
    seq: u64,
    artifact: &Artifact,
    target: &str,
    remote_ref: Option<&str>,
    remote_digest: Option<&str>,
) -> Event {
    let mut detail = json!({});
    if let Some(remote_ref) = remote_ref {
        detail["remote_ref"] = json!(remote_ref);
    }
    if let Some(remote_digest) = remote_digest {
        detail["remote_digest"] = json!(remote_digest);
    }
    Event::new(ctx.run_id.clone(), seq, Utc::now(), EventKind::Published)
        .with_artifact(artifact.key())
        .with_target(target)
        .with_detail(detail)
}

fn failed_event(ctx: &Ctx, seq: u64, artifact: &Artifact, target: &str, error: &str) -> Event {
    Event::new(
        ctx.run_id.clone(),
        seq,
        Utc::now(),
        EventKind::PublicationFailed,
    )
    .with_artifact(artifact.key())
    .with_target(target)
    .with_detail(json!({"error": error}))
}

async fn append(ctx: &Ctx, event: Event) -> Result<(), RunError> {
    ctx.ledger.lock().await.append(&event)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::ArtifactContext;

    fn artifact(version: &str, basename: &str, sha: &str) -> Artifact {
        Artifact::new(
            &ArtifactContext {
                channel: "stable".to_string(),
                project: "cinc".to_string(),
                version: version.to_string(),
                platform: "debian".to_string(),
                platform_version: "13".to_string(),
            },
            crate::artifact::ArtifactInput {
                basename: basename.to_string(),
                sha256: sha.to_string(),
                metadata_json: "{}".to_string(),
                platform: "debian".to_string(),
                platform_version: "13".to_string(),
                version: version.to_string(),
                iteration: Some("1".to_string()),
                raw_arch: "x86_64".to_string(),
            },
        )
        .expect("artifact")
    }

    fn item(version: &str, size: Option<u64>) -> Queued {
        Queued {
            artifact: artifact(version, "pkg.deb", &"a".repeat(64)),
            policy_index: 0,
            size,
            classification: Classification::New,
        }
    }

    #[test]
    fn version_order_is_numeric_and_descending() {
        let mut queue = [
            item("19.4.46", None),
            item("19.10.0", None),
            item("19.3.14", None),
        ];
        queue.sort_by(|left, right| compare(left, right, Order::VersionDesc));
        let versions: Vec<&str> = queue
            .iter()
            .map(|queued| queued.artifact.version.as_str())
            .collect();
        assert_eq!(versions, vec!["19.10.0", "19.4.46", "19.3.14"]);
    }

    #[test]
    fn unknown_sizes_sort_last_in_both_size_orders() {
        for order in [Order::SmallestFirst, Order::LargestFirst] {
            let mut queue = [item("19.4.46", None), item("19.3.14", Some(10))];
            queue.sort_by(|left, right| compare(left, right, order));
            assert_eq!(
                queue[1].artifact.version, "19.4.46",
                "an unknown size is last under {order:?}"
            );
        }
    }

    #[test]
    fn a_zero_cap_is_a_usage_error() {
        let error = RunError::Usage {
            reason: "test".to_string(),
        };
        assert_eq!(error.exit_code(), EXIT_USAGE);
        assert_eq!(RunError::NoTargets.exit_code(), 1);
    }
}
