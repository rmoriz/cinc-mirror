//! Append-only ledger: events are the truth, SQLite is the projection.
//!
//! Every observation, download, publication and incident is recorded as an
//! [`Event`] in the `events` table. `artifacts`, `publications`, `incidents`,
//! `runs` and `cursors` are derived from that log and can be thrown away: call
//! [`Ledger::materialize`] to truncate them and replay the events in
//! `id` (append) order.
//!
//! The database lives at `<state>/ledger.db` in WAL mode. [`Ledger::open`]
//! creates the directory, the database and the schema, and running it again
//! simply applies the migrations that are still missing.
//!
//! # Idempotency
//!
//! `(run_id, seq)` is the event's idempotency key and is `UNIQUE`. Appending
//! the same event twice inserts one row and reduces it once. [`Ledger::apply`]
//! additionally re-runs the reducer so it can repair a projection that was
//! rebuilt or truncated; every reducer is written so the same event produces
//! the same row, including the attempt counter (which counts attempt events
//! rather than incrementing a stored value).
//!
//! # Event detail
//!
//! The typed columns are the identity; `detail` is JSON whose shape depends on
//! the kind:
//!
//! - `artifact_seen`, `imported`: `artifact` (the artifact fields, including
//!   the exact upstream `metadata_json` text and the raw architecture), and
//!   optionally `size`, `upstream_path`, `metadata`.
//! - `verified`: `size` when the download learned it.
//! - `published`: `remote_ref` and `remote_digest` when the target reports them.
//! - `publication_failed`, `publication_interrupted` and
//!   `publication_unrecoverable`: `error`, and optionally `next_attempt_at` as
//!   RFC3339. `publication_unrecoverable` is terminal: the blob is gone locally
//!   and upstream no longer serves it, so the row is not retried.
//! - `hash_changed`: `old_sha256` (required), `new_sha256` (defaults to the new
//!   artifact's digest), optional `old_key` (otherwise derived from the new key)
//!   and the complete replacement under `artifact`, including its
//!   `metadata_json`.
//! - `incident_opened`: `id`, `kind`, optional `artifact_key`,
//!   `old_sha256`, `new_sha256`, `issue_url`, and a nested `detail`.
//! - `incident_acked`: `id`, optional `note` and `issue_url`.
//! - `run_started`: `effective_policy`, `order`, `max_bytes`,
//!   `transport_order`, `host`, `leased`.
//! - `run_finished`: `outcome`, `summary`, optional `leased`, and an optional
//!   `cursor` object (`fingerprint`, `last_version`, `last_artifact_key`).
//! - `plan_recorded`: as `run_started`, plus `summary`; the plan appears as a
//!   run whose outcome is `planned`.
//!
//! `download_started` and `lease_taken_over` are audit events only.
//! `publication_started` marks a target's publication as `uploading`; an
//! `publication_interrupted` event makes the row pending again.
//!
//! # Local presence
//!
//! `artifacts.local` is 1 after `verified` and 0 after `local_gc`. A publication
//! therefore keeps its `published` status when the local blob is deleted;
//! verification uses the flag to skip a deliberate local removal.
//!
//! # Durable files
//!
//! [`files::LedgerStore`] keeps the event log as NDJSON in a git worktree and
//! [`git::Lease`] guards a run with an advisory lease on its own ref. The
//! database can be thrown away at any time; [`files::LedgerStore::load_all`]
//! rebuilds it from the branch.

pub mod files;
pub mod git;

pub use files::{LedgerFilesError, LedgerStore, RUNS_DIR};
pub use git::{Lease, LeaseError, LeaseHolder, LedgerGitError, LEASE_REF};

use std::collections::{HashMap, HashSet};
use std::fmt;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;

use chrono::{DateTime, SecondsFormat, Utc};
use rusqlite::{params, Connection, OptionalExtension, Row};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::artifact::Artifact;
use crate::fsutil;
use crate::version::Version;

/// File name of the SQLite database below the state directory.
const DB_FILE: &str = "ledger.db";

/// Ordered migrations; index `n` is schema version `n + 1`.
///
/// Append new files here instead of editing a released migration. The schema
/// itself uses `IF NOT EXISTS`, so a migration that is interrupted between
/// `execute_batch` and the version insert is safe to run again.
const MIGRATIONS: &[&str] = &[
    include_str!("schema.sql"),
    include_str!("schema_v2.sql"),
    include_str!("schema_v3.sql"),
];

const ARTIFACT_COLUMNS: &str = "a.key, a.upstream_path, a.sha256, a.size, a.basename, \
     a.project, a.channel, a.version, a.iteration, a.platform, a.platform_version, \
     a.arch, a.metadata_json, a.first_seen, a.last_seen, a.superseded_by, \
     a.supersedes, a.local, a.raw_arch, a.tag_override";

const PUBLICATION_COLUMNS: &str = "artifact_key, target, status, remote_ref, remote_digest, \
     attempts, next_attempt_at, last_error, updated_at";

const INCIDENT_COLUMNS: &str = "id, artifact_key, kind, old_sha256, new_sha256, \
     detected_at, detail_json, state, issue_url, ack_note";

const RUN_COLUMNS: &str = "run_id, effective_policy, \"order\", max_bytes, transport_order, \
     host, started_at, finished_at, outcome, summary_json, leased";

const CURSOR_COLUMNS: &str = "fingerprint, last_version, last_artifact_key, updated_at";

/// One event kind, serialised as a stable snake_case string.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    /// A run acquired the ledger and began.
    RunStarted,
    /// A run ended, successfully or not.
    RunFinished,
    /// Upstream metadata described an artifact.
    ArtifactSeen,
    /// A payload download started.
    DownloadStarted,
    /// A payload matched its expected hashes and entered the store.
    Verified,
    /// A publication attempt started.
    PublicationStarted,
    /// A target accepted a publication.
    Published,
    /// A publication attempt failed and may be retried.
    PublicationFailed,
    /// A publication was interrupted; the next run retries it.
    PublicationInterrupted,
    /// An acknowledged superseded publication is retired.
    PublicationSuperseded,
    /// A publication this mirror cannot restore: the local blob is gone and
    /// upstream no longer serves it.
    PublicationUnrecoverable,
    /// The bytes behind a published artifact changed upstream.
    HashChanged,
    /// An incident was opened.
    IncidentOpened,
    /// An incident was acknowledged.
    IncidentAcked,
    /// An artifact that predates the ledger was imported from a target.
    Imported,
    /// A verified local blob was deleted after publishing.
    LocalGc,
    /// A stale lease was taken over.
    LeaseTakenOver,
    /// A plan was recorded.
    PlanRecorded,
}

impl EventKind {
    /// The stable wire and database spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::RunStarted => "run_started",
            Self::RunFinished => "run_finished",
            Self::ArtifactSeen => "artifact_seen",
            Self::DownloadStarted => "download_started",
            Self::Verified => "verified",
            Self::PublicationStarted => "publication_started",
            Self::Published => "published",
            Self::PublicationFailed => "publication_failed",
            Self::PublicationInterrupted => "publication_interrupted",
            Self::PublicationSuperseded => "publication_superseded",
            Self::PublicationUnrecoverable => "publication_unrecoverable",
            Self::HashChanged => "hash_changed",
            Self::IncidentOpened => "incident_opened",
            Self::IncidentAcked => "incident_acked",
            Self::Imported => "imported",
            Self::LocalGc => "local_gc",
            Self::LeaseTakenOver => "lease_taken_over",
            Self::PlanRecorded => "plan_recorded",
        }
    }
}

impl fmt::Display for EventKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for EventKind {
    type Err = LedgerError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value {
            "run_started" => Self::RunStarted,
            "run_finished" => Self::RunFinished,
            "artifact_seen" => Self::ArtifactSeen,
            "download_started" => Self::DownloadStarted,
            "verified" => Self::Verified,
            "publication_started" => Self::PublicationStarted,
            "published" => Self::Published,
            "publication_failed" => Self::PublicationFailed,
            "publication_interrupted" => Self::PublicationInterrupted,
            "publication_superseded" => Self::PublicationSuperseded,
            "publication_unrecoverable" => Self::PublicationUnrecoverable,
            "hash_changed" => Self::HashChanged,
            "incident_opened" => Self::IncidentOpened,
            "incident_acked" => Self::IncidentAcked,
            "imported" => Self::Imported,
            "local_gc" => Self::LocalGc,
            "lease_taken_over" => Self::LeaseTakenOver,
            "plan_recorded" => Self::PlanRecorded,
            other => {
                return Err(LedgerError::EventKind {
                    value: other.to_string(),
                })
            }
        })
    }
}

/// How far a publication to one target has progressed.
///
/// The database stores the snake_case string; the known set is enforced here in
/// Rust rather than with a SQL `CHECK`, so adding a state stays a code change.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PublicationStatus {
    /// Queued for publication.
    Pending,
    /// An upload is in flight.
    Uploading,
    /// A failed upload was scheduled for another attempt.
    Retry,
    /// The last attempt failed.
    Failed,
    /// The process disappeared mid-upload.
    Interrupted,
    /// Every target has the bytes.
    Published,
    /// The publication was retired after an acknowledged hash change.
    Superseded,
    /// The publication cannot be restored: the local blob is gone and upstream
    /// no longer serves the bytes. An incident records it for a human.
    Unrecoverable,
}

impl PublicationStatus {
    /// The stable wire and database spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Uploading => "uploading",
            Self::Retry => "retry",
            Self::Failed => "failed",
            Self::Interrupted => "interrupted",
            Self::Published => "published",
            Self::Superseded => "superseded",
            Self::Unrecoverable => "unrecoverable",
        }
    }
}

impl fmt::Display for PublicationStatus {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for PublicationStatus {
    type Err = LedgerError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value {
            "pending" => Self::Pending,
            "uploading" => Self::Uploading,
            "retry" => Self::Retry,
            "failed" => Self::Failed,
            "interrupted" => Self::Interrupted,
            "published" => Self::Published,
            "superseded" => Self::Superseded,
            "unrecoverable" => Self::Unrecoverable,
            other => {
                return Err(LedgerError::PublicationStatus {
                    value: other.to_string(),
                })
            }
        })
    }
}

/// The kinds of incident the ledger can hold.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentKind {
    /// Upstream bytes changed for an artifact that was already published.
    HashChanged,
    /// Two artifacts claim the same tag or path with different bytes.
    TagConflict,
    /// The upstream artifact or a local blob is unrecoverable.
    Unrecoverable,
    /// Two upstream architectures map to one public architecture.
    ArchCollision,
}

impl IncidentKind {
    /// The stable wire and database spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::HashChanged => "hash_changed",
            Self::TagConflict => "tag_conflict",
            Self::Unrecoverable => "unrecoverable",
            Self::ArchCollision => "arch_collision",
        }
    }
}

impl fmt::Display for IncidentKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for IncidentKind {
    type Err = LedgerError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value {
            "hash_changed" => Self::HashChanged,
            "tag_conflict" => Self::TagConflict,
            "unrecoverable" => Self::Unrecoverable,
            "arch_collision" => Self::ArchCollision,
            other => {
                return Err(LedgerError::IncidentKind {
                    value: other.to_string(),
                })
            }
        })
    }
}

/// Whether an incident still needs a human decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncidentState {
    /// Needs a decision.
    Open,
    /// Reviewed and acknowledged.
    Acked,
}

impl IncidentState {
    /// The stable wire and database spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Acked => "acked",
        }
    }
}

impl fmt::Display for IncidentState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl FromStr for IncidentState {
    type Err = LedgerError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        Ok(match value {
            "open" => Self::Open,
            "acked" => Self::Acked,
            other => {
                return Err(LedgerError::IncidentState {
                    value: other.to_string(),
                })
            }
        })
    }
}

/// One append-only ledger record.
///
/// `(run_id, seq)` is the idempotency key. `artifact_key` and `target` are the
/// rows the event touches; `detail` carries the kind-specific values described
/// in the module documentation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Event {
    /// Identifier of the run that produced the event.
    pub run_id: String,
    /// Position within the run, starting at 1.
    pub seq: u64,
    /// When the event happened, UTC.
    #[serde(with = "millis")]
    pub ts: DateTime<Utc>,
    /// What happened.
    pub kind: EventKind,
    /// The artifact the event is about, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact_key: Option<String>,
    /// The target the event is about, when there is one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Kind-specific payload.
    #[serde(default)]
    pub detail: Value,
}

impl Event {
    /// A bare event without an artifact, target or detail.
    #[must_use]
    pub fn new(run_id: impl Into<String>, seq: u64, ts: DateTime<Utc>, kind: EventKind) -> Self {
        Self {
            run_id: run_id.into(),
            seq,
            ts,
            kind,
            artifact_key: None,
            target: None,
            detail: Value::Null,
        }
    }

    /// Attach the artifact key.
    #[must_use]
    pub fn with_artifact(mut self, key: impl Into<String>) -> Self {
        self.artifact_key = Some(key.into());
        self
    }

    /// Attach the target name.
    #[must_use]
    pub fn with_target(mut self, target: impl Into<String>) -> Self {
        self.target = Some(target.into());
        self
    }

    /// Attach the kind-specific detail.
    #[must_use]
    pub fn with_detail(mut self, detail: Value) -> Self {
        self.detail = detail;
        self
    }
}

/// A materialised artifact row: the identity plus what the ledger learned.
#[derive(Debug, Clone, PartialEq)]
pub struct ArtifactRow {
    /// The canonical artifact.
    ///
    /// A ledger round trip restores every identity field, including the exact
    /// upstream metadata text and the raw architecture spelling, so a
    /// reconstructed artifact publishes byte-identical layers.
    pub artifact: Artifact,
    /// Upstream-shaped path the artifact occupies, independent of its digest.
    pub upstream_path: String,
    /// Size in bytes, when a listing, `HEAD` or verification supplied it.
    pub size: Option<u64>,
    /// Upstream metadata as recorded, or `Null`.
    pub metadata: Value,
    /// When the ledger first saw this key.
    pub first_seen: DateTime<Utc>,
    /// When the ledger last saw it.
    pub last_seen: DateTime<Utc>,
    /// The replacement key after a hash change.
    pub superseded_by: Option<String>,
    /// The key this row replaced after a hash change.
    pub supersedes: Option<String>,
    /// Whether the verified blob is still in the local store.
    pub local: bool,
}

/// A materialised publication row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publication {
    /// The artifact being published.
    pub artifact_key: String,
    /// The target name.
    pub target: String,
    /// Progress of this publication.
    pub status: PublicationStatus,
    /// Target-specific reference, e.g. an OCI tag or an rsync path.
    pub remote_ref: Option<String>,
    /// Digest reported by the target, when it reports one.
    pub remote_digest: Option<String>,
    /// Number of recorded publication attempts.
    pub attempts: u64,
    /// Earliest time the next retry may start.
    pub next_attempt_at: Option<DateTime<Utc>>,
    /// Error from the last failed or interrupted attempt.
    pub last_error: Option<String>,
    /// When the row last changed.
    pub updated_at: DateTime<Utc>,
}

/// A materialised incident row.
#[derive(Debug, Clone, PartialEq)]
pub struct Incident {
    /// Stable incident identifier.
    pub id: String,
    /// The artifact the incident concerns, when it concerns one.
    pub artifact_key: Option<String>,
    /// What kind of incident this is.
    pub kind: IncidentKind,
    /// The digest that was published.
    pub old_sha256: Option<String>,
    /// The digest that replaced it.
    pub new_sha256: Option<String>,
    /// When the incident was detected.
    pub detected_at: DateTime<Utc>,
    /// Kind-specific detail.
    pub detail: Value,
    /// Whether the incident still needs a decision.
    pub state: IncidentState,
    /// GitHub issue created for the incident, when one was.
    pub issue_url: Option<String>,
    /// The note written when the incident was acknowledged.
    pub ack_note: Option<String>,
}

/// Which incidents [`Ledger::incidents`] returns.
#[derive(Debug, Clone, Default)]
pub struct IncidentFilter {
    /// Restrict to one state.
    pub state: Option<IncidentState>,
    /// Restrict to one kind.
    pub kind: Option<IncidentKind>,
    /// Restrict to one artifact key.
    pub artifact_key: Option<String>,
}

impl IncidentFilter {
    /// Only incidents that still need a decision.
    #[must_use]
    pub fn open() -> Self {
        Self {
            state: Some(IncidentState::Open),
            ..Self::default()
        }
    }
}

/// A materialised run row.
#[derive(Debug, Clone, PartialEq)]
pub struct Run {
    /// The run identifier.
    pub run_id: String,
    /// The resolved policy JSON the run executed.
    pub effective_policy: Value,
    /// The queue order, e.g. `version_desc`.
    pub order: Option<String>,
    /// The byte cap, when one was set.
    pub max_bytes: Option<u64>,
    /// The transports in the order they were tried.
    pub transport_order: Vec<String>,
    /// Host that ran it.
    pub host: String,
    /// When the run started.
    pub started_at: DateTime<Utc>,
    /// When it finished; `None` while it is running.
    pub finished_at: Option<DateTime<Utc>>,
    /// Outcome label, e.g. `success`, `partial` or `planned`.
    pub outcome: Option<String>,
    /// The run's summary JSON.
    pub summary: Value,
    /// Whether the run held the ledger lease.
    pub leased: bool,
}

/// A resume cursor for a capped backfill policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor {
    /// Deterministic fingerprint of the policy the cursor belongs to.
    pub fingerprint: String,
    /// Last version that was completed.
    pub last_version: Option<String>,
    /// Last artifact key that was completed, for deterministic resumption.
    pub last_artifact_key: Option<String>,
    /// When the cursor was written.
    pub updated_at: DateTime<Utc>,
}

/// The ledger database.
#[derive(Debug)]
pub struct Ledger {
    conn: Connection,
}

impl Ledger {
    /// Open (or create) `<state_dir>/ledger.db`.
    ///
    /// The directory is created when missing, the database is put into WAL
    /// mode with foreign keys enabled, and every migration that is not yet
    /// applied is run. Opening the same directory again is safe.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError::Io`] when the state directory cannot be created,
    /// [`LedgerError::Sqlite`] when the database cannot be opened or migrated.
    pub fn open(state_dir: &Path) -> Result<Self, LedgerError> {
        let root = fsutil::expand_tilde(state_dir);
        fs::create_dir_all(&root).map_err(|source| LedgerError::Io {
            path: root.clone(),
            source,
        })?;

        let mut conn = Connection::open(root.join(DB_FILE))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA foreign_keys = ON;",
        )?;
        migrate(&mut conn)?;
        Ok(Self { conn })
    }

    /// Append an event and update the derived rows.
    ///
    /// An event whose `(run_id, seq)` is already present is ignored entirely,
    /// including the reducer, so a retried append cannot double-count an
    /// attempt or open a second incident.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the insert or the reducer fails. The insert
    /// and the reducer share one transaction, so a failed reducer leaves no
    /// event behind.
    pub fn append(&mut self, event: &Event) -> Result<(), LedgerError> {
        let tx = self.conn.transaction()?;
        if insert_event(&tx, event)? == 1 {
            reduce(&tx, event)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Apply an event to the derived rows, inserting it when it is missing.
    ///
    /// Unlike [`Ledger::append`] this always runs the reducer, which makes it
    /// the entry point for replaying an event whose derived rows were lost.
    /// Every reducer is idempotent: applying one event twice produces the same
    /// rows (attempt counters are counted from `events`, incidents are unique).
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the event cannot be inserted or reduced.
    pub fn apply(&mut self, event: &Event) -> Result<(), LedgerError> {
        let tx = self.conn.transaction()?;
        insert_event(&tx, event)?;
        reduce(&tx, event)?;
        tx.commit()?;
        Ok(())
    }

    /// Rebuild every derived table from the event log.
    ///
    /// `artifacts`, `publications`, `incidents`, `runs` and `cursors` are
    /// truncated and replayed in insertion (`id`) order. The `events` table
    /// is never modified.
    ///
    /// Replaying in `id` order is deliberate: rows are only ever appended, so
    /// `id` order is exactly the order the live projection was built in. Event
    /// timestamps come from different hosts and can be skewed; replaying by
    /// `ts` could apply a `verified` before its `artifact_seen` (silently
    /// losing `local = 1`) or a `hash_changed` before the artifact it
    /// supersedes (failing the whole rebuild).
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the truncation or a replay step fails; the
    /// whole rebuild is one transaction, so a failure leaves the previous
    /// projection in place.
    pub fn materialize(&mut self) -> Result<(), LedgerError> {
        let tx = self.conn.transaction()?;
        tx.execute_batch(
            "DELETE FROM publications;
             DELETE FROM incidents;
             DELETE FROM artifacts;
             DELETE FROM runs;
             DELETE FROM cursors;",
        )?;

        let events = {
            let mut statement = tx.prepare(
                "SELECT run_id, seq, ts, kind, artifact_key, target, detail_json
                 FROM events ORDER BY id",
            )?;
            let rows = statement.query_map([], event_from_row)?;
            rows.collect::<rusqlite::Result<Vec<_>>>()?
        };
        for event in &events {
            reduce(&tx, event)?;
        }

        tx.commit()?;
        Ok(())
    }

    /// Artifacts that still need publishing to `target`.
    ///
    /// An artifact is pending when it has no publication row for the target, or
    /// when its row is `pending`, `retry`, `failed` or `interrupted` and its
    /// backoff has expired. Artifacts superseded by a hash change and
    /// publications marked `superseded` are excluded. The result is ordered by
    /// version descending (numerically, so `19.10` sorts above `19.4`), then by
    /// project, platform, platform version, architecture and basename.
    ///
    /// The returned `Artifact::raw_arch` repeats the public architecture; see
    /// [`ArtifactRow`].
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn pending(&self, target: &str) -> Result<Vec<Artifact>, LedgerError> {
        let sql = format!(
            "SELECT {ARTIFACT_COLUMNS}
             FROM artifacts a
             LEFT JOIN publications p
                    ON p.artifact_key = a.key AND p.target = ?1
             WHERE a.superseded_by IS NULL
               AND (p.artifact_key IS NULL
                    OR p.status IN ('pending', 'retry', 'failed', 'interrupted'))
               AND (p.artifact_key IS NULL
                    OR p.next_attempt_at IS NULL
                    OR p.next_attempt_at <= ?2)"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows =
            statement.query_map(params![target, ts_text(Utc::now())], artifact_row_from_row)?;
        let mut artifacts = Vec::new();
        for row in rows {
            artifacts.push(row?.artifact);
        }
        artifacts.sort_by(compare_pending);
        Ok(artifacts)
    }

    /// Every artifact, ordered by key.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn artifacts(&self) -> Result<Vec<ArtifactRow>, LedgerError> {
        let sql = format!("SELECT {ARTIFACT_COLUMNS} FROM artifacts a ORDER BY a.key");
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map([], artifact_row_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(LedgerError::from)
    }

    /// One artifact row, if it is known.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn artifact(&self, key: &str) -> Result<Option<ArtifactRow>, LedgerError> {
        let sql = format!("SELECT {ARTIFACT_COLUMNS} FROM artifacts a WHERE a.key = ?1");
        let mut statement = self.conn.prepare(&sql)?;
        statement
            .query_row(params![key], artifact_row_from_row)
            .optional()
            .map_err(LedgerError::from)
    }

    /// The digest-qualified tag of every artifact that has one, by key.
    ///
    /// A qualified tag is a publication reference the mirror already used; a
    /// crawl keeps it instead of reintroducing the descriptive tag it was moved
    /// away from.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn tag_overrides(&self) -> Result<HashMap<String, String>, LedgerError> {
        let mut statement = self
            .conn
            .prepare("SELECT key, tag_override FROM artifacts WHERE tag_override IS NOT NULL")?;
        let rows = statement.query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        rows.collect::<rusqlite::Result<HashMap<_, _>>>()
            .map_err(LedgerError::from)
    }

    /// Every artifact row, including rows superseded by a hash change, ordered
    /// by key.
    ///
    /// Verification and repair work from the complete ledger, not from the
    /// policies of the current run: an artifact that today's policy no longer
    /// selects is still part of the mirror. [`Ledger::artifacts`] is the same
    /// list with the materialised columns; use it when the local-presence flag
    /// matters.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn all_artifacts(&self) -> Result<Vec<Artifact>, LedgerError> {
        self.artifacts()
            .map(|rows| rows.into_iter().map(|row| row.artifact).collect())
    }

    /// Every publication row for one artifact, ordered by target.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn publications_for(&self, artifact_key: &str) -> Result<Vec<Publication>, LedgerError> {
        let sql = format!(
            "SELECT {PUBLICATION_COLUMNS} FROM publications WHERE artifact_key = ?1 \
             ORDER BY target"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params![artifact_key], publication_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(LedgerError::from)
    }

    /// Every publication row for `target`, ordered by artifact key.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn publications(&self, target: &str) -> Result<Vec<Publication>, LedgerError> {
        let sql = format!(
            "SELECT {PUBLICATION_COLUMNS} FROM publications WHERE target = ?1 \
             ORDER BY artifact_key"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(params![target], publication_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(LedgerError::from)
    }

    /// One publication row, if it exists.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn publication(
        &self,
        artifact_key: &str,
        target: &str,
    ) -> Result<Option<Publication>, LedgerError> {
        let sql = format!(
            "SELECT {PUBLICATION_COLUMNS} FROM publications \
             WHERE artifact_key = ?1 AND target = ?2"
        );
        let mut statement = self.conn.prepare(&sql)?;
        statement
            .query_row(params![artifact_key, target], publication_from_row)
            .optional()
            .map_err(LedgerError::from)
    }

    /// Incident rows matching `filter`, newest first.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn incidents(&self, filter: IncidentFilter) -> Result<Vec<Incident>, LedgerError> {
        let sql = format!(
            "SELECT {INCIDENT_COLUMNS} FROM incidents
             WHERE (?1 IS NULL OR state = ?1)
               AND (?2 IS NULL OR kind = ?2)
               AND (?3 IS NULL OR artifact_key = ?3)
             ORDER BY detected_at DESC, id ASC"
        );
        let mut statement = self.conn.prepare(&sql)?;
        let rows = statement.query_map(
            params![
                filter.state.map(IncidentState::as_str),
                filter.kind.map(IncidentKind::as_str),
                filter.artifact_key.as_deref(),
            ],
            incident_from_row,
        )?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(LedgerError::from)
    }

    /// One incident row, if it is known.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn incident(&self, id: &str) -> Result<Option<Incident>, LedgerError> {
        let sql = format!("SELECT {INCIDENT_COLUMNS} FROM incidents WHERE id = ?1");
        let mut statement = self.conn.prepare(&sql)?;
        statement
            .query_row(params![id], incident_from_row)
            .optional()
            .map_err(LedgerError::from)
    }

    /// One run row, if it is known.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn run(&self, run_id: &str) -> Result<Option<Run>, LedgerError> {
        let sql = format!("SELECT {RUN_COLUMNS} FROM runs WHERE run_id = ?1");
        let mut statement = self.conn.prepare(&sql)?;
        statement
            .query_row(params![run_id], run_from_row)
            .optional()
            .map_err(LedgerError::from)
    }

    /// One resume cursor, if it is known.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn cursor(&self, fingerprint: &str) -> Result<Option<Cursor>, LedgerError> {
        let sql = format!("SELECT {CURSOR_COLUMNS} FROM cursors WHERE fingerprint = ?1");
        let mut statement = self.conn.prepare(&sql)?;
        statement
            .query_row(params![fingerprint], cursor_from_row)
            .optional()
            .map_err(LedgerError::from)
    }

    /// Write the resume cursor for `fingerprint` into the derived table.
    ///
    /// A backfill records its cursor through the `cursor` object of its
    /// `run_finished` event, so the row is rebuildable by
    /// [`Ledger::materialize`]. This is the same upsert for callers that need to
    /// repair the projection without replaying the log; `None` values clear the
    /// stored position.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the upsert fails.
    pub fn set_cursor(
        &mut self,
        fingerprint: &str,
        last_version: Option<&str>,
        last_artifact_key: Option<&str>,
    ) -> Result<(), LedgerError> {
        upsert_cursor(
            &self.conn,
            fingerprint,
            last_version,
            last_artifact_key,
            &ts_text(Utc::now()),
        )
    }

    /// Canonical keys whose publication to `target` is `published`.
    ///
    /// The caller intersects the sets of every enabled target to decide whether
    /// an artifact is fully satisfied.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn satisfied_keys(&self, target: &str) -> Result<HashSet<String>, LedgerError> {
        let mut statement = self.conn.prepare(
            "SELECT artifact_key FROM publications
             WHERE target = ?1 AND status = 'published'",
        )?;
        let rows = statement.query_map(params![target], |row| row.get::<_, String>(0))?;
        rows.collect::<rusqlite::Result<HashSet<_>>>()
            .map_err(LedgerError::from)
    }

    /// Every applied event in append order.
    ///
    /// The order is the insertion order of the `events` table, which is the
    /// order the projection was built in. Compaction writes snapshots in this
    /// order and export prints them in it.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn events(&self) -> Result<Vec<Event>, LedgerError> {
        let mut statement = self.conn.prepare(
            "SELECT run_id, seq, ts, kind, artifact_key, target, detail_json
             FROM events ORDER BY id",
        )?;
        let rows = statement.query_map([], event_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(LedgerError::from)
    }

    /// Every event one run appended, in sequence order.
    ///
    /// This is what the command layer writes to `runs/<run_id>.ndjson` after a
    /// run finishes. The order is `seq`, not insertion order, because one
    /// process may append the events of several interleaved commands.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn events_for_run(&self, run_id: &str) -> Result<Vec<Event>, LedgerError> {
        let mut statement = self.conn.prepare(
            "SELECT run_id, seq, ts, kind, artifact_key, target, detail_json
             FROM events WHERE run_id = ?1 ORDER BY seq",
        )?;
        let rows = statement.query_map(params![run_id], event_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(LedgerError::from)
    }

    /// Number of recorded events.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn event_count(&self) -> Result<u64, LedgerError> {
        let count: i64 = self
            .conn
            .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
        Ok(u64::try_from(count).unwrap_or(0))
    }

    /// Highest event row id, or `0` when the log is empty.
    ///
    /// A command layer snapshots this before a run and passes it to
    /// [`Ledger::events_since`] afterwards, which is how it learns every event
    /// the run appended (the incident flow uses its own run ids).
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn event_cursor(&self) -> Result<i64, LedgerError> {
        Ok(self
            .conn
            .query_row("SELECT COALESCE(MAX(id), 0) FROM events", [], |row| {
                row.get(0)
            })?)
    }

    /// Every event appended after `cursor`, in append order.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn events_since(&self, cursor: i64) -> Result<Vec<Event>, LedgerError> {
        let mut statement = self.conn.prepare(
            "SELECT run_id, seq, ts, kind, artifact_key, target, detail_json
             FROM events WHERE id > ?1 ORDER BY id",
        )?;
        let rows = statement.query_map(params![cursor], event_from_row)?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(LedgerError::from)
    }

    /// Whether any event was recorded under `run_id`.
    ///
    /// A run id is a one-shot event namespace: `(run_id, seq)` is the
    /// idempotency key, so reusing a run id would make later appends collide
    /// with recorded events and be discarded silently. Commands that mint their
    /// own events check this before allocating a sequence.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn has_events_for_run(&self, run_id: &str) -> Result<bool, LedgerError> {
        let found = self
            .conn
            .query_row(
                "SELECT 1 FROM events WHERE run_id = ?1 LIMIT 1",
                params![run_id],
                |_| Ok(()),
            )
            .optional()?;
        Ok(found.is_some())
    }

    /// The highest applied schema version.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerError`] when the query fails.
    pub fn schema_version(&self) -> Result<i64, LedgerError> {
        Ok(self.conn.query_row(
            "SELECT COALESCE(MAX(version), 0) FROM schema_version",
            [],
            |row| row.get(0),
        )?)
    }
}

/// Apply every migration the database has not seen yet.
fn migrate(conn: &mut Connection) -> Result<(), LedgerError> {
    conn.execute_batch("CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY)")?;
    let current: i64 = conn.query_row(
        "SELECT COALESCE(MAX(version), 0) FROM schema_version",
        [],
        |row| row.get(0),
    )?;

    for (index, sql) in MIGRATIONS.iter().enumerate() {
        let version = i64::try_from(index).unwrap_or(i64::MAX) + 1;
        if version <= current {
            continue;
        }
        let tx = conn.transaction()?;
        tx.execute_batch(sql)?;
        tx.execute(
            "INSERT INTO schema_version (version) VALUES (?1)",
            params![version],
        )?;
        tx.commit()?;
    }
    Ok(())
}

/// Insert one event, ignoring a duplicate `(run_id, seq)`.
///
/// Returns the number of inserted rows: 1 for a new event, 0 for a duplicate.
fn insert_event(conn: &Connection, event: &Event) -> Result<usize, LedgerError> {
    let seq = i64::try_from(event.seq).map_err(|_| LedgerError::InvalidDetail {
        run_id: event.run_id.clone(),
        seq: event.seq,
        reason: "sequence does not fit in SQLite INTEGER".to_string(),
    })?;
    let detail = serde_json::to_string(&event.detail)?;
    conn.execute(
        "INSERT OR IGNORE INTO events
             (run_id, seq, ts, kind, artifact_key, target, detail_json)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![
            event.run_id,
            seq,
            ts_text(event.ts),
            event.kind.as_str(),
            event.artifact_key,
            event.target,
            detail,
        ],
    )
    .map_err(LedgerError::from)
}

/// Project one event into the derived tables.
fn reduce(conn: &Connection, event: &Event) -> Result<(), LedgerError> {
    match event.kind {
        EventKind::RunStarted => reduce_run_started(conn, event),
        EventKind::RunFinished => reduce_run_finished(conn, event),
        EventKind::ArtifactSeen => reduce_artifact_seen(conn, event),
        EventKind::DownloadStarted | EventKind::LeaseTakenOver => Ok(()),
        EventKind::Verified => reduce_verified(conn, event),
        EventKind::PublicationStarted => reduce_publication_started(conn, event),
        EventKind::Published => reduce_published(conn, event),
        EventKind::PublicationFailed => {
            reduce_publication_attempt(conn, event, PublicationStatus::Failed)
        }
        EventKind::PublicationInterrupted => {
            reduce_publication_attempt(conn, event, PublicationStatus::Interrupted)
        }
        EventKind::PublicationSuperseded => reduce_publication_superseded(conn, event),
        EventKind::PublicationUnrecoverable => {
            reduce_publication_attempt(conn, event, PublicationStatus::Unrecoverable)
        }
        EventKind::HashChanged => reduce_hash_changed(conn, event),
        EventKind::IncidentOpened => reduce_incident_opened(conn, event),
        EventKind::IncidentAcked => reduce_incident_acked(conn, event),
        EventKind::Imported => reduce_imported(conn, event),
        EventKind::LocalGc => reduce_local_gc(conn, event),
        EventKind::PlanRecorded => reduce_plan_recorded(conn, event),
    }
}

fn reduce_artifact_seen(conn: &Connection, event: &Event) -> Result<(), LedgerError> {
    let detail = detail_artifact(event)?;
    upsert_artifact(conn, event, &detail, None)?;
    Ok(())
}

fn reduce_verified(conn: &Connection, event: &Event) -> Result<(), LedgerError> {
    let key = require_key(event)?;
    let size = event.detail.get("size").and_then(Value::as_u64);
    conn.execute(
        "UPDATE artifacts
         SET local = 1, size = COALESCE(?1, size), last_seen = MAX(last_seen, ?2)
         WHERE key = ?3",
        params![sql_opt_u64(size), ts_text(event.ts), key],
    )?;
    Ok(())
}

fn reduce_local_gc(conn: &Connection, event: &Event) -> Result<(), LedgerError> {
    let key = require_key(event)?;
    conn.execute(
        "UPDATE artifacts SET local = 0 WHERE key = ?1",
        params![key],
    )?;
    Ok(())
}

fn reduce_publication_started(conn: &Connection, event: &Event) -> Result<(), LedgerError> {
    let key = require_key(event)?;
    let target = require_target(event)?;
    let attempts = attempt_count(conn, key, target)?;

    conn.execute(
        "INSERT INTO publications
             (artifact_key, target, status, remote_ref, remote_digest, attempts,
              next_attempt_at, last_error, updated_at)
         VALUES (?1, ?2, 'uploading', NULL, NULL, ?3, NULL, NULL, ?4)
         ON CONFLICT (artifact_key, target) DO UPDATE SET
             status = 'uploading',
             attempts = excluded.attempts,
             next_attempt_at = NULL,
             updated_at = excluded.updated_at",
        params![key, target, sql_u64(attempts), ts_text(event.ts)],
    )?;
    Ok(())
}

fn reduce_published(conn: &Connection, event: &Event) -> Result<(), LedgerError> {
    let key = require_key(event)?;
    let target = require_target(event)?;
    let remote_ref = event.detail.get("remote_ref").and_then(Value::as_str);
    let remote_digest = event.detail.get("remote_digest").and_then(Value::as_str);
    let attempts = attempt_count(conn, key, target)?;

    conn.execute(
        "INSERT INTO publications
             (artifact_key, target, status, remote_ref, remote_digest, attempts,
              next_attempt_at, last_error, updated_at)
         VALUES (?1, ?2, 'published', ?3, ?4, ?5, NULL, NULL, ?6)
         ON CONFLICT (artifact_key, target) DO UPDATE SET
             status = 'published',
             remote_ref = COALESCE(excluded.remote_ref, publications.remote_ref),
             remote_digest = COALESCE(excluded.remote_digest, publications.remote_digest),
             attempts = excluded.attempts,
             next_attempt_at = NULL,
             last_error = NULL,
             updated_at = excluded.updated_at",
        params![
            key,
            target,
            remote_ref,
            remote_digest,
            sql_u64(attempts),
            ts_text(event.ts),
        ],
    )?;
    Ok(())
}

fn reduce_publication_attempt(
    conn: &Connection,
    event: &Event,
    status: PublicationStatus,
) -> Result<(), LedgerError> {
    let key = require_key(event)?;
    let target = require_target(event)?;
    let error = event.detail.get("error").and_then(Value::as_str);
    let next_attempt_at = detail_timestamp(event, "next_attempt_at")?;
    let attempts = attempt_count(conn, key, target)?;

    conn.execute(
        "INSERT INTO publications
             (artifact_key, target, status, remote_ref, remote_digest, attempts,
              next_attempt_at, last_error, updated_at)
         VALUES (?1, ?2, ?3, NULL, NULL, ?4, ?5, ?6, ?7)
         ON CONFLICT (artifact_key, target) DO UPDATE SET
             status = excluded.status,
             attempts = excluded.attempts,
             next_attempt_at = excluded.next_attempt_at,
             last_error = COALESCE(excluded.last_error, publications.last_error),
             updated_at = excluded.updated_at",
        params![
            key,
            target,
            status.as_str(),
            sql_u64(attempts),
            next_attempt_at,
            error,
            ts_text(event.ts),
        ],
    )?;
    Ok(())
}

fn reduce_publication_superseded(conn: &Connection, event: &Event) -> Result<(), LedgerError> {
    let key = require_key(event)?;
    let target = require_target(event)?;
    let exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM publications WHERE artifact_key = ?1 AND target = ?2)",
        params![key, target],
        |row| row.get(0),
    )?;
    if !exists {
        return Err(LedgerError::UnknownPublication {
            artifact_key: key.to_string(),
            target: target.to_string(),
        });
    }
    conn.execute(
        "UPDATE publications
         SET status = 'superseded', next_attempt_at = NULL, updated_at = ?1
         WHERE artifact_key = ?2 AND target = ?3",
        params![ts_text(event.ts), key, target],
    )?;
    Ok(())
}

fn reduce_hash_changed(conn: &Connection, event: &Event) -> Result<(), LedgerError> {
    let detail = detail_artifact(event)?;
    let new_key = require_key(event)?.to_string();
    let old_sha256 = require_detail_str(event, "old_sha256")?.to_string();
    let new_sha256 = event
        .detail
        .get("new_sha256")
        .and_then(Value::as_str)
        .map_or_else(|| detail.sha256.clone(), ToString::to_string);
    if new_sha256 != detail.sha256 {
        return Err(LedgerError::InvalidDetail {
            run_id: event.run_id.clone(),
            seq: event.seq,
            reason: format!(
                "new_sha256 `{new_sha256}` does not match artifact digest `{}`",
                detail.sha256
            ),
        });
    }
    let old_key = match detail_str(event, "old_key") {
        Some(key) => key.to_string(),
        None => {
            superseded_key(&new_key, &old_sha256).ok_or_else(|| LedgerError::InvalidDetail {
                run_id: event.run_id.clone(),
                seq: event.seq,
                reason: format!("cannot derive the superseded key from `{new_key}`"),
            })?
        }
    };

    let old_exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM artifacts WHERE key = ?1)",
        params![old_key],
        |row| row.get(0),
    )?;
    if !old_exists {
        return Err(LedgerError::UnknownArtifact {
            key: old_key,
            run_id: event.run_id.clone(),
            seq: event.seq,
        });
    }

    upsert_artifact(conn, event, &detail, Some(&old_key))?;
    conn.execute(
        "UPDATE artifacts SET superseded_by = ?1 WHERE key = ?2",
        params![new_key, old_key],
    )?;

    // The replacement starts un-published on every target the old bytes had
    // reached. `INSERT OR IGNORE` keeps a target that is already published (a
    // duplicate event must not reset it) and is a no-op on replay.
    conn.execute(
        "INSERT OR IGNORE INTO publications
             (artifact_key, target, status, attempts, updated_at)
         SELECT ?1, target, 'pending', 0, ?2
         FROM publications WHERE artifact_key = ?3",
        params![new_key, ts_text(event.ts), old_key],
    )?;

    let id = incident_id(
        IncidentKind::HashChanged,
        Some(&new_key),
        Some(&old_sha256),
        Some(&new_sha256),
    );
    let issue_url = detail_str(event, "issue_url");
    conn.execute(
        "INSERT OR IGNORE INTO incidents
             (id, artifact_key, kind, old_sha256, new_sha256, detected_at,
              detail_json, state, issue_url)
         VALUES (?1, ?2, 'hash_changed', ?3, ?4, ?5, ?6, 'open', ?7)",
        params![
            id,
            new_key,
            old_sha256,
            new_sha256,
            ts_text(event.ts),
            serde_json::to_string(&event.detail)?,
            issue_url,
        ],
    )?;
    Ok(())
}

fn reduce_incident_opened(conn: &Connection, event: &Event) -> Result<(), LedgerError> {
    let kind = IncidentKind::from_str(require_detail_str(event, "kind")?)?;
    let artifact_key = detail_str(event, "artifact_key")
        .map(ToString::to_string)
        .or_else(|| event.artifact_key.clone());
    let old_sha256 = detail_str(event, "old_sha256").map(ToString::to_string);
    let new_sha256 = detail_str(event, "new_sha256").map(ToString::to_string);
    let id = detail_str(event, "id").map_or_else(
        || {
            incident_id(
                kind,
                artifact_key.as_deref(),
                old_sha256.as_deref(),
                new_sha256.as_deref(),
            )
        },
        ToString::to_string,
    );
    let detail = event.detail.get("detail").cloned().unwrap_or(Value::Null);
    let issue_url = detail_str(event, "issue_url");

    conn.execute(
        "INSERT OR IGNORE INTO incidents
             (id, artifact_key, kind, old_sha256, new_sha256, detected_at,
              detail_json, state, issue_url)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, 'open', ?8)",
        params![
            id,
            artifact_key,
            kind.as_str(),
            old_sha256,
            new_sha256,
            ts_text(event.ts),
            serde_json::to_string(&detail)?,
            issue_url,
        ],
    )?;
    Ok(())
}

fn reduce_incident_acked(conn: &Connection, event: &Event) -> Result<(), LedgerError> {
    let id = require_detail_str(event, "id")?;
    let note = detail_str(event, "note");
    let issue_url = detail_str(event, "issue_url");
    let changed = conn.execute(
        "UPDATE incidents
         SET state = 'acked',
             ack_note = COALESCE(?1, ack_note),
             issue_url = COALESCE(?2, issue_url)
         WHERE id = ?3",
        params![note, issue_url, id],
    )?;
    if changed == 0 {
        return Err(LedgerError::UnknownIncident { id: id.to_string() });
    }
    Ok(())
}

fn reduce_imported(conn: &Connection, event: &Event) -> Result<(), LedgerError> {
    let detail = detail_artifact(event)?;
    let artifact = upsert_artifact(conn, event, &detail, None)?;
    let Some(target) = event.target.as_deref() else {
        return Ok(());
    };
    let key = artifact.key();
    let remote_ref = event.detail.get("remote_ref").and_then(Value::as_str);
    let remote_digest = event.detail.get("remote_digest").and_then(Value::as_str);

    conn.execute(
        "INSERT INTO publications
             (artifact_key, target, status, remote_ref, remote_digest, attempts,
              next_attempt_at, last_error, updated_at)
         VALUES (?1, ?2, 'published', ?3, ?4, 0, NULL, NULL, ?5)
         ON CONFLICT (artifact_key, target) DO UPDATE SET
             status = 'published',
             remote_ref = COALESCE(excluded.remote_ref, publications.remote_ref),
             remote_digest = COALESCE(excluded.remote_digest, publications.remote_digest),
             updated_at = excluded.updated_at",
        params![key, target, remote_ref, remote_digest, ts_text(event.ts)],
    )?;
    Ok(())
}

fn reduce_run_started(conn: &Connection, event: &Event) -> Result<(), LedgerError> {
    let policy = event
        .detail
        .get("effective_policy")
        .cloned()
        .unwrap_or(Value::Null);
    let order = detail_str(event, "order");
    let max_bytes = event.detail.get("max_bytes").and_then(Value::as_u64);
    let transport_order = event
        .detail
        .get("transport_order")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let host = detail_str(event, "host").unwrap_or_default();
    let leased = event
        .detail
        .get("leased")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    conn.execute(
        "INSERT INTO runs
             (run_id, effective_policy, \"order\", max_bytes, transport_order,
              host, started_at, leased)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT (run_id) DO UPDATE SET
             effective_policy = excluded.effective_policy,
             \"order\" = COALESCE(excluded.\"order\", runs.\"order\"),
             max_bytes = COALESCE(excluded.max_bytes, runs.max_bytes),
             transport_order = excluded.transport_order,
             host = CASE WHEN excluded.host <> '' THEN excluded.host ELSE runs.host END,
             started_at = MIN(runs.started_at, excluded.started_at),
             leased = excluded.leased",
        params![
            event.run_id,
            serde_json::to_string(&policy)?,
            order,
            sql_opt_u64(max_bytes),
            serde_json::to_string(&transport_order)?,
            host,
            ts_text(event.ts),
            leased,
        ],
    )?;
    Ok(())
}

fn reduce_run_finished(conn: &Connection, event: &Event) -> Result<(), LedgerError> {
    let outcome = detail_str(event, "outcome");
    let summary = event
        .detail
        .get("summary")
        .or_else(|| event.detail.get("summary_json"))
        .cloned()
        .unwrap_or(Value::Null);
    let leased = event.detail.get("leased").and_then(Value::as_bool);
    let timestamp = ts_text(event.ts);

    conn.execute(
        "INSERT INTO runs
             (run_id, started_at, finished_at, outcome, summary_json, leased)
         VALUES (?1, ?2, ?2, ?3, ?4, COALESCE(?5, 0))
         ON CONFLICT (run_id) DO UPDATE SET
             finished_at = excluded.finished_at,
             outcome = COALESCE(excluded.outcome, runs.outcome),
             summary_json = CASE
                 WHEN excluded.summary_json <> 'null' THEN excluded.summary_json
                 ELSE runs.summary_json
             END,
             leased = COALESCE(?5, runs.leased)",
        params![
            event.run_id,
            timestamp,
            outcome,
            serde_json::to_string(&summary)?,
            leased,
        ],
    )?;

    if let Some(cursor) = event.detail.get("cursor").filter(|value| !value.is_null()) {
        let fingerprint = cursor
            .get("fingerprint")
            .and_then(Value::as_str)
            .ok_or_else(|| LedgerError::MissingDetail {
                run_id: event.run_id.clone(),
                seq: event.seq,
                field: "cursor.fingerprint",
            })?;
        let last_version = cursor.get("last_version").and_then(Value::as_str);
        let last_artifact_key = cursor.get("last_artifact_key").and_then(Value::as_str);
        // Absent or null fields clear the position: an uncapped backfill run
        // has finished the queue and must not resume from an old key.
        upsert_cursor(
            conn,
            fingerprint,
            last_version,
            last_artifact_key,
            &timestamp,
        )?;
    }
    Ok(())
}

/// Insert or replace one resume cursor.
fn upsert_cursor(
    conn: &Connection,
    fingerprint: &str,
    last_version: Option<&str>,
    last_artifact_key: Option<&str>,
    updated_at: &str,
) -> Result<(), LedgerError> {
    conn.execute(
        "INSERT INTO cursors
             (fingerprint, last_version, last_artifact_key, updated_at)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT (fingerprint) DO UPDATE SET
             last_version = excluded.last_version,
             last_artifact_key = excluded.last_artifact_key,
             updated_at = excluded.updated_at",
        params![fingerprint, last_version, last_artifact_key, updated_at],
    )?;
    Ok(())
}

fn reduce_plan_recorded(conn: &Connection, event: &Event) -> Result<(), LedgerError> {
    let policy = event
        .detail
        .get("effective_policy")
        .cloned()
        .unwrap_or(Value::Null);
    let order = detail_str(event, "order");
    let max_bytes = event.detail.get("max_bytes").and_then(Value::as_u64);
    let transport_order = event
        .detail
        .get("transport_order")
        .cloned()
        .unwrap_or_else(|| Value::Array(Vec::new()));
    let host = detail_str(event, "host").unwrap_or_default();
    let summary = event.detail.get("summary").cloned().unwrap_or(Value::Null);
    let timestamp = ts_text(event.ts);

    conn.execute(
        "INSERT OR IGNORE INTO runs
             (run_id, effective_policy, \"order\", max_bytes, transport_order,
              host, started_at, finished_at, outcome, summary_json, leased)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?7, 'planned', ?8, 0)",
        params![
            event.run_id,
            serde_json::to_string(&policy)?,
            order,
            sql_opt_u64(max_bytes),
            serde_json::to_string(&transport_order)?,
            host,
            timestamp,
            serde_json::to_string(&summary)?,
        ],
    )?;
    Ok(())
}

/// Insert or refresh one artifact row.
fn upsert_artifact(
    conn: &Connection,
    event: &Event,
    detail: &ArtifactDetail,
    supersedes: Option<&str>,
) -> Result<Artifact, LedgerError> {
    let artifact = detail.to_artifact();
    ensure_key(event, &artifact)?;

    let key = artifact.key();
    let upstream_path = detail
        .upstream_path
        .clone()
        .unwrap_or_else(|| artifact.rsync_relpath());
    let metadata_json = artifact.metadata_json.clone();
    let iteration = artifact.iteration.map(|value| value.to_string());
    let timestamp = ts_text(event.ts);

    conn.execute(
        "INSERT INTO artifacts
             (key, upstream_path, sha256, size, basename, project, channel,
              version, iteration, platform, platform_version, arch, metadata_json,
              first_seen, last_seen, supersedes, local, raw_arch, tag_override)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13,
                 ?14, ?14, ?15, 0, ?16, ?17)
         ON CONFLICT (key) DO UPDATE SET
             upstream_path = excluded.upstream_path,
             sha256 = excluded.sha256,
             size = COALESCE(excluded.size, artifacts.size),
             basename = excluded.basename,
             project = excluded.project,
             channel = excluded.channel,
             version = excluded.version,
             iteration = excluded.iteration,
             platform = excluded.platform,
             platform_version = excluded.platform_version,
             arch = excluded.arch,
             raw_arch = excluded.raw_arch,
             tag_override = COALESCE(excluded.tag_override, artifacts.tag_override),
             metadata_json = CASE
                 WHEN excluded.metadata_json <> 'null' THEN excluded.metadata_json
                 ELSE artifacts.metadata_json
             END,
             last_seen = MAX(artifacts.last_seen, excluded.last_seen),
             supersedes = COALESCE(excluded.supersedes, artifacts.supersedes)",
        params![
            key,
            upstream_path,
            artifact.sha256,
            sql_opt_u64(detail.size),
            artifact.basename,
            artifact.project,
            artifact.channel,
            artifact.version,
            iteration,
            artifact.platform,
            artifact.platform_version,
            artifact.arch,
            metadata_json,
            timestamp,
            supersedes,
            artifact.raw_arch,
            artifact.tag_override,
        ],
    )?;
    Ok(artifact)
}

/// The number of recorded publication attempts for one artifact and target.
fn attempt_count(conn: &Connection, key: &str, target: &str) -> Result<u64, LedgerError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM events
         WHERE artifact_key = ?1 AND target = ?2
           AND kind IN ('published', 'publication_failed', 'publication_interrupted')",
        params![key, target],
        |row| row.get(0),
    )?;
    Ok(u64::try_from(count).unwrap_or(0))
}

/// Build the stable incident id for a detection triple.
///
/// Detection and acknowledgement both need the same id, so this is public API
/// rather than a detail of the reducer. The id is `<kind>-<16 hex>`, derived
/// from the kind, artifact key and both digests.
#[must_use]
pub fn incident_id(
    kind: IncidentKind,
    artifact_key: Option<&str>,
    old_sha256: Option<&str>,
    new_sha256: Option<&str>,
) -> String {
    incident_id_for(kind.as_str(), artifact_key, old_sha256, new_sha256)
}

fn incident_id_for(kind: &str, key: Option<&str>, old: Option<&str>, new: Option<&str>) -> String {
    let mut hasher = Sha256::new();
    for part in [
        kind,
        key.unwrap_or(""),
        old.unwrap_or(""),
        new.unwrap_or(""),
    ] {
        hasher.update(part.as_bytes());
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let mut hex = String::with_capacity(digest.len() * 2);
    for byte in digest {
        hex.push_str(&format!("{byte:02x}"));
    }
    format!("{kind}-{}", &hex[..16])
}

/// The old key when a hash change names only the replacement key.
#[must_use]
pub fn superseded_key(new_key: &str, old_sha256: &str) -> Option<String> {
    let (prefix, _) = new_key.rsplit_once('/')?;
    Some(format!("{prefix}/{old_sha256}"))
}

/// The `detail.artifact` object an event carries for `artifact`.
///
/// Producers (the incident flow and the runner) use this instead of building
/// the object by hand so the exact metadata text and raw architecture survive
/// the ledger round trip.
#[must_use]
pub fn artifact_detail(artifact: &Artifact) -> Value {
    json!({
        "channel": artifact.channel,
        "project": artifact.project,
        "version": artifact.version,
        "platform": artifact.platform,
        "platform_version": artifact.platform_version,
        "arch": artifact.arch,
        "raw_arch": artifact.raw_arch,
        "basename": artifact.basename,
        "sha256": artifact.sha256,
        "metadata_json": artifact.metadata_json,
        "iteration": artifact.iteration,
        "tag_override": artifact.tag_override,
    })
}

fn sql_u64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn sql_opt_u64(value: Option<u64>) -> Option<i64> {
    value.map(sql_u64)
}

fn require_key(event: &Event) -> Result<&str, LedgerError> {
    event
        .artifact_key
        .as_deref()
        .ok_or_else(|| LedgerError::MissingDetail {
            run_id: event.run_id.clone(),
            seq: event.seq,
            field: "artifact_key",
        })
}

fn require_target(event: &Event) -> Result<&str, LedgerError> {
    event
        .target
        .as_deref()
        .ok_or_else(|| LedgerError::MissingDetail {
            run_id: event.run_id.clone(),
            seq: event.seq,
            field: "target",
        })
}

fn detail_str<'a>(event: &'a Event, field: &str) -> Option<&'a str> {
    event.detail.get(field).and_then(Value::as_str)
}

fn require_detail_str<'a>(event: &'a Event, field: &'static str) -> Result<&'a str, LedgerError> {
    detail_str(event, field).ok_or_else(|| LedgerError::MissingDetail {
        run_id: event.run_id.clone(),
        seq: event.seq,
        field,
    })
}

fn detail_artifact(event: &Event) -> Result<ArtifactDetail, LedgerError> {
    let value = event
        .detail
        .get("artifact")
        .ok_or_else(|| LedgerError::MissingDetail {
            run_id: event.run_id.clone(),
            seq: event.seq,
            field: "artifact",
        })?;
    let mut detail: ArtifactDetail =
        serde_json::from_value(value.clone()).map_err(|error| LedgerError::InvalidDetail {
            run_id: event.run_id.clone(),
            seq: event.seq,
            reason: format!("artifact detail: {error}"),
        })?;
    // `size`, `upstream_path` and `metadata` describe the row as a whole rather
    // than the identity, so producers may put them beside `artifact`.
    if detail.size.is_none() {
        detail.size = event.detail.get("size").and_then(Value::as_u64);
    }
    if detail.upstream_path.is_none() {
        detail.upstream_path = detail_str(event, "upstream_path").map(ToString::to_string);
    }
    if detail.metadata.is_null() {
        detail.metadata = event.detail.get("metadata").cloned().unwrap_or(Value::Null);
    }
    if detail.metadata_json.is_none() {
        detail.metadata_json = detail_str(event, "metadata_json").map(ToString::to_string);
    }
    Ok(detail)
}

fn detail_timestamp(event: &Event, field: &'static str) -> Result<Option<String>, LedgerError> {
    match detail_str(event, field) {
        Some(raw) => {
            let parsed = DateTime::parse_from_rfc3339(raw)
                .map(|value| value.with_timezone(&Utc))
                .map_err(|error| LedgerError::InvalidDetail {
                    run_id: event.run_id.clone(),
                    seq: event.seq,
                    reason: format!("`{field}` is not RFC3339: {error}"),
                })?;
            Ok(Some(ts_text(parsed)))
        }
        None => Ok(None),
    }
}

fn ensure_key(event: &Event, artifact: &Artifact) -> Result<(), LedgerError> {
    if let Some(key) = event.artifact_key.as_deref() {
        if key != artifact.key() {
            return Err(LedgerError::InvalidDetail {
                run_id: event.run_id.clone(),
                seq: event.seq,
                reason: format!(
                    "artifact_key `{key}` does not match artifact `{}`",
                    artifact.key()
                ),
            });
        }
    }
    Ok(())
}

/// The artifact fields carried inside an event's `detail.artifact`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ArtifactDetail {
    channel: String,
    project: String,
    version: String,
    platform: String,
    platform_version: String,
    arch: String,
    #[serde(default)]
    raw_arch: Option<String>,
    basename: String,
    sha256: String,
    #[serde(default)]
    iteration: Option<u64>,
    #[serde(default)]
    size: Option<u64>,
    #[serde(default)]
    upstream_path: Option<String>,
    /// The exact upstream metadata text, published verbatim by targets.
    #[serde(default)]
    metadata_json: Option<String>,
    #[serde(default)]
    metadata: Value,
    /// Digest-qualified tag when the artifact lost its descriptive tag to
    /// another upstream file.
    #[serde(default)]
    tag_override: Option<String>,
}

impl ArtifactDetail {
    fn to_artifact(&self) -> Artifact {
        Artifact {
            channel: self.channel.clone(),
            project: self.project.clone(),
            version: self.version.clone(),
            platform: self.platform.clone(),
            platform_version: self.platform_version.clone(),
            arch: self.arch.clone(),
            raw_arch: self.raw_arch.clone().unwrap_or_else(|| self.arch.clone()),
            basename: self.basename.clone(),
            sha256: self.sha256.clone(),
            // A new event carries the exact upstream text. Events written
            // before that field existed only have the parsed detail, which is
            // the closest reconstruction available.
            metadata_json: self
                .metadata_json
                .clone()
                .unwrap_or_else(|| self.metadata.to_string()),
            iteration: self.iteration,
            superseded: false,
            tag_override: self.tag_override.clone(),
        }
    }
}

fn artifact_row_from_row(row: &Row<'_>) -> rusqlite::Result<ArtifactRow> {
    let iteration: Option<String> = row.get(8)?;
    let iteration = iteration
        .map(|raw| {
            raw.parse::<u64>()
                .map_err(|error| conversion_error(8, error))
        })
        .transpose()?;
    let metadata_json: String = row.get(12)?;
    let metadata =
        serde_json::from_str(&metadata_json).map_err(|error| conversion_error(12, error))?;
    let size: Option<i64> = row.get(3)?;
    let local: i64 = row.get(17)?;
    let arch: String = row.get(11)?;
    // Version 1 rows have no raw architecture; the public spelling is the only
    // value they can supply.
    let stored_raw_arch: String = row.get(18)?;
    let raw_arch = if stored_raw_arch.is_empty() {
        arch.clone()
    } else {
        stored_raw_arch
    };

    Ok(ArtifactRow {
        artifact: Artifact {
            channel: row.get(6)?,
            project: row.get(5)?,
            version: row.get(7)?,
            platform: row.get(9)?,
            platform_version: row.get(10)?,
            arch,
            raw_arch,
            basename: row.get(4)?,
            sha256: row.get(2)?,
            metadata_json,
            iteration,
            superseded: false,
            tag_override: row.get(19)?,
        },
        upstream_path: row.get(1)?,
        size: size.map(|value| u64::try_from(value).unwrap_or(0)),
        metadata,
        first_seen: timestamp_column(row, 13)?,
        last_seen: timestamp_column(row, 14)?,
        superseded_by: row.get(15)?,
        supersedes: row.get(16)?,
        local: local != 0,
    })
}

fn publication_from_row(row: &Row<'_>) -> rusqlite::Result<Publication> {
    let status: String = row.get(2)?;
    let status =
        PublicationStatus::from_str(&status).map_err(|error| conversion_error(2, error))?;
    let attempts: i64 = row.get(5)?;

    Ok(Publication {
        artifact_key: row.get(0)?,
        target: row.get(1)?,
        status,
        remote_ref: row.get(3)?,
        remote_digest: row.get(4)?,
        attempts: u64::try_from(attempts).unwrap_or(0),
        next_attempt_at: optional_timestamp_column(row, 6)?,
        last_error: row.get(7)?,
        updated_at: timestamp_column(row, 8)?,
    })
}

fn incident_from_row(row: &Row<'_>) -> rusqlite::Result<Incident> {
    let kind: String = row.get(2)?;
    let kind = IncidentKind::from_str(&kind).map_err(|error| conversion_error(2, error))?;
    let state: String = row.get(7)?;
    let state = IncidentState::from_str(&state).map_err(|error| conversion_error(7, error))?;
    let detail_json: String = row.get(6)?;
    let detail = serde_json::from_str(&detail_json).map_err(|error| conversion_error(6, error))?;

    Ok(Incident {
        id: row.get(0)?,
        artifact_key: row.get(1)?,
        kind,
        old_sha256: row.get(3)?,
        new_sha256: row.get(4)?,
        detected_at: timestamp_column(row, 5)?,
        detail,
        state,
        issue_url: row.get(8)?,
        ack_note: row.get(9)?,
    })
}

fn run_from_row(row: &Row<'_>) -> rusqlite::Result<Run> {
    let policy_json: String = row.get(1)?;
    let effective_policy =
        serde_json::from_str(&policy_json).map_err(|error| conversion_error(1, error))?;
    let transport_json: String = row.get(4)?;
    let transport: Value =
        serde_json::from_str(&transport_json).map_err(|error| conversion_error(4, error))?;
    let transport_order = transport
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect()
        })
        .unwrap_or_default();
    let summary_json: String = row.get(9)?;
    let summary =
        serde_json::from_str(&summary_json).map_err(|error| conversion_error(9, error))?;
    let max_bytes: Option<i64> = row.get(3)?;
    let leased: i64 = row.get(10)?;

    Ok(Run {
        run_id: row.get(0)?,
        effective_policy,
        order: row.get(2)?,
        max_bytes: max_bytes.map(|value| u64::try_from(value).unwrap_or(0)),
        transport_order,
        host: row.get(5)?,
        started_at: timestamp_column(row, 6)?,
        finished_at: optional_timestamp_column(row, 7)?,
        outcome: row.get(8)?,
        summary,
        leased: leased != 0,
    })
}

fn cursor_from_row(row: &Row<'_>) -> rusqlite::Result<Cursor> {
    Ok(Cursor {
        fingerprint: row.get(0)?,
        last_version: row.get(1)?,
        last_artifact_key: row.get(2)?,
        updated_at: timestamp_column(row, 3)?,
    })
}

fn event_from_row(row: &Row<'_>) -> rusqlite::Result<Event> {
    let seq: i64 = row.get(1)?;
    let seq = u64::try_from(seq).map_err(|error| conversion_error(1, error))?;
    let kind: String = row.get(3)?;
    let kind = EventKind::from_str(&kind).map_err(|error| conversion_error(3, error))?;
    let detail_json: String = row.get(6)?;
    let detail = serde_json::from_str(&detail_json).map_err(|error| conversion_error(6, error))?;

    Ok(Event {
        run_id: row.get(0)?,
        seq,
        ts: timestamp_column(row, 2)?,
        kind,
        artifact_key: row.get(4)?,
        target: row.get(5)?,
        detail,
    })
}

fn timestamp_column(row: &Row<'_>, index: usize) -> rusqlite::Result<DateTime<Utc>> {
    let raw: String = row.get(index)?;
    DateTime::parse_from_rfc3339(&raw)
        .map(|value| value.with_timezone(&Utc))
        .map_err(|error| conversion_error(index, error))
}

fn optional_timestamp_column(
    row: &Row<'_>,
    index: usize,
) -> rusqlite::Result<Option<DateTime<Utc>>> {
    match row.get::<_, Option<String>>(index)? {
        Some(raw) => DateTime::parse_from_rfc3339(&raw)
            .map(|value| Some(value.with_timezone(&Utc)))
            .map_err(|error| conversion_error(index, error)),
        None => Ok(None),
    }
}

fn conversion_error<E>(index: usize, error: E) -> rusqlite::Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    rusqlite::Error::FromSqlConversionFailure(index, rusqlite::types::Type::Text, Box::new(error))
}

/// UTC RFC3339 with milliseconds, fixed width so TEXT ordering is time order.
fn ts_text(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Millis, true)
}

/// Pending order: version descending, then the path fields ascending.
fn compare_pending(left: &Artifact, right: &Artifact) -> std::cmp::Ordering {
    version_desc(&left.version, &right.version)
        .then_with(|| left.project.cmp(&right.project))
        .then_with(|| left.platform.cmp(&right.platform))
        .then_with(|| left.platform_version.cmp(&right.platform_version))
        .then_with(|| left.arch.cmp(&right.arch))
        .then_with(|| left.basename.cmp(&right.basename))
        .then_with(|| left.key().cmp(&right.key()))
}

fn version_desc(left: &str, right: &str) -> std::cmp::Ordering {
    match (Version::from_str(left), Version::from_str(right)) {
        (Ok(left), Ok(right)) => right.cmp(&left),
        _ => right.cmp(left),
    }
}

/// Serde adapter for UTC timestamps with milliseconds.
mod millis {
    use chrono::{DateTime, SecondsFormat, Utc};
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S>(value: &DateTime<Utc>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_rfc3339_opts(SecondsFormat::Millis, true))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<DateTime<Utc>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        DateTime::parse_from_rfc3339(&raw)
            .map(|value| value.with_timezone(&Utc))
            .map_err(serde::de::Error::custom)
    }
}

/// Errors raised by the ledger.
#[derive(Debug, Error)]
pub enum LedgerError {
    /// SQLite rejected a statement.
    #[error("sqlite: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// A derived value could not be encoded as JSON.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// The state directory could not be created.
    #[error("i/o failed for {path}: {source}")]
    Io {
        /// Path the operation was working on.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// An event or row names an unknown event kind.
    #[error("invalid event kind `{value}`")]
    EventKind {
        /// The rejected value.
        value: String,
    },

    /// A publication row names an unknown status.
    #[error("invalid publication status `{value}`")]
    PublicationStatus {
        /// The rejected value.
        value: String,
    },

    /// A record names an unknown incident kind.
    #[error("invalid incident kind `{value}`")]
    IncidentKind {
        /// The rejected value.
        value: String,
    },

    /// A record names an unknown incident state.
    #[error("invalid incident state `{value}`")]
    IncidentState {
        /// The rejected value.
        value: String,
    },

    /// An event is missing a field its kind requires.
    #[error("event {run_id}/{seq} is missing `{field}`")]
    MissingDetail {
        /// Run that produced the event.
        run_id: String,
        /// Position within the run.
        seq: u64,
        /// The missing field.
        field: &'static str,
    },

    /// An event carries a field that cannot be used.
    #[error("event {run_id}/{seq}: {reason}")]
    InvalidDetail {
        /// Run that produced the event.
        run_id: String,
        /// Position within the run.
        seq: u64,
        /// Why the detail was rejected.
        reason: String,
    },

    /// A hash change names an artifact the ledger has never seen.
    #[error("unknown artifact `{key}` referenced by event {run_id}/{seq}")]
    UnknownArtifact {
        /// The missing key.
        key: String,
        /// Run that produced the event.
        run_id: String,
        /// Position within the run.
        seq: u64,
    },

    /// A status event names a publication row that does not exist.
    #[error("unknown publication `{artifact_key}` on `{target}`")]
    UnknownPublication {
        /// The artifact key.
        artifact_key: String,
        /// The target name.
        target: String,
    },

    /// An acknowledgement names an incident that does not exist.
    #[error("unknown incident `{id}`")]
    UnknownIncident {
        /// The incident id.
        id: String,
    },
}
