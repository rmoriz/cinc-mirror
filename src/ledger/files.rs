//! Durable ledger segments: NDJSON files in a git worktree.
//!
//! The SQLite database is a projection; these files are the record. One file
//! belongs to exactly one run, so parallel writers never edit the same lines and
//! a push conflict is always a whole-file conflict that fetch/rebase resolves.
//!
//! Layout inside the worktree:
//!
//! - `runs/<run_id>.ndjson` — one event per line, sorted by sequence.
//! - `snapshot-<n>.ndjson` — a compacted replay of every event in append order.
//! - `incidents/<id>.json` — written by the incident flow.
//!
//! The [`LedgerStore`] also caches file stamps in `<state>/ledger.hwm` so a
//! re-run can skip files it already applied. That cache is an optimisation: when
//! the database is empty the cache is ignored, so deleting `ledger.db` and
//! re-reading the branch always rebuilds the ledger.

use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use super::git::LedgerGitError;
use super::{Event, Ledger, LedgerError};
use crate::fsutil;

/// Directory below the worktree root that holds one NDJSON file per run.
pub const RUNS_DIR: &str = "runs";

/// Prefix of a compacted segment.
const SNAPSHOT_PREFIX: &str = "snapshot-";
/// Suffix every ledger segment carries.
const SEGMENT_SUFFIX: &str = ".ndjson";
/// Run files `gc` always keeps, even when the newest snapshot covers them.
pub const RUN_RETENTION: usize = 20;
/// File below the state directory that skips unchanged segments.
const HIGH_WATER_FILE: &str = "ledger.hwm";

/// The ledger's files in a git worktree.
///
/// Constructing the store does not touch the network; call
/// [`LedgerStore::sync`] before reading or writing segments.
#[derive(Debug, Clone)]
pub struct LedgerStore {
    pub(crate) workdir: PathBuf,
    pub(crate) remote: String,
    pub(crate) branch: String,
}

impl LedgerStore {
    /// A store for `workdir` backed by `remote_url` and `branch`.
    ///
    /// `remote_url` is used for every git command instead of a configured
    /// remote, so tests and CI can point the store at a local bare repository.
    /// A leading `~` in `workdir` is expanded like the state directory itself.
    #[must_use]
    pub fn new(workdir: PathBuf, remote_url: String, branch: String) -> Self {
        Self {
            workdir: fsutil::expand_tilde(&workdir),
            remote: remote_url,
            branch,
        }
    }

    /// The git worktree holding the segments.
    #[must_use]
    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    /// The remote URL every git command uses.
    #[must_use]
    pub fn remote(&self) -> &str {
        &self.remote
    }

    /// The ledger branch.
    #[must_use]
    pub fn branch(&self) -> &str {
        &self.branch
    }

    /// Write one run's events to `runs/<run_id>.ndjson`.
    ///
    /// The events are sorted by sequence and written one JSON object per line.
    /// A file is replaced atomically, so a crash cannot leave half a line that
    /// the next reader would reject.
    ///
    /// The file is not committed; call [`LedgerStore::commit_and_push`] when the
    /// run is complete.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFilesError::EmptyRun`] for an empty slice,
    /// [`LedgerFilesError::MixedRuns`] when the events name different runs,
    /// [`LedgerFilesError::InvalidRunId`] for a run id that would escape the
    /// `runs/` directory, and [`LedgerFilesError::Io`] when the file cannot be
    /// written.
    pub fn write_run(&self, events: &[Event]) -> Result<PathBuf, LedgerFilesError> {
        let Some(first) = events.first() else {
            return Err(LedgerFilesError::EmptyRun);
        };
        let run_id = first.run_id.as_str();
        if !is_valid_run_id(run_id) {
            return Err(LedgerFilesError::InvalidRunId {
                run_id: run_id.to_string(),
            });
        }
        if events.iter().any(|event| event.run_id != run_id) {
            return Err(LedgerFilesError::MixedRuns);
        }
        self.ensure_repo()?;

        let mut sorted: Vec<&Event> = events.iter().collect();
        sorted.sort_by_key(|event| event.seq);

        let runs = self.workdir.join(RUNS_DIR);
        fs::create_dir_all(&runs).map_err(|source| LedgerFilesError::Io {
            path: runs.clone(),
            source,
        })?;
        let path = runs.join(format!("{run_id}{SEGMENT_SUFFIX}"));
        write_segment(&path, sorted)?;
        Ok(path)
    }

    /// Replay every segment in the worktree into `ledger`.
    ///
    /// Snapshots are read first, highest number first, followed by the run files
    /// in ascending file name order. Replaying is idempotent because
    /// [`Ledger::apply`] keys on `(run_id, seq)`, so overlapping snapshots and
    /// run files are harmless.
    ///
    /// Files unchanged since the last successful load are skipped through
    /// `<state>/ledger.hwm`. When the database has no events yet the cache is
    /// ignored, so a deleted database is always rebuilt from the branch.
    ///
    /// Returns the number of events replayed; skipped files are not counted.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFilesError::Parse`] with the file and line of a malformed
    /// segment, [`LedgerFilesError::Database`] when a reducer rejects an event,
    /// and [`LedgerFilesError::Io`] when a file cannot be read.
    pub fn load_all(&self, ledger: &mut Ledger) -> Result<u64, LedgerFilesError> {
        self.ensure_repo()?;
        let segments = self.segments()?;
        let known = if ledger.event_count()? == 0 {
            HighWater::default()
        } else {
            self.read_high_water()
        };

        let mut seen = HighWater::default();
        let mut loaded = 0_u64;
        for segment in &segments {
            let stamp = stamp(&segment.path)?;
            if known.files.get(&segment.key) == Some(&stamp) {
                continue;
            }
            let events = read_segment(&segment.path)?;
            for event in &events {
                ledger.apply(event)?;
            }
            loaded += u64::try_from(events.len()).unwrap_or(0);
            seen.files.insert(segment.key.clone(), stamp);
        }

        self.write_high_water(&seen);
        Ok(loaded)
    }

    /// Write every applied event to `snapshot-<next>.ndjson` and commit it.
    ///
    /// The snapshot follows the database's append order, which is the order the
    /// run files were replayed in. Run files are left alone; [`LedgerStore::gc`]
    /// deletes the ones a snapshot covers.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFilesError`] when the snapshot cannot be written or the
    /// commit and push fail.
    pub fn compact(&self, ledger: &Ledger) -> Result<PathBuf, LedgerFilesError> {
        self.ensure_repo()?;
        let events = ledger.events()?;
        let number = self.next_snapshot()?;
        let path = self
            .workdir
            .join(format!("{SNAPSHOT_PREFIX}{number}{SEGMENT_SUFFIX}"));
        write_segment(&path, events.iter())?;
        self.commit_and_push(
            &path,
            &format!("ledger: snapshot {number} with {} events", events.len()),
        )?;
        Ok(path)
    }

    /// Delete run files that the newest snapshot already contains.
    ///
    /// The last [`RUN_RETENTION`] run files are kept regardless, so a snapshot
    /// never replaces the recent history a human debugs. Returns the deleted
    /// paths, oldest first; nothing is committed when nothing was covered.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerFilesError`] when a segment cannot be read or removed, or
    /// when the deletion cannot be committed and pushed.
    pub fn gc(&self) -> Result<Vec<PathBuf>, LedgerFilesError> {
        self.ensure_repo()?;
        let Some(snapshot) = self.newest_snapshot()? else {
            return Ok(Vec::new());
        };
        let covered: HashSet<(String, u64)> = read_segment(&snapshot)?
            .into_iter()
            .map(|event| (event.run_id, event.seq))
            .collect();

        let runs = self.run_files()?;
        let keep = runs.len().saturating_sub(RUN_RETENTION);
        let mut removed = Vec::new();
        for path in runs.iter().take(keep) {
            let events = read_segment(path)?;
            if events
                .iter()
                .all(|event| covered.contains(&(event.run_id.clone(), event.seq)))
            {
                fs::remove_file(path).map_err(|source| LedgerFilesError::Io {
                    path: path.clone(),
                    source,
                })?;
                removed.push(path.clone());
            }
        }

        if !removed.is_empty() {
            self.commit_and_push(
                &self.workdir.join(RUNS_DIR),
                &format!("ledger: gc {} covered run files", removed.len()),
            )?;
        }
        Ok(removed)
    }

    /// Directory holding the SQLite database and the high-water mark.
    fn state_dir(&self) -> PathBuf {
        match self.workdir.parent() {
            Some(parent) if !parent.as_os_str().is_empty() => parent.to_path_buf(),
            _ => PathBuf::from("."),
        }
    }

    /// Every segment in replay order: snapshots highest first, then runs.
    fn segments(&self) -> Result<Vec<Segment>, LedgerFilesError> {
        let mut segments: Vec<Segment> = self
            .snapshot_files()?
            .into_iter()
            .rev()
            .map(|(_, path)| Segment {
                key: path
                    .file_name()
                    .map_or_else(String::new, |name| name.to_string_lossy().into_owned()),
                path,
            })
            .collect();

        segments.extend(self.run_files()?.into_iter().map(|path| Segment {
            key: format!(
                "{RUNS_DIR}/{}",
                path.file_name()
                    .map_or_else(String::new, |name| name.to_string_lossy().into_owned())
            ),
            path,
        }));
        Ok(segments)
    }

    /// Snapshot files as `(number, path)`, ascending by number.
    fn snapshot_files(&self) -> Result<Vec<(u64, PathBuf)>, LedgerFilesError> {
        let mut snapshots = Vec::new();
        for path in list_files(&self.workdir)? {
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            if let Some(number) = snapshot_number(name) {
                snapshots.push((number, path));
            }
        }
        snapshots.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        Ok(snapshots)
    }

    /// Run files, ascending by file name.
    fn run_files(&self) -> Result<Vec<PathBuf>, LedgerFilesError> {
        let mut runs: Vec<PathBuf> = list_files(&self.workdir.join(RUNS_DIR))?
            .into_iter()
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| !name.starts_with('.') && name.ends_with(SEGMENT_SUFFIX))
            })
            .collect();
        runs.sort();
        Ok(runs)
    }

    fn newest_snapshot(&self) -> Result<Option<PathBuf>, LedgerFilesError> {
        Ok(self.snapshot_files()?.pop().map(|(_, path)| path))
    }

    fn next_snapshot(&self) -> Result<u64, LedgerFilesError> {
        Ok(self
            .snapshot_files()?
            .last()
            .map_or(1, |(number, _)| number.saturating_add(1)))
    }

    fn read_high_water(&self) -> HighWater {
        let path = self.state_dir().join(HIGH_WATER_FILE);
        fs::read_to_string(&path)
            .ok()
            .and_then(|body| serde_json::from_str(&body).ok())
            .unwrap_or_default()
    }

    fn write_high_water(&self, high_water: &HighWater) {
        let path = self.state_dir().join(HIGH_WATER_FILE);
        let body = match serde_json::to_vec_pretty(high_water) {
            Ok(body) => body,
            Err(error) => {
                tracing::warn!(%error, "cannot encode the ledger high-water mark");
                return;
            }
        };
        if let Err(error) = fs::write(&path, body) {
            // The cache is an optimisation; failing to record it must not fail
            // a load whose events are already applied.
            tracing::warn!(
                %error,
                path = %path.display(),
                "cannot write the ledger high-water mark"
            );
        }
    }
}

/// One segment in replay order.
struct Segment {
    path: PathBuf,
    /// Cache key: the path relative to the worktree.
    key: String,
}

/// Files applied by the last successful [`LedgerStore::load_all`].
#[derive(Debug, Default, Serialize, Deserialize)]
struct HighWater {
    files: BTreeMap<String, FileStamp>,
}

/// Size and modification time of a segment when it was last applied.
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
struct FileStamp {
    mtime_ns: u64,
    size: u64,
}

/// Every regular file directly below `root`; a missing directory is empty.
fn list_files(root: &Path) -> Result<Vec<PathBuf>, LedgerFilesError> {
    let mut files = Vec::new();
    if !root.is_dir() {
        return Ok(files);
    }
    let entries = fs::read_dir(root).map_err(|source| LedgerFilesError::Io {
        path: root.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| LedgerFilesError::Io {
            path: root.to_path_buf(),
            source,
        })?;
        let path = entry.path();
        if path.is_file() {
            files.push(path);
        }
    }
    Ok(files)
}

fn snapshot_number(name: &str) -> Option<u64> {
    let rest = name.strip_prefix(SNAPSHOT_PREFIX)?;
    let number = rest.strip_suffix(SEGMENT_SUFFIX)?;
    number.parse().ok()
}

fn stamp(path: &Path) -> Result<FileStamp, LedgerFilesError> {
    let metadata = fs::metadata(path).map_err(|source| LedgerFilesError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mtime_ns = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .and_then(|elapsed| u64::try_from(elapsed.as_nanos()).ok())
        .unwrap_or(0);
    Ok(FileStamp {
        mtime_ns,
        size: metadata.len(),
    })
}

fn read_segment(path: &Path) -> Result<Vec<Event>, LedgerFilesError> {
    let body = fs::read_to_string(path).map_err(|source| LedgerFilesError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let mut events = Vec::new();
    for (index, line) in body.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let event: Event =
            serde_json::from_str(line).map_err(|source| LedgerFilesError::Parse {
                path: path.to_path_buf(),
                line: index + 1,
                source,
            })?;
        events.push(event);
    }
    Ok(events)
}

/// Write events one JSON object per line, atomically replacing `path`.
fn write_segment<'a>(
    path: &Path,
    events: impl IntoIterator<Item = &'a Event>,
) -> Result<(), LedgerFilesError> {
    let mut body = String::new();
    for event in events {
        body.push_str(&serde_json::to_string(event)?);
        body.push('\n');
    }

    // A dot-prefixed temporary is ignored by the segment scan if a crash
    // leaves it behind.
    let temporary = path.with_file_name(format!(
        ".{}.tmp",
        path.file_name()
            .map_or_else(String::new, |name| name.to_string_lossy().into_owned())
    ));
    fs::write(&temporary, body).map_err(|source| LedgerFilesError::Io {
        path: temporary.clone(),
        source,
    })?;
    fs::rename(&temporary, path).map_err(|source| {
        let _ = fs::remove_file(&temporary);
        LedgerFilesError::Io {
            path: path.to_path_buf(),
            source,
        }
    })?;
    Ok(())
}

/// Whether a run id can be used as `<run_id>.ndjson` without escaping the
/// directory.
pub(crate) fn is_valid_run_id(run_id: &str) -> bool {
    !run_id.is_empty()
        && run_id.len() <= 128
        && !run_id.starts_with('.')
        && run_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "-_.".contains(character))
}

/// Errors raised by the ledger files.
#[derive(Debug, Error)]
pub enum LedgerFilesError {
    /// A segment or the high-water mark could not be read or written.
    #[error("i/o failed for {path}: {source}")]
    Io {
        /// Path the operation was working on.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// An event could not be encoded.
    #[error("cannot encode a ledger event: {0}")]
    Json(#[from] serde_json::Error),

    /// A segment line is not a valid event.
    #[error("cannot parse {path} line {line}: {source}")]
    Parse {
        /// The offending segment.
        path: PathBuf,
        /// One-based line number.
        line: usize,
        /// Underlying parse error.
        #[source]
        source: serde_json::Error,
    },

    /// A run file needs at least one event.
    #[error("cannot write a run file without events")]
    EmptyRun,

    /// One run file cannot hold events from several runs.
    #[error("the events belong to different runs")]
    MixedRuns,

    /// The run id would escape the runs directory.
    #[error("run id `{run_id}` is not safe to use as a file name")]
    InvalidRunId {
        /// The rejected run id.
        run_id: String,
    },

    /// A git operation failed.
    #[error(transparent)]
    Git(#[from] LedgerGitError),

    /// The database rejected an event.
    #[error(transparent)]
    Database(#[from] LedgerError),
}
