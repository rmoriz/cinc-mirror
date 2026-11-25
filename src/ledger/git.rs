//! Git transport for the ledger branch and the advisory lease.
//!
//! The ledger is a git branch: one NDJSON file per run, committed by one writer
//! and pushed fast-forward. A rejected push is not an error in itself — the
//! branch may simply have advanced — so [`LedgerStore::commit_and_push`] pulls
//! with `--rebase` and retries. A worktree with local changes is never reset
//! over; [`LedgerStore::sync`] refuses it instead.
//!
//! The lease is a one-line JSON blob on the dedicated ref
//! `refs/heads/ledger-lease` so heartbeats never touch the event files. It is
//! advisory: acquisition and refresh are best effort, and only a live foreign
//! lease that a push proves exists refuses the run.
//!
//! Every commit is made with an explicit identity so a bare CI image without a
//! configured `user.name` can still write the ledger.

use std::fmt;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::Duration;

use chrono::{DateTime, Duration as ChronoDuration, SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;

use super::files::{is_valid_run_id, LedgerStore};
use super::Event;

/// The ref the lease lives on, off the ledger branch.
pub const LEASE_REF: &str = "refs/heads/ledger-lease";

/// Name of the lease blob inside the lease commit.
const LEASE_FILE: &str = "lease.json";
/// Readme committed with a freshly created ledger branch.
const README_FILE: &str = "README.md";
/// Content of that readme; the branch is not a source checkout.
const README_CONTENT: &str = "ledger for cinc-mirror\n";
/// Push attempts before a rejection is reported.
const PUSH_ATTEMPTS: u32 = 3;
/// Git identity used for every ledger commit.
const IDENTITY: [&str; 4] = [
    "-c",
    "user.name=cinc-mirror",
    "-c",
    "user.email=cinc-mirror@localhost",
];

impl LedgerStore {
    /// Bring the worktree in line with the remote ledger branch.
    ///
    /// A missing worktree is cloned. When the remote has no ledger branch yet,
    /// the worktree is initialised with an orphan branch, a readme is committed
    /// and the branch is pushed, so two first runs converge through the ordinary
    /// push conflict path.
    ///
    /// An existing worktree is fetched and reset to the remote tip, but only
    /// when it is clean: a dirty worktree is refused with
    /// [`LedgerGitError::Dirty`] rather than silently discarding local work.
    ///
    /// Committed work that was never pushed (a run whose
    /// [`LedgerStore::commit_and_push`] was rejected) is never reset away: sync
    /// pushes those commits first, and when the remote has advanced in the
    /// meantime it returns [`LedgerGitError::UnpushedCommits`] leaving `HEAD`
    /// and the working tree untouched for an explicit rebase.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerGitError`] when git is unavailable, the remote cannot be
    /// reached, the worktree is dirty, or a command fails.
    pub fn sync(&self) -> Result<(), LedgerGitError> {
        if self.workdir.join(".git").exists() {
            self.fetch_and_reset()
        } else {
            self.clone_or_init()
        }
    }

    /// Commit one file below the worktree and push the ledger branch.
    ///
    /// The file is staged with `git add -A`, so a caller may also pass the
    /// `runs/` directory to record deletions. When the path has no changes to
    /// commit (a retried run), the commit is skipped and only the push happens.
    ///
    /// A rejected push is retried three times, each time after
    /// `git pull --rebase` onto the advanced branch. Conflicts are never forced.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerGitError::PushRejected`] when every attempt is rejected,
    /// [`LedgerGitError::OutsideWorktree`] for a path the store does not own, and
    /// [`LedgerGitError`] for any failing git command.
    pub fn commit_and_push(&self, path: &Path, message: &str) -> Result<(), LedgerGitError> {
        self.ensure_repo()?;
        let relative = self.relative_path(path)?;
        ok(
            git_in(&self.workdir, &["add", "-A", "--", &relative]),
            "add",
        )?;

        // `git diff --cached --quiet` exits 1 when the path has staged changes
        // and anything else when the comparison itself failed.
        let staged = run(
            git_in(
                &self.workdir,
                &["diff", "--cached", "--quiet", "--", &relative],
            ),
            "diff",
        )?;
        match staged.status.code() {
            Some(0) => {}
            Some(1) => {
                ok(
                    git_in_identity(
                        &self.workdir,
                        &["commit", "--quiet", "-m", message, "--", &relative],
                    ),
                    "commit",
                )?;
            }
            _ => return Err(failure(&staged, "diff")),
        }

        let refspec = format!("HEAD:refs/heads/{}", self.branch);
        let mut reason = String::new();
        for attempt in 1..=PUSH_ATTEMPTS {
            let push = run(
                git_in(&self.workdir, &["push", "--quiet", &self.remote, &refspec]),
                "push",
            )?;
            if push.status.success() {
                return Ok(());
            }
            reason = String::from_utf8_lossy(&push.stderr).trim().to_string();
            if !is_rejection(&reason) {
                return Err(failure(&push, "push"));
            }
            if attempt < PUSH_ATTEMPTS {
                ok(
                    git_in_identity(
                        &self.workdir,
                        &["pull", "--quiet", "--rebase", &self.remote, &self.branch],
                    ),
                    "pull --rebase",
                )?;
            }
        }
        Err(LedgerGitError::PushRejected {
            branch: self.branch.clone(),
            attempts: PUSH_ATTEMPTS,
            reason,
        })
    }

    /// Whether the worktree is a git repository.
    ///
    /// # Errors
    ///
    /// Returns [`LedgerGitError::NotInitialized`] when the worktree is absent or
    /// has not been synced yet.
    pub(crate) fn ensure_repo(&self) -> Result<(), LedgerGitError> {
        if self.workdir.join(".git").exists() {
            Ok(())
        } else {
            Err(LedgerGitError::NotInitialized {
                workdir: self.workdir.clone(),
            })
        }
    }

    /// Make sure a repository exists, cloning it when it does not.
    pub(crate) fn ensure_ready(&self) -> Result<(), LedgerGitError> {
        if self.workdir.join(".git").exists() {
            Ok(())
        } else {
            self.sync()
        }
    }

    fn clone_or_init(&self) -> Result<(), LedgerGitError> {
        if let Some(parent) = self.workdir.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|source| LedgerGitError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            }
        }

        if self.remote_has_branch()? {
            let mut command = git(&[
                "clone",
                "--quiet",
                "--branch",
                &self.branch,
                "--single-branch",
                &self.remote,
            ]);
            command.arg(&self.workdir);
            ok(command, "clone")?;
            return Ok(());
        }
        self.init_orphan_branch()
    }

    fn remote_has_branch(&self) -> Result<bool, LedgerGitError> {
        let reference = format!("refs/heads/{}", self.branch);
        let output = ok(
            git(&["ls-remote", "--heads", &self.remote, &reference]),
            "ls-remote",
        )?;
        Ok(!text(&output).is_empty())
    }

    fn init_orphan_branch(&self) -> Result<(), LedgerGitError> {
        let mut command = git(&["init", "--quiet"]);
        command.arg(&self.workdir);
        ok(command, "init")?;

        let reference = format!("refs/heads/{}", self.branch);
        ok(
            git_in(&self.workdir, &["symbolic-ref", "HEAD", &reference]),
            "symbolic-ref",
        )?;

        let readme = self.workdir.join(README_FILE);
        fs::write(&readme, README_CONTENT).map_err(|source| LedgerGitError::Io {
            path: readme.clone(),
            source,
        })?;
        ok(git_in(&self.workdir, &["add", "--", README_FILE]), "add")?;
        ok(
            git_in_identity(
                &self.workdir,
                &[
                    "commit",
                    "--quiet",
                    "-m",
                    "ledger: initialize",
                    "--",
                    README_FILE,
                ],
            ),
            "commit",
        )?;

        // A missing `origin` is not fatal: every command names the remote URL
        // explicitly, but a human in the worktree expects to see it.
        let _ = run(
            git_in(&self.workdir, &["remote", "add", "origin", &self.remote]),
            "remote add",
        );

        let refspec = format!("HEAD:{reference}");
        let push = run(
            git_in(&self.workdir, &["push", "--quiet", &self.remote, &refspec]),
            "push",
        )?;
        if push.status.success() {
            return Ok(());
        }

        // Another run bootstrapped the branch between our probe and our push:
        // adopt its tip instead of failing the first run.
        match self.fetch_and_reset() {
            Ok(()) => Ok(()),
            Err(_) => Err(failure(&push, "push")),
        }
    }

    fn fetch_and_reset(&self) -> Result<(), LedgerGitError> {
        self.ensure_repo()?;
        let status = ok(git_in(&self.workdir, &["status", "--porcelain"]), "status")?;
        if !text(&status).is_empty() {
            return Err(LedgerGitError::Dirty {
                workdir: self.workdir.clone(),
            });
        }

        let reference = format!("refs/heads/{}", self.branch);
        ok(
            git_in(
                &self.workdir,
                &["fetch", "--quiet", "--no-tags", &self.remote, &reference],
            ),
            "fetch",
        )?;

        // A run whose push was rejected leaves a commit that exists only here.
        // Resetting to the remote tip would delete it (and its run file), so
        // publish it first and refuse the sync when the remote has moved.
        let ahead = ok(
            git_in(&self.workdir, &["rev-list", "--count", "FETCH_HEAD..HEAD"]),
            "rev-list",
        )?;
        let ahead = text(&ahead)
            .parse::<u64>()
            .map_err(|error| LedgerGitError::Command {
                action: "rev-list".to_string(),
                status: "0".to_string(),
                stderr: format!("unexpected `git rev-list --count` output: {error}"),
            })?;
        if ahead > 0 {
            let refspec = format!("HEAD:refs/heads/{}", self.branch);
            let push = run(
                git_in(&self.workdir, &["push", "--quiet", &self.remote, &refspec]),
                "push",
            )?;
            if !push.status.success() {
                return Err(LedgerGitError::UnpushedCommits {
                    branch: self.branch.clone(),
                    count: ahead,
                    reason: String::from_utf8_lossy(&push.stderr).trim().to_string(),
                });
            }
            // The push made `HEAD` the remote tip; there is nothing to reset to
            // and `FETCH_HEAD` is stale now.
            return Ok(());
        }

        ok(
            git_in(&self.workdir, &["reset", "--quiet", "--hard", "FETCH_HEAD"]),
            "reset",
        )?;
        Ok(())
    }

    fn relative_path(&self, path: &Path) -> Result<String, LedgerGitError> {
        let relative =
            path.strip_prefix(&self.workdir)
                .map_err(|_| LedgerGitError::OutsideWorktree {
                    path: path.to_path_buf(),
                })?;
        if relative.as_os_str().is_empty() {
            return Err(LedgerGitError::OutsideWorktree {
                path: path.to_path_buf(),
            });
        }
        relative
            .to_str()
            .map(ToString::to_string)
            .ok_or_else(|| LedgerGitError::NonUtf8Path {
                path: path.to_path_buf(),
            })
    }
}

/// One lease holder, serialised as `lease.json` on the lease ref.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseHolder {
    /// Run that holds the lease.
    pub run_id: String,
    /// Host that ran it.
    pub host: String,
    /// Process id of the holder, for a human reading the ref.
    pub pid: u32,
    /// When the lease was acquired.
    pub acquired_at: DateTime<Utc>,
    /// After this instant the lease may be stolen.
    pub expires_at: DateTime<Utc>,
    /// Free-form note; empty for the mirror's own leases.
    #[serde(default)]
    pub note: String,
}

impl fmt::Display for LeaseHolder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "run `{}` on {} (pid {}) until {}",
            self.run_id,
            self.host,
            self.pid,
            self.expires_at.to_rfc3339_opts(SecondsFormat::Secs, true)
        )
    }
}

/// A lease this process holds on the ledger.
///
/// The lease is advisory: it is written to its own ref so a heartbeat never
/// touches an event file. Dropping it without [`Lease::release`] leaves the ref
/// behind until it expires.
#[derive(Debug)]
pub struct Lease {
    holder: LeaseHolder,
    taken_over: Option<LeaseHolder>,
    store: LedgerStore,
    ttl: ChronoDuration,
}

impl Lease {
    /// Take the ledger lease for `run_id`, or report who holds it.
    ///
    /// An unexpired lease held by another run is [`LeaseError::Busy`]; the same
    /// run may re-acquire its own lease. An expired lease is stolen and the
    /// previous holder is available through [`Lease::taken_over`], which is how
    /// the run records a `lease_taken_over` event.
    ///
    /// The write is pushed with `--force-with-lease` against the ref that was
    /// read. A rejected push is re-read once: a live foreign lease that appeared
    /// in the meantime is reported as [`LeaseError::Busy`].
    ///
    /// # Errors
    ///
    /// Returns [`LeaseError::Busy`] for a live foreign lease,
    /// [`LeaseError::InvalidRunId`] for a run id that cannot be a file name, and
    /// [`LeaseError::Git`] when the remote cannot be read or written.
    pub fn acquire(
        store: &LedgerStore,
        run_id: &str,
        ttl: Duration,
    ) -> Result<Option<Self>, LeaseError> {
        if !is_valid_run_id(run_id) {
            return Err(LeaseError::InvalidRunId {
                run_id: run_id.to_string(),
            });
        }
        let ttl = ChronoDuration::from_std(ttl).map_err(|_| LeaseError::InvalidTtl)?;
        store.ensure_ready()?;

        match acquire_once(store, run_id, ttl)? {
            Acquisition::Granted { holder, previous } => {
                Ok(Some(Self::granted(store, ttl, holder, previous)))
            }
            Acquisition::Busy(holder) => Err(LeaseError::Busy { holder }),
            Acquisition::Rejected(first) => {
                tracing::warn!(
                    %first,
                    "the lease push was rejected; re-reading the lease ref"
                );
                // The ref moved under us. Read it again: a live foreign lease is
                // the answer, anything else may simply be a retried heartbeat.
                match acquire_once(store, run_id, ttl)? {
                    Acquisition::Granted { holder, previous } => {
                        Ok(Some(Self::granted(store, ttl, holder, previous)))
                    }
                    Acquisition::Busy(holder) => Err(LeaseError::Busy { holder }),
                    Acquisition::Rejected(second) => Err(LeaseError::Git(second)),
                }
            }
        }
    }

    /// Build the handle after a successful push, logging a takeover once.
    fn granted(
        store: &LedgerStore,
        ttl: ChronoDuration,
        holder: LeaseHolder,
        previous: Option<LeaseHolder>,
    ) -> Self {
        if let Some(previous) = &previous {
            tracing::warn!(
                previous_run_id = %previous.run_id,
                previous_host = %previous.host,
                "taking over an expired ledger lease"
            );
        }
        Self {
            holder,
            taken_over: previous,
            store: store.clone(),
            ttl,
        }
    }

    /// The holder record this lease wrote.
    #[must_use]
    pub fn holder(&self) -> &LeaseHolder {
        &self.holder
    }

    /// The previous holder when this acquisition stole an expired lease.
    #[must_use]
    pub fn taken_over(&self) -> Option<&LeaseHolder> {
        self.taken_over.as_ref()
    }

    /// The `lease_taken_over` event for this run's event file, if a lease was
    /// stolen. The caller owns the sequence number.
    #[must_use]
    pub fn takeover_event(&self, seq: u64) -> Option<Event> {
        self.taken_over.as_ref().map(|previous| {
            Event::new(
                self.holder.run_id.clone(),
                seq,
                Utc::now(),
                super::EventKind::LeaseTakenOver,
            )
            .with_detail(json!({
                "previous_run_id": previous.run_id,
                "previous_host": previous.host,
                "previous_pid": previous.pid,
                "previous_expires_at": previous.expires_at
                    .to_rfc3339_opts(SecondsFormat::Millis, true),
            }))
        })
    }

    /// Extend the lease to `now + ttl` and push the new blob.
    ///
    /// A failed heartbeat is a warning, never a failed run: the local lease is
    /// kept and the next refresh tries again. Returns `Ok(false)` when the
    /// remote could not be updated or no longer holds this run's lease.
    ///
    /// # Errors
    ///
    /// The current implementation reports failures through `Ok(false)`; the
    /// result is only an error if a future implementation finds one that must
    /// stop the run.
    pub fn refresh(&mut self) -> Result<bool, LeaseError> {
        match self.try_refresh() {
            Ok(pushed) => Ok(pushed),
            Err(error) => {
                tracing::warn!(
                    %error,
                    "the ledger lease refresh failed; the run continues unleased"
                );
                Ok(false)
            }
        }
    }

    fn try_refresh(&mut self) -> Result<bool, LeaseError> {
        let Some((oid, current)) = read_lease(&self.store)? else {
            tracing::warn!("the ledger lease disappeared; the run continues unleased");
            return Ok(false);
        };
        if current.run_id != self.holder.run_id {
            tracing::warn!(
                holder = %current,
                "the ledger lease was taken over; the run continues unleased"
            );
            return Ok(false);
        }

        let mut holder = self.holder.clone();
        holder.expires_at = Utc::now() + self.ttl;
        push_lease(&self.store, &holder, Some(&oid))?;
        self.holder = holder;
        Ok(true)
    }

    /// Delete the lease ref, if this run still holds it.
    ///
    /// Best effort: the lease is deleted with `--force-with-lease` against the
    /// ref that was read, so a lease stolen by another run is never removed by
    /// mistake. A failure leaves the lease to expire and is only a warning.
    ///
    /// # Errors
    ///
    /// The current implementation reports failures as a warning and returns
    /// `Ok(())`; a run must not fail because its lease could not be dropped.
    pub fn release(self) -> Result<(), LeaseError> {
        if let Err(error) = self.try_release() {
            tracing::warn!(
                %error,
                "releasing the ledger lease failed; leaving it to expire"
            );
        }
        Ok(())
    }

    fn try_release(&self) -> Result<(), LedgerGitError> {
        let Some((oid, current)) = read_lease(&self.store)? else {
            let _ = run(
                git_in(&self.store.workdir, &["update-ref", "-d", LEASE_REF]),
                "update-ref",
            );
            return Ok(());
        };
        if current.run_id != self.holder.run_id {
            tracing::warn!(
                holder = %current,
                "not releasing a lease another run now holds"
            );
            return Ok(());
        }
        delete_lease(&self.store, &oid)
    }
}

/// One attempt at acquiring the lease.
enum Acquisition {
    /// The lease was written and pushed.
    Granted {
        /// The record that was pushed.
        holder: LeaseHolder,
        /// The previous holder when an expired lease was stolen.
        previous: Option<LeaseHolder>,
    },
    /// An unexpired lease is held by another run.
    Busy(LeaseHolder),
    /// The push lost a race; the caller may re-read once.
    Rejected(LedgerGitError),
}

fn acquire_once(
    store: &LedgerStore,
    run_id: &str,
    ttl: ChronoDuration,
) -> Result<Acquisition, LeaseError> {
    let remote = read_lease(store)?;
    let now = Utc::now();
    let previous = match &remote {
        Some((_, holder)) if holder.run_id != run_id && holder.expires_at > now => {
            return Ok(Acquisition::Busy(holder.clone()));
        }
        Some((_, holder)) if holder.run_id != run_id => Some(holder.clone()),
        _ => None,
    };

    let holder = LeaseHolder {
        run_id: run_id.to_string(),
        host: hostname(),
        pid: std::process::id(),
        acquired_at: now,
        expires_at: now + ttl,
        note: String::new(),
    };
    let expected = remote.as_ref().map(|(oid, _)| oid.as_str());
    match push_lease(store, &holder, expected) {
        Ok(()) => Ok(Acquisition::Granted { holder, previous }),
        Err(error) => Ok(Acquisition::Rejected(error)),
    }
}

/// Read the lease from the remote, fetching it into `FETCH_HEAD` first.
///
/// Returns the commit the lease was read from together with the record, so the
/// writer can push with `--force-with-lease` against exactly that commit.
fn read_lease(store: &LedgerStore) -> Result<Option<(String, LeaseHolder)>, LedgerGitError> {
    let output = ok(
        git(&["ls-remote", "--heads", &store.remote, LEASE_REF]),
        "ls-remote",
    )?;
    if text(&output).is_empty() {
        return Ok(None);
    }
    store.ensure_repo()?;
    ok(
        git_in(
            &store.workdir,
            &[
                "fetch",
                "--quiet",
                "--force",
                "--no-tags",
                &store.remote,
                LEASE_REF,
            ],
        ),
        "fetch lease",
    )?;
    let oid = text(&ok(
        git_in(&store.workdir, &["rev-parse", "FETCH_HEAD"]),
        "rev-parse",
    )?);

    let show = run(
        git_in(&store.workdir, &["show", &format!("{oid}:{LEASE_FILE}")]),
        "show lease",
    )?;
    if !show.status.success() {
        let stderr = String::from_utf8_lossy(&show.stderr);
        if stderr.contains("does not exist") || stderr.contains("exists on disk, but not in") {
            return Err(LedgerGitError::MissingLeaseFile {
                commit: oid,
                file: LEASE_FILE,
            });
        }
        return Err(failure(&show, "show lease"));
    }

    let holder = serde_json::from_slice::<LeaseHolder>(&show.stdout).map_err(|source| {
        LedgerGitError::LeaseJson {
            location: format!("{}:{LEASE_FILE}", store.remote),
            source,
        }
    })?;
    Ok(Some((oid, holder)))
}

/// Write and push a lease commit without checking out the lease branch.
///
/// The blob, tree and commit are built with plumbing so the ledger worktree
/// stays on the ledger branch and never sees a checkout conflict. Each lease
/// commit is a fresh root so the ref never accumulates heartbeat history: every
/// reader fetches exactly one small commit.
fn push_lease(
    store: &LedgerStore,
    holder: &LeaseHolder,
    expected: Option<&str>,
) -> Result<(), LedgerGitError> {
    store.ensure_repo()?;
    let mut body =
        serde_json::to_vec_pretty(holder).map_err(|source| LedgerGitError::LeaseJson {
            location: LEASE_FILE.to_string(),
            source,
        })?;
    body.push(b'\n');

    let blob = text(&check(
        run_with_stdin(
            git_in(&store.workdir, &["hash-object", "-w", "--stdin"]),
            &body,
            "hash-object",
        )?,
        "hash-object",
    )?);
    let tree_entry = format!("100644 blob {blob}\t{LEASE_FILE}\n");
    let tree = text(&check(
        run_with_stdin(
            git_in(&store.workdir, &["mktree"]),
            tree_entry.as_bytes(),
            "mktree",
        )?,
        "mktree",
    )?);

    let message = format!(
        "lease: {} until {}",
        holder.run_id,
        holder.expires_at.to_rfc3339_opts(SecondsFormat::Secs, true)
    );
    let commit = text(&ok(
        git_in_identity(
            &store.workdir,
            &["commit-tree", tree.as_str(), "-m", message.as_str()],
        ),
        "commit-tree",
    )?);

    let refspec = format!("{commit}:{LEASE_REF}");
    let expectation = match expected {
        Some(oid) => format!("--force-with-lease={LEASE_REF}:{oid}"),
        // An empty expectation means "the ref must not exist yet".
        None => format!("--force-with-lease={LEASE_REF}:"),
    };
    ok(
        git_in(
            &store.workdir,
            &["push", "--quiet", &expectation, &store.remote, &refspec],
        ),
        "push lease",
    )?;
    ok(
        git_in(&store.workdir, &["update-ref", LEASE_REF, &commit]),
        "update-ref lease",
    )?;
    Ok(())
}

fn delete_lease(store: &LedgerStore, expected: &str) -> Result<(), LedgerGitError> {
    let expectation = format!("--force-with-lease={LEASE_REF}:{expected}");
    ok(
        git_in(
            &store.workdir,
            &[
                "push",
                "--quiet",
                &expectation,
                &store.remote,
                &format!(":{LEASE_REF}"),
            ],
        ),
        "delete lease",
    )?;
    let _ = run(
        git_in(&store.workdir, &["update-ref", "-d", LEASE_REF]),
        "update-ref delete",
    );
    Ok(())
}

/// Best-effort host name for the lease record.
fn hostname() -> String {
    let mut buffer = [0_u8; 256];
    // SAFETY: the buffer is valid for its declared length and `gethostname`
    // only writes within it.
    let result = unsafe { libc::gethostname(buffer.as_mut_ptr().cast(), buffer.len()) };
    if result == 0 {
        let length = buffer
            .iter()
            .position(|byte| *byte == 0)
            .unwrap_or(buffer.len());
        if let Ok(name) = std::str::from_utf8(&buffer[..length]) {
            if !name.is_empty() {
                return name.to_string();
            }
        }
    }
    std::env::var("HOSTNAME")
        .ok()
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| "unknown".to_string())
}

fn is_rejection(stderr: &str) -> bool {
    ["non-fast-forward", "fetch first", "rejected"]
        .iter()
        .any(|needle| stderr.contains(needle))
}

fn configure(mut command: Command) -> Command {
    // A CI image has no terminal; prompting would hang the mirror.
    command.env("GIT_TERMINAL_PROMPT", "0");
    command
}

fn git(args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command.args(args);
    configure(command)
}

fn git_in(workdir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(workdir).args(args);
    configure(command)
}

fn git_in_identity(workdir: &Path, args: &[&str]) -> Command {
    let mut command = Command::new("git");
    command.arg("-C").arg(workdir).args(IDENTITY).args(args);
    configure(command)
}

fn run(mut command: Command, action: &str) -> Result<Output, LedgerGitError> {
    command.output().map_err(|source| LedgerGitError::Process {
        action: action.to_string(),
        source,
    })
}

fn run_with_stdin(
    mut command: Command,
    input: &[u8],
    action: &str,
) -> Result<Output, LedgerGitError> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(|source| LedgerGitError::Process {
        action: action.to_string(),
        source,
    })?;
    if let Some(mut stdin) = child.stdin.take() {
        stdin
            .write_all(input)
            .map_err(|source| LedgerGitError::Process {
                action: action.to_string(),
                source,
            })?;
    }
    child
        .wait_with_output()
        .map_err(|source| LedgerGitError::Process {
            action: action.to_string(),
            source,
        })
}

fn check(output: Output, action: &str) -> Result<Output, LedgerGitError> {
    if output.status.success() {
        Ok(output)
    } else {
        Err(failure(&output, action))
    }
}

fn ok(command: Command, action: &str) -> Result<Output, LedgerGitError> {
    check(run(command, action)?, action)
}

fn failure(output: &Output, action: &str) -> LedgerGitError {
    LedgerGitError::Command {
        action: action.to_string(),
        status: output
            .status
            .code()
            .map_or_else(|| "signal".to_string(), |code| code.to_string()),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    }
}

fn text(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).trim().to_string()
}

/// Errors raised by git operations on the ledger.
#[derive(Debug, Error)]
pub enum LedgerGitError {
    /// git could not be started or could not be talked to.
    #[error("cannot run git {action}: {source}")]
    Process {
        /// The failing operation.
        action: String,
        /// Underlying process error.
        #[source]
        source: io::Error,
    },

    /// A git command exited non-zero.
    #[error("git {action} failed ({status}): {stderr}")]
    Command {
        /// The failing operation.
        action: String,
        /// Exit code, or `signal`.
        status: String,
        /// Trimmed stderr.
        stderr: String,
    },

    /// A local file could not be read or written.
    #[error("i/o failed for {path}: {source}")]
    Io {
        /// Path the operation was working on.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The worktree has not been cloned yet.
    #[error("ledger worktree {} is not a git repository", .workdir.display())]
    NotInitialized {
        /// The worktree that is missing.
        workdir: PathBuf,
    },

    /// The worktree has local changes that `sync` will not discard.
    #[error("ledger worktree {} has uncommitted changes", .workdir.display())]
    Dirty {
        /// The worktree holding the changes.
        workdir: PathBuf,
    },

    /// A path belongs to a different worktree than the store.
    #[error("ledger path {} is outside the worktree", .path.display())]
    OutsideWorktree {
        /// The rejected path.
        path: PathBuf,
    },

    /// A path cannot be passed to git as an argument.
    #[error("path {} is not valid UTF-8", .path.display())]
    NonUtf8Path {
        /// The rejected path.
        path: PathBuf,
    },

    /// Every push attempt lost the race or was refused.
    #[error("push to `{branch}` was rejected after {attempts} attempts: {reason}")]
    PushRejected {
        /// The branch that was pushed.
        branch: String,
        /// How many attempts were made.
        attempts: u32,
        /// Last stderr from git.
        reason: String,
    },

    /// The worktree has commits the remote does not have, and they do not
    /// fast-forward onto the remote tip.
    #[error(
        "the ledger worktree has {count} unpushed commit(s) on `{branch}` \
         that the remote cannot fast-forward: {reason}"
    )]
    UnpushedCommits {
        /// The branch that has local commits.
        branch: String,
        /// How many commits exist only locally.
        count: u64,
        /// Last stderr from the failed push.
        reason: String,
    },

    /// The lease blob is not valid JSON.
    #[error("cannot decode the lease at {location}: {source}")]
    LeaseJson {
        /// Where the lease was read from.
        location: String,
        /// Underlying parse error.
        #[source]
        source: serde_json::Error,
    },

    /// The lease ref exists but does not contain a lease.
    #[error("lease commit {commit} has no {file}")]
    MissingLeaseFile {
        /// The commit the ref points at.
        commit: String,
        /// The file that is missing.
        file: &'static str,
    },
}

/// Errors raised by the ledger lease.
#[derive(Debug, Error)]
pub enum LeaseError {
    /// Another run holds an unexpired lease.
    #[error("the ledger lease is busy: {holder}")]
    Busy {
        /// Who holds it.
        holder: LeaseHolder,
    },

    /// The run id cannot be part of a file name or a lease.
    #[error("run id `{run_id}` cannot own the ledger lease")]
    InvalidRunId {
        /// The rejected run id.
        run_id: String,
    },

    /// The requested ttl does not fit a timestamp.
    #[error("the lease ttl is out of range")]
    InvalidTtl,

    /// A git operation failed.
    #[error(transparent)]
    Git(#[from] LedgerGitError),
}
