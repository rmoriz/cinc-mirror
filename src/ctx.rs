//! The state one command needs, shared by the runner, verify, repair and
//! bootstrap.
//!
//! Construction is the caller's job (`main` after the ledger is synced and the
//! lease is held): [`Ctx`] deliberately does not open, sync or commit anything.
//! The ledger is behind a [`tokio::sync::Mutex`] because its SQLite connection
//! is not `Sync` and every command serialises ledger access through it; the
//! other fields are cheaply shared.
//!
//! The source carries its payload ladder already, and the rate limiter is passed
//! explicitly to downloads by the runner, so a [`Ctx`] can be cloned into a
//! worker pool without reconnecting.

use std::path::PathBuf;
use std::sync::Arc;

use tokio::sync::Mutex;

use crate::config::Config;
use crate::ledger::Ledger;
use crate::net::RateLimiter;
use crate::scope::ResolvedScope;
use crate::source::Source;
use crate::store::Store;
use crate::targets::TargetSet;

/// Everything a run needs, built once by the command layer.
#[derive(Debug)]
pub struct Ctx {
    /// The validated configuration; `run_id`, limits and order are per run.
    pub config: Arc<Config>,
    /// Policies selected for this run.
    pub scope: ResolvedScope,
    /// Upstream listings, metadata and payloads.
    pub source: Source,
    /// Content-addressed package bytes.
    pub store: Store,
    /// The ledger database, serialised behind one async mutex.
    pub ledger: Mutex<Ledger>,
    /// Every enabled publication target, in configuration order.
    pub targets: TargetSet,
    /// Shared download bandwidth cap.
    pub rate: Arc<RateLimiter>,
    /// Identifier of the current run; it prefixes every event this run appends.
    pub run_id: String,
    /// Expanded state directory, so helpers do not re-resolve `~`.
    pub state_dir: PathBuf,
}
