//! Command-line surface.
//!
//! Subcommands are declared here as they are specified; behaviour is added task
//! by task. Anything that is not implemented yet fails loudly rather than
//! pretending to work.

use std::path::PathBuf;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(
    name = "cinc-mirror",
    version,
    about = "Mirror CINC packages to OCI registries and rsync targets"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Command,

    /// Path to mirror.toml [default: ./mirror.toml when present]
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Crawl upstream and publish every new artifact
    Mirror,
    /// Estimate a run without downloading or publishing package bytes
    Plan,
    /// Fill historical versions that are not mirrored yet
    Backfill,
    /// Re-hash and compare known artifacts
    Verify,
    /// Re-publish or re-fetch artifacts that need repair
    Repair,
    /// Inspect and acknowledge integrity incidents
    Incidents {
        #[command(subcommand)]
        action: IncidentsCommand,
    },
    /// Manage the committed ledger
    Ledger {
        #[command(subcommand)]
        action: LedgerCommand,
    },
    /// Inspect configured targets
    Targets {
        #[command(subcommand)]
        action: TargetsCommand,
    },
    /// Validate configuration
    Config {
        #[command(subcommand)]
        action: ConfigCommand,
    },
}

impl Command {
    /// Stable subcommand name for diagnostics.
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Self::Mirror => "mirror",
            Self::Plan => "plan",
            Self::Backfill => "backfill",
            Self::Verify => "verify",
            Self::Repair => "repair",
            Self::Incidents { .. } => "incidents",
            Self::Ledger { .. } => "ledger",
            Self::Targets { .. } => "targets",
            Self::Config { .. } => "config",
        }
    }
}

#[derive(Debug, Subcommand)]
pub enum IncidentsCommand {
    /// List open incidents
    List,
    /// Show one incident
    Show { id: String },
    /// Acknowledge an incident
    Ack {
        id: String,
        /// Move the descriptive tag to the replacement digest
        #[arg(long)]
        republish: bool,
        /// Note recorded with the acknowledgement
        #[arg(short, long)]
        note: Option<String>,
    },
}

#[derive(Debug, Subcommand)]
pub enum LedgerCommand {
    /// Rebuild ledger rows from an existing mirror
    Bootstrap,
    /// Fetch the ledger branch
    Pull,
    /// Push the ledger branch
    Push,
    /// Compact ledger segments
    Compact,
    /// Garbage-collect superseded ledger data
    Gc,
    /// Export ledger rows
    Export,
}

#[derive(Debug, Subcommand)]
pub enum TargetsCommand {
    /// List configured targets
    List,
    /// Probe configured targets
    Check,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Validate the configuration without network access
    Check,
}
