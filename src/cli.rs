//! Command-line surface.
//!
//! Subcommands are declared here as they are specified; behaviour is added task
//! by task. Anything that is not implemented yet fails loudly rather than
//! pretending to work.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::config::{Config, ConfigError};
use crate::scope::ScopeArgs;

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
    Plan(PlanArgs),
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
            Self::Plan(_) => "plan",
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

/// Scope filters shared by `mirror`, `backfill` and `plan`.
///
/// The flags are parsed here and resolved by [`crate::scope`]; this type only
/// carries them so the command surface stays in one place.
#[derive(Debug, Args)]
pub struct ScopeFilterArgs {
    /// Project or policy id to run; repeatable
    #[arg(long = "project", value_name = "P")]
    pub projects: Vec<String>,

    /// Run every enabled policy
    #[arg(long)]
    pub everything: bool,

    /// Additional version globs; a version must match these and the policy
    #[arg(long = "versions", value_name = "SPEC")]
    pub versions: Vec<String>,

    /// Clear the effective version bounds
    #[arg(long)]
    pub all_versions: bool,

    /// Additional platform allow-list, or `*`
    #[arg(long = "platform", value_name = "P")]
    pub platforms: Vec<String>,

    /// `<version>` or `<platform>/<version>` allow-list; repeatable
    #[arg(long = "platform-version", value_name = "V")]
    pub platform_versions: Vec<String>,

    /// Architecture allow-list, or `*`
    #[arg(long = "arch", value_name = "A")]
    pub arches: Vec<String>,

    /// Raise the effective version floor
    #[arg(long = "min-version", value_name = "V")]
    pub min_version: Option<String>,

    /// Override a configuration field as `<key>=<value>`
    #[arg(long = "set", value_name = "KEY=VALUE")]
    pub set: Vec<String>,
}

impl ScopeFilterArgs {
    /// Project the parsed flags onto [`ScopeArgs`].
    #[must_use]
    pub fn to_scope_args(&self) -> ScopeArgs {
        ScopeArgs {
            projects: self.projects.clone(),
            everything: self.everything,
            versions: self.versions.clone(),
            all_versions: self.all_versions,
            platforms: self.platforms.clone(),
            platform_versions: self.platform_versions.clone(),
            arches: self.arches.clone(),
            min_version: self.min_version.clone(),
        }
    }

    /// Apply `--set` overrides to `config` before resolution.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] for a malformed override or an unknown key.
    pub fn apply_sets(&self, config: &mut Config) -> Result<(), ConfigError> {
        config.apply_overrides(&self.set)
    }
}

/// Which grouping the text report highlights.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum PlanGrouping {
    #[default]
    Project,
    Platform,
    Arch,
    Target,
}

/// Arguments to `plan`.
#[derive(Debug, Args)]
pub struct PlanArgs {
    #[command(flatten)]
    pub filters: ScopeFilterArgs,

    /// Print the plan as JSON instead of a text summary
    #[arg(long)]
    pub json: bool,

    /// Group the summary by project, platform, arch or target
    #[arg(long, value_enum, default_value_t = PlanGrouping::Project)]
    pub by: PlanGrouping,

    /// Write the plan JSON to this file instead of `plan-<run_id>.json`
    #[arg(long, value_name = "FILE")]
    pub out: Option<PathBuf>,

    /// Append a plan event to the ledger
    #[arg(long)]
    pub record: bool,
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
