//! Command-line surface.
//!
//! Subcommands are declared here as they are specified; behaviour is added task
//! by task. Anything that is not implemented yet fails loudly rather than
//! pretending to work.

use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

use crate::config::{Config, ConfigError};
use crate::repair::RepairOpts;
use crate::runner::{Order, RunOpts};
use crate::scope::ScopeArgs;
use crate::verify::VerifyOpts;

/// How tracing events are rendered on stderr.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum LogFormat {
    /// Human-readable lines.
    #[default]
    Text,
    /// One JSON object per event, for a log collector.
    Json,
}

#[derive(Debug, Parser)]
#[command(
    name = "cinc-mirror",
    version,
    about = "Mirror Cinc packages to OCI registries and rsync targets"
)]
pub struct Cli {
    #[command(subcommand)]
    pub cmd: Command,

    /// Path to mirror.toml [default: ./mirror.toml when present]
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Continue when the ledger lease cannot be taken because the remote is
    /// unreachable; a live lease held by another run still refuses the run
    #[arg(long, global = true)]
    pub allow_unleased: bool,

    /// Format of tracing output on stderr
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Text)]
    pub log_format: LogFormat,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Crawl upstream and publish every new artifact
    Mirror(MirrorArgs),
    /// Estimate a run without downloading or publishing package bytes
    Plan(PlanArgs),
    /// Fill historical versions that are not mirrored yet
    Backfill(BackfillArgs),
    /// Re-hash and compare known artifacts
    Verify(VerifyArgs),
    /// Re-publish or re-fetch artifacts that need repair
    Repair(RepairArgs),
    /// Delete publications the policy no longer selects
    #[command(long_about = "Delete publications the policy no longer selects.\n\n\
                      The command crawls upstream to learn what the policies still want, \
                      then deletes what it still finds, at most `--limit` references per \
                      target. It neither downloads nor publishes package bytes.")]
    Prune(PruneArgs),
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
            Self::Mirror(_) => "mirror",
            Self::Plan(_) => "plan",
            Self::Backfill(_) => "backfill",
            Self::Verify(_) => "verify",
            Self::Repair(_) => "repair",
            Self::Prune(_) => "prune",
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

/// The `--order` spelling.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, ValueEnum)]
pub enum OrderChoice {
    /// Version descending, then the policy and path components.
    ///
    /// Projects are interleaved, so a run advances every project instead of
    /// draining one project's whole history first.
    #[default]
    VersionDesc,
    /// Smallest known size first.
    SmallestFirst,
    /// Largest known size first.
    LargestFirst,
}

impl OrderChoice {
    /// Map the parsed flag onto the runner's order.
    #[must_use]
    pub fn to_order(self) -> Order {
        match self {
            Self::VersionDesc => Order::VersionDesc,
            Self::SmallestFirst => Order::SmallestFirst,
            Self::LargestFirst => Order::LargestFirst,
        }
    }
}

/// Queue and limit flags shared by `mirror` and `backfill`.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Stop after this many artifacts
    #[arg(long = "limit", value_name = "N", value_parser = parse_positive)]
    pub limit: Option<usize>,

    /// Stop once this many download bytes were transferred (the crossing
    /// artifact is finished); accepts units such as 2GiB or 500MB
    #[arg(long = "limit-bytes", value_name = "SIZE", value_parser = parse_byte_size)]
    pub limit_bytes: Option<u64>,

    /// Queue order
    #[arg(long = "order", value_enum, default_value_t = OrderChoice::VersionDesc)]
    pub order: OrderChoice,

    /// Delete each store blob once every enabled target has published it
    #[arg(long)]
    pub gc_after: bool,

    /// Delete publications the policy no longer selects at the end of the run
    /// (default: `[retention] prune`)
    #[arg(long)]
    pub prune: bool,

    /// Report what would happen without downloading or publishing (a prune
    /// deletes the first candidate per target as a capability probe)
    #[arg(long)]
    pub dry_run: bool,

    /// Print the summary as JSON instead of one text line
    #[arg(long)]
    pub json: bool,
}

impl RunArgs {
    /// Project the parsed flags onto [`RunOpts`].
    #[must_use]
    pub fn to_run_opts(&self) -> RunOpts {
        RunOpts {
            max_artifacts: self.limit,
            max_bytes: self.limit_bytes,
            order: self.order.to_order(),
            gc_after: self.gc_after,
            prune: self.prune,
            dry_run: self.dry_run,
            ..RunOpts::default()
        }
    }
}

/// Accept a positive count for `--limit`.
fn parse_positive(raw: &str) -> Result<usize, String> {
    let value: usize = raw
        .parse()
        .map_err(|_| "expected a positive integer".to_string())?;
    if value == 0 {
        return Err("the limit must be greater than zero".to_string());
    }
    Ok(value)
}

/// Arguments to `verify`.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// Verify only these targets; repeatable (default: every enabled target)
    #[arg(long = "target", value_name = "NAME")]
    pub targets: Vec<String>,

    /// Re-hash the local store blobs as well
    #[arg(long, conflicts_with = "sample")]
    pub deep: bool,

    /// Check a deterministic sample of this many artifacts
    #[arg(long, value_name = "N", value_parser = parse_sample)]
    pub sample: Option<usize>,

    /// Print the report as JSON
    #[arg(long)]
    pub json: bool,
}

impl VerifyArgs {
    /// Project the parsed flags onto [`VerifyOpts`].
    #[must_use]
    pub fn to_opts(&self) -> VerifyOpts {
        VerifyOpts {
            targets: non_empty(&self.targets),
            deep: self.deep,
            sample: self.sample,
        }
    }
}

/// Arguments to `repair`.
#[derive(Debug, Args)]
pub struct RepairArgs {
    /// Repair only these targets; repeatable (default: every enabled target)
    #[arg(long = "target", value_name = "NAME")]
    pub targets: Vec<String>,

    /// Repair only these projects; repeatable (default: every project in the
    /// ledger)
    #[arg(long = "project", value_name = "P")]
    pub projects: Vec<String>,

    /// Repair at most this many broken publications
    #[arg(long = "limit", value_name = "N", value_parser = parse_positive)]
    pub limit: Option<usize>,

    /// Also restore publications a prune deleted (re-downloads and re-publishes
    /// them)
    #[arg(long)]
    pub include_pruned: bool,

    /// Print the report as JSON
    #[arg(long)]
    pub json: bool,
}

impl RepairArgs {
    /// Project the parsed flags onto [`RepairOpts`].
    #[must_use]
    pub fn to_opts(&self) -> RepairOpts {
        RepairOpts {
            targets: non_empty(&self.targets),
            projects: non_empty(&self.projects),
            limit: self.limit,
            include_pruned: self.include_pruned,
        }
    }
}

/// Arguments to `prune`.
#[derive(Debug, Args)]
pub struct PruneArgs {
    #[command(flatten)]
    pub filters: ScopeFilterArgs,

    /// Prune only these oci targets; repeatable (default: every enabled oci
    /// target)
    #[arg(long = "target", value_name = "NAME")]
    pub targets: Vec<String>,

    /// Delete at most this many references per target (default: `[retention]
    /// max_deletions`)
    #[arg(long = "limit", value_name = "N", value_parser = parse_positive)]
    pub limit: Option<usize>,

    /// Report what would be deleted without deleting (the first reference per
    /// target is deleted for real to probe the endpoint)
    #[arg(long)]
    pub dry_run: bool,

    /// Print the report as JSON
    #[arg(long)]
    pub json: bool,
}

/// `None` when the repeatable flag was not given at all.
fn non_empty(values: &[String]) -> Option<Vec<String>> {
    (!values.is_empty()).then(|| values.to_vec())
}

/// Accept a positive artifact count for `--sample`.
fn parse_sample(raw: &str) -> Result<usize, String> {
    let value: usize = raw
        .parse()
        .map_err(|_| "expected a positive integer".to_string())?;
    if value == 0 {
        return Err("the sample must be greater than zero".to_string());
    }
    Ok(value)
}

/// Arguments to `mirror`.
#[derive(Debug, Args)]
pub struct MirrorArgs {
    #[command(flatten)]
    pub filters: ScopeFilterArgs,

    #[command(flatten)]
    pub run: RunArgs,
}

/// Arguments to `backfill`: the mirror flags plus the stored resume cursor.
#[derive(Debug, Args)]
pub struct BackfillArgs {
    #[command(flatten)]
    pub filters: ScopeFilterArgs,

    #[command(flatten)]
    pub run: RunArgs,
}

/// Parse a byte size such as `500`, `2GiB` or `1.5GB`.
///
/// Decimal units are powers of ten and `*iB` units are powers of two, matching
/// the bandwidth parser. A value of zero is accepted by the parser and rejected
/// by the runner as a usage error, so the flag parses and the failure has one
/// home.
fn parse_byte_size(raw: &str) -> Result<u64, String> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("expected a byte size such as `2GiB` or `500MB`".to_string());
    }

    let split = value
        .find(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    let amount: f64 = number
        .parse()
        .map_err(|_| "the size is not a number".to_string())?;
    if !amount.is_finite() || amount < 0.0 {
        return Err("the size must be a finite, non-negative number".to_string());
    }

    let multiplier: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" => 1_000,
        "kib" => 1_024,
        "m" | "mb" => 1_000_000,
        "mib" => 1_048_576,
        "g" | "gb" => 1_000_000_000,
        "gib" => 1_073_741_824,
        "t" | "tb" => 1_000_000_000_000,
        "tib" => 1_099_511_627_776,
        _ => {
            return Err(
                "expected B, KiB, MiB, GiB or TiB (decimal KB/MB/GB/TB also accepted)".to_string(),
            )
        }
    };

    let bytes = amount * multiplier as f64;
    if !bytes.is_finite() || bytes > u64::MAX as f64 {
        return Err("the size is too large".to_string());
    }
    Ok(bytes.round() as u64)
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
    /// List incidents, open first and newest first
    List {
        /// Print the list as a JSON array
        #[arg(long)]
        json: bool,
    },
    /// Show one incident
    Show { id: String },
    /// Acknowledge an incident
    Ack {
        id: String,
        /// Move the descriptive tag to the replacement digest
        #[arg(long)]
        republish: bool,
        /// Note recorded with the acknowledgement
        #[arg(short = 'm', long)]
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
    Check {
        /// Also probe every enabled target (auth, registry and rsync host)
        #[arg(long)]
        probe: bool,
    },
}

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::{Cli, Command, IncidentsCommand};

    #[test]
    fn allow_unleased_parses_before_and_after_the_subcommand() {
        let before = Cli::try_parse_from(["cinc-mirror", "--allow-unleased", "mirror"])
            .expect("a global flag before the subcommand");
        assert!(before.allow_unleased);
        assert!(matches!(before.cmd, Command::Mirror(_)));

        let after = Cli::try_parse_from(["cinc-mirror", "backfill", "--allow-unleased"])
            .expect("a global flag after the subcommand");
        assert!(after.allow_unleased);
        assert!(matches!(after.cmd, Command::Backfill(_)));

        let default = Cli::try_parse_from(["cinc-mirror", "mirror"]).expect("no flag");
        assert!(!default.allow_unleased);
    }

    #[test]
    fn incidents_ack_parses_republish_and_the_short_note() {
        let cli = Cli::try_parse_from([
            "cinc-mirror",
            "incidents",
            "ack",
            "hash_changed-0123456789abcdef",
            "--republish",
            "-m",
            "checked upstream",
        ])
        .expect("ack arguments");

        let Command::Incidents {
            action:
                IncidentsCommand::Ack {
                    id,
                    republish,
                    note,
                },
        } = cli.cmd
        else {
            panic!("expected incidents ack");
        };
        assert_eq!(id, "hash_changed-0123456789abcdef");
        assert!(republish);
        assert_eq!(note.as_deref(), Some("checked upstream"));
    }

    #[test]
    fn mirror_parses_limits_order_and_gc() {
        let cli = Cli::try_parse_from([
            "cinc-mirror",
            "mirror",
            "--limit",
            "3",
            "--limit-bytes",
            "2GiB",
            "--order",
            "smallest-first",
            "--gc-after",
            "--dry-run",
        ])
        .expect("mirror arguments");

        let Command::Mirror(args) = cli.cmd else {
            panic!("expected mirror");
        };
        let opts = args.run.to_run_opts();
        assert_eq!(opts.max_artifacts, Some(3));
        assert_eq!(opts.max_bytes, Some(2_147_483_648));
        assert_eq!(opts.order, crate::runner::Order::SmallestFirst);
        assert!(opts.gc_after);
        assert!(opts.dry_run);
    }

    #[test]
    fn verify_parses_targets_deep_and_sample() {
        let cli = Cli::try_parse_from([
            "cinc-mirror",
            "verify",
            "--target",
            "oci",
            "--target",
            "rsync",
            "--deep",
        ])
        .expect("verify arguments");

        let Command::Verify(args) = cli.cmd else {
            panic!("expected verify");
        };
        let opts = args.to_opts();
        assert_eq!(
            opts.targets,
            Some(vec!["oci".to_string(), "rsync".to_string()])
        );
        assert!(opts.deep);
        assert_eq!(opts.sample, None);

        let default = Cli::try_parse_from(["cinc-mirror", "verify"]).expect("no flags");
        let Command::Verify(args) = default.cmd else {
            panic!("expected verify");
        };
        assert_eq!(args.to_opts().targets, None);
        assert!(!args.to_opts().deep);
    }

    #[test]
    fn verify_rejects_deep_with_sample_and_a_zero_sample() {
        for arguments in [
            vec!["cinc-mirror", "verify", "--deep", "--sample", "2"],
            vec!["cinc-mirror", "verify", "--sample", "0"],
        ] {
            assert!(
                Cli::try_parse_from(arguments.clone()).is_err(),
                "{arguments:?} must be rejected"
            );
        }
    }

    #[test]
    fn repair_parses_targets_projects_and_limit() {
        let cli = Cli::try_parse_from([
            "cinc-mirror",
            "repair",
            "--target",
            "rsync",
            "--project",
            "cinc",
            "--project",
            "omnibus-toolchain",
            "--limit",
            "4",
        ])
        .expect("repair arguments");

        let Command::Repair(args) = cli.cmd else {
            panic!("expected repair");
        };
        let opts = args.to_opts();
        assert_eq!(opts.targets, Some(vec!["rsync".to_string()]));
        assert_eq!(
            opts.projects,
            Some(vec!["cinc".to_string(), "omnibus-toolchain".to_string()])
        );
        assert_eq!(opts.limit, Some(4));
    }

    #[test]
    fn repair_without_project_keeps_every_project() {
        let cli = Cli::try_parse_from(["cinc-mirror", "repair"]).expect("repair arguments");
        let Command::Repair(args) = cli.cmd else {
            panic!("expected repair");
        };
        assert_eq!(args.to_opts().projects, None);
    }

    #[test]
    fn byte_sizes_accept_units_and_zero() {
        assert_eq!(super::parse_byte_size("512"), Ok(512));
        assert_eq!(super::parse_byte_size("2GiB"), Ok(2_147_483_648));
        assert_eq!(super::parse_byte_size("500MB"), Ok(500_000_000));
        assert_eq!(super::parse_byte_size("0"), Ok(0));
        for value in ["", "fast", "-1MiB", "1XiB"] {
            assert!(
                super::parse_byte_size(value).is_err(),
                "`{value}` must be rejected"
            );
        }
    }
}
