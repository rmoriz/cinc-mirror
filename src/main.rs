use std::path::{Path, PathBuf};
use std::process;

use anyhow::bail;
use cinc_mirror::cli::{Cli, Command, ConfigCommand};
use cinc_mirror::config::{
    Config, ConfigError, ProjectPolicy, TargetConfig, TargetKind, DEFAULT_CONFIG_FILE,
};
use clap::Parser;

const EXIT_OK: i32 = 0;
const EXIT_ERROR: i32 = 1;
const EXIT_CONFIG: i32 = 5;
const EXIT_USAGE: i32 = 64;

fn main() {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(error) => {
            let informational = matches!(
                error.kind(),
                clap::error::ErrorKind::DisplayHelp | clap::error::ErrorKind::DisplayVersion
            );
            let _ = error.print();
            process::exit(if informational { EXIT_OK } else { EXIT_USAGE });
        }
    };

    if let Err(error) = run(cli) {
        eprintln!("error: {error:#}");
        let code = if error.downcast_ref::<ConfigError>().is_some() {
            EXIT_CONFIG
        } else {
            EXIT_ERROR
        };
        process::exit(code);
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let config_path = selected_config_path(cli.config);

    match cli.cmd {
        Command::Config { action } => match action {
            ConfigCommand::Check => {
                let config = Config::load(config_path.as_deref())?;
                config.validate()?;
                print_config(config_path.as_deref(), &config);
            }
        },
        command => bail!("not implemented: {}", command.name()),
    }

    Ok(())
}

/// Mirror the discovery [`Config::load`] performs so the check can report which
/// file (if any) was used.
fn selected_config_path(explicit: Option<PathBuf>) -> Option<PathBuf> {
    explicit.or_else(|| {
        let default = PathBuf::from(DEFAULT_CONFIG_FILE);
        default.is_file().then_some(default)
    })
}

fn print_config(path: Option<&Path>, config: &Config) {
    match path {
        Some(path) => println!("config: {}", path.display()),
        None => println!("config: none (built-in defaults)"),
    }
    println!("state_dir: {}", config.state_dir.display());
    println!(
        "concurrency: {} downloads, {} uploads",
        config.concurrency, config.upload_concurrency
    );
    println!("max_bandwidth: {}", config.max_bandwidth);
    println!(
        "transport: {}",
        config
            .transport
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("metadata_transport: {}", config.metadata_transport);
    println!(
        "ledger: {} branch {}",
        config.ledger.remote, config.ledger.branch
    );

    println!("policies: {}", config.projects.len());
    for policy in &config.projects {
        println!(
            "  {}",
            describe_policy(policy, config.min_version.as_deref())
        );
    }

    let enabled = config
        .targets
        .iter()
        .filter(|target| target.enabled)
        .count();
    println!("targets: {} ({} enabled)", config.targets.len(), enabled);
    for target in &config.targets {
        println!("  {}", describe_target(target));
    }

    println!("config OK");
}

fn describe_policy(policy: &ProjectPolicy, global_floor: Option<&str>) -> String {
    let floor = policy
        .min_version
        .as_deref()
        .or(global_floor)
        .unwrap_or("-");
    let ceiling = policy.max_version.as_deref().unwrap_or("-");
    let mut versions = format!("{floor}..{ceiling}");
    if policy.all_versions {
        versions.push_str(",all_versions");
    }
    if !policy.versions.is_empty() {
        versions.push_str(&format!(",globs={}", policy.versions.join(",")));
    }

    let state = if policy.enabled { "" } else { " disabled" };
    format!(
        "{} project={} channel={} versions={} platforms={} arches={}{}",
        policy.id, policy.project, policy.channel, versions, policy.platforms, policy.arches, state
    )
}

fn describe_target(target: &TargetConfig) -> String {
    let state = if target.enabled {
        "enabled"
    } else {
        "disabled"
    };

    match target.kind {
        TargetKind::Oci => format!(
            "{} kind={} {} auth={} registry={}/{}",
            target.name,
            target.kind,
            state,
            target.auth,
            target.registry.as_deref().unwrap_or("-"),
            target.namespace.as_deref().unwrap_or("-")
        ),
        TargetKind::Rsync => format!(
            "{} kind={} {} auth={} url={}",
            target.name,
            target.kind,
            state,
            target.auth,
            target
                .url
                .as_deref()
                .map(redact_url)
                .unwrap_or_else(|| "-".to_string())
        ),
    }
}

/// Hide a password embedded in URL userinfo. Configuration never needs one, but
/// a user may paste one, and `config check` output must not echo secrets.
fn redact_url(url: &str) -> String {
    let Some((scheme, rest)) = url.split_once("://") else {
        return url.to_string();
    };

    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, Some(path)),
        None => (rest, None),
    };

    let authority = match authority.rsplit_once('@') {
        Some((userinfo, host)) if userinfo.contains(':') => {
            let user = userinfo.split_once(':').map_or(userinfo, |(user, _)| user);
            format!("{user}:***@{host}")
        }
        _ => authority.to_string(),
    };

    match path {
        Some(path) => format!("{scheme}://{authority}/{path}"),
        None => format!("{scheme}://{authority}"),
    }
}
