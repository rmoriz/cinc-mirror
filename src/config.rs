//! Configuration model for `mirror.toml`.
//!
//! The file is the single source of truth for what is mirrored: every project
//! is an explicit policy and every target is named. Unknown keys are errors so
//! a typo cannot silently widen or narrow a run.

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use serde::de::{self, SeqAccess, Unexpected, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::version::{Version, VersionGlob};

/// Name of the configuration file discovered in the working directory when no
/// explicit path is given.
pub const DEFAULT_CONFIG_FILE: &str = "mirror.toml";

/// Errors raised while loading, validating or overriding configuration.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("cannot read config file {}: {source}", path.display())]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    #[error("cannot parse config file {}: {source}", path.display())]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },

    #[error("duplicate policy id `{0}`")]
    DuplicatePolicyId(String),

    #[error("duplicate target name `{0}`")]
    DuplicateTargetName(String),

    #[error("{context}: field `{field}` must not be empty")]
    EmptyField {
        context: String,
        field: &'static str,
    },

    #[error(
        "policy `{policy_id}`: platform_versions references platform `{platform}` \
         which is not listed in platforms"
    )]
    PlatformVersionForUnlistedPlatform { policy_id: String, platform: String },

    #[error(
        "invalid version bound `{value}`: expected dot-separated numeric segments \
         such as `19.4.46`"
    )]
    InvalidVersionBound { value: String },

    #[error(
        "invalid version glob `{value}`: expected dot-separated numeric segments, \
         `*` or `?`"
    )]
    InvalidVersionGlob { value: String },

    #[error("{context}: min_version `{min}` is above max_version `{max}`")]
    MinAboveMax {
        context: String,
        min: String,
        max: String,
    },

    #[error("unknown --set key `{0}`")]
    UnknownSetKey(String),

    #[error("invalid --set override `{0}`: expected <key>=<value>")]
    InvalidOverride(String),

    #[error("invalid value `{value}` for --set key `{key}`: expected {expected}")]
    InvalidSetValue {
        key: String,
        value: String,
        expected: &'static str,
    },

    #[error("invalid transport `{0}`: expected ftp, ftps or https")]
    InvalidTransport(String),

    #[error("target `{name}` is invalid: {reason}")]
    InvalidTarget { name: String, reason: String },

    #[error("metadata_transport must be `https`")]
    MetadataTransportNotHttps,

    #[error("`{field}` must be greater than zero")]
    ZeroConcurrency { field: &'static str },
}

/// Payload transports, in ladder order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TransportKind {
    Ftp,
    Ftps,
    Https,
}

impl fmt::Display for TransportKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Ftp => "ftp",
            Self::Ftps => "ftps",
            Self::Https => "https",
        })
    }
}

impl FromStr for TransportKind {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "ftp" => Ok(Self::Ftp),
            "ftps" => Ok(Self::Ftps),
            "https" => Ok(Self::Https),
            other => Err(ConfigError::InvalidTransport(other.to_string())),
        }
    }
}

/// An exact allow-list or the `*` wildcard.
///
/// Serialises as `"*"` or an array of values, matching the TOML spelling.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Selection {
    #[default]
    All,
    Only(Vec<String>),
}

impl Selection {
    /// Whether every value is allowed.
    #[must_use]
    pub fn is_all(&self) -> bool {
        match self {
            Self::All => true,
            Self::Only(values) => values.iter().any(|value| value == "*"),
        }
    }

    /// Whether `value` is allowed by this selection.
    #[must_use]
    pub fn allows(&self, value: &str) -> bool {
        match self {
            Self::All => true,
            Self::Only(values) => values.iter().any(|item| item == "*" || item == value),
        }
    }
}

impl fmt::Display for Selection {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::All => formatter.write_str("*"),
            Self::Only(values) => formatter.write_str(&values.join(",")),
        }
    }
}

impl Serialize for Selection {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::All => serializer.serialize_str("*"),
            Self::Only(values) => values.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Selection {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SelectionVisitor;

        impl<'de> Visitor<'de> for SelectionVisitor {
            type Value = Selection;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("`\"*\"` or an array of names")
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: de::Error,
            {
                if value == "*" {
                    Ok(Selection::All)
                } else {
                    Err(E::invalid_value(Unexpected::Str(value), &self))
                }
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(value) = sequence.next_element::<String>()? {
                    values.push(value);
                }
                Ok(Selection::Only(values))
            }
        }

        deserializer.deserialize_any(SelectionVisitor)
    }
}

/// Ledger branch and remote.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct LedgerConfig {
    pub branch: String,
    pub remote: String,
}

impl Default for LedgerConfig {
    fn default() -> Self {
        Self {
            branch: "ledger".to_string(),
            remote: "origin".to_string(),
        }
    }
}

/// One mirrored project, scoped to a channel and an allow-list of versions,
/// platforms and architectures.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectPolicy {
    pub id: String,
    pub project: String,
    pub channel: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_version: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub versions: Vec<String>,
    #[serde(default)]
    pub all_versions: bool,
    #[serde(default)]
    pub platforms: Selection,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub platform_versions: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub arches: Selection,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

impl ProjectPolicy {
    /// A policy with an id and otherwise empty scope, ready for `--set` to
    /// complete it.
    #[must_use]
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            project: String::new(),
            channel: String::new(),
            min_version: None,
            max_version: None,
            versions: Vec::new(),
            all_versions: false,
            platforms: Selection::All,
            platform_versions: BTreeMap::new(),
            arches: Selection::All,
            enabled: true,
        }
    }

    #[must_use]
    pub fn with_project(mut self, project: impl Into<String>) -> Self {
        self.project = project.into();
        self
    }

    #[must_use]
    pub fn with_channel(mut self, channel: impl Into<String>) -> Self {
        self.channel = channel.into();
        self
    }

    fn set_field(&mut self, field: &str, value: &str, key: &str) -> Result<(), ConfigError> {
        match field {
            "project" => {
                self.project = non_empty_value(key, value, "a non-empty project name")?;
            }
            "channel" => {
                self.channel = non_empty_value(key, value, "a non-empty channel name")?;
            }
            "min_version" => self.min_version = Some(checked_version_bound(value)?),
            "max_version" => self.max_version = Some(checked_version_bound(value)?),
            "versions" => {
                let values = parse_list(key, value)?;
                for glob in &values {
                    parse_version_glob(glob)?;
                }
                self.versions = values;
            }
            "all_versions" => self.all_versions = parse_bool(key, value)?,
            "platforms" => self.platforms = parse_selection(key, value)?,
            "arches" => self.arches = parse_selection(key, value)?,
            "enabled" => self.enabled = parse_bool(key, value)?,
            _ => return Err(ConfigError::UnknownSetKey(key.to_string())),
        }
        Ok(())
    }
}

/// What kind of target receives artifacts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Oci,
    Rsync,
}

impl fmt::Display for TargetKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Oci => "oci",
            Self::Rsync => "rsync",
        })
    }
}

/// How a target authenticates.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetAuth {
    Docker,
    Basic,
    Bearer,
    #[default]
    Anonymous,
    #[serde(rename = "ssh-key")]
    SshKey,
    Daemon,
}

impl fmt::Display for TargetAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Docker => "docker",
            Self::Basic => "basic",
            Self::Bearer => "bearer",
            Self::Anonymous => "anonymous",
            Self::SshKey => "ssh-key",
            Self::Daemon => "daemon",
        })
    }
}

/// One publication target.
///
/// Credential material itself is never stored here; `auth` selects where it is
/// read from at use time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetConfig {
    pub name: String,
    pub kind: TargetKind,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub namespace: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(default)]
    pub auth: TargetAuth,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_bandwidth: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password_file: Option<PathBuf>,
}

impl TargetConfig {
    /// Validate fields that depend on the target kind.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.name.trim().is_empty() {
            return Err(ConfigError::EmptyField {
                context: "target".to_string(),
                field: "name",
            });
        }

        match self.kind {
            TargetKind::Oci => {
                if trim_optional(self.registry.as_deref()).is_none() {
                    return Err(invalid_target(&self.name, "oci targets require `registry`"));
                }
                if trim_optional(self.namespace.as_deref()).is_none() {
                    return Err(invalid_target(
                        &self.name,
                        "oci targets require `namespace`",
                    ));
                }
                if !matches!(
                    self.auth,
                    TargetAuth::Docker
                        | TargetAuth::Basic
                        | TargetAuth::Bearer
                        | TargetAuth::Anonymous
                ) {
                    return Err(invalid_target(
                        &self.name,
                        format!("auth `{}` is not valid for an oci target", self.auth),
                    ));
                }
            }
            TargetKind::Rsync => {
                let Some(url) = trim_optional(self.url.as_deref()) else {
                    return Err(invalid_target(&self.name, "rsync targets require `url`"));
                };
                let wants_ssh = url.starts_with("ssh://");
                let wants_daemon = url.starts_with("rsync://");
                if !wants_ssh && !wants_daemon {
                    return Err(invalid_target(
                        &self.name,
                        "rsync url must start with `ssh://` or `rsync://`",
                    ));
                }
                match self.auth {
                    TargetAuth::SshKey if wants_ssh => {}
                    TargetAuth::Daemon if wants_daemon => {}
                    TargetAuth::SshKey | TargetAuth::Daemon => {
                        return Err(invalid_target(
                            &self.name,
                            format!(
                                "auth `{}` does not match the address form of `{url}`",
                                self.auth
                            ),
                        ));
                    }
                    other => {
                        return Err(invalid_target(
                            &self.name,
                            format!(
                                "auth `{other}` is not valid for an rsync target \
                                 (use `ssh-key` or `daemon`)"
                            ),
                        ));
                    }
                }
            }
        }

        Ok(())
    }
}

/// The complete configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Config {
    pub state_dir: PathBuf,
    pub concurrency: u32,
    pub upload_concurrency: u32,
    pub max_bandwidth: String,
    pub transport: Vec<TransportKind>,
    pub metadata_transport: TransportKind,
    pub min_version: Option<String>,
    pub projects: Vec<ProjectPolicy>,
    pub ledger: LedgerConfig,
    pub targets: Vec<TargetConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            state_dir: PathBuf::from("~/.local/state/cinc-mirror"),
            concurrency: 4,
            upload_concurrency: 2,
            max_bandwidth: "0".to_string(),
            transport: vec![
                TransportKind::Ftp,
                TransportKind::Ftps,
                TransportKind::Https,
            ],
            metadata_transport: TransportKind::Https,
            min_version: None,
            projects: Vec::new(),
            ledger: LedgerConfig::default(),
            targets: Vec::new(),
        }
    }
}

impl Config {
    /// Load configuration from `path`, or from [`DEFAULT_CONFIG_FILE`] in the
    /// working directory, or fall back to defaults when neither exists.
    ///
    /// An explicitly requested file must exist. Loading does not validate;
    /// call [`Config::validate`] before acting on the result.
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigError> {
        match path {
            Some(path) => Self::load_file(path),
            None => {
                let default = Path::new(DEFAULT_CONFIG_FILE);
                if default.is_file() {
                    Self::load_file(default)
                } else {
                    Ok(Self::default())
                }
            }
        }
    }

    fn load_file(path: &Path) -> Result<Self, ConfigError> {
        let contents = fs::read_to_string(path).map_err(|source| ConfigError::Read {
            path: path.to_path_buf(),
            source,
        })?;

        toml::from_str(&contents).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    /// Validate cross-field invariants. This performs no network access.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.state_dir.as_os_str().is_empty() {
            return Err(ConfigError::EmptyField {
                context: "config".to_string(),
                field: "state_dir",
            });
        }
        if self.concurrency == 0 {
            return Err(ConfigError::ZeroConcurrency {
                field: "concurrency",
            });
        }
        if self.upload_concurrency == 0 {
            return Err(ConfigError::ZeroConcurrency {
                field: "upload_concurrency",
            });
        }
        if self.transport.is_empty() {
            return Err(ConfigError::EmptyField {
                context: "config".to_string(),
                field: "transport",
            });
        }
        if self.metadata_transport != TransportKind::Https {
            return Err(ConfigError::MetadataTransportNotHttps);
        }
        if let Some(min) = &self.min_version {
            parse_version_bound(min)?;
        }

        let global_floor = self.min_version.as_deref();
        let mut policy_ids = HashSet::new();
        for policy in &self.projects {
            if policy.id.trim().is_empty() {
                return Err(ConfigError::EmptyField {
                    context: "project policy".to_string(),
                    field: "id",
                });
            }
            if !policy_ids.insert(policy.id.as_str()) {
                return Err(ConfigError::DuplicatePolicyId(policy.id.clone()));
            }
            if policy.project.trim().is_empty() {
                return Err(ConfigError::EmptyField {
                    context: format!("policy `{}`", policy.id),
                    field: "project",
                });
            }
            if policy.channel.trim().is_empty() {
                return Err(ConfigError::EmptyField {
                    context: format!("policy `{}`", policy.id),
                    field: "channel",
                });
            }

            for bound in [policy.min_version.as_deref(), policy.max_version.as_deref()]
                .into_iter()
                .flatten()
            {
                parse_version_bound(bound)?;
            }
            for glob in &policy.versions {
                parse_version_glob(glob)?;
            }

            let fallback = if policy.all_versions {
                None
            } else {
                global_floor
            };
            let floor = policy.min_version.as_deref().or(fallback);
            if let (Some(min), Some(max)) = (floor, policy.max_version.as_deref()) {
                if compare_version_bounds(min, max)? == Ordering::Greater {
                    return Err(ConfigError::MinAboveMax {
                        context: format!("policy `{}`", policy.id),
                        min: min.to_string(),
                        max: max.to_string(),
                    });
                }
            }

            if !policy.platforms.is_all() {
                for platform in policy.platform_versions.keys() {
                    if !policy.platforms.allows(platform) {
                        return Err(ConfigError::PlatformVersionForUnlistedPlatform {
                            policy_id: policy.id.clone(),
                            platform: platform.clone(),
                        });
                    }
                }
            }
        }

        let mut target_names = HashSet::new();
        for target in &self.targets {
            target.validate()?;
            if !target_names.insert(target.name.as_str()) {
                return Err(ConfigError::DuplicateTargetName(target.name.clone()));
            }
        }

        Ok(())
    }

    /// Apply `--set <key>=<value>` overrides in place.
    ///
    /// Policy ids are addressed as `<id>.<field>`; a bare key (or
    /// `ledger.<field>`) targets a global setting. An unknown policy id adds a
    /// policy that later overrides must complete. Values are syntax-checked but
    /// the resulting configuration still needs [`Config::validate`].
    pub fn apply_overrides(&mut self, overrides: &[String]) -> Result<(), ConfigError> {
        for raw in overrides {
            let (key, value) = raw
                .split_once('=')
                .ok_or_else(|| ConfigError::InvalidOverride(raw.clone()))?;
            if key.is_empty() {
                return Err(ConfigError::InvalidOverride(raw.clone()));
            }

            match key.rsplit_once('.') {
                Some(("ledger", field)) => match field {
                    "branch" => {
                        self.ledger.branch =
                            non_empty_value(key, value, "a non-empty branch name")?;
                    }
                    "remote" => {
                        self.ledger.remote =
                            non_empty_value(key, value, "a non-empty remote name")?;
                    }
                    _ => return Err(ConfigError::UnknownSetKey(key.to_string())),
                },
                Some((policy_id, field)) => {
                    let index = match self
                        .projects
                        .iter()
                        .position(|policy| policy.id == policy_id)
                    {
                        Some(index) => index,
                        None => {
                            self.projects.push(ProjectPolicy::new(policy_id));
                            self.projects.len() - 1
                        }
                    };
                    self.projects[index].set_field(field, value, key)?;
                }
                None => self.set_global_field(key, value)?,
            }
        }

        Ok(())
    }

    fn set_global_field(&mut self, key: &str, value: &str) -> Result<(), ConfigError> {
        match key {
            "state_dir" => {
                self.state_dir = PathBuf::from(non_empty_value(key, value, "a path")?);
            }
            "concurrency" => self.concurrency = parse_u32(key, value)?,
            "upload_concurrency" => self.upload_concurrency = parse_u32(key, value)?,
            "max_bandwidth" => {
                self.max_bandwidth = non_empty_value(
                    key,
                    value,
                    "a bandwidth such as `40MiB/s` or `0` for unlimited",
                )?;
            }
            "transport" => self.transport = parse_transport_list(key, value)?,
            "metadata_transport" => {
                self.metadata_transport = value
                    .trim()
                    .parse::<TransportKind>()
                    .map_err(|_| ConfigError::InvalidTransport(value.trim().to_string()))?;
            }
            "min_version" => self.min_version = Some(checked_version_bound(value)?),
            _ => return Err(ConfigError::UnknownSetKey(key.to_string())),
        }

        Ok(())
    }
}

fn default_true() -> bool {
    true
}

fn invalid_target(name: &str, reason: impl Into<String>) -> ConfigError {
    ConfigError::InvalidTarget {
        name: name.to_string(),
        reason: reason.into(),
    }
}

fn trim_optional(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn parse_version_bound(value: &str) -> Result<Version, ConfigError> {
    Version::from_str(value).map_err(|_| ConfigError::InvalidVersionBound {
        value: value.to_string(),
    })
}

fn parse_version_glob(value: &str) -> Result<VersionGlob, ConfigError> {
    VersionGlob::from_str(value).map_err(|_| ConfigError::InvalidVersionGlob {
        value: value.to_string(),
    })
}

fn compare_version_bounds(left: &str, right: &str) -> Result<Ordering, ConfigError> {
    Ok(parse_version_bound(left)?.cmp(&parse_version_bound(right)?))
}

fn set_value_error(key: &str, value: &str, expected: &'static str) -> ConfigError {
    ConfigError::InvalidSetValue {
        key: key.to_string(),
        value: value.to_string(),
        expected,
    }
}

fn non_empty_value(key: &str, value: &str, expected: &'static str) -> Result<String, ConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        Err(set_value_error(key, value, expected))
    } else {
        Ok(trimmed.to_string())
    }
}

fn checked_version_bound(value: &str) -> Result<String, ConfigError> {
    let trimmed = value.trim();
    parse_version_bound(trimmed)?;
    Ok(trimmed.to_string())
}

fn parse_u32(key: &str, value: &str) -> Result<u32, ConfigError> {
    value
        .trim()
        .parse::<u32>()
        .map_err(|_| set_value_error(key, value, "a non-negative integer"))
}

fn parse_bool(key: &str, value: &str) -> Result<bool, ConfigError> {
    match value.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(set_value_error(key, value, "`true` or `false`")),
    }
}

fn parse_list(key: &str, value: &str) -> Result<Vec<String>, ConfigError> {
    let expected = "a comma-separated list of non-empty values";
    value
        .split(',')
        .map(|item| {
            let item = item.trim();
            if item.is_empty() {
                Err(set_value_error(key, value, expected))
            } else {
                Ok(item.to_string())
            }
        })
        .collect()
}

fn parse_selection(key: &str, value: &str) -> Result<Selection, ConfigError> {
    let trimmed = value.trim();
    if trimmed == "*" {
        Ok(Selection::All)
    } else {
        parse_list(key, value).map(Selection::Only)
    }
}

fn parse_transport_list(key: &str, value: &str) -> Result<Vec<TransportKind>, ConfigError> {
    parse_list(key, value)?
        .iter()
        .map(|item| TransportKind::from_str(item))
        .collect()
}
