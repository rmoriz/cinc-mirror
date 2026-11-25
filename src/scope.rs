//! Scope resolution: configuration policies intersected with CLI filters.
//!
//! Resolution is always: config -> `--set` (already applied to [`Config`]) ->
//! CLI filters -> intersection. Filters narrow, except `--all-versions`, which
//! clears the effective version bounds. Policies are returned in configuration
//! order so two runs over the same configuration produce the same work.
//!
//! The resolver does no I/O: it is a pure function of the configuration and the
//! requested filters.

use std::collections::BTreeMap;

use thiserror::Error;

use crate::config::{Config, ProjectPolicy, Selection};
use crate::version::{Version, VersionError, VersionGlob, VersionGlobError};

/// CLI filters applied on top of the configuration.
///
/// This mirrors the filter flags of `mirror`, `plan` and `backfill` without
/// depending on the CLI layer, so resolution stays testable on its own.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ScopeArgs {
    /// `--project`: policy ids, or bare project names selecting every policy
    /// for that project.
    pub projects: Vec<String>,
    /// `--everything`: every enabled policy. Mutually exclusive with
    /// [`ScopeArgs::projects`].
    pub everything: bool,
    /// `--versions`: additional version globs; a version must match both the
    /// policy globs and these.
    pub versions: Vec<String>,
    /// `--all-versions`: clear the effective min/max bounds.
    pub all_versions: bool,
    /// `--platform`: additional platform allow-list, or `*`.
    pub platforms: Vec<String>,
    /// `--platform-version`: `<version>` or `<platform>/<version>` allow-list.
    pub platform_versions: Vec<String>,
    /// `--arch`: additional architecture allow-list, or `*`.
    pub arches: Vec<String>,
    /// `--min-version`: raises the effective floor, never lowers it.
    pub min_version: Option<String>,
}

/// A `--platform-version` filter entry.
///
/// `debian/13` restricts one platform; a bare `13` matches that platform
/// version on any platform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformVersion {
    pub platform: Option<String>,
    pub version: String,
}

impl PlatformVersion {
    fn parse(value: &str) -> Result<Self, ScopeError> {
        match value.split_once('/') {
            Some((platform, version)) => {
                if platform.is_empty() || version.is_empty() || version.contains('/') {
                    return Err(ScopeError::InvalidPlatformVersion {
                        value: value.to_string(),
                    });
                }
                Ok(Self {
                    platform: Some(platform.to_string()),
                    version: version.to_string(),
                })
            }
            None => {
                if value.is_empty() {
                    return Err(ScopeError::InvalidPlatformVersion {
                        value: value.to_string(),
                    });
                }
                Ok(Self {
                    platform: None,
                    version: value.to_string(),
                })
            }
        }
    }

    /// Whether this filter allows `platform`/`version`.
    #[must_use]
    pub fn matches(&self, platform: &str, version: &str) -> bool {
        if self.version != version {
            return false;
        }
        match &self.platform {
            Some(expected) => expected == platform,
            None => true,
        }
    }
}

/// One policy after configuration, `--set` and CLI filters are combined.
///
/// Use the `allows_*` methods for decisions. `versions` and `platform_versions`
/// are the policy's own allow-lists; `cli_versions` and
/// `cli_platform_versions` are the additional CLI allow-lists, and a value must
/// satisfy both layers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPolicy {
    pub id: String,
    pub project: String,
    pub channel: String,
    /// Effective floor, after the global floor, the policy floor and CLI
    /// narrowing. `None` means unbounded.
    pub min_version: Option<Version>,
    /// Effective ceiling. `None` means unbounded.
    pub max_version: Option<Version>,
    /// The policy's version globs; empty means every version.
    pub versions: Vec<VersionGlob>,
    /// Additional `--versions` globs; empty means no extra restriction.
    pub cli_versions: Vec<VersionGlob>,
    pub platforms: Selection,
    pub platform_versions: BTreeMap<String, Vec<String>>,
    pub cli_platform_versions: Vec<PlatformVersion>,
    pub arches: Selection,
    /// Whether the effective bounds were widened by the policy flag or
    /// `--all-versions`.
    pub all_versions: bool,
}

impl ResolvedPolicy {
    /// Whether `version` is inside the effective bounds and matches every
    /// configured glob layer.
    #[must_use]
    pub fn allows_version(&self, version: &Version) -> bool {
        if let Some(min) = &self.min_version {
            if version < min {
                return false;
            }
        }
        if let Some(max) = &self.max_version {
            if version > max {
                return false;
            }
        }
        if !self.versions.is_empty() && !self.versions.iter().any(|glob| glob.matches(version)) {
            return false;
        }
        if !self.cli_versions.is_empty()
            && !self.cli_versions.iter().any(|glob| glob.matches(version))
        {
            return false;
        }
        true
    }

    /// Whether `platform` is selected.
    #[must_use]
    pub fn allows_platform(&self, platform: &str) -> bool {
        self.platforms.allows(platform)
    }

    /// Whether `platform`/`version` is selected.
    ///
    /// A platform without an entry in either allow-list is unrestricted.
    #[must_use]
    pub fn allows_platform_version(&self, platform: &str, version: &str) -> bool {
        if let Some(allowed) = self.platform_versions.get(platform) {
            if !allowed.iter().any(|item| item == version) {
                return false;
            }
        }
        if self.cli_platform_versions.is_empty() {
            return true;
        }
        self.cli_platform_versions
            .iter()
            .any(|filter| filter.matches(platform, version))
    }

    /// Whether `arch` is selected.
    #[must_use]
    pub fn allows_arch(&self, arch: &str) -> bool {
        self.arches.allows(arch)
    }
}

/// The policies selected for one run, in configuration order.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ResolvedScope {
    pub policies: Vec<ResolvedPolicy>,
}

impl ResolvedScope {
    /// Number of selected policies.
    #[must_use]
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// Whether no policy was selected.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}

/// Why a scope could not be resolved.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ScopeError {
    #[error(transparent)]
    InvalidVersion(#[from] VersionError),

    #[error(transparent)]
    InvalidVersionGlob(#[from] VersionGlobError),

    #[error("--everything cannot be combined with --project `{project}`")]
    EverythingWithProject { project: String },

    #[error("unknown project or policy selector `{selector}`")]
    UnknownProject { selector: String },

    #[error(
        "invalid platform version filter `{value}`: \
         expected `VERSION` or `PLATFORM/VERSION`"
    )]
    InvalidPlatformVersion { value: String },

    #[error(
        "policy `{policy_id}`: min_version `{min}` is above max_version `{max}` \
         after CLI filters"
    )]
    MinAboveMax {
        policy_id: String,
        min: String,
        max: String,
    },
}

impl Config {
    /// Resolve the configured policies against `args`.
    ///
    /// `--set` overrides must already be stored on the configuration; call
    /// [`Config::apply_overrides`] first. The configuration is not validated
    /// here, but malformed bounds or globs found during resolution are reported
    /// as [`ScopeError`].
    pub fn resolve(&self, args: &ScopeArgs) -> Result<ResolvedScope, ScopeError> {
        if args.everything {
            if let Some(project) = args.projects.first() {
                return Err(ScopeError::EverythingWithProject {
                    project: project.clone(),
                });
            }
        }

        let filters = Filters::from_args(args)?;
        let global_floor = match &self.min_version {
            Some(raw) => Some(raw.parse::<Version>()?),
            None => None,
        };

        let mut policies = Vec::new();
        for policy in self.select(args)? {
            policies.push(resolve_policy(policy, global_floor.as_ref(), &filters)?);
        }

        Ok(ResolvedScope { policies })
    }

    /// Policies in configuration order. Without `--project`, only enabled
    /// policies run (whether or not `--everything` is given). An explicit
    /// `--project` also reaches a disabled policy, so a single policy can be
    /// tested without editing the configuration.
    fn select<'config>(
        &'config self,
        args: &ScopeArgs,
    ) -> Result<Vec<&'config ProjectPolicy>, ScopeError> {
        if args.projects.is_empty() {
            return Ok(self
                .projects
                .iter()
                .filter(|policy| policy.enabled)
                .collect());
        }

        let mut selected = vec![false; self.projects.len()];
        for selector in &args.projects {
            let mut matched_id = false;
            for (index, policy) in self.projects.iter().enumerate() {
                if policy.id == *selector {
                    selected[index] = true;
                    matched_id = true;
                }
            }
            if matched_id {
                continue;
            }

            let mut matched_project = false;
            for (index, policy) in self.projects.iter().enumerate() {
                if policy.project == *selector {
                    selected[index] = true;
                    matched_project = true;
                }
            }
            if !matched_project {
                return Err(ScopeError::UnknownProject {
                    selector: selector.clone(),
                });
            }
        }

        Ok(self
            .projects
            .iter()
            .zip(selected)
            .filter_map(|(policy, chosen)| chosen.then_some(policy))
            .collect())
    }
}

/// CLI filters in their parsed form.
struct Filters {
    versions: Vec<VersionGlob>,
    min_version: Option<Version>,
    platforms: Selection,
    platform_versions: Vec<PlatformVersion>,
    arches: Selection,
    all_versions: bool,
}

impl Filters {
    fn from_args(args: &ScopeArgs) -> Result<Self, ScopeError> {
        let versions = args
            .versions
            .iter()
            .map(|raw| raw.parse::<VersionGlob>().map_err(ScopeError::from))
            .collect::<Result<Vec<_>, _>>()?;
        let min_version = match &args.min_version {
            Some(raw) => Some(raw.parse::<Version>()?),
            None => None,
        };
        let platform_versions = args
            .platform_versions
            .iter()
            .map(|raw| PlatformVersion::parse(raw))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Self {
            versions,
            min_version,
            platforms: selection_filter(&args.platforms),
            platform_versions,
            arches: selection_filter(&args.arches),
            all_versions: args.all_versions,
        })
    }
}

fn resolve_policy(
    policy: &ProjectPolicy,
    global_floor: Option<&Version>,
    filters: &Filters,
) -> Result<ResolvedPolicy, ScopeError> {
    let own_floor = match &policy.min_version {
        Some(raw) => Some(raw.parse::<Version>()?),
        None => None,
    };
    let ceiling = match &policy.max_version {
        Some(raw) => Some(raw.parse::<Version>()?),
        None => None,
    };

    // `all_versions` clears the global fallback, not the policy's own floor.
    let default_floor = if policy.all_versions {
        None
    } else {
        global_floor.cloned()
    };
    let mut floor = own_floor.or(default_floor);
    let mut max = ceiling;
    let mut all_versions = policy.all_versions;

    if filters.all_versions {
        floor = None;
        max = None;
        all_versions = true;
    }
    if let Some(cli_min) = &filters.min_version {
        let raises = match &floor {
            Some(current) => cli_min > current,
            None => true,
        };
        if raises {
            floor = Some(cli_min.clone());
        }
    }

    if let (Some(min), Some(max)) = (&floor, &max) {
        if min > max {
            return Err(ScopeError::MinAboveMax {
                policy_id: policy.id.clone(),
                min: min.to_string(),
                max: max.to_string(),
            });
        }
    }

    let versions = policy
        .versions
        .iter()
        .map(|raw| raw.parse::<VersionGlob>().map_err(ScopeError::from))
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ResolvedPolicy {
        id: policy.id.clone(),
        project: policy.project.clone(),
        channel: policy.channel.clone(),
        min_version: floor,
        max_version: max,
        versions,
        cli_versions: filters.versions.clone(),
        platforms: intersect(&policy.platforms, &filters.platforms),
        platform_versions: policy.platform_versions.clone(),
        cli_platform_versions: filters.platform_versions.clone(),
        arches: intersect(&policy.arches, &filters.arches),
        all_versions,
    })
}

fn selection_filter(values: &[String]) -> Selection {
    if values.is_empty() || values.iter().any(|value| value == "*") {
        Selection::All
    } else {
        Selection::Only(values.to_vec())
    }
}

/// Intersect two allow-lists, preserving the order of `base`.
fn intersect(base: &Selection, filter: &Selection) -> Selection {
    if filter.is_all() {
        return base.clone();
    }
    if base.is_all() {
        return filter.clone();
    }

    match base {
        Selection::Only(values) => Selection::Only(
            values
                .iter()
                .filter(|value| filter.allows(value))
                .cloned()
                .collect(),
        ),
        Selection::All => filter.clone(),
    }
}
