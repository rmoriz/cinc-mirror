//! Plan: the same crawl and diff as `mirror`, without downloading or
//! publishing.
//!
//! `plan` never takes the ledger lease and writes nothing to the ledger. It
//! learns which artifacts are already satisfied from the caller, which keeps
//! the estimate testable before the ledger exists and lets the CLI pass
//! `ledger.satisfied_keys()` at wiring time.
//!
//! Sizes are advisory (upstream metadata has no size), so an unresolvable size
//! counts as zero bytes rather than failing the estimate. Free space is reported
//! the same way: a plan larger than the disk is a useful plan, not an error.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

use serde::Serialize;
use serde_json::{json, Value};
use thiserror::Error;

use crate::artifact::Artifact;
use crate::config::Config;
use crate::crawl::{collect_tag_collisions, crawl, dedup_collisions, CrawlError, TagCollision};
use crate::fsutil::free_bytes;
use crate::scope::{ResolvedPolicy, ResolvedScope};
use crate::source::{Source, SourceError};

/// How many of the largest single artifacts a plan reports.
const LARGEST_LIMIT: usize = 20;

/// Totals for one group (project, platform, architecture or target).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct GroupTotals {
    /// Artifacts in the group.
    pub artifacts: usize,
    /// Sum of their sizes in bytes.
    pub bytes: u64,
    /// Bytes of artifacts the caller reported as satisfied.
    pub satisfied_bytes: u64,
}

/// The state-directory free-space check.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpaceCheck {
    /// State directory that was checked.
    pub state_dir: String,
    /// Free bytes, or `None` when the filesystem cannot answer.
    pub free_bytes: Option<u64>,
    /// Bytes that still have to be downloaded.
    pub required_bytes: u64,
    /// Whether `required_bytes` fits in `free_bytes`; `None` when unknown.
    pub fits: Option<bool>,
}

/// One tag collision as the plan reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CollisionDetail {
    /// Descriptive tag both artifacts claim.
    pub tag: String,
    /// Canonical key of the artifact the crawl keeps.
    pub kept: String,
    /// Canonical key of the artifact the crawl excludes.
    pub conflicting: String,
    /// Upstream path of the excluded artifact, which may be an alias path.
    pub upstream_path: String,
}

impl CollisionDetail {
    fn new(collision: &TagCollision) -> Self {
        Self {
            tag: collision.tag.clone(),
            kept: collision.first.key(),
            conflicting: collision.conflicting.key(),
            upstream_path: collision.upstream_path.clone(),
        }
    }
}

/// The estimate produced by [`build`].
#[derive(Debug, Clone, Serialize)]
pub struct Plan {
    /// Number of crawled artifacts, satisfied ones included.
    pub artifacts: usize,
    /// Sum of all artifact sizes.
    pub total_bytes: u64,
    /// Bytes of artifacts the caller reported as satisfied.
    pub satisfied_bytes: u64,
    /// Tag collisions the crawl reported. The conflicting artifacts are
    /// excluded from every count; `mirror` opens an incident for each.
    pub collisions: usize,
    /// The collisions behind [`Plan::collisions`], for inspection.
    pub collision_details: Vec<CollisionDetail>,
    /// Metadata documents the crawl could not represent because their
    /// platform or version contradicts the upstream directory.
    pub skipped: usize,
    /// Totals per project.
    pub by_project: BTreeMap<String, GroupTotals>,
    /// Totals per platform.
    pub by_platform: BTreeMap<String, GroupTotals>,
    /// Totals per public architecture.
    pub by_arch: BTreeMap<String, GroupTotals>,
    /// Totals per enabled target. Every enabled target receives every artifact,
    /// so each entry mirrors the overall totals.
    pub by_target: BTreeMap<String, GroupTotals>,
    /// Largest single artifacts as `(canonical key, bytes)`, at most
    /// [`LARGEST_LIMIT`] entries, size descending then key ascending.
    pub largest: Vec<(String, u64)>,
    /// Free-space report for the state directory.
    pub space: SpaceCheck,
    /// The resolved policies this estimate describes.
    pub effective_policy: Value,
    /// Projected download duration at the configured bandwidth, when capped.
    pub projected_seconds: Option<u64>,
}

impl Plan {
    /// Serialise the plan as pretty, deterministic JSON.
    ///
    /// Struct fields serialise in declaration order and every map is a
    /// `BTreeMap`, so two calls on the same plan produce identical bytes.
    /// These types cannot fail to serialise; the fallback keeps the signature
    /// panic-free.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|_| "{\"error\":\"plan serialisation failed\"}".to_string())
    }

    /// Write [`Plan::to_json`] to `path`, creating parent directories.
    ///
    /// # Errors
    ///
    /// Returns the underlying I/O error when the directory or file cannot be
    /// written.
    pub fn write(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)?;
            }
        }
        fs::write(path, self.to_json())
    }
}

/// Build a plan for `scope`.
///
/// `satisfied` holds the canonical keys already published to every enabled
/// target; the caller owns that knowledge (the ledger in production).
///
/// # Errors
///
/// Returns [`PlanError::Crawl`] when the crawl fails,
/// [`PlanError::Sizes`] when a directory listing needed for sizes fails, and
/// [`PlanError::Bandwidth`] when `max_bandwidth` cannot be parsed.
pub async fn build(
    source: &Source,
    config: &Config,
    scope: &ResolvedScope,
    satisfied: &HashSet<String>,
) -> Result<Plan, PlanError> {
    let mut candidates: BTreeMap<String, Artifact> = BTreeMap::new();
    let mut collisions: Vec<TagCollision> = Vec::new();
    let mut skipped = 0;
    for policy in &scope.policies {
        let outcome = crawl(source, policy).await?;
        skipped += outcome.skipped;
        for artifact in outcome.artifacts {
            candidates.entry(artifact.key()).or_insert(artifact);
        }
        collisions.extend(outcome.collisions);
    }
    // The same version number on two channels can produce one descriptive tag
    // with different bytes; keep the first candidate and report the other like
    // a crawl collision.
    for collision in collect_tag_collisions(candidates.values()) {
        candidates.remove(&collision.conflicting.key());
        collisions.push(collision);
    }
    let collisions = dedup_collisions(collisions);

    let mut directories: BTreeMap<String, Vec<&Artifact>> = BTreeMap::new();
    for artifact in candidates.values() {
        directories
            .entry(directory_of(artifact))
            .or_default()
            .push(artifact);
    }

    let mut size_by_key: HashMap<String, u64> = HashMap::new();
    for (directory, artifacts) in &directories {
        let sizes = source
            .sizes(directory)
            .await
            .map_err(|source| PlanError::Sizes {
                dir: directory.clone(),
                source,
            })?;
        for artifact in artifacts {
            size_by_key.insert(
                artifact.key(),
                sizes.get(&artifact.basename).copied().unwrap_or(0),
            );
        }
    }

    let mut plan = Plan {
        artifacts: 0,
        total_bytes: 0,
        satisfied_bytes: 0,
        collisions: collisions.len(),
        collision_details: collisions.iter().map(CollisionDetail::new).collect(),
        skipped,
        by_project: BTreeMap::new(),
        by_platform: BTreeMap::new(),
        by_arch: BTreeMap::new(),
        by_target: BTreeMap::new(),
        largest: Vec::new(),
        space: SpaceCheck {
            state_dir: config.state_dir.display().to_string(),
            free_bytes: None,
            required_bytes: 0,
            fits: None,
        },
        effective_policy: policies_json(scope),
        projected_seconds: None,
    };

    for artifact in candidates.values() {
        let size = size_by_key.get(&artifact.key()).copied().unwrap_or(0);
        let is_satisfied = satisfied.contains(&artifact.key());

        plan.artifacts += 1;
        plan.total_bytes = plan.total_bytes.saturating_add(size);
        if is_satisfied {
            plan.satisfied_bytes = plan.satisfied_bytes.saturating_add(size);
        }

        add(&mut plan.by_project, &artifact.project, size, is_satisfied);
        add(
            &mut plan.by_platform,
            &artifact.platform,
            size,
            is_satisfied,
        );
        add(&mut plan.by_arch, &artifact.arch, size, is_satisfied);
        plan.largest.push((artifact.key(), size));
    }

    for target in config.targets.iter().filter(|target| target.enabled) {
        plan.by_target.insert(
            target.name.clone(),
            GroupTotals {
                artifacts: plan.artifacts,
                bytes: plan.total_bytes,
                satisfied_bytes: plan.satisfied_bytes,
            },
        );
    }

    plan.largest
        .sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
    plan.largest.truncate(LARGEST_LIMIT);

    let required = plan.total_bytes.saturating_sub(plan.satisfied_bytes);
    // An unanswerable disk check is an unknown check, never a failed plan.
    let free = free_bytes(&config.state_dir).ok().flatten();
    plan.space = SpaceCheck {
        state_dir: config.state_dir.display().to_string(),
        free_bytes: free,
        required_bytes: required,
        fits: free.map(|free| free >= required),
    };

    let rate = parse_bandwidth(&config.max_bandwidth).map_err(|reason| PlanError::Bandwidth {
        value: config.max_bandwidth.clone(),
        reason,
    })?;
    plan.projected_seconds = rate.map(|rate| required.div_ceil(rate));

    Ok(plan)
}

/// `channel/project/version/platform/platform_version`.
fn directory_of(artifact: &Artifact) -> String {
    format!(
        "{}/{}/{}/{}/{}",
        artifact.channel,
        artifact.project,
        artifact.version,
        artifact.platform,
        artifact.platform_version
    )
}

fn add(groups: &mut BTreeMap<String, GroupTotals>, key: &str, size: u64, satisfied: bool) {
    let totals = groups.entry(key.to_string()).or_default();
    totals.artifacts += 1;
    totals.bytes = totals.bytes.saturating_add(size);
    if satisfied {
        totals.satisfied_bytes = totals.satisfied_bytes.saturating_add(size);
    }
}

/// The resolved policies as JSON, preserving every field that affects selection.
///
/// The runner records this in its `run_started` event, so the plan and the run
/// row describe the same policy the same way.
#[must_use]
pub fn policies_json(scope: &ResolvedScope) -> Value {
    Value::Array(scope.policies.iter().map(policy_json).collect())
}

fn policy_json(policy: &ResolvedPolicy) -> Value {
    json!({
        "id": policy.id,
        "project": policy.project,
        "channel": policy.channel,
        "min_version": policy.min_version.as_ref().map(ToString::to_string),
        "max_version": policy.max_version.as_ref().map(ToString::to_string),
        "versions": policy.versions.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "all_versions": policy.all_versions,
        "platforms": &policy.platforms,
        "platform_versions": &policy.platform_versions,
        "arches": &policy.arches,
        "cli_versions": policy.cli_versions.iter().map(ToString::to_string).collect::<Vec<_>>(),
        "cli_platform_versions": policy
            .cli_platform_versions
            .iter()
            .map(|filter| json!({"platform": filter.platform, "version": filter.version}))
            .collect::<Vec<_>>(),
    })
}

/// Parse a bandwidth such as `40MiB/s`, `10MB/s` or `0`.
///
/// `Ok(None)` means unlimited. Decimal units are powers of ten, `*iB` units are
/// powers of two. A fractional number is rounded to whole bytes per second.
///
/// # Errors
///
/// Returns a reason when the value is empty, not a number, negative, has an
/// unknown unit or is too large for `u64`.
pub fn parse_bandwidth(raw: &str) -> Result<Option<u64>, &'static str> {
    let value = raw.trim();
    if value.is_empty() {
        return Err("expected a rate such as `40MiB/s` or `0` for unlimited");
    }

    let value = value
        .strip_suffix("/s")
        .or_else(|| value.strip_suffix("/S"))
        .unwrap_or(value)
        .trim();

    let split = value
        .find(|ch: char| !(ch.is_ascii_digit() || ch == '.'))
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    let amount: f64 = number.parse().map_err(|_| "the rate is not a number")?;
    if !amount.is_finite() || amount < 0.0 {
        return Err("the rate must be a finite, non-negative number");
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
        _ => return Err("expected B, KiB, MiB, GiB or TiB (decimal KB/MB/GB/TB also accepted)"),
    };

    let bytes = amount * multiplier as f64;
    if !bytes.is_finite() || bytes > u64::MAX as f64 {
        return Err("the rate is too large");
    }

    let bytes = bytes.round() as u64;
    if bytes == 0 {
        Ok(None)
    } else {
        Ok(Some(bytes))
    }
}

/// Errors raised while building a plan.
#[derive(Debug, Error)]
pub enum PlanError {
    /// The crawl or a tag check failed.
    #[error(transparent)]
    Crawl(#[from] CrawlError),

    /// Sizes could not be resolved for one directory.
    #[error("cannot resolve sizes for `{dir}`: {source}")]
    Sizes {
        /// Directory relative to the upstream root.
        dir: String,
        /// Underlying source error.
        #[source]
        source: SourceError,
    },

    /// `max_bandwidth` is not a usable rate.
    #[error("invalid max_bandwidth `{value}`: {reason}")]
    Bandwidth {
        /// The rejected value.
        value: String,
        /// Why it was rejected.
        reason: &'static str,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bandwidth_units_and_unlimited() {
        assert_eq!(parse_bandwidth("0"), Ok(None));
        assert_eq!(parse_bandwidth("0MiB/s"), Ok(None));
        assert_eq!(parse_bandwidth("10485760"), Ok(Some(10_485_760)));
        assert_eq!(parse_bandwidth("10MiB/s"), Ok(Some(10_485_760)));
        assert_eq!(parse_bandwidth("40MiB"), Ok(Some(41_943_040)));
        assert_eq!(parse_bandwidth("10MB/s"), Ok(Some(10_000_000)));
        assert_eq!(parse_bandwidth("512KiB/s"), Ok(Some(524_288)));
        assert_eq!(parse_bandwidth("1.5MiB/s"), Ok(Some(1_572_864)));
    }

    #[test]
    fn rejects_unusable_bandwidths() {
        for value in ["", "fast", "-1MiB/s", "10XiB/s", "1e9"] {
            assert!(
                parse_bandwidth(value).is_err(),
                "`{value}` must be rejected"
            );
        }
    }
}
