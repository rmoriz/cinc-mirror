//! Crawl one resolved policy into concrete artifacts.
//!
//! The walk is shaped like upstream:
//! `<channel>/<project>/<version>/<platform>/<platform_version>/`.
//! Directory entries that are not directories, or version directories that do
//! not parse, are ignored so a stray `README` beside the releases cannot break a
//! run. Every `*.metadata.json` sibling is fetched and validated; the artifact
//! is built from the metadata and the resolved policy values.
//!
//! Upstream publishes the same Windows package under several compatibility
//! directories (`windows/10`, `/11`, `/2016`, `/2022`, ...) while the metadata
//! names one canonical platform version. The metadata is authoritative for the
//! artifact identity, so those aliases collapse into one artifact instead of
//! aborting the crawl.
//!
//! The result is deterministic: versions descending, then platform,
//! platform_version, architecture and basename ascending. Two different digests
//! under one descriptive tag are an upstream anomaly, not a failed run: the
//! crawl keeps the first artifact, reports the pair as a [`TagCollision`] and
//! leaves the decision to the incident flow.

use std::collections::{BTreeMap, HashSet};

use thiserror::Error;

use crate::artifact::{Artifact, ArtifactContext, ArtifactError};
use crate::scope::ResolvedPolicy;
use crate::source::{Source, SourceError};
use crate::version::Version;

/// Marks the metadata document beside a package.
const METADATA_SUFFIX: &str = ".metadata.json";

/// What one crawl produced.
#[derive(Debug, Clone, Default)]
pub struct CrawlOutcome {
    /// Artifacts that may be published, in deterministic order, collisions
    /// excluded.
    pub artifacts: Vec<Artifact>,
    /// Tag collisions found on the way; the conflicting artifact of each is
    /// not in `artifacts`.
    pub collisions: Vec<TagCollision>,
}

/// Two artifacts map to one descriptive tag but do not carry the same bytes.
///
/// Upstream publishes two raw architectures that map to one public one (or the
/// same version on two channels); the first artifact is kept and published,
/// the conflicting one is excluded so the descriptive tag never holds two
/// digests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagCollision {
    /// Upstream path of the conflicting artifact.
    pub upstream_path: String,
    /// The descriptive tag both artifacts map to.
    pub tag: String,
    /// The artifact the crawl keeps.
    pub first: Artifact,
    /// The artifact the crawl excludes.
    pub conflicting: Artifact,
}

/// Crawl every artifact selected by `policy`.
///
/// A tag collision does not fail the crawl: the first artifact (in the
/// deterministic directory order) is kept, the conflicting one is reported in
/// [`CrawlOutcome::collisions`] and excluded from [`CrawlOutcome::artifacts`].
///
/// # Errors
///
/// Returns [`CrawlError::List`] when a directory cannot be listed,
/// [`CrawlError::Metadata`] when a metadata document cannot be fetched or
/// parsed, and [`CrawlError::Artifact`] when the metadata contradicts the
/// crawl context.
pub async fn crawl(source: &Source, policy: &ResolvedPolicy) -> Result<CrawlOutcome, CrawlError> {
    let mut outcome = CrawlOutcome::default();
    let mut keys = HashSet::new();
    let mut tags = BTreeMap::new();

    let root = format!("{}/{}", policy.channel, policy.project);
    let mut versions: Vec<(Version, String)> = list_dirs(source, &root)
        .await?
        .into_iter()
        .filter_map(|name| name.parse::<Version>().ok().map(|version| (version, name)))
        .filter(|(version, _)| policy.allows_version(version))
        .collect();
    versions.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));

    for (_, version_name) in versions {
        let version_dir = format!("{root}/{version_name}");
        for platform in list_dirs(source, &version_dir)
            .await?
            .into_iter()
            .filter(|platform| policy.allows_platform(platform))
        {
            let platform_dir = format!("{version_dir}/{platform}");
            for platform_version in
                list_dirs(source, &platform_dir)
                    .await?
                    .into_iter()
                    .filter(|platform_version| {
                        policy.allows_platform_version(&platform, platform_version)
                    })
            {
                let directory = format!("{platform_dir}/{platform_version}");
                let mut found = artifacts_in_dir(
                    source,
                    policy,
                    &version_name,
                    &platform,
                    &platform_version,
                    &directory,
                )
                .await?;
                found.sort_by(|left, right| {
                    left.arch
                        .cmp(&right.arch)
                        .then_with(|| left.basename.cmp(&right.basename))
                        .then_with(|| left.sha256.cmp(&right.sha256))
                });

                for artifact in found {
                    if !policy.allows_arch(&artifact.arch) || !keys.insert(artifact.key()) {
                        continue;
                    }
                    match record_tag(&mut tags, &artifact) {
                        Some(collision) => outcome.collisions.push(collision),
                        None => outcome.artifacts.push(artifact),
                    }
                }
            }
        }
    }

    Ok(outcome)
}

/// Detect tag collisions in a merged candidate list.
///
/// The first artifact in iteration order is kept; every artifact that maps to a
/// tag already held by different bytes is reported as the conflicting one. The
/// caller must exclude each `conflicting` artifact from the candidates it
/// publishes.
pub fn collect_tag_collisions<'a>(
    artifacts: impl IntoIterator<Item = &'a Artifact>,
) -> Vec<TagCollision> {
    let mut tags = BTreeMap::new();
    let mut collisions = Vec::new();
    for artifact in artifacts {
        if let Some(collision) = record_tag(&mut tags, artifact) {
            collisions.push(collision);
        }
    }
    collisions
}

/// Drop collisions that two policies reported for the same artifact pair.
///
/// Two policies that crawl the same directory see the same collision; the
/// incident flow keys on the artifact pair, so one entry is enough.
pub fn dedup_collisions(mut collisions: Vec<TagCollision>) -> Vec<TagCollision> {
    let mut seen = HashSet::new();
    collisions
        .retain(|collision| seen.insert((collision.first.key(), collision.conflicting.key())));
    collisions
}

/// Record `artifact`'s claim on its descriptive tag.
///
/// The first artifact to claim a tag owns it; a later artifact with different
/// bytes under the same tag is reported as a collision and never inserted.
fn record_tag(tags: &mut BTreeMap<String, Artifact>, artifact: &Artifact) -> Option<TagCollision> {
    let tag = artifact.tag();
    match tags.get(&tag) {
        Some(first) if first.sha256 != artifact.sha256 => Some(TagCollision {
            upstream_path: artifact.rsync_relpath(),
            tag,
            first: first.clone(),
            conflicting: artifact.clone(),
        }),
        Some(_) => None,
        None => {
            tags.insert(tag, artifact.clone());
            None
        }
    }
}

/// Directory names directly below `dir`, sorted.
async fn list_dirs(source: &Source, dir: &str) -> Result<Vec<String>, CrawlError> {
    let entries = source.list(dir).await.map_err(|source| CrawlError::List {
        dir: dir.to_string(),
        source,
    })?;
    let mut names: Vec<String> = entries
        .into_iter()
        .filter(|entry| entry.is_dir)
        .map(|entry| entry.name)
        .collect();
    names.sort();
    Ok(names)
}

/// Fetch every metadata document in one platform_version directory.
async fn artifacts_in_dir(
    source: &Source,
    policy: &ResolvedPolicy,
    version: &str,
    platform: &str,
    platform_version: &str,
    dir: &str,
) -> Result<Vec<Artifact>, CrawlError> {
    let entries = source.list(dir).await.map_err(|source| CrawlError::List {
        dir: dir.to_string(),
        source,
    })?;
    let mut documents: Vec<String> = entries
        .into_iter()
        .filter(|entry| !entry.is_dir && entry.name.ends_with(METADATA_SUFFIX))
        .map(|entry| entry.name)
        .collect();
    documents.sort();

    let context = ArtifactContext {
        channel: policy.channel.clone(),
        project: policy.project.clone(),
        version: version.to_string(),
        platform: platform.to_string(),
        platform_version: platform_version.to_string(),
    };

    let mut artifacts = Vec::new();
    for document in documents {
        let path = format!("{dir}/{document}");
        let metadata = source
            .metadata(&path)
            .await
            .map_err(|source| CrawlError::Metadata {
                path: path.clone(),
                source,
            })?;
        let artifact = {
            // The directory only locates this copy; the metadata names the
            // canonical platform version. Building the artifact under the
            // directory name would publish one package once per compatibility
            // alias, so take the metadata value when it provides one.
            let mut artifact_context = context.clone();
            if !metadata.platform_version.is_empty() {
                artifact_context
                    .platform_version
                    .clone_from(&metadata.platform_version);
            }
            Artifact::new(&artifact_context, metadata.to_input())
                .map_err(|source| CrawlError::Artifact { path, source })?
        };
        artifacts.push(artifact);
    }

    Ok(artifacts)
}

/// Errors raised while crawling a policy.
#[derive(Debug, Error)]
pub enum CrawlError {
    /// A directory could not be listed.
    #[error("cannot list `{dir}`: {source}")]
    List {
        /// Directory relative to the upstream root.
        dir: String,
        /// Underlying source error.
        #[source]
        source: SourceError,
    },

    /// A metadata document could not be read.
    #[error("cannot read metadata `{path}`: {source}")]
    Metadata {
        /// Metadata path relative to the upstream root.
        path: String,
        /// Underlying source error.
        #[source]
        source: SourceError,
    },

    /// Metadata contradicted the crawl context.
    #[error("cannot build artifact from `{path}`: {source}")]
    Artifact {
        /// Metadata path relative to the upstream root.
        path: String,
        /// Underlying artifact error.
        #[source]
        source: ArtifactError,
    },
}
