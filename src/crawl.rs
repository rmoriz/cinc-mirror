//! Crawl one resolved policy into concrete artifacts.
//!
//! The walk is shaped like upstream:
//! `<channel>/<project>/<version>/<platform>/<platform_version>/`.
//! Directory entries that are not directories, or version directories that do
//! not parse, are ignored so a stray `README` beside the releases cannot break a
//! run. Every `*.metadata.json` sibling is fetched and validated; the artifact
//! is built from the metadata and the resolved policy values.
//!
//! The result is deterministic: versions descending, then platform,
//! platform_version, architecture and basename ascending. Two different digests
//! under one descriptive tag are refused because they would become an incident
//! later, not an estimate.

use std::collections::{BTreeMap, HashSet};

use thiserror::Error;

use crate::artifact::{Artifact, ArtifactContext, ArtifactError};
use crate::scope::ResolvedPolicy;
use crate::source::{Source, SourceError};
use crate::version::Version;

/// Marks the metadata document beside a package.
const METADATA_SUFFIX: &str = ".metadata.json";

/// Crawl every artifact selected by `policy`.
///
/// # Errors
///
/// Returns [`CrawlError::List`] when a directory cannot be listed,
/// [`CrawlError::Metadata`] when a metadata document cannot be fetched or
/// parsed, [`CrawlError::Artifact`] when the metadata contradicts the crawl
/// context, and [`CrawlError::TagCollision`] when two different digests share a
/// tag.
pub async fn crawl(source: &Source, policy: &ResolvedPolicy) -> Result<Vec<Artifact>, CrawlError> {
    let mut artifacts = Vec::new();
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
                    record_tag(&mut tags, &artifact)?;
                    artifacts.push(artifact);
                }
            }
        }
    }

    Ok(artifacts)
}

/// Refuse two different digests under one descriptive tag.
pub(crate) fn check_tag_collisions<'a>(
    artifacts: impl IntoIterator<Item = &'a Artifact>,
) -> Result<(), CrawlError> {
    let mut tags = BTreeMap::new();
    for artifact in artifacts {
        record_tag(&mut tags, artifact)?;
    }
    Ok(())
}

fn record_tag(tags: &mut BTreeMap<String, String>, artifact: &Artifact) -> Result<(), CrawlError> {
    let tag = artifact.tag();
    match tags.get(&tag) {
        Some(sha256) if *sha256 != artifact.sha256 => Err(CrawlError::TagCollision {
            tag,
            first_sha256: sha256.clone(),
            second_sha256: artifact.sha256.clone(),
        }),
        Some(_) => Ok(()),
        None => {
            tags.insert(tag, artifact.sha256.clone());
            Ok(())
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
        let artifact = Artifact::new(&context, metadata.to_input())
            .map_err(|source| CrawlError::Artifact { path, source })?;
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

    /// Two artifacts map to one tag but have different bytes.
    #[error(
        "tag `{tag}` collides: `{first_sha256}` and `{second_sha256}` are different artifacts"
    )]
    TagCollision {
        /// The shared tag.
        tag: String,
        /// Digest of the first artifact.
        first_sha256: String,
        /// Digest of the second artifact.
        second_sha256: String,
    },
}
