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
//! aborting the crawl. Some historical documents name a value that is not a
//! usable path component (`debian/13` claiming `trixie/sid`); there the
//! directory value stands. A document that lands under a directory whose
//! platform or version contradicts it is skipped and counted, because the
//! tree cannot be represented faithfully; the plan reports the count and
//! `RUST_LOG=debug` names the paths.
//!
//! The result is deterministic: versions descending, then platform,
//! platform_version, architecture and basename ascending. Two different digests
//! under one descriptive tag are an upstream anomaly, not a failed run: the
//! first artifact keeps the tag, the next one is published under the tag plus
//! its digest, and the pair is reported as a [`TagCollision`] for the incident
//! flow.

use std::collections::{BTreeMap, HashMap, HashSet};

use thiserror::Error;

use crate::artifact::{is_safe_component, Artifact, ArtifactContext, ArtifactError};
use crate::scope::ResolvedPolicy;
use crate::source::{Source, SourceError};
use crate::version::Version;

/// Marks the metadata document beside a package.
const METADATA_SUFFIX: &str = ".metadata.json";

/// What one crawl produced.
#[derive(Debug, Clone, Default)]
pub struct CrawlOutcome {
    /// Artifacts that may be published, in deterministic order.
    pub artifacts: Vec<Artifact>,
    /// Tag collisions found on the way. The conflicting artifact is still in
    /// `artifacts`, published under a digest-qualified tag.
    pub collisions: Vec<TagCollision>,
    /// Metadata documents skipped because their platform or version
    /// contradicts the upstream directory. They cannot be represented
    /// faithfully; the plan surfaces the count.
    pub skipped: usize,
}

/// Two upstream files claim one descriptive tag but do not carry the same
/// bytes.
///
/// Upstream publishes the same package under several compatibility directories
/// (`windows/10`, `/11`, `/2016`, ...) and occasionally rebuilds a file in
/// place; the copies share a descriptive tag even though their bytes differ.
/// The first artifact keeps the plain tag and the latecomer is qualified with
/// its digest, so both files are mirrored instead of one being dropped. The
/// pair is reported so a human sees that upstream splits one reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TagCollision {
    /// Upstream path of the conflicting artifact.
    pub upstream_path: String,
    /// The descriptive tag both artifacts map to.
    pub tag: String,
    /// The artifact that keeps the descriptive tag.
    pub first: Artifact,
    /// The artifact published under the digest-qualified tag.
    pub conflicting: Artifact,
}

/// Crawl every artifact selected by `policy`.
///
/// A tag collision does not fail the crawl: the first artifact (in the
/// deterministic directory order) keeps the descriptive tag, the conflicting
/// one is published under a digest-qualified tag, and the pair is reported in
/// [`CrawlOutcome::collisions`].
///
/// `overrides` holds the qualified tags the ledger already knows. They win over
/// the crawl order, so a known pair cannot swap references just because the
/// upstream listing ranks it differently today.
///
/// # Errors
///
/// Returns [`CrawlError::List`] when a directory cannot be listed,
/// [`CrawlError::Metadata`] when a metadata document cannot be fetched or
/// parsed, and [`CrawlError::Artifact`] when the metadata contradicts the
/// crawl context.
pub async fn crawl(
    source: &Source,
    policy: &ResolvedPolicy,
    overrides: &HashMap<String, String>,
) -> Result<CrawlOutcome, CrawlError> {
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
                let (mut found, skipped) = artifacts_in_dir(
                    source,
                    policy,
                    &version_name,
                    &platform,
                    &platform_version,
                    &directory,
                )
                .await?;
                outcome.skipped += skipped;
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
                    let mut artifact = artifact;
                    if artifact.tag_override.is_none() {
                        if let Some(known) = overrides.get(&artifact.key()) {
                            artifact.tag_override = Some(known.clone());
                        }
                    }
                    if let Some(collision) = record_tag(&mut tags, &mut artifact) {
                        outcome.collisions.push(collision);
                    }
                    outcome.artifacts.push(artifact);
                }
            }
        }
    }

    Ok(outcome)
}

/// Detect tag collisions in a merged candidate list.
///
/// Runs over artifacts that were already merged from several policies. Every
/// artifact that maps to a tag already held by different bytes is reported as
/// the conflicting one and gets its digest appended to the tag. Callers keep
/// both artifacts in the queue.
///
/// `overrides` holds the qualified tags the ledger already knows. A crawl can
/// order a known pair the other way round; reusing the stored reference keeps
/// the artifact where the mirror published it instead of moving it to the plain
/// tag (and onto the other member's bytes) a second time.
pub fn collect_tag_collisions<'a>(
    artifacts: impl IntoIterator<Item = &'a mut Artifact>,
    overrides: &HashMap<String, String>,
) -> Vec<TagCollision> {
    let mut tags = BTreeMap::new();
    let mut collisions = Vec::new();
    for artifact in artifacts {
        if artifact.tag_override.is_none() {
            if let Some(known) = overrides.get(&artifact.key()) {
                artifact.tag_override = Some(known.clone());
            }
        }
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
/// bytes under the same tag is qualified with its digest, so it still publishes
/// under a reference of its own, and reported as a collision.
fn record_tag(
    tags: &mut BTreeMap<String, Artifact>,
    artifact: &mut Artifact,
) -> Option<TagCollision> {
    let tag = artifact.tag();
    match tags.get(&tag) {
        Some(first) if first.sha256 != artifact.sha256 => {
            artifact.qualify_tag_with_digest();
            Some(TagCollision {
                upstream_path: artifact.rsync_relpath(),
                tag,
                first: first.clone(),
                conflicting: artifact.clone(),
            })
        }
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
) -> Result<(Vec<Artifact>, usize), CrawlError> {
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
    let mut skipped = 0;
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
            // Some historical trees are misplaced (for example a stray
            // `.../3.0.28/13/sid/` whose metadata says `platform: debian`).
            // Such a document cannot be represented under this layout, so it
            // is skipped instead of aborting the whole crawl.
            let platform_contradicts = !metadata.platform.is_empty()
                && (metadata.platform != context.platform
                    || !is_safe_component(&metadata.platform));
            let version_contradicts = !metadata.version.is_empty()
                && (metadata.version != context.version || !is_safe_component(&metadata.version));
            if platform_contradicts || version_contradicts {
                skipped += 1;
                tracing::debug!(
                    path = %path,
                    metadata_platform = %metadata.platform,
                    metadata_version = %metadata.version,
                    crawl_platform = %context.platform,
                    crawl_version = %context.version,
                    "skipping artifact whose metadata does not fit its upstream directory"
                );
                continue;
            }

            // The directory only locates this copy; the metadata names the
            // canonical platform version. Building the artifact under the
            // directory name would publish one package once per compatibility
            // alias, so take the metadata value when it provides a usable one.
            // A value like `trixie/sid` cannot be a path component or tag, so
            // the directory value stays and the metadata claim is ignored.
            let mut artifact_context = context.clone();
            let mut input = metadata.to_input();
            if !metadata.platform_version.is_empty() {
                if is_safe_component(&metadata.platform_version) {
                    artifact_context
                        .platform_version
                        .clone_from(&metadata.platform_version);
                } else {
                    input.platform_version.clear();
                }
            }
            Artifact::new(&artifact_context, input)
                .map_err(|source| CrawlError::Artifact { path, source })?
        };
        artifacts.push(artifact);
    }

    Ok((artifacts, skipped))
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
