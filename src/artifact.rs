//! Artifact identity: the canonical key, the descriptive tag and the upstream
//! shaped rsync path.
//!
//! Every later layer keys on these values, so the rules are fixed here rather
//! than recomputed by the ledger, the OCI target and the rsync target:
//!
//! - key: `<channel>/<project>/<version>/<platform>/<platform_version>/<arch>/<sha256>`
//! - tag: `<version>-<platform>-<platform_version>-<arch>[-r<iteration>]`
//! - rsync path: `<channel>/<project>/<version>/<platform>/<platform_version>/<basename>`
//!
//! The module performs no I/O. Moving a superseded artifact, uploading a tag or
//! fetching bytes is the business of the targets.

use std::fmt;

use thiserror::Error;

/// Manifest `artifactType` for a mirrored CINC package.
pub const ARTIFACT_TYPE: &str = "application/vnd.cinc.package.v1+json";

/// Maximum tag length accepted by the published namespace.
///
/// Longer tags are truncated and suffixed with `-<sha12>` so two long names
/// stay distinguishable while the descriptive prefix stays readable.
pub const MAX_TAG_LEN: usize = 128;

/// Characters a sanitised tag component may contain.
const TAG_ALPHABET: &str = "abcdefghijklmnopqrstuvwxyz0123456789._-";

/// The crawl values that scope an artifact on the upstream index.
///
/// These are the values already resolved for the current crawl, not values read
/// back from a `metadata.json`. [`ArtifactInput`] carries the metadata values and
/// [`Artifact::new`] refuses to merge contradictory ones.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactContext {
    /// Release channel, e.g. `stable`.
    pub channel: String,
    /// Upstream project, e.g. `cinc`.
    pub project: String,
    /// Concrete version being crawled, e.g. `19.4.46`.
    pub version: String,
    /// Platform name, e.g. `debian`.
    pub platform: String,
    /// Platform release, e.g. `13`.
    pub platform_version: String,
}

/// The artifact values read from upstream metadata.
///
/// This is a plain struct on purpose: the source layer builds it (Task 5 adds
/// `Metadata::to_input`), but this module does not depend on that layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArtifactInput {
    /// Upstream file name, a single path component.
    pub basename: String,
    /// Hex-encoded SHA-256 of the file, lowercase or uppercase.
    pub sha256: String,
    /// Exact upstream `*.metadata.json` document, published verbatim as the
    /// OCI metadata layer.
    pub metadata_json: String,
    /// Platform claimed by the metadata; empty means "use the crawl value".
    pub platform: String,
    /// Platform release claimed by the metadata; empty means "use the crawl
    /// value".
    pub platform_version: String,
    /// Version claimed by the metadata; empty means "use the crawl value".
    pub version: String,
    /// Upstream iteration, as a string or number rendered by the source layer.
    pub iteration: Option<String>,
    /// Architecture as published upstream, e.g. `x86_64`.
    pub raw_arch: String,
}

/// A validated artifact, identified by channel, project, version, platform,
/// architecture and digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Artifact {
    /// Release channel.
    pub channel: String,
    /// Upstream project.
    pub project: String,
    /// Concrete version.
    pub version: String,
    /// Platform name.
    pub platform: String,
    /// Platform release.
    pub platform_version: String,
    /// Architecture in the public namespace, e.g. `amd64`.
    pub arch: String,
    /// Architecture as published upstream, e.g. `x86_64`.
    pub raw_arch: String,
    /// Upstream file name.
    pub basename: String,
    /// Lowercase hex SHA-256 of the file.
    pub sha256: String,
    /// Exact upstream `*.metadata.json` document as received.
    ///
    /// The OCI target publishes these bytes verbatim as the `metadata.json`
    /// layer; nothing re-serialises them, so unknown upstream fields and
    /// digest cross-checks survive the mirror.
    pub metadata_json: String,
    /// Upstream iteration when it is neither absent nor `1`.
    pub iteration: Option<u64>,
    /// Publish under [`Artifact::superseded_tag`] instead of the descriptive
    /// tag.
    ///
    /// The incident flow sets this when a tag already holds different bytes.
    /// It is a publication choice, not part of the artifact identity:
    /// [`Artifact::key`] and [`Artifact::tag`] ignore it.
    pub superseded: bool,
}

impl Artifact {
    /// Validate the metadata against the crawl context and build the artifact.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactError::InvalidBasename`] when the file name is not a
    /// single safe component, [`ArtifactError::InvalidSha256`] when the digest is
    /// not 64 hex characters, [`ArtifactError::InvalidComponent`] when a context
    /// value cannot be used as a path component, and
    /// [`ArtifactError::ContextMismatch`] when the metadata names a different
    /// platform, platform release or version than the crawl.
    pub fn new(context: &ArtifactContext, input: ArtifactInput) -> Result<Self, ArtifactError> {
        validate_component("channel", &context.channel)?;
        validate_component("project", &context.project)?;
        validate_component("version", &context.version)?;
        validate_component("platform", &context.platform)?;
        validate_component("platform_version", &context.platform_version)?;
        validate_component("raw_arch", &input.raw_arch)?;

        validate_basename(&input.basename)?;
        let sha256 = validate_sha256(&input.sha256)?;

        match_field("platform", &context.platform, &input.platform)?;
        match_field(
            "platform_version",
            &context.platform_version,
            &input.platform_version,
        )?;
        match_field("version", &context.version, &input.version)?;

        Ok(Self {
            channel: context.channel.clone(),
            project: context.project.clone(),
            version: context.version.clone(),
            platform: context.platform.clone(),
            platform_version: context.platform_version.clone(),
            arch: mapped_arch(&input.raw_arch),
            raw_arch: input.raw_arch,
            basename: input.basename,
            sha256,
            metadata_json: input.metadata_json,
            iteration: normalize_iteration(input.iteration.as_deref()),
            superseded: false,
        })
    }

    /// Publish this artifact under its superseded name.
    #[must_use]
    pub fn with_superseded(mut self, superseded: bool) -> Self {
        self.superseded = superseded;
        self
    }

    /// The canonical artifact key.
    ///
    /// This includes the digest, so a superseded artifact and its replacement
    /// are distinct keys even when they share an upstream path.
    #[must_use]
    pub fn key(&self) -> String {
        format!(
            "{}/{}/{}/{}/{}/{}/{}",
            self.channel,
            self.project,
            self.version,
            self.platform,
            self.platform_version,
            self.arch,
            self.sha256
        )
    }

    /// The descriptive tag, capped at [`MAX_TAG_LEN`] bytes.
    ///
    /// Iteration `1` keeps the historical name; any other parsed iteration adds
    /// `-r<iteration>`.
    #[must_use]
    pub fn tag(&self) -> String {
        let mut tag = sanitize_component(&format!(
            "{}-{}-{}-{}",
            self.version, self.platform, self.platform_version, self.arch
        ));
        if let Some(iteration) = self.iteration {
            tag.push_str(&format!("-r{iteration}"));
        }
        cap_tag(tag, self.short_sha())
    }

    /// The tag used to publish a superseded artifact.
    ///
    /// Equal to [`Artifact::tag`] plus `-<sha12>` and capped like the tag
    /// itself.
    #[must_use]
    pub fn superseded_tag(&self) -> String {
        let short = self.short_sha();
        cap_tag(format!("{}-{short}", self.tag()), short)
    }

    /// The artifact's path below an rsync target root, shaped like upstream.
    ///
    /// The architecture is carried by the basename, so the directory layout is
    /// `<channel>/<project>/<version>/<platform>/<platform_version>/<basename>`.
    #[must_use]
    pub fn rsync_relpath(&self) -> String {
        format!(
            "{}/{}/{}/{}/{}/{}",
            self.channel,
            self.project,
            self.version,
            self.platform,
            self.platform_version,
            self.basename
        )
    }

    /// The path a superseded artifact occupies below an rsync target root.
    ///
    /// The replacement keeps the upstream directory and appends
    /// `.superseded-<sha12>` to the basename, so the canonical name can keep
    /// serving the old bytes until the incident is acknowledged.
    #[must_use]
    pub fn rsync_superseded_relpath(&self) -> String {
        let mut path = self.rsync_relpath();
        path.push_str(".superseded-");
        path.push_str(self.short_sha());
        path
    }

    /// Check that `other` may share this artifact's descriptive tag.
    ///
    /// Two artifacts with the same tag must have identical bytes. A different
    /// digest under the same tag is the arch or iteration collision that later
    /// becomes an incident.
    ///
    /// # Errors
    ///
    /// Returns [`ArtifactError::TagCollision`] when the tags are equal and the
    /// digests differ.
    pub fn check_tag_collision(&self, other: &Self) -> Result<(), ArtifactError> {
        let tag = self.tag();
        if tag == other.tag() && self.sha256 != other.sha256 {
            return Err(ArtifactError::TagCollision {
                tag,
                first_sha256: self.sha256.clone(),
                second_sha256: other.sha256.clone(),
            });
        }
        Ok(())
    }

    /// The first twelve hex characters of the digest.
    fn short_sha(&self) -> &str {
        &self.sha256[..12]
    }
}

/// Map an upstream architecture to the public namespace.
///
/// Known values map to their historical names; anything else is sanitised and
/// passed through so a new upstream architecture does not need a code change.
#[must_use]
pub fn mapped_arch(raw: &str) -> String {
    match raw {
        "x86_64" => "amd64".to_string(),
        "aarch64" => "arm64".to_string(),
        "armv7l" | "armv7hl" => "armv7".to_string(),
        "i386" | "i686" => "386".to_string(),
        other => sanitize_component(other),
    }
}

/// Lowercase a value and keep it inside the published character set.
///
/// Uppercase becomes lowercase, `+` and `:` become `_` as they historically
/// did, and every other character outside `[a-z0-9._-]` becomes `_`. The result
/// is ASCII and therefore safe to truncate at a byte boundary.
#[must_use]
pub fn sanitize_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            let lowered = ch.to_ascii_lowercase();
            if lowered.is_ascii() && TAG_ALPHABET.contains(lowered) {
                lowered
            } else {
                '_'
            }
        })
        .collect()
}

/// Errors raised while building an artifact.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ArtifactError {
    /// The upstream file name is empty, `.`, `..` or contains a path separator.
    #[error("invalid basename `{value}`: expected a single path component")]
    InvalidBasename {
        /// The rejected value.
        value: String,
    },

    /// The digest is not exactly 64 hex characters.
    #[error("invalid sha256 `{value}`: expected 64 hex characters")]
    InvalidSha256 {
        /// The rejected value.
        value: String,
    },

    /// A context value cannot be used as a path component.
    #[error("invalid {field} component `{value}`")]
    InvalidComponent {
        /// Name of the offending field.
        field: &'static str,
        /// The rejected value.
        value: String,
    },

    /// Metadata contradicts the crawl context.
    #[error("metadata {field} `{found}` does not match crawl value `{expected}`")]
    ContextMismatch {
        /// Name of the offending field.
        field: &'static str,
        /// Value from the crawl context.
        expected: String,
        /// Value from the upstream metadata.
        found: String,
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

impl fmt::Display for Artifact {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.key())
    }
}

fn validate_component(field: &'static str, value: &str) -> Result<(), ArtifactError> {
    if is_safe_component(value) {
        Ok(())
    } else {
        Err(ArtifactError::InvalidComponent {
            field,
            value: value.to_string(),
        })
    }
}

fn validate_basename(value: &str) -> Result<(), ArtifactError> {
    if is_safe_component(value) {
        Ok(())
    } else {
        Err(ArtifactError::InvalidBasename {
            value: value.to_string(),
        })
    }
}

pub(crate) fn is_safe_component(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains('/')
        && !value.contains('\\')
        && !value.chars().any(char::is_control)
}

fn validate_sha256(value: &str) -> Result<String, ArtifactError> {
    let normalised = value.to_ascii_lowercase();
    let valid = normalised.len() == 64
        && normalised
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if valid {
        Ok(normalised)
    } else {
        Err(ArtifactError::InvalidSha256 {
            value: value.to_string(),
        })
    }
}

fn match_field(field: &'static str, expected: &str, found: &str) -> Result<(), ArtifactError> {
    if found.is_empty() || found == expected {
        Ok(())
    } else {
        Err(ArtifactError::ContextMismatch {
            field,
            expected: expected.to_string(),
            found: found.to_string(),
        })
    }
}

fn normalize_iteration(value: Option<&str>) -> Option<u64> {
    let parsed = value?.trim().parse::<u64>().ok()?;
    if parsed <= 1 {
        None
    } else {
        Some(parsed)
    }
}

fn cap_tag(mut tag: String, short_sha: &str) -> String {
    if tag.len() > MAX_TAG_LEN {
        let keep = MAX_TAG_LEN - 1 - short_sha.len();
        tag.truncate(keep);
        tag.push('-');
        tag.push_str(short_sha);
    }
    tag
}
