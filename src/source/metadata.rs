//! The upstream `*.metadata.json` model.
//!
//! Upstream publishes one metadata document beside every artifact. It names the
//! file and carries the digests the mirror verifies against. The document is
//! much larger than the mirror needs, so unknown fields are ignored; only the
//! fields below are read.
//!
//! `iteration` arrives as a JSON number (`1`, `2`, ...) while the rest of the
//! crate speaks strings, so it is rendered to its decimal form on the way in.

use serde::{Deserialize, Deserializer};
use thiserror::Error;

use crate::artifact::ArtifactInput;

/// The subset of an upstream `*.metadata.json` the mirror uses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// The exact document text as received.
    ///
    /// The OCI target publishes this verbatim, so the mirror must not
    /// re-serialise the parsed subset: unknown fields and the numeric
    /// `iteration` keep their upstream spelling.
    pub raw_json: String,
    /// Upstream file name, a single path component.
    pub basename: String,
    /// Lowercase or uppercase hex SHA-256; the gate for verification.
    pub sha256: String,
    /// Platform name, e.g. `debian`.
    pub platform: String,
    /// Platform release, e.g. `13`.
    pub platform_version: String,
    /// Architecture as published upstream, e.g. `x86_64`.
    pub arch: String,
    /// Concrete version, e.g. `19.4.46`.
    pub version: String,
    /// Optional hex SHA-512 cross-check.
    pub sha512: Option<String>,
    /// Optional hex SHA-1 cross-check.
    pub sha1: Option<String>,
    /// Optional hex MD5 cross-check.
    pub md5: Option<String>,
    /// Upstream iteration rendered as a string, e.g. `Some("2")`.
    pub iteration: Option<String>,
}

impl Metadata {
    /// Parse an upstream metadata document.
    ///
    /// Unknown fields are tolerated. Every field the mirror relies on is
    /// required; a missing (or `null`) one is a [`MetadataError::MissingField`].
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError::InvalidJson`] when the document is not valid
    /// JSON or a field has the wrong type, and [`MetadataError::MissingField`]
    /// when a required field is absent.
    pub fn from_json(json: &str) -> Result<Self, MetadataError> {
        let raw: RawMetadata = serde_json::from_str(json)
            .map_err(|error| MetadataError::InvalidJson(error.to_string()))?;

        Ok(Self {
            raw_json: json.to_string(),
            basename: required("basename", raw.basename)?,
            sha256: required("sha256", raw.sha256)?,
            platform: required("platform", raw.platform)?,
            platform_version: required("platform_version", raw.platform_version)?,
            arch: required("arch", raw.arch)?,
            version: required("version", raw.version)?,
            sha512: raw.sha512,
            sha1: raw.sha1,
            md5: raw.md5,
            iteration: raw.iteration,
        })
    }

    /// Project the metadata into the values [`crate::artifact::Artifact`] needs.
    ///
    /// The crawl context supplies channel, project and version; this carries
    /// the upstream identity and digests beside it.
    #[must_use]
    pub fn to_input(&self) -> ArtifactInput {
        ArtifactInput {
            basename: self.basename.clone(),
            sha256: self.sha256.clone(),
            metadata_json: self.raw_json.clone(),
            platform: self.platform.clone(),
            platform_version: self.platform_version.clone(),
            version: self.version.clone(),
            iteration: self.iteration.clone(),
            raw_arch: self.arch.clone(),
        }
    }
}

/// Errors raised while parsing upstream metadata.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum MetadataError {
    /// A required field is absent or `null`.
    #[error("metadata is missing required field `{0}`")]
    MissingField(&'static str),

    /// The document is not valid JSON or a field has the wrong type.
    #[error("invalid metadata JSON: {0}")]
    InvalidJson(String),
}

#[derive(Debug, Deserialize)]
struct RawMetadata {
    basename: Option<String>,
    sha256: Option<String>,
    platform: Option<String>,
    platform_version: Option<String>,
    arch: Option<String>,
    version: Option<String>,
    #[serde(default)]
    sha512: Option<String>,
    #[serde(default)]
    sha1: Option<String>,
    #[serde(default)]
    md5: Option<String>,
    #[serde(default, deserialize_with = "deserialize_iteration")]
    iteration: Option<String>,
}

fn required(field: &'static str, value: Option<String>) -> Result<String, MetadataError> {
    value.ok_or(MetadataError::MissingField(field))
}

fn deserialize_iteration<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Iteration {
        Text(String),
        Number(serde_json::Number),
    }

    Ok(
        Option::<Iteration>::deserialize(deserializer)?.map(|iteration| match iteration {
            Iteration::Text(text) => text,
            Iteration::Number(number) => number.to_string(),
        }),
    )
}
