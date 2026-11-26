//! Publish artifacts as OCI image manifests.
//!
//! One repository per upstream project (`<namespace>/<project>`), one tag per
//! artifact ([`Artifact::tag`]), and one image manifest per tag. The manifest
//! carries the package as its first layer and the exact upstream
//! `metadata.json` document as its second, so `oras pull` of a tag yields the
//! same two files the legacy shell script pushed. The document is carried
//! verbatim on the artifact; nothing re-serialises it.
//!
//! The manifest is the publication: its digest is what the ledger stores and
//! what `verify` compares. A tag that already holds a different package digest
//! is never overwritten; the caller learns about the conflict and decides
//! through the incident flow whether the replacement belongs under the
//! superseded name.
//!
//! # Blobs
//!
//! Every layer is uploaded by digest before the manifest is written. An
//! upload is skipped when `HEAD` says the blob already exists, so re-publishing
//! a package after a partial run costs three `HEAD`s and no package bytes.

use std::path::Path;

use async_trait::async_trait;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::artifact::{Artifact, ARTIFACT_TYPE};
use crate::config::{Config, TargetConfig};
use crate::oci::{package_layer_digest, OciError, Registry, MANIFEST_MEDIA_TYPE};

use super::{PutOutcome, Target, TargetError};

/// Media type of the empty config document.
const EMPTY_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.empty.v1+json";

/// The two bytes every OCI image manifest needs as its config.
const EMPTY_CONFIG: &[u8] = b"{}";

/// Media type of the package layer.
const PACKAGE_MEDIA_TYPE: &str = "application/octet-stream";

/// Media type of the metadata layer.
const METADATA_MEDIA_TYPE: &str = "application/json";

/// File name and layer title of the metadata document.
const METADATA_NAME: &str = "metadata.json";

/// Layer title annotation.
const TITLE_ANNOTATION: &str = "org.opencontainers.image.title";

/// Annotation naming the source repository of the image.
///
/// Registry and GitHub use it to link a pushed package to the repository it
/// belongs to; without it a package stays unlinked, shows up without its
/// repository and gets no README, permissions or retention from it.
const SOURCE_ANNOTATION: &str = "org.opencontainers.image.source";

/// One OCI registry target.
#[derive(Debug)]
pub struct OciTarget {
    name: String,
    registry: Registry,
}

impl OciTarget {
    /// Build a target around an already configured registry client.
    ///
    /// The repository namespace comes from the client, so tests can point a
    /// target at a local registry without a configuration file.
    #[must_use]
    pub fn new(name: impl Into<String>, registry: Registry) -> Self {
        Self {
            name: name.into(),
            registry,
        }
    }

    /// Build the target described by one configuration entry.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::Oci`] when the entry is not an OCI target or its
    /// auth mode has no usable credentials.
    pub fn from_target(target: &TargetConfig, config: &Config) -> Result<Self, TargetError> {
        Ok(Self::new(
            target.name.clone(),
            Registry::from_target(target, config)?,
        ))
    }

    /// Repository path for `artifact`: `<namespace>/<project>`.
    fn repo(&self, artifact: &Artifact) -> String {
        format!("{}/{}", self.registry.namespace(), artifact.project)
    }

    /// Tag the artifact is published under.
    fn reference(&self, artifact: &Artifact) -> String {
        if artifact.superseded {
            artifact.superseded_tag()
        } else {
            artifact.tag()
        }
    }

    fn outcome(&self, repo: &str, reference: &str, digest: String) -> PutOutcome {
        PutOutcome {
            remote_ref: format!("{}/{}:{}", self.registry.registry(), repo, reference),
            remote_digest: digest,
        }
    }

    /// Upload `bytes` unless the registry already has the blob.
    async fn ensure_bytes(
        &self,
        repo: &str,
        bytes: &[u8],
        digest: &str,
    ) -> Result<(), TargetError> {
        if !self.registry.head_blob(repo, digest).await? {
            self.registry.upload_bytes(repo, bytes, digest).await?;
        }
        Ok(())
    }

    /// Upload the package file unless the registry already has the blob.
    async fn ensure_file(&self, repo: &str, path: &Path, digest: &str) -> Result<(), TargetError> {
        if !self.registry.head_blob(repo, digest).await? {
            self.registry.upload_blob(repo, path, digest).await?;
        }
        Ok(())
    }

    /// Write the manifest for `artifact`.
    ///
    /// `allow_replace` is the acknowledged-republish switch: with it the
    /// manifest overwrites a canonical tag that currently names different
    /// package bytes. Ordinary [`Target::put`] passes `false`, so a conflict is
    /// reported before any blob is uploaded.
    async fn publish(
        &self,
        artifact: &Artifact,
        package: &Path,
        allow_replace: bool,
    ) -> Result<PutOutcome, TargetError> {
        let repo = self.repo(artifact);
        let reference = self.reference(artifact);
        let incoming = package_digest(artifact);

        if let Some(existing) = self
            .registry
            .package_digest_for_tag(&repo, &reference)
            .await?
        {
            if existing == incoming {
                // The tag already points at these exact bytes; the existing
                // manifest is the publication.
                let (_, manifest_digest) = self.registry.get_manifest(&repo, &reference).await?;
                return Ok(self.outcome(&repo, &reference, manifest_digest));
            }
            if !allow_replace {
                return Err(TargetError::TagConflict {
                    tag: reference,
                    existing,
                    incoming,
                });
            }
        }

        let size = tokio::fs::metadata(package)
            .await
            .map_err(|source| OciError::Io {
                path: package.to_path_buf(),
                source,
            })?
            .len();

        let metadata_bytes = artifact.metadata_json.as_bytes();
        let metadata_digest = sha256_digest(metadata_bytes);

        self.ensure_bytes(&repo, EMPTY_CONFIG, &sha256_digest(EMPTY_CONFIG))
            .await?;
        self.ensure_file(&repo, package, &incoming).await?;
        self.ensure_bytes(&repo, metadata_bytes, &metadata_digest)
            .await?;

        let source = source_url(self.registry.namespace());
        let manifest = manifest_document(
            artifact,
            &incoming,
            size,
            metadata_bytes,
            &metadata_digest,
            source.as_deref(),
        );
        let manifest_digest = self
            .registry
            .put_manifest(&repo, &reference, &manifest)
            .await?;

        Ok(self.outcome(&repo, &reference, manifest_digest))
    }
}

#[async_trait]
impl Target for OciTarget {
    fn name(&self) -> &str {
        &self.name
    }

    async fn probe(&self) -> Result<(), TargetError> {
        self.registry.probe().await?;
        Ok(())
    }

    async fn exists(&self, artifact: &Artifact) -> Result<Option<String>, TargetError> {
        let repo = self.repo(artifact);
        let reference = self.reference(artifact);
        Ok(self
            .registry
            .package_digest_for_tag(&repo, &reference)
            .await?)
    }

    async fn put(&self, artifact: &Artifact, package: &Path) -> Result<PutOutcome, TargetError> {
        self.publish(artifact, package, false).await
    }

    async fn republish(
        &self,
        artifact: &Artifact,
        package: &Path,
    ) -> Result<PutOutcome, TargetError> {
        // An acknowledged republish always targets the canonical tag, even if
        // the caller still carries the superseded flag from the detection run.
        let mut canonical = artifact.clone();
        canonical.superseded = false;
        self.publish(&canonical, package, true).await
    }

    async fn verify(&self, artifact: &Artifact) -> Result<(), TargetError> {
        let repo = self.repo(artifact);
        let reference = self.reference(artifact);

        let (manifest, _) = match self.registry.get_manifest(&repo, &reference).await {
            Ok(value) => value,
            Err(error) if error.is_not_found() => {
                return Err(TargetError::NotPublished { tag: reference })
            }
            Err(error) => return Err(error.into()),
        };

        let incoming = package_digest(artifact);
        match package_layer_digest(&manifest) {
            Some(existing) if existing == incoming => {}
            Some(existing) => {
                return Err(TargetError::TagConflict {
                    tag: reference,
                    existing,
                    incoming,
                })
            }
            None => return Err(TargetError::NotPublished { tag: reference }),
        }

        if !has_metadata_layer(&manifest) {
            return Err(TargetError::MissingLayer {
                tag: reference,
                title: METADATA_NAME.to_string(),
            });
        }

        Ok(())
    }
}

/// `sha256:<hex>` of the artifact's verified package digest.
fn package_digest(artifact: &Artifact) -> String {
    format!("sha256:{}", artifact.sha256)
}

/// The repository URL an `owner/repo` namespace stands for.
///
/// GHCR package names nest the project under the repository name
/// (`<owner>/<repo>/<project>`), so a namespace of exactly two segments names
/// the GitHub repository the package belongs to. An owner-only namespace says
/// nothing about a repository, so no source is claimed then.
#[must_use]
fn source_url(namespace: &str) -> Option<String> {
    let mut parts = namespace.split('/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some(owner), Some(repo), None) if !owner.is_empty() && !repo.is_empty() => {
            Some(format!("https://github.com/{owner}/{repo}"))
        }
        _ => None,
    }
}

/// The OCI image manifest for one artifact.
fn manifest_document(
    artifact: &Artifact,
    package_digest: &str,
    package_size: u64,
    metadata: &[u8],
    metadata_digest: &str,
    source: Option<&str>,
) -> Value {
    let mut annotations = serde_json::Map::new();
    annotations.insert(
        "org.opencontainers.artifact.title".to_string(),
        json!(artifact.basename),
    );
    annotations.insert(
        "org.opencontainers.artifact.description.platform".to_string(),
        json!(artifact.platform),
    );
    annotations.insert(
        "org.opencontainers.artifact.description.platform-version".to_string(),
        json!(artifact.platform_version),
    );
    annotations.insert(
        "org.opencontainers.artifact.description.machine".to_string(),
        json!(artifact.arch),
    );
    annotations.insert(
        "org.opencontainers.artifact.description.version".to_string(),
        json!(artifact.version),
    );
    if let Some(source) = source {
        annotations.insert(SOURCE_ANNOTATION.to_string(), json!(source));
    }
    json!({
        "schemaVersion": 2,
        "mediaType": MANIFEST_MEDIA_TYPE,
        "artifactType": ARTIFACT_TYPE,
        "config": {
            "mediaType": EMPTY_CONFIG_MEDIA_TYPE,
            "digest": sha256_digest(EMPTY_CONFIG),
            "size": EMPTY_CONFIG.len(),
        },
        "layers": [
            {
                "mediaType": PACKAGE_MEDIA_TYPE,
                "digest": package_digest,
                "size": package_size,
                "annotations": {TITLE_ANNOTATION: artifact.basename},
            },
            {
                "mediaType": METADATA_MEDIA_TYPE,
                "digest": metadata_digest,
                "size": metadata.len(),
                "annotations": {TITLE_ANNOTATION: METADATA_NAME},
            },
        ],
        "annotations": annotations,
    })
}

/// Whether the manifest carries the metadata layer the mirror always writes.
fn has_metadata_layer(manifest: &Value) -> bool {
    manifest
        .get("layers")
        .and_then(Value::as_array)
        .is_some_and(|layers| {
            layers.iter().any(|layer| {
                layer.get("mediaType").and_then(Value::as_str) == Some(METADATA_MEDIA_TYPE)
                    && layer
                        .get("annotations")
                        .and_then(|annotations| annotations.get(TITLE_ANNOTATION))
                        .and_then(Value::as_str)
                        == Some(METADATA_NAME)
            })
        })
}

fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    format!("sha256:{hex}")
}

#[cfg(test)]
mod tests {
    use super::source_url;

    #[test]
    fn a_nested_namespace_names_the_repository() {
        assert_eq!(
            source_url("octocat/hello-world").as_deref(),
            Some("https://github.com/octocat/hello-world")
        );
    }

    #[test]
    fn an_owner_only_or_deeper_namespace_names_no_repository() {
        assert_eq!(source_url("octocat"), None);
        assert_eq!(source_url("a/b/c"), None);
        assert_eq!(source_url("/repo"), None);
        assert_eq!(source_url("owner/"), None);
    }
}
