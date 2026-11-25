//! Publish artifacts as OCI image manifests.
//!
//! One repository per upstream project (`<namespace>/<project>`), one tag per
//! artifact ([`Artifact::tag`]), and one image manifest per tag. The manifest
//! carries the package as its first layer and the upstream-shaped
//! `metadata.json` as its second, so `oras pull` of a tag yields the same two
//! files the legacy shell script pushed.
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
            return Err(TargetError::TagConflict {
                tag: reference,
                existing,
                incoming,
            });
        }

        let size = tokio::fs::metadata(package)
            .await
            .map_err(|source| OciError::Io {
                path: package.to_path_buf(),
                source,
            })?
            .len();

        let metadata_bytes =
            serde_json::to_vec(&metadata_document(artifact)).map_err(|source| {
                TargetError::Manifest {
                    tag: reference.clone(),
                    reason: format!("the metadata document is not serialisable: {source}"),
                }
            })?;
        let metadata_digest = sha256_digest(&metadata_bytes);

        self.ensure_bytes(&repo, EMPTY_CONFIG, &sha256_digest(EMPTY_CONFIG))
            .await?;
        self.ensure_file(&repo, package, &incoming).await?;
        self.ensure_bytes(&repo, &metadata_bytes, &metadata_digest)
            .await?;

        let manifest =
            manifest_document(artifact, &incoming, size, &metadata_bytes, &metadata_digest);
        let manifest_digest = self
            .registry
            .put_manifest(&repo, &reference, &manifest)
            .await?;

        Ok(self.outcome(&repo, &reference, manifest_digest))
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

/// The metadata layer's content.
///
/// It mirrors the fields upstream publishes in `*.metadata.json`; the entire
/// upstream document is not kept in the store, so the target writes the subset
/// that identifies the package. `arch` keeps the upstream spelling so a
/// consumer sees the same value the package name carries.
fn metadata_document(artifact: &Artifact) -> Value {
    json!({
        "arch": artifact.raw_arch,
        "basename": artifact.basename,
        "iteration": artifact.iteration,
        "platform": artifact.platform,
        "platform_version": artifact.platform_version,
        "sha256": artifact.sha256,
        "version": artifact.version,
    })
}

/// The OCI image manifest for one artifact.
fn manifest_document(
    artifact: &Artifact,
    package_digest: &str,
    package_size: u64,
    metadata: &[u8],
    metadata_digest: &str,
) -> Value {
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
        "annotations": {
            "org.opencontainers.artifact.title": artifact.basename,
            "org.opencontainers.artifact.description.platform": artifact.platform,
            "org.opencontainers.artifact.description.platform-version": artifact.platform_version,
            "org.opencontainers.artifact.description.machine": artifact.arch,
            "org.opencontainers.artifact.description.version": artifact.version,
        },
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
