//! Publication targets.
//!
//! A [`Target`] is one place an artifact can be published: an OCI registry, an
//! rsync host, and later the places the plan adds. The runner uploads every
//! artifact to every enabled target, so the trait keeps only the operations
//! that are meaningful everywhere: probe the destination, ask whether an
//! artifact is already there, publish it, and verify a publication.
//!
//! [`TargetSet`] is built once from the configuration and shared between
//! workers; the targets themselves are behind an [`Arc`] because a registry
//! client holds a token cache that must not be copied per upload.
//!
//! # Immutability
//!
//! `put` never replaces a tag that already holds different package bytes. It
//! reports [`TargetError::TagConflict`] instead and leaves the registry
//! untouched; the incident flow decides whether the replacement goes out under
//! the superseded name.

pub mod oci_target;

use std::fmt;
use std::path::Path;
use std::sync::Arc;

use async_trait::async_trait;
use thiserror::Error;

use crate::artifact::Artifact;
use crate::config::{Config, TargetConfig, TargetKind};
use crate::oci::OciError;

pub use oci_target::OciTarget;

/// What a successful publication wrote, as the target reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutOutcome {
    /// Address a human can retry or inspect, e.g.
    /// `ghcr.io/org/repo/project:<tag>`.
    pub remote_ref: String,
    /// Digest that identifies the published object in the target.
    ///
    /// For an OCI target this is the manifest digest; an rsync target reports
    /// the package SHA-256.
    pub remote_digest: String,
}

/// Errors raised by a target.
#[derive(Debug, Error)]
pub enum TargetError {
    /// The tag already holds different package bytes.
    #[error("tag `{tag}` already holds {existing}; refusing to publish {incoming}")]
    TagConflict {
        /// The contested tag.
        tag: String,
        /// Package digest already published under the tag.
        existing: String,
        /// Package digest the caller wanted to publish.
        incoming: String,
    },

    /// The target has no publication for the artifact.
    #[error("tag `{tag}` is not published")]
    NotPublished {
        /// The tag that was resolved.
        tag: String,
    },

    /// The tag exists but lacks a layer the mirror always writes.
    #[error("tag `{tag}` is missing the `{title}` layer")]
    MissingLayer {
        /// The tag that was resolved.
        tag: String,
        /// Layer title annotation that is missing.
        title: String,
    },

    /// The target kind exists in the configuration model but not in this
    /// build.
    #[error("target kind `{kind}` is not implemented yet")]
    UnsupportedKind {
        /// The configured kind.
        kind: TargetKind,
    },

    /// The manifest could not be built.
    #[error("cannot build the manifest for tag `{tag}`: {reason}")]
    Manifest {
        /// The tag being published.
        tag: String,
        /// What went wrong while building it.
        reason: String,
    },

    /// The registry client failed.
    #[error(transparent)]
    Oci(#[from] OciError),
}

/// One place artifacts are published to.
///
/// Implementations are shared between workers, so they must be `Send + Sync`
/// and must not mutate state that a concurrent `put` would corrupt.
#[async_trait]
pub trait Target: Send + Sync {
    /// Configured name, unique within a [`TargetSet`].
    fn name(&self) -> &str;

    /// Check that the destination is reachable and the credentials work.
    async fn probe(&self) -> Result<(), TargetError>;

    /// The package digest already published for `artifact`, if any.
    async fn exists(&self, artifact: &Artifact) -> Result<Option<String>, TargetError>;

    /// Publish `package` for `artifact`.
    ///
    /// The package bytes were verified before this call; a target streams them
    /// and does not re-hash. Publishing an identical package again is a no-op
    /// that returns the existing publication.
    async fn put(&self, artifact: &Artifact, package: &Path) -> Result<PutOutcome, TargetError>;

    /// Check that the publication for `artifact` is complete and current.
    async fn verify(&self, artifact: &Artifact) -> Result<(), TargetError>;
}

/// The enabled targets of one configuration, in configuration order.
pub struct TargetSet {
    targets: Vec<Arc<dyn Target>>,
}

impl TargetSet {
    /// Build a target for every enabled entry of `config.targets`.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::UnsupportedKind`] for a kind this build cannot
    /// construct, and [`TargetError::Oci`] when an OCI target lacks usable
    /// credentials or configuration.
    pub fn from_config(config: &Config) -> Result<Self, TargetError> {
        let mut targets = Vec::new();
        for target in config.targets.iter().filter(|target| target.enabled) {
            targets.push(build(config, target)?);
        }
        Ok(Self { targets })
    }

    /// Every enabled target, in configuration order.
    #[must_use]
    pub fn all(&self) -> &[Arc<dyn Target>] {
        &self.targets
    }
}

impl fmt::Debug for TargetSet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_list()
            .entries(self.targets.iter().map(|target| target.name()))
            .finish()
    }
}

fn build(config: &Config, target: &TargetConfig) -> Result<Arc<dyn Target>, TargetError> {
    match target.kind {
        TargetKind::Oci => Ok(Arc::new(OciTarget::from_target(target, config)?)),
        TargetKind::Rsync => Err(TargetError::UnsupportedKind { kind: target.kind }),
    }
}
