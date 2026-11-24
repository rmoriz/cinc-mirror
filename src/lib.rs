//! CINC package mirror.
//!
//! The crate is split into a library so the crawling, verification and
//! publication logic stays testable without a process boundary. The binary is
//! a thin CLI wrapper around it.

pub mod artifact;
pub mod cli;
pub mod config;
pub mod scope;
pub mod version;

pub use artifact::{
    mapped_arch, sanitize_component, Artifact, ArtifactContext, ArtifactError, ArtifactInput,
    ARTIFACT_TYPE, MAX_TAG_LEN,
};
pub use cli::{Cli, Command};
pub use config::{
    Config, ConfigError, LedgerConfig, ProjectPolicy, Selection, TargetAuth, TargetConfig,
    TargetKind, TransportKind,
};
pub use scope::{PlatformVersion, ResolvedPolicy, ResolvedScope, ScopeArgs, ScopeError};
pub use version::{Segment, Version, VersionError, VersionGlob, VersionGlobError};
