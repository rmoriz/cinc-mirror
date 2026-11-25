//! CINC package mirror.
//!
//! The crate is split into a library so the crawling, verification and
//! publication logic stays testable without a process boundary. The binary is
//! a thin CLI wrapper around it.

pub mod artifact;
pub mod cli;
pub mod config;
pub mod crawl;
pub mod hash;
pub mod plan;
pub mod scope;
pub mod source;
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
pub use crawl::{crawl, CrawlError};
pub use hash::{hash_file, hash_reader, ExpectedHashes, Hasher, Hashes, VerifyOutcome};
pub use plan::{build, GroupTotals, Plan, PlanError, SpaceCheck};
pub use scope::{PlatformVersion, ResolvedPolicy, ResolvedScope, ScopeArgs, ScopeError};
pub use source::index::{parse_index, IndexEntry};
pub use source::metadata::{Metadata, MetadataError};
pub use source::transport::{
    DownloadError, DownloadOutcome, FtpTransport, FtpsTransport, HttpsTransport, PayloadTransport,
    RetryPolicy, TransportError,
};
pub use source::{Source, SourceConfig, SourceError};
pub use version::{Segment, Version, VersionError, VersionGlob, VersionGlobError};
