//! CINC package mirror.
//!
//! The crate is split into a library so the crawling, verification and
//! publication logic stays testable without a process boundary. The binary is
//! a thin CLI wrapper around it.

pub mod artifact;
pub mod bootstrap;
pub mod cli;
pub mod config;
pub mod crawl;
pub mod ctx;
pub mod fsutil;
pub mod hash;
pub mod incident;
pub mod ledger;
pub mod net;
pub mod oci;
pub mod plan;
pub mod repair;
pub mod report;
pub mod runner;
pub mod scope;
pub mod source;
pub mod store;
pub mod targets;
pub mod verify;
pub mod version;

pub use artifact::{
    mapped_arch, sanitize_component, Artifact, ArtifactContext, ArtifactError, ArtifactInput,
    ARTIFACT_TYPE, MAX_TAG_LEN,
};
pub use bootstrap::{BootstrapError, BootstrapReport};
pub use cli::{Cli, Command};
pub use config::{
    Config, ConfigError, IncidentConfig, LedgerConfig, ProjectPolicy, Selection, TargetAuth,
    TargetConfig, TargetKind, TransportKind,
};
pub use crawl::{crawl, CrawlError};
pub use ctx::Ctx;
pub use hash::{hash_file, hash_reader, ExpectedHashes, Hasher, Hashes, VerifyOutcome};
pub use ledger::{
    ArtifactRow, Cursor, Event, EventKind, Incident, IncidentFilter, IncidentKind, IncidentState,
    Lease, LeaseError, LeaseHolder, Ledger, LedgerError, LedgerFilesError, LedgerGitError,
    LedgerStore, Publication, PublicationStatus, Run,
};
pub use net::RateLimiter;
pub use oci::{AuthError, HttpFailure, OciAuth, OciConfig, OciError, Registry};
pub use plan::{build, GroupTotals, Plan, PlanError, SpaceCheck};
pub use repair::{RepairAction, RepairError, RepairOpts, RepairOutcome, RepairReport};
pub use report::Summary;
pub use runner::{run, Order, RunError, RunOpts};
pub use scope::{PlatformVersion, ResolvedPolicy, ResolvedScope, ScopeArgs, ScopeError};
pub use source::index::{parse_index, IndexEntry};
pub use source::metadata::{Metadata, MetadataError};
pub use source::transport::{
    DownloadError, DownloadOutcome, FtpTransport, FtpsTransport, HttpsTransport, PayloadTransport,
    RetryPolicy, TransportError,
};
pub use source::{Source, SourceConfig, SourceError};
pub use store::{Store, StoreError};
pub use targets::{
    OciTarget, PutOutcome, RsyncAddress, RsyncConfig, RsyncTarget, Target, TargetError, TargetSet,
};
pub use verify::{Finding, FindingKind, VerifyError, VerifyOpts, VerifyReport};
pub use version::{Segment, Version, VersionError, VersionGlob, VersionGlobError};
