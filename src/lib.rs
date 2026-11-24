//! CINC package mirror.
//!
//! The crate is split into a library so the crawling, verification and
//! publication logic stays testable without a process boundary. The binary is
//! a thin CLI wrapper around it.

pub mod cli;
pub mod config;

pub use cli::{Cli, Command};
pub use config::{
    Config, ConfigError, LedgerConfig, ProjectPolicy, Selection, TargetAuth, TargetConfig,
    TargetKind, TransportKind,
};
