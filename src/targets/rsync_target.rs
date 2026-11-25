//! Publish artifacts to an rsync destination.
//!
//! Three address forms share one implementation:
//!
//! - `ssh://[user@]host[:port]/path` — transport over SSH with host keys
//!   checked and no interactive prompts (`BatchMode=yes`,
//!   `StrictHostKeyChecking=yes`), optionally with an `identity_file`.
//! - `rsync://host[:port]/module/path` — the rsync daemon protocol, optionally
//!   with a `password_file` whose contents are handed to rsync as
//!   `RSYNC_PASSWORD`.
//! - a plain filesystem path — the same layout written locally, which is what
//!   the integration tests and a local mirror use.
//!
//! The layout mirrors upstream:
//!
//! ```text
//! <base>/<channel>/<project>/<version>/<platform>/<platform_version>/
//!     <basename>
//!     <basename>.metadata.json
//!     <basename>.sha256
//! ```
//!
//! The metadata document is per package, exactly as upstream publishes its
//! `*.metadata.json` files: one platform_version directory holds several
//! architectures and builds, so a shared `metadata.json` would be overwritten
//! by every publication of the directory. A superseded artifact's companion
//! keeps the suffix (`<basename>.superseded-<sha12>.metadata.json`), so
//! preserving the old bytes never touches the canonical metadata. The
//! sidecar contains `<sha256>  <size>\n` and is uploaded **last**, so its
//! presence is the commit marker: an interrupted run leaves a package without
//! a sidecar, which the next run republishes.
//!
//! # Atomicity
//!
//! rsync's default receiver writes to a temporary file in the destination
//! directory and renames it into place, so a reader never sees a half-written
//! package. `--partial-dir=.rsync-partial` keeps the partially received bytes
//! next to the destination for a later resume. This module deliberately does
//! not stage a `.tmp` name and rename it over SSH; the receiver already does
//! that.
//!
//! # Immutability
//!
//! The sidecar is the source of truth for what a destination holds. A sidecar
//! that names a different digest is [`TargetError::TagConflict`], never an
//! upload; the incident flow decides whether the replacement goes out under the
//! superseded name.

use std::io;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::process::Output;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::fs;
use tokio::process::Command;
use url::Url;

use crate::artifact::Artifact;
use crate::config::{TargetAuth, TargetConfig};
use crate::fsutil::expand_tilde;

use super::{PutOutcome, Target, TargetError};

/// Sidecar suffix appended to the package basename.
const SIDECAR_SUFFIX: &str = ".sha256";

/// Staging file name for the metadata document during an upload.
///
/// The destination name is always the per-package
/// `<basename>.metadata.json`; this is only the local temporary copy handed to
/// rsync.
const METADATA_NAME: &str = "metadata.json";

/// Suffix of the metadata document a package carries, mirroring upstream.
const METADATA_SUFFIX: &str = ".metadata.json";

/// Where a rsync target lives.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RsyncAddress {
    /// A directory on this machine.
    Local {
        /// Target root.
        path: PathBuf,
    },
    /// rsync over SSH.
    Ssh {
        /// Login name from the URL, if any.
        user: Option<String>,
        /// Host name or IP address.
        host: String,
        /// Non-default SSH port from the URL.
        port: Option<u16>,
        /// Absolute directory on the remote host.
        path: String,
    },
    /// The rsync daemon protocol.
    Daemon {
        /// Host name or IP address.
        host: String,
        /// Non-default daemon port from the URL.
        port: Option<u16>,
        /// First path component, the daemon module.
        module: String,
        /// Directory below the module, possibly empty.
        path: String,
    },
}

impl RsyncAddress {
    /// Parse a configured address.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::InvalidAddress`] for an unknown scheme, a missing
    /// host or path, credentials embedded in the URL, or a query or fragment.
    pub fn parse(url: &str) -> Result<Self, TargetError> {
        if let Some(rest) = url.strip_prefix("ssh://") {
            let parsed = parse_url(url, "ssh://", rest)?;
            let path = parsed.path().to_string();
            if path.is_empty() || path == "/" {
                return Err(invalid_address(url, "missing remote path"));
            }
            return Ok(Self::Ssh {
                user: user_of(&parsed),
                host: host_of(&parsed),
                port: parsed.port(),
                path,
            });
        }

        if let Some(rest) = url.strip_prefix("rsync://") {
            let parsed = parse_url(url, "rsync://", rest)?;
            let path = parsed.path().trim_matches('/').to_string();
            let (module, below) = path.split_once('/').unwrap_or((path.as_str(), ""));
            if module.is_empty() {
                return Err(invalid_address(url, "missing daemon module"));
            }
            let below = below.trim_matches('/');
            return Ok(Self::Daemon {
                host: host_of(&parsed),
                port: parsed.port(),
                module: module.to_string(),
                path: if below.is_empty() {
                    String::new()
                } else {
                    format!("/{below}")
                },
            });
        }

        if url.contains("://") {
            return Err(invalid_address(
                url,
                "expected `ssh://`, `rsync://` or a local path",
            ));
        }
        if url.is_empty() {
            return Err(invalid_address(url, "empty path"));
        }
        Ok(Self::Local {
            path: expand_tilde(Path::new(url)),
        })
    }
}

/// One configured rsync target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RsyncConfig {
    /// Name unique within the target set.
    pub name: String,
    /// Address as configured.
    pub url: String,
    /// Auth mode; must match the address form.
    pub auth: TargetAuth,
    /// Key handed to SSH for the `ssh://` form.
    pub identity_file: Option<PathBuf>,
    /// File whose contents become `RSYNC_PASSWORD` for the `rsync://` form.
    pub password_file: Option<PathBuf>,
}

/// An rsync publication target.
#[derive(Debug)]
pub struct RsyncTarget {
    name: String,
    address: RsyncAddress,
    identity_file: Option<PathBuf>,
    password_file: Option<PathBuf>,
}

impl RsyncTarget {
    /// Build a target from one configuration entry.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::InvalidAddress`] when the address cannot be
    /// parsed or the auth mode does not belong to its address form.
    pub fn new(config: RsyncConfig) -> Result<Self, TargetError> {
        let address = RsyncAddress::parse(&config.url)?;
        let matches = matches!(
            (&address, config.auth),
            (RsyncAddress::Local { .. }, TargetAuth::Anonymous)
                | (RsyncAddress::Ssh { .. }, TargetAuth::SshKey)
                | (RsyncAddress::Daemon { .. }, TargetAuth::Daemon)
        );
        if !matches {
            return Err(invalid_address(
                &config.url,
                format!(
                    "auth `{}` does not match the address form; use `anonymous` for a \
                     local path, `ssh-key` for `ssh://` and `daemon` for `rsync://`",
                    config.auth
                ),
            ));
        }

        Ok(Self {
            name: config.name,
            address,
            identity_file: config.identity_file.map(|path| expand_tilde(&path)),
            password_file: config.password_file.map(|path| expand_tilde(&path)),
        })
    }

    /// Build the target described by one configuration entry.
    ///
    /// # Errors
    ///
    /// Returns [`TargetError::InvalidAddress`] when the entry has no usable
    /// `url`.
    pub fn from_target(target: &TargetConfig) -> Result<Self, TargetError> {
        let Some(url) = target.url.clone() else {
            return Err(TargetError::InvalidAddress {
                url: String::new(),
                reason: "rsync targets require `url`".to_string(),
            });
        };
        Self::new(RsyncConfig {
            name: target.name.clone(),
            url,
            auth: target.auth,
            identity_file: target.identity_file.clone(),
            password_file: target.password_file.clone(),
        })
    }

    /// Arguments that upload the package for `artifact`.
    ///
    /// This is the exact argv after the program name; the tests pin it so a
    /// dropped host-key option or a stray `-e` on a daemon transfer fails
    /// before it reaches a mirror. The source element is the artifact basename:
    /// production callers substitute the store path and the metadata or
    /// sidecar temp file, the destination is always the upstream-shaped remote
    /// path.
    #[must_use]
    pub fn rsync_args(&self, artifact: &Artifact) -> Vec<String> {
        self.upload_args(
            Path::new(&artifact.basename),
            &self.reference_relpath(artifact),
        )
    }

    /// The path this artifact occupies on the target.
    ///
    /// A superseded artifact uses the suffixed name so the canonical path can
    /// keep serving the bytes it already has.
    fn reference_relpath(&self, artifact: &Artifact) -> String {
        if artifact.superseded {
            artifact.rsync_superseded_relpath()
        } else {
            artifact.rsync_relpath()
        }
    }

    /// The path of the metadata document that belongs to `artifact`.
    ///
    /// Both the canonical and the superseded artifact get a per-package
    /// companion next to their package file, exactly like upstream's
    /// `*.metadata.json`: one directory holds several packages, so a shared
    /// document would be overwritten by every publication.
    fn metadata_relpath(&self, artifact: &Artifact) -> String {
        format!("{}{METADATA_SUFFIX}", self.reference_relpath(artifact))
    }

    /// The metadata companion of the canonical package.
    fn canonical_metadata_relpath(&self, artifact: &Artifact) -> String {
        format!("{}{METADATA_SUFFIX}", artifact.rsync_relpath())
    }

    /// The metadata companion of a superseded package.
    fn superseded_metadata_relpath(&self, artifact: &Artifact) -> String {
        format!("{}{METADATA_SUFFIX}", artifact.rsync_superseded_relpath())
    }

    /// Copy one destination-relative path to another without touching the
    /// source.
    async fn copy_path(&self, from: &str, to: &str) -> Result<(), TargetError> {
        // A target that never received the old artifact has nothing to
        // preserve. The replacement is published there during the republish,
        // and there is no old publication row to retire.
        if !self.file_exists(from).await? {
            return Ok(());
        }
        match &self.address {
            RsyncAddress::Local { .. } => {
                let from_path = self
                    .local_path(from)
                    .expect("local address has a local path");
                let to_path = self.local_path(to).expect("local address has a local path");
                let source = fs::metadata(&from_path)
                    .await
                    .map_err(|source| io_error(from_path.clone(), source))?;
                match fs::metadata(&to_path).await {
                    Ok(existing) if existing.len() == source.len() => return Ok(()),
                    Ok(_) => {}
                    Err(source) if source.kind() == ErrorKind::NotFound => {}
                    Err(source) => return Err(io_error(to_path, source)),
                }
                fs::copy(&from_path, &to_path)
                    .await
                    .map_err(|source| io_error(to_path, source))?;
                Ok(())
            }
            RsyncAddress::Ssh { .. } => {
                let remote = self.ssh_cp_args(from, to);
                let output = self.ssh(&remote).await?;
                ensure_success("ssh cp", output).map(|_| ())
            }
            RsyncAddress::Daemon { .. } => {
                let args = vec!["-s".to_string(), self.daemon_url(from), self.daemon_url(to)];
                let output = self.rsync(&args).await?;
                ensure_success(&command_display("rsync", &args), output).map(|_| ())
            }
        }
    }

    fn upload_args(&self, source: &Path, relative: &str) -> Vec<String> {
        self.upload_args_with(source, relative, false)
    }

    fn upload_args_with(&self, source: &Path, relative: &str, ignore_times: bool) -> Vec<String> {
        let mut args = vec!["-a".to_string(), "--partial-dir=.rsync-partial".to_string()];
        if ignore_times {
            // An acknowledged republish must overwrite a canonical file even
            // when the new sidecar or metadata happens to have the same length
            // and mtime as the old one. Ordinary puts never force past rsync's
            // quick check.
            args.push("--ignore-times".to_string());
        }
        match &self.address {
            RsyncAddress::Local { .. } => {}
            RsyncAddress::Ssh { .. } => {
                // `-s` makes rsync pass the remote path as one protected
                // argument instead of letting the remote shell split it.
                args.push("-s".to_string());
                args.push("-e".to_string());
                args.push(self.ssh_rsh());
            }
            RsyncAddress::Daemon { .. } => {
                args.push("-s".to_string());
                // The daemon receiver cannot be told to create parents any
                // other way; rsync 3.2.3+ grows the destination path.
                args.push("--mkpath".to_string());
            }
        }
        args.push(source.to_string_lossy().into_owned());
        args.push(self.destination_spec(relative));
        args
    }

    /// The destination as rsync spells it: a path, `host:path` or a daemon URL.
    fn destination_spec(&self, relative: &str) -> String {
        match &self.address {
            RsyncAddress::Local { path } => path.join(relative).to_string_lossy().into_owned(),
            RsyncAddress::Ssh {
                user, host, path, ..
            } => {
                let prefix = match user {
                    Some(user) => format!("{user}@{host}"),
                    None => host.clone(),
                };
                format!("{prefix}:{}", joined(path, relative))
            }
            RsyncAddress::Daemon { .. } => self.daemon_url(relative),
        }
    }

    /// The remote path on an SSH host.
    fn ssh_remote_path(&self, relative: &str) -> String {
        match &self.address {
            RsyncAddress::Ssh { path, .. } => joined(path, relative),
            _ => relative.to_string(),
        }
    }

    /// The `rsync://` URL for `relative` below the daemon root.
    fn daemon_url(&self, relative: &str) -> String {
        let RsyncAddress::Daemon {
            host,
            port,
            module,
            path,
        } = &self.address
        else {
            return relative.to_string();
        };
        let port = port.map(|port| format!(":{port}")).unwrap_or_default();
        let base = joined(&format!("rsync://{host}{port}/{module}"), path);
        joined(&base, relative)
    }

    fn local_path(&self, relative: &str) -> Option<PathBuf> {
        match &self.address {
            RsyncAddress::Local { path } => Some(path.join(relative)),
            _ => None,
        }
    }

    /// The `-e` value for the SSH transport.
    fn ssh_rsh(&self) -> String {
        self.ssh_rsh_with(
            self.ssh_port(),
            self.identity_file
                .as_ref()
                .map(|path| path.to_string_lossy())
                .as_deref(),
        )
    }

    fn ssh_rsh_with(&self, port: Option<u16>, identity: Option<&str>) -> String {
        let mut parts = vec!["ssh".to_string()];
        if let Some(port) = port {
            parts.push("-p".to_string());
            parts.push(port.to_string());
        }
        parts.push("-o".to_string());
        parts.push("BatchMode=yes".to_string());
        parts.push("-o".to_string());
        parts.push("StrictHostKeyChecking=yes".to_string());
        if let Some(identity) = identity {
            parts.push("-i".to_string());
            parts.push(shell_quote(identity));
        }
        parts.join(" ")
    }

    fn ssh_port(&self) -> Option<u16> {
        match &self.address {
            RsyncAddress::Ssh { port, .. } => *port,
            _ => None,
        }
    }

    /// Arguments for invoking `ssh` directly (mkdir, cat, test).
    fn ssh_command_args(&self) -> Option<Vec<String>> {
        let RsyncAddress::Ssh {
            user, host, port, ..
        } = &self.address
        else {
            return None;
        };
        let mut args = Vec::new();
        if let Some(port) = port {
            args.push("-p".to_string());
            args.push(port.to_string());
        }
        args.push("-o".to_string());
        args.push("BatchMode=yes".to_string());
        args.push("-o".to_string());
        args.push("StrictHostKeyChecking=yes".to_string());
        if let Some(identity) = &self.identity_file {
            args.push("-i".to_string());
            args.push(identity.to_string_lossy().into_owned());
        }
        args.push(match user {
            Some(user) => format!("{user}@{host}"),
            None => host.clone(),
        });
        Some(args)
    }

    /// Remote `mkdir -p <path>` command for an SSH host.
    ///
    /// The path is one protected argument: the remote shell must not split it
    /// on whitespace, expand a `$`, or read a `;` as a command separator.
    fn ssh_mkdir_args(&self, relative: &str) -> Vec<String> {
        vec![
            "mkdir".to_string(),
            "-p".to_string(),
            shell_quote(&self.ssh_remote_path(relative)),
        ]
    }

    /// Remote `cat <path>` command for an SSH host.
    fn ssh_cat_args(&self, relative: &str) -> Vec<String> {
        vec![
            "cat".to_string(),
            shell_quote(&self.ssh_remote_path(relative)),
        ]
    }

    /// Remote `cp -p -- <from> <to>` command for an SSH host.
    ///
    /// Both paths are one quoted argument; `--` stops `cp` from reading a
    /// leading dash as an option.
    fn ssh_cp_args(&self, from: &str, to: &str) -> Vec<String> {
        vec![
            "cp".to_string(),
            "-p".to_string(),
            "--".to_string(),
            shell_quote(&self.ssh_remote_path(from)),
            shell_quote(&self.ssh_remote_path(to)),
        ]
    }

    /// Remote `test -f <path>` command for an SSH host.
    fn ssh_test_args(&self, relative: &str) -> Vec<String> {
        vec![
            "test".to_string(),
            "-f".to_string(),
            shell_quote(&self.ssh_remote_path(relative)),
        ]
    }

    async fn ssh(&self, remote: &[String]) -> Result<Output, TargetError> {
        let Some(mut args) = self.ssh_command_args() else {
            return Err(TargetError::InvalidAddress {
                url: String::new(),
                reason: "not an ssh target".to_string(),
            });
        };
        args.extend(remote.iter().cloned());
        run("ssh", &args, None).await
    }

    /// Run `rsync`, handing a daemon password to the child when configured.
    async fn rsync(&self, args: &[String]) -> Result<Output, TargetError> {
        let password = self.daemon_password().await?;
        run(
            "rsync",
            args,
            password.as_deref().map(|value| ("RSYNC_PASSWORD", value)),
        )
        .await
    }

    async fn daemon_password(&self) -> Result<Option<String>, TargetError> {
        if !matches!(self.address, RsyncAddress::Daemon { .. }) {
            return Ok(None);
        }
        let Some(path) = &self.password_file else {
            return Ok(None);
        };
        let text = fs::read_to_string(path)
            .await
            .map_err(|source| io_error(path.clone(), source))?;
        Ok(Some(text.trim_end_matches(['\r', '\n']).to_string()))
    }

    /// Create the destination directory before a single-file upload.
    async fn prepare_directory(&self, relative: &str) -> Result<(), TargetError> {
        match &self.address {
            RsyncAddress::Local { .. } => {
                let path = self
                    .local_path(relative)
                    .expect("local address has a local path");
                fs::create_dir_all(&path)
                    .await
                    .map_err(|source| io_error(path, source))
            }
            RsyncAddress::Ssh { .. } => {
                let remote = self.ssh_mkdir_args(relative);
                let output = self.ssh(&remote).await?;
                ensure_success("ssh mkdir -p", output).map(|_| ())
            }
            RsyncAddress::Daemon { .. } => Ok(()),
        }
    }

    async fn upload_file_with(
        &self,
        source: &Path,
        relative: &str,
        ignore_times: bool,
    ) -> Result<(), TargetError> {
        let args = self.upload_args_with(source, relative, ignore_times);
        let output = self.rsync(&args).await?;
        ensure_success(&command_display("rsync", &args), output).map(|_| ())
    }

    async fn read_sidecar(&self, artifact: &Artifact) -> Result<Option<Sidecar>, TargetError> {
        let relative = format!("{}{SIDECAR_SUFFIX}", self.reference_relpath(artifact));
        let bytes = match &self.address {
            RsyncAddress::Local { .. } => {
                let path = self
                    .local_path(&relative)
                    .expect("local address has a local path");
                match fs::read(&path).await {
                    Ok(bytes) => Some(bytes),
                    Err(source) if source.kind() == ErrorKind::NotFound => None,
                    Err(source) => return Err(io_error(path, source)),
                }
            }
            RsyncAddress::Ssh { .. } => {
                let remote = self.ssh_cat_args(&relative);
                let output = self.ssh(&remote).await?;
                if output.status.success() {
                    Some(output.stdout)
                } else if is_missing(&output) {
                    None
                } else {
                    return Err(command_error("ssh cat", output));
                }
            }
            RsyncAddress::Daemon { .. } => {
                let temp = TempDir::create()?;
                let url = self.daemon_url(&relative);
                let args = vec![
                    "-a".to_string(),
                    "-s".to_string(),
                    url,
                    format!("{}/", temp.path().display()),
                ];
                let output = self.rsync(&args).await?;
                if !output.status.success() {
                    if is_missing(&output) {
                        return Ok(None);
                    }
                    return Err(command_error(&command_display("rsync", &args), output));
                }
                let name = relative.rsplit('/').next().unwrap_or(&relative).to_string();
                let path = temp.path().join(&name);
                match fs::read(&path).await {
                    Ok(bytes) => Some(bytes),
                    Err(source) if source.kind() == ErrorKind::NotFound => None,
                    Err(source) => return Err(io_error(path, source)),
                }
            }
        };

        bytes
            .map(|bytes| Sidecar::parse(&relative, &bytes))
            .transpose()
    }

    /// Whether a destination-relative path is a file.
    async fn file_exists(&self, relative: &str) -> Result<bool, TargetError> {
        match &self.address {
            RsyncAddress::Local { .. } => {
                let path = self
                    .local_path(relative)
                    .expect("local address has a local path");
                match fs::metadata(&path).await {
                    Ok(metadata) => Ok(metadata.is_file()),
                    Err(source) if source.kind() == ErrorKind::NotFound => Ok(false),
                    Err(source) => Err(io_error(path, source)),
                }
            }
            RsyncAddress::Ssh { .. } => {
                let remote = self.ssh_test_args(relative);
                let output = self.ssh(&remote).await?;
                if output.status.success() {
                    Ok(true)
                } else if output.status.code() == Some(1) {
                    Ok(false)
                } else {
                    Err(command_error("ssh test -f", output))
                }
            }
            RsyncAddress::Daemon { .. } => {
                let args = vec![
                    "-s".to_string(),
                    "--list-only".to_string(),
                    self.daemon_url(relative),
                ];
                let output = self.rsync(&args).await?;
                if output.status.success() {
                    Ok(true)
                } else if is_missing(&output) {
                    Ok(false)
                } else {
                    Err(command_error(&command_display("rsync", &args), output))
                }
            }
        }
    }

    /// Write the package, metadata and sidecar.
    ///
    /// `allow_replace` is the acknowledged-republish switch: with it a sidecar
    /// that names different bytes is overwritten. Ordinary [`Target::put`]
    /// passes `false`, so a conflict is reported before any byte is transferred.
    async fn publish(
        &self,
        artifact: &Artifact,
        package: &Path,
        allow_replace: bool,
    ) -> Result<PutOutcome, TargetError> {
        let relpath = self.reference_relpath(artifact);
        let metadata_relpath = self.metadata_relpath(artifact);

        // A sidecar alone is not a publication. If the package or the metadata
        // companion is gone, fall through to a normal upload so a repair pass
        // can heal the target; skipping the sidecar write keeps its mtime as
        // the "byte-identical" evidence.
        let mut sidecar_matches = false;
        if let Some(existing) = self.exists(artifact).await? {
            if existing == artifact.sha256 {
                if self.file_exists(&relpath).await? && self.file_exists(&metadata_relpath).await? {
                    return Ok(self.outcome(artifact));
                }
                sidecar_matches = true;
            } else if !allow_replace {
                return Err(TargetError::TagConflict {
                    tag: relpath,
                    existing,
                    incoming: artifact.sha256.clone(),
                });
            }
        }

        let size = fs::metadata(package)
            .await
            .map_err(|source| io_error(package.to_path_buf(), source))?
            .len();

        let directory = directory_of(&relpath);
        self.prepare_directory(&directory).await?;

        self.upload_file_with(package, &relpath, allow_replace)
            .await?;

        let metadata_dir = TempDir::create()?;
        let metadata = metadata_dir.path().join(METADATA_NAME);
        fs::write(&metadata, artifact.metadata_json.as_bytes())
            .await
            .map_err(|source| io_error(metadata.clone(), source))?;
        self.upload_file_with(&metadata, &metadata_relpath, allow_replace)
            .await?;

        // Sidecar last: its presence is the commit marker for the pair above.
        if !sidecar_matches {
            let sidecar_dir = TempDir::create()?;
            let sidecar_name = format!("{}{SIDECAR_SUFFIX}", artifact.basename);
            let sidecar = sidecar_dir.path().join(&sidecar_name);
            fs::write(&sidecar, format!("{}  {size}\n", artifact.sha256))
                .await
                .map_err(|source| io_error(sidecar.clone(), source))?;
            self.upload_file_with(
                &sidecar,
                &format!("{relpath}{SIDECAR_SUFFIX}"),
                allow_replace,
            )
            .await?;
        }

        Ok(self.outcome(artifact))
    }

    fn outcome(&self, artifact: &Artifact) -> PutOutcome {
        PutOutcome {
            remote_ref: self.destination_spec(&self.reference_relpath(artifact)),
            remote_digest: artifact.sha256.clone(),
        }
    }
}

#[async_trait]
impl Target for RsyncTarget {
    fn name(&self) -> &str {
        &self.name
    }

    async fn probe(&self) -> Result<(), TargetError> {
        match &self.address {
            RsyncAddress::Local { path } => fs::create_dir_all(path)
                .await
                .map_err(|source| io_error(path.clone(), source)),
            RsyncAddress::Ssh { .. } => {
                let output = self.ssh(&["true".to_string()]).await?;
                ensure_success("ssh true", output).map(|_| ())
            }
            RsyncAddress::Daemon {
                host, port, module, ..
            } => {
                let port = port.map(|port| format!(":{port}")).unwrap_or_default();
                let args = vec![
                    "-s".to_string(),
                    "--list-only".to_string(),
                    format!("rsync://{host}{port}/{module}/"),
                ];
                let output = self.rsync(&args).await?;
                ensure_success(&command_display("rsync", &args), output).map(|_| ())
            }
        }
    }

    async fn exists(&self, artifact: &Artifact) -> Result<Option<String>, TargetError> {
        Ok(self.read_sidecar(artifact).await?.map(Sidecar::into_sha256))
    }

    async fn put(&self, artifact: &Artifact, package: &Path) -> Result<PutOutcome, TargetError> {
        self.publish(artifact, package, false).await
    }

    async fn republish(
        &self,
        artifact: &Artifact,
        package: &Path,
    ) -> Result<PutOutcome, TargetError> {
        // An acknowledged republish always targets the canonical upstream path,
        // even if the caller still carries the superseded flag from detection.
        let mut canonical = artifact.clone();
        canonical.superseded = false;
        self.publish(&canonical, package, true).await
    }

    async fn preserve_superseded(&self, artifact: &Artifact) -> Result<(), TargetError> {
        self.copy_path(
            &artifact.rsync_relpath(),
            &artifact.rsync_superseded_relpath(),
        )
        .await?;
        self.copy_path(
            &self.canonical_metadata_relpath(artifact),
            &self.superseded_metadata_relpath(artifact),
        )
        .await
    }

    async fn verify(&self, artifact: &Artifact) -> Result<(), TargetError> {
        let relpath = self.reference_relpath(artifact);
        let Some(sidecar) = self.read_sidecar(artifact).await? else {
            return Err(TargetError::NotPublished { tag: relpath });
        };
        if sidecar.sha256 != artifact.sha256 {
            return Err(TargetError::TagConflict {
                tag: relpath,
                existing: sidecar.sha256,
                incoming: artifact.sha256.clone(),
            });
        }
        if !self.file_exists(&relpath).await? {
            return Err(TargetError::NotPublished { tag: relpath });
        }
        let metadata_relpath = self.metadata_relpath(artifact);
        if !self.file_exists(&metadata_relpath).await? {
            return Err(TargetError::NotPublished {
                tag: metadata_relpath,
            });
        }
        Ok(())
    }
}

/// A parsed `<basename>.sha256` document.
#[derive(Debug)]
struct Sidecar {
    sha256: String,
}

impl Sidecar {
    fn parse(relative: &str, bytes: &[u8]) -> Result<Self, TargetError> {
        let text = std::str::from_utf8(bytes).map_err(|_| corrupt(relative, "not UTF-8"))?;
        let mut parts = text.split_whitespace();
        let sha256 = parts
            .next()
            .ok_or_else(|| corrupt(relative, "empty sidecar"))?;
        let valid = sha256.len() == 64 && sha256.bytes().all(|byte| byte.is_ascii_hexdigit());
        if !valid {
            return Err(corrupt(relative, "sha256 is not 64 hex characters"));
        }
        if let Some(size) = parts.next() {
            size.parse::<u64>()
                .map_err(|_| corrupt(relative, "size is not a number"))?;
        }
        Ok(Self {
            sha256: sha256.to_ascii_lowercase(),
        })
    }

    fn into_sha256(self) -> String {
        self.sha256
    }
}

/// A private directory removed when the upload finishes.
struct TempDir {
    path: PathBuf,
}

/// Distinguishes concurrent temp directories within one process.
static TEMP_COUNTER: AtomicU64 = AtomicU64::new(0);

impl TempDir {
    fn create() -> Result<Self, TargetError> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or(0);
        for _ in 0..16 {
            let unique = TEMP_COUNTER.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "cinc-mirror-rsync-{}-{nanos}-{unique}",
                std::process::id()
            ));
            match std::fs::create_dir(&path) {
                Ok(()) => return Ok(Self { path }),
                Err(source) if source.kind() == ErrorKind::AlreadyExists => continue,
                Err(source) => return Err(io_error(path, source)),
            }
        }
        Err(io_error(
            std::env::temp_dir(),
            io::Error::new(
                ErrorKind::AlreadyExists,
                "could not create a unique temporary directory",
            ),
        ))
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn parse_url(url: &str, prefix: &str, rest: &str) -> Result<Url, TargetError> {
    if rest.is_empty() {
        return Err(invalid_address(url, "missing host"));
    }
    let parsed = Url::parse(&format!("{prefix}{rest}"))
        .map_err(|error| invalid_address(url, error.to_string()))?;
    if parsed.password().is_some() {
        return Err(invalid_address(
            url,
            "credentials must not be embedded in the URL",
        ));
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err(invalid_address(url, "query and fragment are not supported"));
    }
    if parsed.host_str().is_none_or(str::is_empty) {
        return Err(invalid_address(url, "missing host"));
    }
    Ok(parsed)
}

fn host_of(url: &Url) -> String {
    // `Url::host_str` keeps the brackets around an IPv6 literal.
    url.host_str().unwrap_or_default().to_string()
}

fn user_of(url: &Url) -> Option<String> {
    let user = url.username();
    if user.is_empty() {
        None
    } else {
        Some(user.to_string())
    }
}

fn joined(base: &str, relative: &str) -> String {
    let base = base.trim_end_matches('/');
    if relative.is_empty() {
        base.to_string()
    } else if base.is_empty() {
        relative.to_string()
    } else {
        format!("{base}/{}", relative.trim_start_matches('/'))
    }
}

fn directory_of(relative: &str) -> String {
    relative
        .rsplit_once('/')
        .map_or_else(String::new, |(directory, _)| directory.to_string())
}

/// Wrap `value` in POSIX single quotes and escape embedded single quotes.
///
/// Inside single quotes a POSIX shell treats every character literally, so a
/// remote path with spaces, `;`, `$`, backticks or globs stays one argument.
/// The only character that needs escaping is the quote itself, closed and
/// reopened as `'\''`.
fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn invalid_address(url: &str, reason: impl Into<String>) -> TargetError {
    TargetError::InvalidAddress {
        url: url.to_string(),
        reason: reason.into(),
    }
}

fn corrupt(path: &str, reason: impl Into<String>) -> TargetError {
    TargetError::Corrupt {
        path: path.to_string(),
        reason: reason.into(),
    }
}

fn io_error(path: PathBuf, source: io::Error) -> TargetError {
    TargetError::Io { path, source }
}

fn command_display(program: &str, args: &[String]) -> String {
    if args.is_empty() {
        program.to_string()
    } else {
        format!("{program} {}", args.join(" "))
    }
}

async fn run(
    program: &'static str,
    args: &[String],
    env: Option<(&str, &str)>,
) -> Result<Output, TargetError> {
    let mut command = Command::new(program);
    command.args(args);
    if let Some((key, value)) = env {
        command.env(key, value);
    }
    command
        .output()
        .await
        .map_err(|source| TargetError::Command {
            command: command_display(program, args),
            status: None,
            stderr: if source.kind() == ErrorKind::NotFound {
                format!("{program} is not installed or not on PATH")
            } else {
                source.to_string()
            },
        })
}

fn ensure_success(command: &str, output: Output) -> Result<Output, TargetError> {
    if output.status.success() {
        Ok(output)
    } else {
        Err(command_error(command, output))
    }
}

fn command_error(command: &str, output: Output) -> TargetError {
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    TargetError::Command {
        command: command.to_string(),
        status: output.status.code(),
        stderr,
    }
}

fn is_missing(output: &Output) -> bool {
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    stderr.contains("no such file or directory") || stderr.contains("no such file")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{Artifact, ArtifactContext, ArtifactInput};

    fn ssh_target() -> RsyncTarget {
        RsyncTarget::new(RsyncConfig {
            name: "ssh".to_string(),
            url: "ssh://mirror@backup.example.org:2222/srv/cinc-mirror".to_string(),
            auth: TargetAuth::SshKey,
            identity_file: None,
            password_file: None,
        })
        .expect("ssh target")
    }

    fn artifact_with_basename(basename: &str) -> Artifact {
        Artifact::new(
            &ArtifactContext {
                channel: "stable".to_string(),
                project: "cinc".to_string(),
                version: "19.4.46".to_string(),
                platform: "debian".to_string(),
                platform_version: "13".to_string(),
            },
            ArtifactInput {
                basename: basename.to_string(),
                sha256: "00".repeat(32),
                metadata_json: "{}".to_string(),
                platform: "debian".to_string(),
                platform_version: "13".to_string(),
                version: "19.4.46".to_string(),
                iteration: Some("1".to_string()),
                raw_arch: "x86_64".to_string(),
            },
        )
        .expect("artifact")
    }

    #[test]
    fn shell_quote_single_quotes_everything() {
        assert_eq!(shell_quote("plain"), "'plain'");
        assert_eq!(shell_quote("a b;c"), "'a b;c'");
        assert_eq!(shell_quote("$HOME `id` *"), "'$HOME `id` *'");
        assert_eq!(shell_quote("a'b"), "'a'\\''b'");
        assert_eq!(shell_quote(""), "''");
    }

    #[test]
    fn ssh_commands_keep_a_metacharacter_basename_in_one_token() {
        let target = ssh_target();
        let artifact = artifact_with_basename("pkg ;$(id)'q.deb");
        let relative = format!("{}{SIDECAR_SUFFIX}", artifact.rsync_relpath());
        let expected =
            "'/srv/cinc-mirror/stable/cinc/19.4.46/debian/13/pkg ;$(id)'\\''q.deb.sha256'";

        for (remote, expected_len) in [
            (target.ssh_cat_args(&relative), 2),
            (target.ssh_mkdir_args(&relative), 3),
            (target.ssh_test_args(&relative), 3),
        ] {
            assert_eq!(
                remote.len(),
                expected_len,
                "the path must stay a single argument: {remote:?}"
            );
            assert_eq!(
                remote.last().map(String::as_str),
                Some(expected),
                "the whole remote path must be one single-quoted token"
            );
        }
    }
}
