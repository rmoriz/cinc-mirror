//! Payload transport ladder.
//!
//! Package bytes are fetched over one of three transports, in the order the
//! mirror configuration lists them (FTP, FTPS, HTTPS by default). Integrity is
//! not a transport property: every completed file is hashed and compared with
//! the metadata's SHA-256 before a download counts as successful.
//!
//! The ladder has three layers:
//!
//! - [`PayloadTransport`] is one rung. [`FtpTransport`] and [`FtpsTransport`]
//!   use `suppaftp` (`SIZE` and `REST`, binary mode, passive, 30 s budgets);
//!   [`HttpsTransport`] uses `reqwest` and an HTTP `Range` request answered with
//!   `206`. The trait is a seam so the ladder's retry, resume and verification
//!   rules can be tested without a TLS server.
//! - [`RetryPolicy`] decides how often a rung is retried and how long it waits:
//!   three attempts per rung, jittered 1/2/4 s backoff.
//! - [`Source::download`](crate::source::Source::download) picks the ladder from
//!   the configuration, resumes the `.part` file the caller points at, and
//!   verifies the result.
//!
//! Resume is deliberately conservative: a partial is only continued when the
//! remote object is known to be *larger* than the partial. If the size is
//! unknown (an FTP server without `SIZE`), if the remote is not larger, if the
//! server ignores the range, or if the range request is refused, the partial is
//! truncated and the file is fetched from zero. A splice across a changed remote
//! is never attempted.

use std::fmt;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use async_trait::async_trait;
use futures::io::AsyncReadExt as _;
use rand::Rng as _;
use reqwest::header::{CONTENT_RANGE, RANGE};
use reqwest::Client;
use suppaftp::types::FileType;
use suppaftp::{AsyncFtpStream, AsyncRustlsFtpStream, FtpError, Mode};
use tokio::io::AsyncWriteExt;
use url::Url;

use crate::config::TransportKind;
use crate::hash::{hash_file, ExpectedHashes, Hasher, Hashes};
use crate::source::{redirect_policy, USER_AGENT};

/// Default ladder order when the caller does not configure one.
pub const DEFAULT_TRANSPORTS: [TransportKind; 3] = [
    TransportKind::Ftp,
    TransportKind::Ftps,
    TransportKind::Https,
];

/// Budget for one FTP control operation (connect, login, `SIZE`, `REST`, `RETR`
/// reply, final reply).
const FTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Inactivity budget for one FTP data read. A large package may legitimately
/// take longer than 30 s overall, so the budget is per read, not per transfer.
const FTP_DATA_TIMEOUT: Duration = Duration::from_secs(30);

/// Read size used while copying a payload to disk.
const DATA_BUFFER_SIZE: usize = 64 * 1024;

/// Attempts per transport before the ladder advances.
const DEFAULT_ATTEMPTS: usize = 3;

/// First backoff step; doubled per retry.
const DEFAULT_BACKOFF: Duration = Duration::from_secs(1);

/// One transport rung.
///
/// `fetch` appends the remote object to `dest` and returns the number of bytes
/// it wrote. It must resume at `resume_from` only when the remote object is
/// larger than that offset; otherwise it truncates `dest` and starts at zero.
/// Callers detect a restart by comparing the file length with the returned byte
/// count (a resumed append leaves the file longer than the bytes written).
#[async_trait]
pub trait PayloadTransport: Send + Sync {
    /// Which rung this is.
    fn kind(&self) -> TransportKind;

    /// Append the remote object to `dest`, starting at `resume_from` when safe.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError`]. `NotFound`, `Auth`, `Forbidden` and `Local`
    /// are permanent; the ladder returns them immediately. `Retryable` and
    /// `Protocol` are retried up to the policy's attempt limit.
    async fn fetch(
        &self,
        remote_path: &str,
        dest: &Path,
        resume_from: u64,
    ) -> Result<u64, TransportError>;
}

/// A failed transport operation.
#[derive(Debug, thiserror::Error)]
pub enum TransportError {
    /// The remote object does not exist.
    #[error("remote file {path} not found")]
    NotFound {
        /// Remote path as requested.
        path: String,
    },

    /// The server rejected the credentials.
    #[error("authentication failed for {path}: {reason}")]
    Auth {
        /// Remote path as requested.
        path: String,
        /// Server explanation.
        reason: String,
    },

    /// The server refuses access for this client.
    #[error("access to {path} forbidden (status {status})")]
    Forbidden {
        /// Remote path as requested.
        path: String,
        /// HTTP status, `403` or `451`.
        status: u16,
    },

    /// A transient failure: another attempt may succeed.
    #[error("transient failure for {path}: {reason}")]
    Retryable {
        /// Remote path as requested.
        path: String,
        /// What went wrong.
        reason: String,
    },

    /// The server answered in a way the transport cannot use.
    #[error("protocol failure for {path}: {reason}")]
    Protocol {
        /// Remote path as requested.
        path: String,
        /// What was wrong with the answer.
        reason: String,
    },

    /// The local destination could not be written.
    #[error("local file error for {path}: {source}")]
    Local {
        /// Local path.
        path: String,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
}

impl TransportError {
    /// Whether retrying, or moving to another rung, cannot help.
    ///
    /// A local write failure is permanent too: a full or read-only disk fails
    /// identically on every transport.
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::NotFound { .. } | Self::Auth { .. } | Self::Forbidden { .. } | Self::Local { .. }
        )
    }

    fn retryable(path: &str, reason: impl Into<String>) -> Self {
        Self::Retryable {
            path: path.to_string(),
            reason: reason.into(),
        }
    }

    fn protocol(path: &str, reason: impl Into<String>) -> Self {
        Self::Protocol {
            path: path.to_string(),
            reason: reason.into(),
        }
    }

    fn local(path: &Path, source: io::Error) -> Self {
        Self::Local {
            path: path.display().to_string(),
            source,
        }
    }
}

/// Retry and backoff policy for one rung.
///
/// The production default is three attempts per rung with a jittered 1 s, 2 s,
/// 4 s backoff. A zero base disables the wait, which is what the tests use.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    attempts: usize,
    base_backoff: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self::new(DEFAULT_ATTEMPTS, DEFAULT_BACKOFF)
    }
}

impl RetryPolicy {
    /// Build a policy with `attempts` tries per rung and `base_backoff` as the
    /// first wait.
    #[must_use]
    pub fn new(attempts: usize, base_backoff: Duration) -> Self {
        Self {
            attempts,
            base_backoff,
        }
    }

    /// Attempts per rung.
    #[must_use]
    pub fn attempts(&self) -> usize {
        self.attempts
    }

    /// Wait before retry number `retry` (zero-based): the base doubled per step,
    /// jittered into the upper half of its window, capped at four base steps.
    fn delay(&self, retry: usize) -> Duration {
        let factor = 1_u32 << retry.min(2);
        let base = self.base_backoff.saturating_mul(factor);
        let half = base / 2;
        if half.is_zero() {
            return base;
        }
        let jitter = u64::try_from(half.as_millis()).unwrap_or(u64::MAX);
        half + Duration::from_millis(rand::thread_rng().gen_range(0..=jitter))
    }
}

/// A completed, verified download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadOutcome {
    /// Hashes computed from the bytes on disk.
    pub hashes: Hashes,
    /// Rung that served the bytes.
    pub transport: TransportKind,
    /// Offset the successful attempt started from; `0` also means that a
    /// transport discarded a partial because the remote was not larger.
    pub resumed_from: u64,
}

/// A download that did not produce verified bytes.
#[derive(Debug)]
pub enum DownloadError {
    /// A rung refused the path permanently; the ladder stopped there.
    Rejected {
        /// Remote path as requested.
        remote_path: String,
        /// Rung that refused it.
        transport: TransportKind,
        /// Why it was refused.
        source: TransportError,
    },

    /// Every rung failed without producing verifiable bytes.
    Exhausted {
        /// Remote path as requested.
        remote_path: String,
        /// Last rung that was tried.
        last_transport: TransportKind,
        /// Last transport error.
        source: TransportError,
        /// Hashes of the partial left on disk, when bytes had been written.
        /// They are reported for diagnosis; the partial is kept so the next run
        /// can resume it.
        observed: Option<Box<Hashes>>,
    },

    /// Every rung that produced a complete file produced the wrong bytes.
    ///
    /// The file is deleted: a corrupt file is never resumed. `observed` is the
    /// last corrupt completion, even when later rungs failed with transport
    /// errors; a later rung that verifies wins and is not reported here.
    Corrupt {
        /// Expected lowercase hex SHA-256.
        expected: String,
        /// Hashes of the bytes that were on disk.
        observed: Box<Hashes>,
    },

    /// The local destination could not be read or written.
    Io {
        /// Local path.
        path: PathBuf,
        /// Underlying I/O error.
        source: io::Error,
    },

    /// The download request itself is unusable.
    Config {
        /// Why the request was refused.
        reason: String,
    },
}

impl fmt::Display for DownloadError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Rejected {
                remote_path,
                transport,
                source,
            } => write!(
                formatter,
                "payload {remote_path} rejected by {transport}: {source}"
            ),
            Self::Exhausted {
                remote_path,
                last_transport,
                source,
                observed,
            } => {
                write!(
                    formatter,
                    "payload transports exhausted for {remote_path} \
                     (last error on {last_transport}: {source})"
                )?;
                if let Some(observed) = observed {
                    write!(
                        formatter,
                        "; partial left on disk has sha256 {} ({} bytes)",
                        observed.sha256, observed.size
                    )?;
                }
                Ok(())
            }
            Self::Corrupt { expected, observed } => write!(
                formatter,
                "payload verification failed: expected sha256 {expected}, \
                 observed sha256 {} over {} bytes",
                observed.sha256, observed.size
            ),
            Self::Io { path, source } => {
                write!(formatter, "local i/o failed for {path:?}: {source}")
            }
            Self::Config { reason } => write!(formatter, "invalid download request: {reason}"),
        }
    }
}

impl std::error::Error for DownloadError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Rejected { source, .. } | Self::Exhausted { source, .. } => Some(source),
            Self::Io { source, .. } => Some(source),
            Self::Corrupt { .. } | Self::Config { .. } => None,
        }
    }
}

/// FTP endpoint shared by the plain and secure rungs.
#[derive(Debug, Clone)]
struct FtpEndpoint {
    host: String,
    port: u16,
    base_path: String,
}

impl FtpEndpoint {
    fn new(host: impl Into<String>, port: u16, base_path: impl Into<String>) -> Self {
        Self {
            host: host.into(),
            port,
            base_path: base_path.into(),
        }
    }

    /// Join the configured base path and the requested path, refusing traversal.
    fn remote_path(&self, remote_path: &str) -> Result<String, TransportError> {
        let mut segments = Vec::new();
        for segment in self.base_path.split('/').chain(remote_path.split('/')) {
            let segment = segment.trim();
            if segment.is_empty() {
                continue;
            }
            if segment == "." || segment == ".." {
                return Err(TransportError::protocol(
                    remote_path,
                    "path traversal is not allowed",
                ));
            }
            segments.push(segment);
        }

        if segments.is_empty() {
            return Err(TransportError::protocol(
                remote_path,
                "the ftp base path and the file path must not both be empty",
            ));
        }

        Ok(segments.join("/"))
    }
}

/// Payload rung over cleartext FTP.
#[derive(Debug, Clone)]
pub struct FtpTransport {
    endpoint: FtpEndpoint,
}

impl FtpTransport {
    /// Point the rung at an FTP host and the path below it.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16, base_path: impl Into<String>) -> Self {
        Self {
            endpoint: FtpEndpoint::new(host, port, base_path),
        }
    }
}

#[async_trait]
impl PayloadTransport for FtpTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Ftp
    }

    async fn fetch(
        &self,
        remote_path: &str,
        dest: &Path,
        resume_from: u64,
    ) -> Result<u64, TransportError> {
        let path = self.endpoint.remote_path(remote_path)?;
        let mut stream = connect_plain(&self.endpoint, remote_path).await?;
        let result = transfer_plain(&mut stream, &path, remote_path, dest, resume_from).await;
        let _ = tokio::time::timeout(FTP_TIMEOUT, stream.quit()).await;
        result
    }
}

/// Payload rung over explicit FTPS (`AUTH TLS`, protected data channel).
#[derive(Debug, Clone)]
pub struct FtpsTransport {
    endpoint: FtpEndpoint,
}

impl FtpsTransport {
    /// Point the rung at an FTPS host and the path below it.
    #[must_use]
    pub fn new(host: impl Into<String>, port: u16, base_path: impl Into<String>) -> Self {
        Self {
            endpoint: FtpEndpoint::new(host, port, base_path),
        }
    }
}

#[async_trait]
impl PayloadTransport for FtpsTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Ftps
    }

    async fn fetch(
        &self,
        remote_path: &str,
        dest: &Path,
        resume_from: u64,
    ) -> Result<u64, TransportError> {
        let path = self.endpoint.remote_path(remote_path)?;
        let mut stream = connect_secure(&self.endpoint, remote_path).await?;
        let result = transfer_secure(&mut stream, &path, remote_path, dest, resume_from).await;
        let _ = tokio::time::timeout(FTP_TIMEOUT, stream.quit()).await;
        result
    }
}

/// Payload rung over HTTPS with `Range` resume.
#[derive(Debug, Clone)]
pub struct HttpsTransport {
    base: Url,
    client: Arc<OnceLock<Client>>,
}

impl HttpsTransport {
    /// Point the rung at an HTTPS base URL.
    ///
    /// The client is built on first use and then pooled, so constructing a rung
    /// cannot fail and a ladder rebuilt for every call still shares connections.
    #[must_use]
    pub fn new(base: Url) -> Self {
        Self {
            base,
            client: Arc::new(OnceLock::new()),
        }
    }

    /// Share a pooled client, used by [`Source`](crate::source::Source) so all
    /// downloads of one source reuse the same connections.
    pub(crate) fn with_client(base: Url, client: Arc<OnceLock<Client>>) -> Self {
        Self { base, client }
    }

    /// Build the object URL below the base, refusing traversal.
    fn url(&self, remote_path: &str) -> Result<Url, TransportError> {
        let mut url = self.base.clone();
        url.set_query(None);
        url.set_fragment(None);

        {
            let mut segments = url.path_segments_mut().map_err(|()| {
                TransportError::protocol(remote_path, "the https base cannot hold path segments")
            })?;
            segments.pop_if_empty();
            for segment in remote_path.split('/') {
                if segment.is_empty() {
                    continue;
                }
                if segment == "." || segment == ".." {
                    return Err(TransportError::protocol(
                        remote_path,
                        "path traversal is not allowed",
                    ));
                }
                segments.push(segment);
            }
        }

        Ok(url)
    }

    /// The pooled client, built on first use.
    fn client(&self, remote_path: &str) -> Result<&Client, TransportError> {
        if let Some(client) = self.client.get() {
            return Ok(client);
        }

        let host = self
            .base
            .host_str()
            .ok_or_else(|| TransportError::protocol(remote_path, "the https base has no host"))?;
        let built = Client::builder()
            .user_agent(USER_AGENT)
            .redirect(redirect_policy(host))
            .build()
            .map_err(|error| {
                TransportError::protocol(
                    remote_path,
                    format!("cannot build the http client: {error}"),
                )
            })?;
        let _ = self.client.set(built);

        self.client
            .get()
            .ok_or_else(|| TransportError::protocol(remote_path, "the http client is unavailable"))
    }
}

#[async_trait]
impl PayloadTransport for HttpsTransport {
    fn kind(&self) -> TransportKind {
        TransportKind::Https
    }

    async fn fetch(
        &self,
        remote_path: &str,
        dest: &Path,
        resume_from: u64,
    ) -> Result<u64, TransportError> {
        let url = self.url(remote_path)?;
        let client = self.client(remote_path)?;

        if resume_from > 0 {
            let response = client
                .get(url.clone())
                .header(RANGE, format!("bytes={resume_from}-"))
                .send()
                .await
                .map_err(|error| {
                    TransportError::retryable(remote_path, format!("request failed: {error}"))
                })?;

            match response.status().as_u16() {
                206 => {
                    // Resume only when the server answered the exact range and
                    // says the object continues past it. Anything else is
                    // treated as an unknown offset and restarted from zero.
                    if let Some((start, total)) = content_range(&response) {
                        if start == resume_from && total > resume_from {
                            return append_body(response, dest, remote_path, false).await;
                        }
                    }
                }
                200 => {
                    // The server ignored the range and sent the whole object.
                    return append_body(response, dest, remote_path, true).await;
                }
                416 => {}
                status => return Err(status_error(remote_path, status)),
            }
        }

        let response = client.get(url).send().await.map_err(|error| {
            TransportError::retryable(remote_path, format!("request failed: {error}"))
        })?;
        let status = response.status().as_u16();
        if !(200..300).contains(&status) {
            return Err(status_error(remote_path, status));
        }

        append_body(response, dest, remote_path, true).await
    }
}

/// The `(start, total)` of a `Content-Range: bytes <start>-<end>/<total>`.
fn content_range(response: &reqwest::Response) -> Option<(u64, u64)> {
    let value = response.headers().get(CONTENT_RANGE)?.to_str().ok()?;
    let range = value.strip_prefix("bytes ")?;
    let (span, total) = range.split_once('/')?;
    let start = span.split_once('-')?.0.trim().parse().ok()?;
    Some((start, total.trim().parse().ok()?))
}

/// Copy a response body to `dest`, truncating first when the range was refused
/// or ignored.
async fn append_body(
    mut response: reqwest::Response,
    dest: &Path,
    remote_path: &str,
    truncate: bool,
) -> Result<u64, TransportError> {
    let mut file = open_dest(dest, truncate).await?;
    let mut written = 0_u64;

    while let Some(chunk) = response.chunk().await.map_err(|error| {
        TransportError::retryable(remote_path, format!("body read failed: {error}"))
    })? {
        file.write_all(&chunk)
            .await
            .map_err(|source| TransportError::local(dest, source))?;
        written += chunk.len() as u64;
    }

    file.flush()
        .await
        .map_err(|source| TransportError::local(dest, source))?;
    Ok(written)
}

fn status_error(remote_path: &str, status: u16) -> TransportError {
    match status {
        404 | 410 => TransportError::NotFound {
            path: remote_path.to_string(),
        },
        401 | 407 => TransportError::Auth {
            path: remote_path.to_string(),
            reason: format!("http {status}"),
        },
        403 | 451 => TransportError::Forbidden {
            path: remote_path.to_string(),
            status,
        },
        408 | 429 | 500..=599 => TransportError::retryable(remote_path, format!("http {status}")),
        other => TransportError::protocol(remote_path, format!("unexpected http status {other}")),
    }
}

/// Open `dest` for appending, or create it empty when `truncate`.
async fn open_dest(dest: &Path, truncate: bool) -> Result<tokio::fs::File, TransportError> {
    let mut options = tokio::fs::OpenOptions::new();
    options.create(true).write(true);
    if truncate {
        options.truncate(true);
    } else {
        options.append(true);
    }
    options
        .open(dest)
        .await
        .map_err(|source| TransportError::local(dest, source))
}

/// Empty `dest`, keeping the file for the append that follows.
async fn truncate_dest(dest: &Path) -> Result<(), TransportError> {
    tokio::fs::File::create(dest)
        .await
        .map(|_| ())
        .map_err(|source| TransportError::local(dest, source))
}

async fn connect_plain(
    endpoint: &FtpEndpoint,
    remote_path: &str,
) -> Result<AsyncFtpStream, TransportError> {
    let host = endpoint.host.as_str();
    let mut stream =
        ftp_timeout(remote_path, AsyncFtpStream::connect((host, endpoint.port))).await?;
    stream.set_mode(Mode::Passive);
    ftp_timeout(remote_path, stream.login("anonymous", "anonymous")).await?;
    ftp_timeout(remote_path, stream.transfer_type(FileType::Binary)).await?;
    Ok(stream)
}

async fn connect_secure(
    endpoint: &FtpEndpoint,
    remote_path: &str,
) -> Result<AsyncRustlsFtpStream, TransportError> {
    let host = endpoint.host.as_str();
    let connector = rustls_connector(remote_path)?;
    let stream = ftp_timeout(
        remote_path,
        AsyncRustlsFtpStream::connect((host, endpoint.port)),
    )
    .await?;
    let mut stream = ftp_timeout(remote_path, stream.into_secure(connector, host)).await?;
    stream.set_mode(Mode::Passive);
    ftp_timeout(remote_path, stream.login("anonymous", "anonymous")).await?;
    ftp_timeout(remote_path, stream.transfer_type(FileType::Binary)).await?;
    Ok(stream)
}

/// A rustls connector trusting the Mozilla root program.
fn rustls_connector(remote_path: &str) -> Result<suppaftp::AsyncRustlsConnector, TransportError> {
    let mut roots = futures_rustls::rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = Arc::new(futures_rustls::rustls::crypto::ring::default_provider());
    let config = futures_rustls::rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|error| {
            TransportError::protocol(remote_path, format!("cannot configure ftps: {error}"))
        })?
        .with_root_certificates(roots)
        .with_no_client_auth();

    Ok(suppaftp::AsyncRustlsConnector::from(
        futures_rustls::TlsConnector::from(Arc::new(config)),
    ))
}

/// Fetch over one FTP control connection, resuming only when the remote size is
/// known to be larger than the partial.
async fn transfer_plain(
    stream: &mut AsyncFtpStream,
    path: &str,
    remote_path: &str,
    dest: &Path,
    resume_from: u64,
) -> Result<u64, TransportError> {
    let size = ftp_size(remote_path, stream.size(path)).await?;
    let offset = prepare_offset(dest, size, resume_from).await?;
    if offset > 0 && !restart_at_plain(stream, offset, remote_path).await {
        // REST was refused or the offset does not fit: appending would
        // duplicate the prefix, so start over.
        truncate_dest(dest).await?;
    }

    let mut data = ftp_timeout(remote_path, stream.retr_as_stream(path)).await?;
    let mut file = open_dest(dest, false).await?;
    let written = copy_data(&mut data, &mut file, remote_path, dest).await?;
    ftp_timeout(remote_path, stream.finalize_retr_stream(data)).await?;
    file.flush()
        .await
        .map_err(|source| TransportError::local(dest, source))?;
    Ok(written)
}

/// Ask a plain FTP session to restart at `offset`; `false` means start over.
async fn restart_at_plain(stream: &mut AsyncFtpStream, offset: u64, remote_path: &str) -> bool {
    let Ok(offset) = usize::try_from(offset) else {
        return false;
    };
    ftp_timeout(remote_path, stream.resume_transfer(offset))
        .await
        .is_ok()
}

/// [`transfer_plain`] over an explicit-TLS control and data connection.
async fn transfer_secure(
    stream: &mut AsyncRustlsFtpStream,
    path: &str,
    remote_path: &str,
    dest: &Path,
    resume_from: u64,
) -> Result<u64, TransportError> {
    let size = ftp_size(remote_path, stream.size(path)).await?;
    let offset = prepare_offset(dest, size, resume_from).await?;
    if offset > 0 && !restart_at_secure(stream, offset, remote_path).await {
        truncate_dest(dest).await?;
    }

    let mut data = ftp_timeout(remote_path, stream.retr_as_stream(path)).await?;
    let mut file = open_dest(dest, false).await?;
    let written = copy_data(&mut data, &mut file, remote_path, dest).await?;
    ftp_timeout(remote_path, stream.finalize_retr_stream(data)).await?;
    file.flush()
        .await
        .map_err(|source| TransportError::local(dest, source))?;
    Ok(written)
}

/// Ask an FTPS session to restart at `offset`; `false` means start over.
async fn restart_at_secure(
    stream: &mut AsyncRustlsFtpStream,
    offset: u64,
    remote_path: &str,
) -> bool {
    let Ok(offset) = usize::try_from(offset) else {
        return false;
    };
    ftp_timeout(remote_path, stream.resume_transfer(offset))
        .await
        .is_ok()
}

/// `SIZE` when the server supports it; `None` means "unknown, start over".
async fn ftp_size(
    remote_path: &str,
    size: impl Future<Output = suppaftp::FtpResult<usize>>,
) -> Result<Option<u64>, TransportError> {
    match ftp_timeout(remote_path, size).await {
        Ok(size) => Ok(Some(u64::try_from(size).unwrap_or(u64::MAX))),
        Err(error) if error.is_fatal() => Err(error),
        Err(_) => Ok(None),
    }
}

/// Decide the offset to request; truncate `dest` when it cannot be continued.
///
/// Returning `0` after truncation is the "start over" decision. The caller only
/// has to issue `REST` for a non-zero offset.
async fn prepare_offset(
    dest: &Path,
    remote_size: Option<u64>,
    resume_from: u64,
) -> Result<u64, TransportError> {
    if resume_from == 0 {
        truncate_dest(dest).await?;
        return Ok(0);
    }

    if remote_size.is_some_and(|size| size > resume_from) {
        return Ok(resume_from);
    }

    // The remote is not larger than the partial (or its size is unknown): start
    // over rather than splice bytes of a possibly different object. Callers see
    // this as `resumed_from == 0`, not as an error.
    truncate_dest(dest).await?;
    Ok(0)
}

/// Copy the data stream to `file`, with a per-read timeout.
async fn copy_data<R>(
    reader: &mut R,
    file: &mut tokio::fs::File,
    remote_path: &str,
    dest: &Path,
) -> Result<u64, TransportError>
where
    R: futures::io::AsyncRead + Unpin,
{
    let mut buffer = vec![0_u8; DATA_BUFFER_SIZE];
    let mut written = 0_u64;

    loop {
        let read = match tokio::time::timeout(FTP_DATA_TIMEOUT, reader.read(&mut buffer)).await {
            Ok(Ok(read)) => read,
            Ok(Err(error)) => {
                return Err(TransportError::retryable(
                    remote_path,
                    format!("data read failed: {error}"),
                ))
            }
            Err(_) => {
                return Err(TransportError::retryable(
                    remote_path,
                    "data read timed out",
                ))
            }
        };

        if read == 0 {
            return Ok(written);
        }

        file.write_all(&buffer[..read])
            .await
            .map_err(|source| TransportError::local(dest, source))?;
        written += read as u64;
    }
}

/// Run one FTP control operation with the control timeout.
async fn ftp_timeout<F, T>(remote_path: &str, future: F) -> Result<T, TransportError>
where
    F: Future<Output = suppaftp::FtpResult<T>>,
{
    match tokio::time::timeout(FTP_TIMEOUT, future).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(ftp_error(remote_path, error)),
        Err(_) => Err(TransportError::retryable(
            remote_path,
            "ftp operation timed out",
        )),
    }
}

/// Classify one `suppaftp` failure.
fn ftp_error(remote_path: &str, error: FtpError) -> TransportError {
    match error {
        FtpError::UnexpectedResponse(response) => {
            let code = response.status.code();
            let reason = String::from_utf8_lossy(&response.body).trim().to_string();
            match code {
                530 | 532 => TransportError::Auth {
                    path: remote_path.to_string(),
                    reason: format!("ftp {code}: {reason}"),
                },
                550 => TransportError::NotFound {
                    path: remote_path.to_string(),
                },
                421..=434 | 450..=452 => {
                    TransportError::retryable(remote_path, format!("ftp {code}: {reason}"))
                }
                other => TransportError::protocol(remote_path, format!("ftp {other}: {reason}")),
            }
        }
        FtpError::ConnectionError(source) => {
            TransportError::retryable(remote_path, format!("connection failed: {source}"))
        }
        FtpError::SecureError(reason) => {
            TransportError::retryable(remote_path, format!("tls failed: {reason}"))
        }
        FtpError::BadResponse => {
            TransportError::protocol(remote_path, "response contains an invalid syntax")
        }
        FtpError::InvalidAddress(source) => {
            TransportError::protocol(remote_path, format!("invalid address: {source}"))
        }
    }
}

/// Download `remote_path` into `dest` through the ladder and verify it.
///
/// `dest` is the `.part` path the caller (the store) owns; its current length is
/// read here and used as the resume offset. The file is only left in place when
/// its size and every expected digest agree.
///
/// A completed file with the wrong bytes is deleted and the ladder continues:
/// the rungs are different servers (an FTP mirror and the HTTPS origin), so one
/// of them may still have the right object. When no rung verifies, a corrupt
/// completion outranks the transport errors of later rungs.
pub(crate) async fn download(
    transports: &[Arc<dyn PayloadTransport>],
    retry: &RetryPolicy,
    remote_path: &str,
    dest: &Path,
    expected: &ExpectedHashes,
) -> Result<DownloadOutcome, DownloadError> {
    if transports.is_empty() {
        return Err(DownloadError::Config {
            reason: "no payload transports are configured".to_string(),
        });
    }
    if retry.attempts() == 0 {
        return Err(DownloadError::Config {
            reason: "at least one attempt per transport is required".to_string(),
        });
    }

    let mut last: Option<(TransportKind, TransportError)> = None;
    let mut corrupt: Option<(String, Box<Hashes>)> = None;

    for transport in transports {
        let kind = transport.kind();

        for attempt in 1..=retry.attempts() {
            match attempt_download(transport.as_ref(), remote_path, dest, expected).await {
                Ok(outcome) => return Ok(outcome),
                Err(AttemptError::Permanent(source)) => {
                    return Err(DownloadError::Rejected {
                        remote_path: remote_path.to_string(),
                        transport: kind,
                        source,
                    })
                }
                Err(AttemptError::Corrupt { expected, observed }) => {
                    // Wrong bytes are never retried on the same rung, but a
                    // different server may hold the right object.
                    corrupt = Some((expected, observed));
                    break;
                }
                Err(AttemptError::Failed(source)) => {
                    last = Some((kind, source));
                }
                Err(AttemptError::Aborted(error)) => return Err(error),
            }

            if attempt < retry.attempts() {
                tokio::time::sleep(retry.delay(attempt - 1)).await;
            }
        }
    }

    if let Some((expected, observed)) = corrupt {
        return Err(DownloadError::Corrupt { expected, observed });
    }

    let Some((last_transport, source)) = last else {
        return Err(DownloadError::Config {
            reason: "no payload transport was attempted".to_string(),
        });
    };

    let observed = match tokio::fs::metadata(dest).await {
        Ok(metadata) if metadata.len() > 0 => hash_file_blocking(dest).await.ok(),
        _ => None,
    };

    Err(DownloadError::Exhausted {
        remote_path: remote_path.to_string(),
        last_transport,
        source,
        observed: observed.map(Box::new),
    })
}

/// Why one attempt did not produce a verified file.
enum AttemptError {
    /// The rung must not be retried and the ladder must stop.
    Permanent(TransportError),
    /// The rung may be retried, then the ladder moves on.
    Failed(TransportError),
    /// A complete file had the wrong bytes: it was deleted, this rung must not
    /// be retried, and the ladder moves on.
    Corrupt {
        /// Expected lowercase hex SHA-256.
        expected: String,
        /// Hashes of the deleted bytes.
        observed: Box<Hashes>,
    },
    /// The ladder must stop with this error (local I/O).
    Aborted(DownloadError),
}

/// One attempt: resume what is on disk, fetch, then hash and verify.
async fn attempt_download(
    transport: &dyn PayloadTransport,
    remote_path: &str,
    dest: &Path,
    expected: &ExpectedHashes,
) -> Result<DownloadOutcome, AttemptError> {
    let resume_from = dest_len(dest).await.map_err(AttemptError::Aborted)?;

    let primed = if resume_from > 0 {
        hash_prefix_blocking(dest, resume_from)
            .await
            .map_err(AttemptError::Aborted)?
    } else {
        Hasher::new()
    };

    let written = transport
        .fetch(remote_path, dest, resume_from)
        .await
        .map_err(|error| {
            if error.is_fatal() {
                AttemptError::Permanent(error)
            } else {
                AttemptError::Failed(error)
            }
        })?;

    let len = dest_len(dest).await.map_err(AttemptError::Aborted)?;
    // A resumed append leaves `resume_from + written` bytes behind; a transport
    // that discarded the prefix leaves exactly `written`.
    let restarted = resume_from > 0 && len == written;

    let hashes = if restarted || resume_from == 0 {
        hash_file_blocking(dest)
            .await
            .map_err(AttemptError::Aborted)?
    } else {
        hash_tail_blocking(dest, resume_from, primed)
            .await
            .map_err(AttemptError::Aborted)?
    };

    if hashes.verify(expected).is_match() {
        return Ok(DownloadOutcome {
            hashes,
            transport: transport.kind(),
            resumed_from: if restarted { 0 } else { resume_from },
        });
    }

    // Wrong bytes are never resumed: delete the file and let the ladder try the
    // next rung. Both digests are kept for the final report.
    let _ = tokio::fs::remove_file(dest).await;
    Err(AttemptError::Corrupt {
        expected: expected.sha256.clone(),
        observed: Box::new(hashes),
    })
}

/// Current length of `dest`; a missing file is an empty partial.
async fn dest_len(dest: &Path) -> Result<u64, DownloadError> {
    match tokio::fs::metadata(dest).await {
        Ok(metadata) => Ok(metadata.len()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(0),
        Err(source) => Err(DownloadError::Io {
            path: dest.to_path_buf(),
            source,
        }),
    }
}

fn blocking_error(path: &Path, error: tokio::task::JoinError) -> DownloadError {
    DownloadError::Io {
        path: path.to_path_buf(),
        source: io::Error::other(format!("hashing task failed: {error}")),
    }
}

async fn hash_file_blocking(path: &Path) -> Result<Hashes, DownloadError> {
    let owned = path.to_path_buf();
    tokio::task::spawn_blocking(move || hash_file(&owned))
        .await
        .map_err(|error| blocking_error(path, error))?
        .map_err(|source| DownloadError::Io {
            path: path.to_path_buf(),
            source,
        })
}

async fn hash_prefix_blocking(path: &Path, len: u64) -> Result<Hasher, DownloadError> {
    let owned = path.to_path_buf();
    tokio::task::spawn_blocking(move || Hasher::read_prefix(&owned, len))
        .await
        .map_err(|error| blocking_error(path, error))?
        .map_err(|source| DownloadError::Io {
            path: path.to_path_buf(),
            source,
        })
}

async fn hash_tail_blocking(
    path: &Path,
    offset: u64,
    primed: Hasher,
) -> Result<Hashes, DownloadError> {
    let owned = path.to_path_buf();
    tokio::task::spawn_blocking(move || primed.read_tail(&owned, offset))
        .await
        .map_err(|error| blocking_error(path, error))?
        .map_err(|source| DownloadError::Io {
            path: path.to_path_buf(),
            source,
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_ladder_is_ftp_then_ftps_then_https() {
        assert_eq!(
            DEFAULT_TRANSPORTS,
            [
                TransportKind::Ftp,
                TransportKind::Ftps,
                TransportKind::Https
            ]
        );
        assert_eq!(RetryPolicy::default().attempts(), 3);
    }

    #[test]
    fn backoff_doubles_and_stays_inside_its_window() {
        let policy = RetryPolicy::new(3, Duration::from_secs(1));

        for (retry, window) in [(0, 1000_u64), (1, 2000), (2, 4000)] {
            let base = Duration::from_millis(window);
            let delay = policy.delay(retry);
            assert!(
                delay >= base / 2 && delay <= base,
                "retry {retry} waited {delay:?}, outside {:?}..={:?}",
                base / 2,
                base
            );
        }
    }

    #[test]
    fn a_zero_backoff_never_waits() {
        let policy = RetryPolicy::new(3, Duration::ZERO);
        assert_eq!(policy.delay(0), Duration::ZERO);
    }

    #[test]
    fn the_ftps_connector_trusts_public_roots() {
        assert!(
            rustls_connector("ftp.osuosl.org").is_ok(),
            "the rustls provider and webpki roots must be usable"
        );
    }

    #[test]
    fn ftp_paths_refuse_traversal_and_join_the_base() {
        let endpoint = FtpEndpoint::new("ftp.example.org", 21, "pub/cinc/files");

        assert_eq!(
            endpoint
                .remote_path("stable/cinc/19.4.46/x.deb")
                .expect("path"),
            "pub/cinc/files/stable/cinc/19.4.46/x.deb"
        );
        assert!(endpoint.remote_path("../etc/passwd").is_err());
        assert!(endpoint.remote_path("stable/../../etc").is_err());
    }

    #[test]
    fn fatal_transport_errors_are_the_permanent_ones() {
        assert!(TransportError::NotFound {
            path: "x".to_string()
        }
        .is_fatal());
        assert!(TransportError::Auth {
            path: "x".to_string(),
            reason: "530".to_string()
        }
        .is_fatal());
        assert!(TransportError::Forbidden {
            path: "x".to_string(),
            status: 403
        }
        .is_fatal());
        assert!(!TransportError::Retryable {
            path: "x".to_string(),
            reason: "503".to_string()
        }
        .is_fatal());
        assert!(!TransportError::Protocol {
            path: "x".to_string(),
            reason: "bad".to_string()
        }
        .is_fatal());
    }
}
