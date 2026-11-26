//! OCI distribution client.
//!
//! The client speaks the [distribution spec][spec] directly over `reqwest`
//! because the mirror needs two things a generic client does not give it: blob
//! uploads streamed from disk in bounded chunks (packages reach hundreds of
//! megabytes and must never be buffered whole), and a bearer token flow that is
//! reusable for a custom streaming `PUT`.
//!
//! [spec]: https://github.com/opencontainers/distribution-spec
//!
//! # Authentication
//!
//! A request is sent unauthenticated first. A `401` carrying
//! `WWW-Authenticate: Bearer realm=...,service=...,scope=...` triggers a token
//! request to the realm with the service and scope the registry asked for; the
//! token is cached per `(registry, repository, scope)` until shortly before its
//! `expires_in` (60 s when the registry does not say) runs out. A `Basic`
//! challenge is answered with the configured basic credentials. Credentials are
//! only sent to the token realm and never logged.
//!
//! [`OciAuth`] mirrors the target configuration: `docker` reads
//! `$DOCKER_CONFIG/config.json` or `~/.docker/config.json` (`auths` entries,
//! base64 `user:password` or `identitytoken`); in CI `GHCR_TOKEN` or
//! `GITHUB_TOKEN` overrides the docker config for `ghcr.io` with
//! `<actor>:<token>` basic credentials. `credHelpers` and `credsStore` would
//! require running an external helper, so they surface as
//! [`AuthError::UnsupportedCredentialHelper`] instead of being silently ignored.
//! `basic` reads `<user>:<password>` from the target's environment or
//! `password_file`; `bearer` takes a pre-issued token from the environment
//! (see [`Registry::from_target`]); `anonymous` never sends credentials.
//!
//! # Uploads
//!
//! [`Registry::upload_blob`] starts a session with `POST
//! /v2/<repo>/blobs/uploads/`, sends repeated `PATCH` requests of at most
//! [`UPLOAD_CHUNK_SIZE`] bytes read from the file, and closes with `PUT
//! <location>?digest=<digest>` and an empty body. Only one chunk is in memory at
//! a time (the read buffer plus the request body copy), so the memory ceiling is
//! the chunk size, not the layer size. A registry that reports a different
//! `Docker-Content-Digest` is an error: the bytes that arrived are not the bytes
//! that were verified.
//!
//! # Retries
//!
//! Blob uploads, manifest writes and manifest reads retry up to four times with
//! a jittered 0.5 s, 1 s, 2 s backoff on `429`, `5xx` and connection errors.
//! `400`, `403` and `404` are terminal. A `401` re-authenticates exactly once
//! before the retry decision is made, and a second `401` is an
//! [`AuthError::Unauthorized`]. Tag pages and manifest deletes retry the same
//! way.
//!
//! Every network wait is bounded. [`OciConfig::request_timeout`] (300 s by
//! default) covers one whole request, including sending a `PATCH` body that a
//! registry accepts and then stops reading; [`OciConfig::idle_read_timeout`]
//! (120 s by default) covers each response body read. An expired budget is a
//! retryable [`OciError::Http`] failure, so a stalled registry retries like a
//! refused connection instead of wedging a worker.

use std::collections::{BTreeSet, HashMap};
use std::fmt;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::engine::general_purpose::STANDARD_NO_PAD as BASE64_NO_PAD;
use base64::Engine as _;
use rand::Rng as _;
use reqwest::header::{AUTHORIZATION, LOCATION, WWW_AUTHENTICATE};
use reqwest::{Client, Method, Response, StatusCode};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use url::Url;

use crate::config::{Config, TargetAuth, TargetConfig, TargetKind};
use crate::source::USER_AGENT;

/// Media type written by [`Registry::put_manifest`].
pub const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// Manifest media types accepted by [`Registry::get_manifest`].
pub const MANIFEST_ACCEPT: &str =
    "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json";

/// Bytes read from the layer and sent per `PATCH` request.
///
/// Four MiB keeps the in-memory window small while giving a 500 MB package a
/// hundred-odd round trips instead of thousands.
pub const UPLOAD_CHUNK_SIZE: usize = 4 * 1024 * 1024;

/// Attempts per retryable operation, including the first try.
const RETRY_ATTEMPTS: usize = 4;

/// First retry wait; doubled per retry and jittered into the upper half.
const RETRY_BASE: Duration = Duration::from_millis(500);

/// Tags requested per page, and the maximum number of pages a listing follows.
const LIST_PAGE_LIMIT: usize = 100;

/// Assumed token lifetime when the token endpoint omits `expires_in`.
const TOKEN_DEFAULT_LIFETIME: u64 = 60;

/// A cached token is refreshed when this close to expiry.
const TOKEN_EXPIRY_MARGIN: Duration = Duration::from_secs(5);

/// Default budget for one response body read.
pub const DEFAULT_IDLE_READ_TIMEOUT: Duration = Duration::from_secs(120);

/// Default budget for one complete request.
pub const DEFAULT_REQUEST_TIMEOUT: Duration = Duration::from_secs(300);

/// Layer title annotation used to find the package layer.
const TITLE_ANNOTATION: &str = "org.opencontainers.image.title";

/// Suffixes that identify a mirrored package layer.
const PACKAGE_SUFFIXES: [&str; 6] = [".deb", ".rpm", ".msi", ".pkg", ".dmg", ".tar.gz"];

/// Registry whose CI token overrides the docker config.
pub(crate) const GHCR_HOST: &str = "ghcr.io";

/// GitHub's conventional CI token user.
const CI_TOKEN_USER: &str = "x-access-token";

/// How the client authenticates against a registry.
///
/// The docker, bearer and basic variants defer credential material as long as
/// possible; `Debug` never prints a secret.
#[derive(Clone, Default)]
pub enum OciAuth {
    /// Read credentials from the docker config, with the CI overrides.
    Docker,
    /// Username and password for registries that authenticate the token
    /// endpoint with HTTP basic auth.
    Basic {
        /// User name.
        username: String,
        /// Password or token used as the password.
        password: String,
    },
    /// A pre-issued bearer token sent on every request.
    Bearer {
        /// The token itself.
        token: String,
    },
    /// Send no credentials; the registry may still issue an anonymous token.
    #[default]
    Anonymous,
}

impl fmt::Debug for OciAuth {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Docker => formatter.write_str("Docker"),
            Self::Basic { username, .. } => formatter
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
            Self::Bearer { .. } => formatter
                .debug_struct("Bearer")
                .field("token", &"<redacted>")
                .finish(),
            Self::Anonymous => formatter.write_str("Anonymous"),
        }
    }
}

/// Everything [`Registry::new`] needs.
#[derive(Debug, Clone)]
pub struct OciConfig {
    /// Registry host, optionally with a scheme and port, e.g. `ghcr.io` or
    /// `127.0.0.1:5000`.
    pub registry: String,
    /// Repository namespace below the registry, e.g. `rmoriz/cinc-mirror`.
    pub namespace: String,
    /// How requests authenticate.
    pub auth: OciAuth,
    /// Use cleartext HTTP. Only for tests and registries on the local machine.
    pub insecure_http: bool,
    /// Budget for one response body read (one `chunk()` await).
    ///
    /// A stalled connection that has already sent its headers fails here
    /// instead of hanging a worker forever. Defaults to
    /// [`DEFAULT_IDLE_READ_TIMEOUT`].
    pub idle_read_timeout: Duration,
    /// Budget for one complete request: connection, request body, response
    /// headers and the body reads between [`Registry::send_once`] callers.
    ///
    /// A registry that accepts a connection and then stops reading our PATCH
    /// body never returns from `send()`; this bounds that wedge. Defaults to
    /// [`DEFAULT_REQUEST_TIMEOUT`].
    pub request_timeout: Duration,
}

impl Default for OciConfig {
    fn default() -> Self {
        Self {
            registry: String::new(),
            namespace: String::new(),
            auth: OciAuth::Anonymous,
            insecure_http: false,
            idle_read_timeout: DEFAULT_IDLE_READ_TIMEOUT,
            request_timeout: DEFAULT_REQUEST_TIMEOUT,
        }
    }
}

impl OciConfig {
    /// An anonymous, HTTPS configuration for `registry` and `namespace`.
    #[must_use]
    pub fn new(registry: impl Into<String>, namespace: impl Into<String>) -> Self {
        Self {
            registry: registry.into(),
            namespace: namespace.into(),
            ..Self::default()
        }
    }
}

/// A distribution client bound to one registry.
///
/// Cloning is not supported: the token cache is shared through `&self`, which
/// is what the upload workers in the OCI target need.
pub struct Registry {
    registry: String,
    base: Url,
    namespace: String,
    auth: OciAuth,
    client: Client,
    tokens: Mutex<HashMap<(String, String), CachedToken>>,
    request_timeout: Duration,
    idle_read_timeout: Duration,
    attempts: usize,
    backoff: Duration,
}

impl fmt::Debug for Registry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Registry")
            .field("registry", &self.registry)
            .field("namespace", &self.namespace)
            .field("auth", &self.auth)
            .finish_non_exhaustive()
    }
}

/// One cached bearer token.
struct CachedToken {
    value: String,
    expires_at: Instant,
}

/// One solved `auths` entry or resolved environment credential.
enum Credential {
    Anonymous,
    Basic { username: String, password: String },
    Bearer { token: String },
}

impl fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Anonymous => formatter.write_str("Anonymous"),
            Self::Basic { username, .. } => formatter
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"<redacted>")
                .finish(),
            Self::Bearer { .. } => formatter
                .debug_struct("Bearer")
                .field("token", &"<redacted>")
                .finish(),
        }
    }
}

impl Credential {
    fn basic_authorization(&self) -> Option<String> {
        match self {
            Self::Basic { username, password } => Some(format!(
                "Basic {}",
                BASE64.encode(format!("{username}:{password}"))
            )),
            _ => None,
        }
    }
}

impl Registry {
    /// Build a client for `config`.
    ///
    /// # Errors
    ///
    /// Returns [`OciError::Config`] when the registry name is empty, uses an
    /// unsupported scheme, or asks for cleartext HTTP without
    /// [`OciConfig::insecure_http`], when a timeout is zero, and when the HTTP
    /// client cannot be built.
    pub fn new(config: OciConfig) -> Result<Self, OciError> {
        let registry = config.registry.trim().to_string();
        if registry.is_empty() {
            return Err(OciError::Config {
                reason: "registry must not be empty".to_string(),
            });
        }
        if config.request_timeout.is_zero() || config.idle_read_timeout.is_zero() {
            return Err(OciError::Config {
                reason: "request_timeout and idle_read_timeout must be greater than zero"
                    .to_string(),
            });
        }

        let base = registry_base(&registry, config.insecure_http)?;
        let host = base.host_str().ok_or_else(|| OciError::Config {
            reason: format!("registry `{registry}` has no host"),
        })?;
        let registry_name = match base.port() {
            Some(port) => format!("{host}:{port}"),
            None => host.to_string(),
        };

        let client = Client::builder()
            .user_agent(USER_AGENT)
            .connect_timeout(Duration::from_secs(30))
            .build()
            .map_err(|error| OciError::Config {
                reason: format!("cannot build the http client: {error}"),
            })?;

        Ok(Self {
            registry: registry_name,
            base,
            namespace: config.namespace.trim().to_string(),
            auth: config.auth,
            client,
            tokens: Mutex::new(HashMap::new()),
            request_timeout: config.request_timeout,
            idle_read_timeout: config.idle_read_timeout,
            attempts: RETRY_ATTEMPTS,
            backoff: RETRY_BASE,
        })
    }

    /// Build a client from a configured OCI target.
    ///
    /// `auth = "basic"` reads `CINC_MIRROR_<TARGET>_USER` and
    /// `CINC_MIRROR_<TARGET>_PASSWORD` (the target name upper-cased with
    /// non-alphanumerics replaced by `_`), falling back to `password_file` for
    /// the password. `auth = "bearer"` reads `CINC_MIRROR_<TARGET>_TOKEN`.
    /// A registry written with an explicit `http://` scheme is treated as a
    /// local registry and switches on cleartext; everything else is HTTPS.
    ///
    /// # Errors
    ///
    /// Returns [`OciError::Config`] for a target that is not an OCI target or
    /// lacks a registry or namespace, and [`OciError::Auth`] when the selected
    /// auth mode is missing its credential material.
    pub fn from_target(target: &TargetConfig, _config: &Config) -> Result<Self, OciError> {
        if target.kind != TargetKind::Oci {
            return Err(OciError::Config {
                reason: format!("target `{}` is not an oci target", target.name),
            });
        }

        let registry = target
            .registry
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| OciError::Config {
                reason: format!("oci target `{}` has no registry", target.name),
            })?;
        let namespace = target
            .namespace
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| OciError::Config {
                reason: format!("oci target `{}` has no namespace", target.name),
            })?;

        let prefix = target_env_prefix(&target.name);
        let auth = match target.auth {
            TargetAuth::Docker => OciAuth::Docker,
            TargetAuth::Anonymous => OciAuth::Anonymous,
            TargetAuth::Basic => {
                let username = env_value(&format!("{prefix}_USER")).ok_or_else(|| {
                    AuthError::MissingCredentials {
                        registry: registry.to_string(),
                    }
                })?;
                let password = match env_value(&format!("{prefix}_PASSWORD")) {
                    Some(password) => password,
                    None => match &target.password_file {
                        Some(path) => read_password_file(path)?,
                        None => {
                            return Err(AuthError::MissingCredentials {
                                registry: registry.to_string(),
                            }
                            .into())
                        }
                    },
                };
                OciAuth::Basic { username, password }
            }
            TargetAuth::Bearer => {
                let token = env_value(&format!("{prefix}_TOKEN")).ok_or_else(|| {
                    AuthError::MissingCredentials {
                        registry: registry.to_string(),
                    }
                })?;
                OciAuth::Bearer { token }
            }
            other => {
                return Err(OciError::Config {
                    reason: format!("auth `{other}` is not valid for an oci target"),
                })
            }
        };

        Self::new(OciConfig {
            registry: registry.to_string(),
            namespace: namespace.to_string(),
            auth,
            insecure_http: registry.starts_with("http://"),
            ..OciConfig::default()
        })
    }

    /// Shorten the retry backoff. The tests use zero; production keeps 0.5 s.
    #[must_use]
    pub fn with_retry_base(mut self, backoff: Duration) -> Self {
        self.backoff = backoff;
        self
    }

    /// Registry host (and port) this client talks to.
    #[must_use]
    pub fn registry(&self) -> &str {
        &self.registry
    }

    /// Configured repository namespace.
    #[must_use]
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Check that the registry answers and that write credentials work.
    ///
    /// `GET /v2/` proves the endpoint; the follow-up token request asks for
    /// `repository:<namespace>:pull,push`, which a read-only or absent
    /// credential cannot obtain. Nothing is written.
    ///
    /// # Errors
    ///
    /// Returns [`OciError`] when the endpoint is unreachable, refuses the
    /// credentials, or the token request fails.
    pub async fn probe(&self) -> Result<(), OciError> {
        let url = self.url_for_dir(&["v2"])?;
        let scope = probe_scope(&self.namespace);
        let authorization = self.initial_authorization(&self.namespace, &scope);
        let response = self
            .send_once(&Method::GET, &url, &[], None, authorization)
            .await?;

        let response = if response.status() == StatusCode::UNAUTHORIZED {
            let challenge = challenge_of(&response, &self.registry)?;
            self.authorize_pinned(&self.namespace, &scope, &challenge)
                .await?;
            let authorization = self.initial_authorization(&self.namespace, &scope);
            self.send_once(&Method::GET, &url, &[], None, authorization)
                .await?
        } else {
            response
        };

        self.check_success(response, &Method::GET, &url)
            .await
            .map(|_| ())
    }

    /// Whether `digest` already exists in `repo`.
    ///
    /// # Errors
    ///
    /// Returns [`OciError`] for anything except a definitive `200` (present) or
    /// `404` (absent).
    pub async fn head_blob(&self, repo: &str, digest: &str) -> Result<bool, OciError> {
        let url = self.url_for(&["v2", repo, "blobs", digest])?;
        self.with_retry(|| self.head_blob_once(repo, &url)).await
    }

    /// Stream `path` into `repo` as `digest`.
    ///
    /// The file is read in [`UPLOAD_CHUNK_SIZE`] chunks; an attempt holds a
    /// small, constant number of chunk-sized buffers regardless of file size. A
    /// retry restarts the upload
    /// session, which is safe because blob uploads are idempotent by digest.
    ///
    /// # Errors
    ///
    /// Returns [`OciError::Io`] when the file cannot be read,
    /// [`OciError::DigestMismatch`] when the registry reports a different digest
    /// for the uploaded bytes, and [`OciError`] for transport and status
    /// failures.
    pub async fn upload_blob(&self, repo: &str, path: &Path, digest: &str) -> Result<(), OciError> {
        let metadata = tokio::fs::metadata(path)
            .await
            .map_err(|source| OciError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        let size = metadata.len();
        self.with_retry(|| self.upload_file_once(repo, path, size, digest))
            .await
    }

    /// Upload `bytes` as a blob in `repo` under `digest`.
    ///
    /// Small synthetic blobs (the empty config document) have no file behind
    /// them; the bytes go in one `PATCH` inside the same upload session, with
    /// the same digest verification and retry ladder as
    /// [`Registry::upload_blob`].
    ///
    /// # Errors
    ///
    /// Returns [`OciError::DigestMismatch`] when the registry reports a
    /// different digest for the uploaded bytes, and [`OciError`] for transport
    /// and status failures.
    pub async fn upload_bytes(
        &self,
        repo: &str,
        bytes: &[u8],
        digest: &str,
    ) -> Result<(), OciError> {
        self.with_retry(|| self.upload_bytes_once(repo, bytes, digest))
            .await
    }

    /// Write `manifest` to `repo` under `reference` and return its digest.
    ///
    /// The returned digest is the registry's `Docker-Content-Digest` when it
    /// sends one; otherwise it is the SHA-256 of the exact bytes sent.
    ///
    /// # Errors
    ///
    /// Returns [`OciError::Config`] when the manifest cannot be serialised and
    /// [`OciError`] on transport or status failures (429, 5xx and connection
    /// errors are retried four times).
    pub async fn put_manifest(
        &self,
        repo: &str,
        reference: &str,
        manifest: &Value,
    ) -> Result<String, OciError> {
        let bytes = serde_json::to_vec(manifest).map_err(|error| OciError::Config {
            reason: format!("cannot serialise the manifest: {error}"),
        })?;
        let url = self.url_for(&["v2", repo, "manifests", reference])?;
        let computed = format!("sha256:{}", sha256_hex(&bytes));
        self.with_retry(|| self.put_manifest_once(repo, &url, &bytes, &computed))
            .await
    }

    /// Read the manifest at `reference`, returning it and its digest.
    ///
    /// # Errors
    ///
    /// Returns [`OciError::NotFound`] when the reference does not exist and
    /// [`OciError::Protocol`] when the registry answers with something that is
    /// not a JSON manifest.
    pub async fn get_manifest(
        &self,
        repo: &str,
        reference: &str,
    ) -> Result<(Value, String), OciError> {
        let url = self.url_for(&["v2", repo, "manifests", reference])?;
        self.with_retry(|| self.get_manifest_once(repo, &url)).await
    }

    /// Every tag in `repo`, sorted.
    ///
    /// Tags are requested [`LIST_PAGE_LIMIT`] at a time and only a `Link` header
    /// whose `rel` is `next` is followed, for at most [`LIST_PAGE_LIMIT`] pages.
    /// A repository that was never published answers `404` and yields an empty
    /// list.
    ///
    /// # Errors
    ///
    /// Returns [`OciError`] on transport and status failures and
    /// [`OciError::Protocol`] when a page is not a JSON tag list.
    pub async fn list_tags(&self, repo: &str) -> Result<Vec<String>, OciError> {
        let mut url = self.url_for(&["v2", repo, "tags", "list"])?;
        url.query_pairs_mut()
            .append_pair("n", &LIST_PAGE_LIMIT.to_string());

        let mut tags = BTreeSet::new();
        for _ in 0..LIST_PAGE_LIMIT {
            let Some(page) = self.with_retry(|| self.tags_page_once(repo, &url)).await? else {
                break;
            };
            tags.extend(page.tags);
            let Some(next) = page.next else {
                break;
            };
            url = self.location_url(&next)?;
        }
        Ok(tags.into_iter().collect())
    }

    /// Digest of the manifest at `reference`, or `None` when it is gone.
    ///
    /// Only the `Docker-Content-Digest` header is used; a `HEAD` that succeeds
    /// without it also reports `None`, so the caller treats the manifest as
    /// absent instead of guessing a digest from a body that was never read.
    ///
    /// # Errors
    ///
    /// Returns [`OciError`] for anything but a success or `404`.
    pub async fn head_manifest(
        &self,
        repo: &str,
        reference: &str,
    ) -> Result<Option<String>, OciError> {
        let url = self.url_for(&["v2", repo, "manifests", reference])?;
        self.with_retry(|| self.head_manifest_once(repo, &url))
            .await
    }

    /// Delete the manifest `digest` from `repo`.
    ///
    /// `200`, `202` and `404` are success: a manifest that is already gone needs
    /// no second delete. A registry without delete support answers `405`, which
    /// surfaces as [`OciError::Status`] with that status.
    ///
    /// # Errors
    ///
    /// Returns [`OciError`] for transport failures and any status other than
    /// `200`, `202` and `404`.
    pub async fn delete_manifest(&self, repo: &str, digest: &str) -> Result<(), OciError> {
        let url = self.url_for(&["v2", repo, "manifests", digest])?;
        self.with_retry(|| self.delete_manifest_once(repo, &url))
            .await
    }

    /// Digest of the package layer of the manifest at `tag`.
    ///
    /// The package layer is the first layer whose
    /// `org.opencontainers.image.title` annotation ends in a package suffix; a
    /// manifest without a matching annotation falls back to its first layer, and
    /// a missing tag or layerless manifest yields `None`.
    ///
    /// # Errors
    ///
    /// Returns [`OciError`] when the manifest cannot be read; a missing tag is
    /// `Ok(None)`, not an error.
    pub async fn package_digest_for_tag(
        &self,
        repo: &str,
        tag: &str,
    ) -> Result<Option<String>, OciError> {
        match self.get_manifest(repo, tag).await {
            Ok((manifest, _)) => Ok(package_layer_digest(&manifest)),
            Err(OciError::NotFound { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    // Requests ---------------------------------------------------------------

    async fn head_blob_once(&self, repo: &str, url: &Url) -> Result<bool, OciError> {
        let response = self
            .request(Method::HEAD, url, repo, &pull_scope(repo), &[], None)
            .await?;
        match response.status() {
            status if status.is_success() => Ok(true),
            StatusCode::NOT_FOUND => Ok(false),
            status => Err(self
                .status_error(&Method::HEAD, url, status, response)
                .await),
        }
    }

    async fn head_manifest_once(&self, repo: &str, url: &Url) -> Result<Option<String>, OciError> {
        let headers = [("accept", MANIFEST_ACCEPT.to_string())];
        let response = self
            .request(Method::HEAD, url, repo, &pull_scope(repo), &headers, None)
            .await?;
        match response.status() {
            status if status.is_success() => Ok(digest_header(&response)),
            StatusCode::NOT_FOUND => Ok(None),
            status => Err(self
                .status_error(&Method::HEAD, url, status, response)
                .await),
        }
    }

    async fn delete_manifest_once(&self, repo: &str, url: &Url) -> Result<(), OciError> {
        let response = self
            .request(Method::DELETE, url, repo, &push_scope(repo), &[], None)
            .await?;
        match response.status() {
            StatusCode::OK | StatusCode::ACCEPTED => {
                self.drain_body(response, &Method::DELETE, url).await
            }
            StatusCode::NOT_FOUND => Ok(()),
            status => Err(self
                .status_error(&Method::DELETE, url, status, response)
                .await),
        }
    }

    async fn tags_page_once(&self, repo: &str, url: &Url) -> Result<Option<TagPage>, OciError> {
        let response = self
            .request(Method::GET, url, repo, &pull_scope(repo), &[], None)
            .await?;
        if response.status() == StatusCode::NOT_FOUND {
            return Ok(None);
        }
        let next = next_link(&response);
        let response = self.check_success(response, &Method::GET, url).await?;
        let bytes = self.read_body(response, &Method::GET, url).await?;
        let body: TagListBody =
            serde_json::from_slice(&bytes).map_err(|error| OciError::Protocol {
                registry: self.registry.clone(),
                reason: format!("tag list at {url} is not valid JSON: {error}"),
            })?;
        Ok(Some(TagPage {
            tags: body.tags.unwrap_or_default(),
            next,
        }))
    }

    async fn upload_file_once(
        &self,
        repo: &str,
        path: &Path,
        size: u64,
        digest: &str,
    ) -> Result<(), OciError> {
        let Some(mut location) = self.begin_upload(repo, digest).await? else {
            return Ok(());
        };

        let mut file = tokio::fs::File::open(path)
            .await
            .map_err(|source| OciError::Io {
                path: path.to_path_buf(),
                source,
            })?;
        let mut buffer = vec![0_u8; UPLOAD_CHUNK_SIZE];
        let mut sent = 0_u64;

        loop {
            let filled = fill(&mut file, &mut buffer)
                .await
                .map_err(|source| OciError::Io {
                    path: path.to_path_buf(),
                    source,
                })?;
            if filled == 0 {
                break;
            }

            sent = self
                .patch_upload(repo, &mut location, sent, &buffer[..filled])
                .await?;
        }

        if sent != size {
            return Err(OciError::Io {
                path: path.to_path_buf(),
                source: io::Error::other(format!(
                    "the layer changed size during upload: expected {size} bytes, read {sent}"
                )),
            });
        }

        self.finish_upload(repo, &location, digest).await
    }

    async fn upload_bytes_once(
        &self,
        repo: &str,
        bytes: &[u8],
        digest: &str,
    ) -> Result<(), OciError> {
        let Some(mut location) = self.begin_upload(repo, digest).await? else {
            return Ok(());
        };

        if !bytes.is_empty() {
            self.patch_upload(repo, &mut location, 0, bytes).await?;
        }

        self.finish_upload(repo, &location, digest).await
    }

    /// Start an upload session and return its location, or `None` when the
    /// registry deduplicated the blob and finished the upload immediately.
    async fn begin_upload(&self, repo: &str, digest: &str) -> Result<Option<Url>, OciError> {
        let start = self.url_for_dir(&["v2", repo, "blobs", "uploads"])?;
        let response = self
            .request(Method::POST, &start, repo, &push_scope(repo), &[], None)
            .await?;

        let reported = digest_header(&response);
        let status = response.status();
        if status == StatusCode::CREATED {
            // Some registries deduplicate and finish the upload immediately.
            self.drain_body(response, &Method::POST, &start).await?;
            check_upload_digest(reported.as_deref(), digest)?;
            return Ok(None);
        }
        let response = self.check_success(response, &Method::POST, &start).await?;
        let location = location_header(&response).ok_or_else(|| OciError::Protocol {
            registry: self.registry.clone(),
            reason: format!("upload start at {start} returned no Location header"),
        })?;
        self.drain_body(response, &Method::POST, &start).await?;
        Ok(Some(self.location_url(&location)?))
    }

    /// Send one `PATCH` chunk and return the offset after it.
    async fn patch_upload(
        &self,
        repo: &str,
        location: &mut Url,
        offset: u64,
        chunk: &[u8],
    ) -> Result<u64, OciError> {
        let headers = [(
            "content-range",
            format!("{}-{}", offset, offset + chunk.len() as u64 - 1),
        )];
        let response = self
            .request(
                Method::PATCH,
                location,
                repo,
                &push_scope(repo),
                &headers,
                Some(("application/octet-stream", chunk)),
            )
            .await?;
        let next = location_header(&response);
        let response = self
            .check_success(response, &Method::PATCH, location)
            .await?;
        self.drain_body(response, &Method::PATCH, location).await?;
        if let Some(next) = next {
            *location = self.location_url(&next)?;
        }
        Ok(offset + chunk.len() as u64)
    }

    /// Close the upload session with `PUT <location>?digest=<digest>`.
    async fn finish_upload(
        &self,
        repo: &str,
        location: &Url,
        digest: &str,
    ) -> Result<(), OciError> {
        let mut finish = location.clone();
        finish.query_pairs_mut().append_pair("digest", digest);
        let response = self
            .request(
                Method::PUT,
                &finish,
                repo,
                &push_scope(repo),
                &[],
                Some(("application/octet-stream", &[])),
            )
            .await?;
        let reported = digest_header(&response);
        let response = self.check_success(response, &Method::PUT, &finish).await?;
        self.drain_body(response, &Method::PUT, &finish).await?;

        check_upload_digest(reported.as_deref(), digest)
    }

    async fn put_manifest_once(
        &self,
        repo: &str,
        url: &Url,
        bytes: &[u8],
        computed: &str,
    ) -> Result<String, OciError> {
        let headers = [("accept", MANIFEST_ACCEPT.to_string())];
        let response = self
            .request(
                Method::PUT,
                url,
                repo,
                &push_scope(repo),
                &headers,
                Some((MANIFEST_MEDIA_TYPE, bytes)),
            )
            .await?;
        let reported = digest_header(&response);
        let response = self.check_success(response, &Method::PUT, url).await?;
        self.drain_body(response, &Method::PUT, url).await?;
        Ok(reported.unwrap_or_else(|| computed.to_string()))
    }

    async fn get_manifest_once(&self, repo: &str, url: &Url) -> Result<(Value, String), OciError> {
        let headers = [("accept", MANIFEST_ACCEPT.to_string())];
        let response = self
            .request(Method::GET, url, repo, &pull_scope(repo), &headers, None)
            .await?;
        let reported = digest_header(&response);
        let response = self.check_success(response, &Method::GET, url).await?;
        let bytes = self.read_body(response, &Method::GET, url).await?;
        let digest = reported.unwrap_or_else(|| format!("sha256:{}", sha256_hex(&bytes)));
        let manifest = serde_json::from_slice(&bytes).map_err(|error| OciError::Protocol {
            registry: self.registry.clone(),
            reason: format!("manifest at {url} is not valid JSON: {error}"),
        })?;
        Ok((manifest, digest))
    }

    /// Send one request, solving a single `401` challenge on the way.
    async fn request(
        &self,
        method: Method,
        url: &Url,
        repo: &str,
        scope: &str,
        headers: &[(&'static str, String)],
        body: Option<(&str, &[u8])>,
    ) -> Result<Response, OciError> {
        let authorization = self.initial_authorization(repo, scope);
        let response = self
            .send_once(&method, url, headers, body, authorization)
            .await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return Ok(response);
        }

        let challenge = challenge_of(&response, &self.registry)?;
        self.forget_token(repo, scope);
        let authorization = self.authorize(repo, scope, &challenge).await?;
        let response = self
            .send_once(&method, url, headers, body, authorization)
            .await?;
        if response.status() == StatusCode::UNAUTHORIZED {
            return Err(AuthError::Unauthorized {
                registry: self.registry.clone(),
            }
            .into());
        }
        Ok(response)
    }

    async fn send_once(
        &self,
        method: &Method,
        url: &Url,
        headers: &[(&'static str, String)],
        body: Option<(&str, &[u8])>,
        authorization: Option<String>,
    ) -> Result<Response, OciError> {
        let mut builder = self.client.request(method.clone(), url.clone());
        if let Some(authorization) = authorization {
            builder = builder.header(AUTHORIZATION, authorization);
        }
        for (name, value) in headers {
            builder = builder.header(*name, value.as_str());
        }
        if let Some((content_type, bytes)) = body {
            builder = builder
                .header("content-type", content_type)
                .body(bytes.to_vec());
        }

        let method = method.as_str().to_string();
        let url = url.to_string();
        match tokio::time::timeout(self.request_timeout, builder.send()).await {
            Ok(Ok(response)) => Ok(response),
            Ok(Err(source)) => Err(OciError::Http {
                method,
                url,
                source: HttpFailure::Request(source),
            }),
            Err(_) => Err(OciError::Http {
                method,
                url,
                source: HttpFailure::Timeout {
                    waited: self.request_timeout,
                    phase: "waiting for the response",
                },
            }),
        }
    }

    /// Reject a non-success status, keeping the body for the error message.
    async fn check_success(
        &self,
        response: Response,
        method: &Method,
        url: &Url,
    ) -> Result<Response, OciError> {
        let status = response.status();
        if status.is_success() {
            return Ok(response);
        }
        if status == StatusCode::NOT_FOUND {
            return Err(OciError::NotFound {
                method: method.as_str().to_string(),
                url: url.to_string(),
            });
        }
        Err(self.status_error(method, url, status, response).await)
    }

    async fn status_error(
        &self,
        method: &Method,
        url: &Url,
        status: StatusCode,
        response: Response,
    ) -> OciError {
        let body = self
            .read_body(response, method, url)
            .await
            .unwrap_or_default();
        OciError::Status {
            method: method.as_str().to_string(),
            url: url.to_string(),
            status: status.as_u16(),
            body: truncate(&String::from_utf8_lossy(&body)),
        }
    }

    /// Read a response body with a per-read budget.
    ///
    /// Every `chunk()` await is wrapped in [`Registry`]'s idle read timeout, so
    /// a registry that sends headers and then stalls the body fails with a
    /// retryable [`OciError::Http`] instead of hanging the worker.
    async fn read_body(
        &self,
        mut response: Response,
        method: &Method,
        url: &Url,
    ) -> Result<Vec<u8>, OciError> {
        let mut body = Vec::new();
        loop {
            match tokio::time::timeout(self.idle_read_timeout, response.chunk()).await {
                Ok(Ok(Some(chunk))) => body.extend_from_slice(&chunk),
                Ok(Ok(None)) => return Ok(body),
                Ok(Err(source)) => {
                    return Err(OciError::Http {
                        method: method.as_str().to_string(),
                        url: url.to_string(),
                        source: HttpFailure::Request(source),
                    })
                }
                Err(_) => {
                    return Err(OciError::Http {
                        method: method.as_str().to_string(),
                        url: url.to_string(),
                        source: HttpFailure::Timeout {
                            waited: self.idle_read_timeout,
                            phase: "reading the response body",
                        },
                    })
                }
            }
        }
    }

    /// Read and discard a response body so the connection can be reused.
    async fn drain_body(
        &self,
        response: Response,
        method: &Method,
        url: &Url,
    ) -> Result<(), OciError> {
        self.read_body(response, method, url).await.map(|_| ())
    }

    /// Run `operation` up to the retry limit on transient failures.
    async fn with_retry<T, F, Fut>(&self, mut operation: F) -> Result<T, OciError>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<T, OciError>>,
    {
        let mut attempt = 0;
        loop {
            match operation().await {
                Ok(value) => return Ok(value),
                Err(error) if error.is_retryable() && attempt + 1 < self.attempts => {
                    tokio::time::sleep(self.delay(attempt)).await;
                    attempt += 1;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// Wait before retry `retry`: the base doubled, jittered into its upper half.
    fn delay(&self, retry: usize) -> Duration {
        let factor = 1_u32 << retry.min(2);
        let base = self.backoff.saturating_mul(factor);
        let half = base / 2;
        if half.is_zero() {
            return base;
        }
        let jitter = u64::try_from(half.as_millis()).unwrap_or(u64::MAX);
        half + Duration::from_millis(rand::thread_rng().gen_range(0..=jitter))
    }

    // Authentication ---------------------------------------------------------

    fn initial_authorization(&self, repo: &str, scope: &str) -> Option<String> {
        if let Some(token) = self.cached_token(repo, scope) {
            return Some(format!("Bearer {token}"));
        }
        match &self.auth {
            OciAuth::Bearer { token } => Some(format!("Bearer {token}")),
            _ => None,
        }
    }

    fn cached_token(&self, repo: &str, scope: &str) -> Option<String> {
        let tokens = self.tokens.lock().unwrap_or_else(PoisonError::into_inner);
        let token = tokens.get(&(repo.to_string(), scope.to_string()))?;
        if token.expires_at > Instant::now() + TOKEN_EXPIRY_MARGIN {
            Some(token.value.clone())
        } else {
            None
        }
    }

    fn cache_token(&self, repo: &str, scope: &str, value: &str, expires_at: Instant) {
        let mut tokens = self.tokens.lock().unwrap_or_else(PoisonError::into_inner);
        tokens.insert(
            (repo.to_string(), scope.to_string()),
            CachedToken {
                value: value.to_string(),
                expires_at,
            },
        );
    }

    fn forget_token(&self, repo: &str, scope: &str) {
        let mut tokens = self.tokens.lock().unwrap_or_else(PoisonError::into_inner);
        tokens.remove(&(repo.to_string(), scope.to_string()));
    }

    fn resolve_credential(&self) -> Result<Credential, AuthError> {
        match &self.auth {
            OciAuth::Anonymous => Ok(Credential::Anonymous),
            OciAuth::Basic { username, password } => Ok(Credential::Basic {
                username: username.clone(),
                password: password.clone(),
            }),
            OciAuth::Bearer { token } => Ok(Credential::Bearer {
                token: token.clone(),
            }),
            OciAuth::Docker => docker_credential(&self.registry),
        }
    }

    /// Answer one challenge and return the `Authorization` value to retry with.
    async fn authorize(
        &self,
        repo: &str,
        desired_scope: &str,
        challenge: &Challenge,
    ) -> Result<Option<String>, OciError> {
        self.authorize_inner(repo, desired_scope, challenge, true)
            .await
    }

    /// Like [`Registry::authorize`], but a probe asks for its own scope rather
    /// than the one the registry happened to advertise.
    async fn authorize_pinned(
        &self,
        repo: &str,
        desired_scope: &str,
        challenge: &Challenge,
    ) -> Result<Option<String>, OciError> {
        self.authorize_inner(repo, desired_scope, challenge, false)
            .await
    }

    async fn authorize_inner(
        &self,
        repo: &str,
        desired_scope: &str,
        challenge: &Challenge,
        prefer_challenge_scope: bool,
    ) -> Result<Option<String>, OciError> {
        let credential = self.resolve_credential()?;

        match challenge.scheme.as_str() {
            "bearer" => {
                if let Credential::Bearer { token } = &credential {
                    // A pre-issued token is already the answer; asking the
                    // realm to exchange it would only launder it.
                    return Ok(Some(format!("Bearer {token}")));
                }
                let realm = challenge
                    .params
                    .get("realm")
                    .filter(|realm| !realm.is_empty())
                    .ok_or_else(|| AuthError::Challenge {
                        registry: self.registry.clone(),
                        reason: "bearer challenge without a realm".to_string(),
                    })?;
                let scope = match challenge
                    .params
                    .get("scope")
                    .filter(|scope| !scope.is_empty())
                {
                    Some(scope) if prefer_challenge_scope => scope.as_str(),
                    _ => desired_scope,
                };
                let service = challenge.params.get("service").map(String::as_str);
                let token = self
                    .fetch_token(realm, service, scope, &credential, repo, desired_scope)
                    .await?;
                Ok(Some(format!("Bearer {token}")))
            }
            "basic" => credential.basic_authorization().map(Some).ok_or_else(|| {
                OciError::from(AuthError::MissingCredentials {
                    registry: self.registry.clone(),
                })
            }),
            other => Err(AuthError::Challenge {
                registry: self.registry.clone(),
                reason: format!("unsupported challenge scheme `{other}`"),
            }
            .into()),
        }
    }

    async fn fetch_token(
        &self,
        realm: &str,
        service: Option<&str>,
        scope: &str,
        credential: &Credential,
        repo: &str,
        desired_scope: &str,
    ) -> Result<String, OciError> {
        let mut url = Url::parse(realm).map_err(|error| AuthError::Challenge {
            registry: self.registry.clone(),
            reason: format!("token realm `{realm}` is not a URL: {error}"),
        })?;
        {
            let mut query = url.query_pairs_mut();
            if let Some(service) = service {
                query.append_pair("service", service);
            }
            if !scope.is_empty() {
                query.append_pair("scope", scope);
            }
        }

        let mut request = self.client.get(url.clone());
        if let Credential::Basic { username, password } = credential {
            request = request.basic_auth(username, Some(password));
        }

        let response = match tokio::time::timeout(self.request_timeout, request.send()).await {
            Ok(Ok(response)) => response,
            Ok(Err(source)) => {
                return Err(OciError::Http {
                    method: "GET".to_string(),
                    url: url.to_string(),
                    source: HttpFailure::Request(source),
                })
            }
            Err(_) => {
                return Err(OciError::Http {
                    method: "GET".to_string(),
                    url: url.to_string(),
                    source: HttpFailure::Timeout {
                        waited: self.request_timeout,
                        phase: "waiting for the token response",
                    },
                })
            }
        };
        let status = response.status();
        let body = self.read_body(response, &Method::GET, &url).await?;
        let body = String::from_utf8_lossy(&body).to_string();
        if !status.is_success() {
            return Err(AuthError::Token {
                url: url.to_string(),
                status: status.as_u16(),
                body: truncate(&body),
            }
            .into());
        }

        let value: Value = serde_json::from_str(&body).map_err(|error| AuthError::TokenBody {
            url: url.to_string(),
            reason: format!("the token response is not JSON: {error}"),
        })?;
        let token = value
            .get("token")
            .or_else(|| value.get("access_token"))
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| AuthError::TokenBody {
                url: url.to_string(),
                reason: "the token response carries no token".to_string(),
            })?;
        let lifetime = value
            .get("expires_in")
            .and_then(|value| {
                value
                    .as_u64()
                    .or_else(|| value.as_str().and_then(|value| value.parse().ok()))
            })
            .unwrap_or(TOKEN_DEFAULT_LIFETIME);
        let expires_at = Instant::now()
            .checked_add(Duration::from_secs(lifetime))
            .unwrap_or_else(Instant::now);

        self.cache_token(repo, scope, token, expires_at);
        if desired_scope != scope {
            self.cache_token(repo, desired_scope, token, expires_at);
        }

        Ok(token.to_string())
    }

    // URLs -------------------------------------------------------------------

    fn url_for(&self, parts: &[&str]) -> Result<Url, OciError> {
        self.build_url(parts, false)
    }

    fn url_for_dir(&self, parts: &[&str]) -> Result<Url, OciError> {
        self.build_url(parts, true)
    }

    fn build_url(&self, parts: &[&str], trailing_slash: bool) -> Result<Url, OciError> {
        let mut url = self.base.clone();
        url.set_query(None);
        url.set_fragment(None);

        {
            let mut segments = url.path_segments_mut().map_err(|()| OciError::Config {
                reason: format!("`{}` cannot hold path segments", self.base),
            })?;
            segments.pop_if_empty();
            for part in parts {
                if part.trim().is_empty() {
                    return Err(OciError::Config {
                        reason: "registry paths must not be empty".to_string(),
                    });
                }
                for segment in part.split('/') {
                    if segment.is_empty() || segment == "." || segment == ".." {
                        return Err(OciError::Config {
                            reason: format!("invalid registry path segment in `{part}`"),
                        });
                    }
                    segments.push(segment);
                }
            }
            if trailing_slash {
                segments.push("");
            }
        }

        Ok(url)
    }

    /// Resolve a registry-provided `Location`, refusing a host change so a token
    /// is never forwarded elsewhere.
    fn location_url(&self, location: &str) -> Result<Url, OciError> {
        let url = match Url::parse(location) {
            Ok(url) => url,
            Err(_) => self
                .base
                .join(location)
                .map_err(|error| OciError::Protocol {
                    registry: self.registry.clone(),
                    reason: format!("cannot resolve upload location `{location}`: {error}"),
                })?,
        };
        if url.scheme() != self.base.scheme()
            || url.host_str() != self.base.host_str()
            || url.port_or_known_default() != self.base.port_or_known_default()
        {
            return Err(OciError::Protocol {
                registry: self.registry.clone(),
                reason: format!("refusing upload location `{url}`: it leaves the registry"),
            });
        }
        Ok(url)
    }
}

/// Why a request failed at the transport level.
///
/// Timeouts are part of this class on purpose: a stalled connection is a
/// transient fault, so it goes through the same four-attempt ladder as a
/// refused connection.
#[derive(Debug, Error)]
pub enum HttpFailure {
    /// The request failed before a usable response arrived.
    #[error(transparent)]
    Request(#[from] reqwest::Error),

    /// The request or one body read exceeded its budget.
    #[error("timed out after {waited:?} while {phase}")]
    Timeout {
        /// The budget that expired.
        waited: Duration,
        /// What the client was waiting for.
        phase: &'static str,
    },
}

/// Errors raised by the OCI client.
#[derive(Debug, Error)]
pub enum OciError {
    /// The client configuration is unusable.
    #[error("invalid oci configuration: {reason}")]
    Config {
        /// Why the configuration was rejected.
        reason: String,
    },

    /// Authentication could not be established or was rejected.
    #[error(transparent)]
    Auth(#[from] AuthError),

    /// A request could not be completed.
    #[error("{method} {url} failed: {source}")]
    Http {
        /// HTTP method.
        method: String,
        /// Request URL.
        url: String,
        /// Underlying transport failure, including a timeout.
        #[source]
        source: HttpFailure,
    },

    /// The registry answered with an unexpected status.
    #[error("{method} {url} returned HTTP {status}: {body}")]
    Status {
        /// HTTP method.
        method: String,
        /// Request URL.
        url: String,
        /// Status code.
        status: u16,
        /// Response body, truncated for logs.
        body: String,
    },

    /// The requested object does not exist.
    #[error("{method} {url} returned HTTP 404")]
    NotFound {
        /// HTTP method.
        method: String,
        /// Request URL.
        url: String,
    },

    /// The registry answered in a way the client cannot use.
    #[error("registry {registry} answered unexpectedly: {reason}")]
    Protocol {
        /// Registry host.
        registry: String,
        /// What was wrong with the answer.
        reason: String,
    },

    /// The local layer file could not be read.
    #[error("cannot read {path}: {source}")]
    Io {
        /// Local path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The registry reported a different digest for the uploaded bytes.
    #[error("registry reported digest {observed} for an upload of {expected}")]
    DigestMismatch {
        /// Digest the caller verified.
        expected: String,
        /// Digest the registry reported.
        observed: String,
    },
}

impl OciError {
    /// Whether another attempt may succeed: throttling, server errors and
    /// connection failures are transient; authentication and bad requests are
    /// not.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        match self {
            Self::Status { status, .. } => *status == 429 || (500..600).contains(status),
            Self::Http { .. } => true,
            _ => false,
        }
    }

    /// Whether the registry said the object does not exist.
    #[must_use]
    pub fn is_not_found(&self) -> bool {
        matches!(self, Self::NotFound { .. })
    }
}

/// Errors raised while resolving or using registry credentials.
#[derive(Debug, Error)]
pub enum AuthError {
    /// No credential material is available for a mode that requires it.
    #[error("no credentials are configured for {registry}")]
    MissingCredentials {
        /// Registry host.
        registry: String,
    },

    /// The docker config could not be read.
    #[error("cannot read docker config {path}: {source}")]
    DockerConfig {
        /// Config path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The docker config is not valid JSON.
    #[error("cannot parse docker config {path}: {source}")]
    DockerConfigParse {
        /// Config path.
        path: PathBuf,
        /// Underlying parse error.
        #[source]
        source: serde_json::Error,
    },

    /// The docker config delegates the credential to a helper binary.
    #[error(
        "docker config {path} stores the credential for {registry} in credential helper \
         `{helper}`, which this client does not run; configure basic or bearer credentials"
    )]
    UnsupportedCredentialHelper {
        /// Config path.
        path: PathBuf,
        /// Registry the credential belongs to.
        registry: String,
        /// Helper or store name.
        helper: String,
    },

    /// An `auth` value is not valid base64.
    #[error("invalid base64 credential in docker config {path}: {source}")]
    CredentialEncoding {
        /// Config path.
        path: PathBuf,
        /// Underlying decode error.
        #[source]
        source: base64::DecodeError,
    },

    /// An `auth` value decoded but does not hold `user:password`.
    #[error("invalid credential in docker config {path}: {reason}")]
    InvalidCredential {
        /// Config path.
        path: PathBuf,
        /// What was wrong.
        reason: String,
    },

    /// A configured password file could not be read.
    #[error("cannot read password file {path}: {source}")]
    CredentialFile {
        /// File path.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// The registry rejected the credentials.
    #[error("registry {registry} rejected the credentials")]
    Unauthorized {
        /// Registry host.
        registry: String,
    },

    /// The authentication challenge could not be used.
    #[error("registry {registry} sent an unusable authentication challenge: {reason}")]
    Challenge {
        /// Registry host.
        registry: String,
        /// What was wrong with the challenge.
        reason: String,
    },

    /// The token endpoint answered with a failure status.
    #[error("token request to {url} returned HTTP {status}: {body}")]
    Token {
        /// Token endpoint URL.
        url: String,
        /// Status code.
        status: u16,
        /// Response body, truncated for logs.
        body: String,
    },

    /// The token endpoint answered with something that is not a token.
    #[error("token response from {url} is unusable: {reason}")]
    TokenBody {
        /// Token endpoint URL.
        url: String,
        /// What was wrong with the body.
        reason: String,
    },
}

/// One page of a tag listing: the tags and the `rel="next"` target, if any.
#[derive(Debug)]
struct TagPage {
    tags: Vec<String>,
    next: Option<String>,
}

/// JSON body of a tag listing page.
#[derive(Debug, serde::Deserialize)]
struct TagListBody {
    tags: Option<Vec<String>>,
}

/// One parsed `WWW-Authenticate` challenge.
#[derive(Debug, Clone)]
struct Challenge {
    scheme: String,
    params: HashMap<String, String>,
}

impl Challenge {
    fn parse(header: &str) -> Self {
        let header = header.trim();
        let (scheme, rest) = header.split_once(' ').unwrap_or((header, ""));
        let mut params = HashMap::new();
        let mut current = String::new();
        let mut quoted = false;

        for character in rest.chars() {
            match character {
                '"' => {
                    quoted = !quoted;
                    current.push(character);
                }
                ',' if !quoted => {
                    insert_parameter(&mut params, &current);
                    current.clear();
                }
                _ => current.push(character),
            }
        }
        insert_parameter(&mut params, &current);

        Self {
            scheme: scheme.trim().to_ascii_lowercase(),
            params,
        }
    }
}

fn insert_parameter(params: &mut HashMap<String, String>, part: &str) {
    if let Some((key, value)) = part.split_once('=') {
        let value = value.trim().trim_matches('"');
        if !key.trim().is_empty() && !value.is_empty() {
            params.insert(key.trim().to_ascii_lowercase(), value.to_string());
        }
    }
}

fn challenge_of(response: &Response, registry: &str) -> Result<Challenge, AuthError> {
    let header = response
        .headers()
        .get(WWW_AUTHENTICATE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| AuthError::Challenge {
            registry: registry.to_string(),
            reason: "HTTP 401 without a WWW-Authenticate header".to_string(),
        })?;
    Ok(Challenge::parse(header))
}

/// Target of the first `Link` header entry whose `rel` is `next`.
fn next_link(response: &Response) -> Option<String> {
    response
        .headers()
        .get_all("link")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .find_map(next_link_in)
}

fn next_link_in(value: &str) -> Option<String> {
    value.split(',').find_map(|entry| {
        let (target, parameters) = entry.split_once('>')?;
        let target = target.trim().strip_prefix('<')?;
        let follows = parameters.split(';').any(|parameter| {
            matches!(
                parameter.split_once('='),
                Some((name, rel))
                    if name.trim().eq_ignore_ascii_case("rel")
                        && rel.trim().trim_matches('"').eq_ignore_ascii_case("next")
            )
        });
        follows.then(|| target.to_string())
    })
}

fn digest_header(response: &Response) -> Option<String> {
    response
        .headers()
        .get("docker-content-digest")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn location_header(response: &Response) -> Option<String> {
    response
        .headers()
        .get(LOCATION)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

fn check_upload_digest(reported: Option<&str>, expected: &str) -> Result<(), OciError> {
    match reported {
        Some(reported) if reported != expected => Err(OciError::DigestMismatch {
            expected: expected.to_string(),
            observed: reported.to_string(),
        }),
        _ => Ok(()),
    }
}

/// Read until `buffer` is full or the file ends.
async fn fill(file: &mut tokio::fs::File, buffer: &mut [u8]) -> io::Result<usize> {
    use tokio::io::AsyncReadExt as _;

    let mut filled = 0;
    while filled < buffer.len() {
        let read = file.read(&mut buffer[filled..]).await?;
        if read == 0 {
            break;
        }
        filled += read;
    }
    Ok(filled)
}

fn pull_scope(repo: &str) -> String {
    format!("repository:{repo}:pull")
}

fn push_scope(repo: &str) -> String {
    format!("repository:{repo}:pull,push")
}

fn probe_scope(namespace: &str) -> String {
    if namespace.is_empty() {
        String::new()
    } else {
        format!("repository:{namespace}:pull,push")
    }
}

/// Pick the package layer digest out of a manifest.
///
/// The package layer is the first layer whose
/// `org.opencontainers.image.title` annotation ends in a package suffix; a
/// manifest without a matching annotation falls back to its first layer, and a
/// layerless manifest yields `None`.
#[must_use]
pub fn package_layer_digest(manifest: &Value) -> Option<String> {
    let layers = manifest.get("layers")?.as_array()?;
    let mut first = None;

    for layer in layers {
        let digest = layer.get("digest").and_then(Value::as_str);
        if first.is_none() {
            first = digest.map(str::to_string);
        }
        let Some(title) = layer
            .get("annotations")
            .and_then(|annotations| annotations.get(TITLE_ANNOTATION))
            .and_then(Value::as_str)
        else {
            continue;
        };
        let title = title.to_ascii_lowercase();
        if PACKAGE_SUFFIXES
            .iter()
            .any(|suffix| title.ends_with(suffix))
        {
            return digest.map(str::to_string);
        }
    }

    first
}

fn registry_base(registry: &str, insecure_http: bool) -> Result<Url, OciError> {
    let candidate = if registry.contains("://") {
        registry.trim_end_matches('/').to_string()
    } else if insecure_http {
        format!("http://{}", registry.trim_end_matches('/'))
    } else {
        format!("https://{}", registry.trim_end_matches('/'))
    };

    let url = Url::parse(&candidate).map_err(|error| OciError::Config {
        reason: format!("invalid registry `{registry}`: {error}"),
    })?;

    match url.scheme() {
        "https" => {}
        "http" if insecure_http => {}
        "http" => {
            return Err(OciError::Config {
                reason: format!(
                    "registry `{registry}` is cleartext; insecure_http is for tests and \
                     local registries only"
                ),
            })
        }
        other => {
            return Err(OciError::Config {
                reason: format!("unsupported registry scheme `{other}`"),
            })
        }
    }

    if url.host_str().is_none() {
        return Err(OciError::Config {
            reason: format!("registry `{registry}` has no host"),
        });
    }

    Ok(url)
}

/// Resolve the credential for a docker-config registry.
fn docker_credential(registry: &str) -> Result<Credential, AuthError> {
    if registry.eq_ignore_ascii_case(GHCR_HOST) {
        for variable in ["GHCR_TOKEN", "GITHUB_TOKEN"] {
            if let Some(token) = env_value(variable) {
                let username =
                    env_value("GITHUB_ACTOR").unwrap_or_else(|| CI_TOKEN_USER.to_string());
                return Ok(Credential::Basic {
                    username,
                    password: token,
                });
            }
        }
    }

    let Some(path) = docker_config_path() else {
        return Ok(Credential::Anonymous);
    };
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Credential::Anonymous),
        Err(source) => return Err(AuthError::DockerConfig { path, source }),
    };
    let config: Value =
        serde_json::from_str(&text).map_err(|source| AuthError::DockerConfigParse {
            path: path.clone(),
            source,
        })?;

    if let Some(entry) = config
        .get("auths")
        .and_then(Value::as_object)
        .and_then(|auths| {
            auths
                .iter()
                .find(|(key, _)| auth_key_matches(key, registry))
                .map(|(_, entry)| entry)
        })
    {
        if let Some(credential) = credential_from_entry(&path, entry)? {
            return Ok(credential);
        }
    }

    if let Some(helper) = config
        .get("credHelpers")
        .and_then(Value::as_object)
        .and_then(|helpers| {
            helpers
                .iter()
                .find(|(key, _)| auth_key_matches(key, registry))
                .and_then(|(_, helper)| helper.as_str())
        })
    {
        return Err(AuthError::UnsupportedCredentialHelper {
            path,
            registry: registry.to_string(),
            helper: helper.to_string(),
        });
    }

    if let Some(store) = config.get("credsStore").and_then(Value::as_str) {
        return Err(AuthError::UnsupportedCredentialHelper {
            path,
            registry: registry.to_string(),
            helper: store.to_string(),
        });
    }

    Ok(Credential::Anonymous)
}

fn credential_from_entry(path: &Path, entry: &Value) -> Result<Option<Credential>, AuthError> {
    if let Some(token) = entry
        .get("identitytoken")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        return Ok(Some(Credential::Bearer {
            token: token.to_string(),
        }));
    }

    if let Some(encoded) = entry
        .get("auth")
        .and_then(Value::as_str)
        .filter(|value| !value.is_empty())
    {
        let encoded = encoded.trim();
        let decoded = BASE64
            .decode(encoded)
            .or_else(|_| BASE64_NO_PAD.decode(encoded))
            .map_err(|source| AuthError::CredentialEncoding {
                path: path.to_path_buf(),
                source,
            })?;
        let text = String::from_utf8(decoded).map_err(|_| AuthError::InvalidCredential {
            path: path.to_path_buf(),
            reason: "the auth value is not utf-8".to_string(),
        })?;
        let (username, password) =
            text.split_once(':')
                .ok_or_else(|| AuthError::InvalidCredential {
                    path: path.to_path_buf(),
                    reason: "the auth value is not `user:password`".to_string(),
                })?;
        return Ok(Some(Credential::Basic {
            username: username.to_string(),
            password: password.to_string(),
        }));
    }

    if let (Some(username), Some(password)) = (
        entry.get("username").and_then(Value::as_str),
        entry.get("password").and_then(Value::as_str),
    ) {
        return Ok(Some(Credential::Basic {
            username: username.to_string(),
            password: password.to_string(),
        }));
    }

    Ok(None)
}

fn docker_config_path() -> Option<PathBuf> {
    if let Some(directory) = env_value("DOCKER_CONFIG") {
        return Some(PathBuf::from(directory).join("config.json"));
    }
    env_value("HOME").map(|home| PathBuf::from(home).join(".docker").join("config.json"))
}

/// Whether a docker-config key such as `https://ghcr.io/v1/` names `registry`.
fn auth_key_matches(key: &str, registry: &str) -> bool {
    let key = key.trim().trim_end_matches('/');
    let key = key
        .strip_prefix("https://")
        .or_else(|| key.strip_prefix("http://"))
        .unwrap_or(key);
    let host = key.split('/').next().unwrap_or(key);
    host.eq_ignore_ascii_case(registry)
}

fn read_password_file(path: &Path) -> Result<String, AuthError> {
    let contents = std::fs::read_to_string(path).map_err(|source| AuthError::CredentialFile {
        path: path.to_path_buf(),
        source,
    })?;
    let password = contents.trim_end_matches(['\r', '\n']);
    if password.is_empty() {
        return Err(AuthError::InvalidCredential {
            path: path.to_path_buf(),
            reason: "the password file is empty".to_string(),
        });
    }
    Ok(password.to_string())
}

/// `<NAME>` in `CINC_MIRROR_<NAME>_{USER,PASSWORD,TOKEN}`.
fn target_env_prefix(name: &str) -> String {
    let mut sanitized = String::with_capacity(name.len());
    for character in name.chars() {
        if character.is_ascii_alphanumeric() {
            sanitized.push(character.to_ascii_uppercase());
        } else {
            sanitized.push('_');
        }
    }
    format!("CINC_MIRROR_{sanitized}")
}

pub(crate) fn env_value(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Keep error bodies short enough for a log line and a ledger note.
fn truncate(value: &str) -> String {
    const LIMIT: usize = 512;
    if value.len() <= LIMIT {
        return value.to_string();
    }
    let mut end = LIMIT;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}...", &value[..end])
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

    /// Serialises tests that mutate process-wide environment variables.
    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        ENV_LOCK.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Sets or removes an environment variable, restoring the previous value.
    struct EnvVar {
        key: &'static str,
        previous: Option<OsString>,
    }

    impl EnvVar {
        fn set(key: &'static str, value: &str) -> Self {
            let previous = std::env::var_os(key);
            std::env::set_var(key, value);
            Self { key, previous }
        }

        fn unset(key: &'static str) -> Self {
            let previous = std::env::var_os(key);
            std::env::remove_var(key);
            Self { key, previous }
        }
    }

    impl Drop for EnvVar {
        fn drop(&mut self) {
            match &self.previous {
                Some(value) => std::env::set_var(self.key, value),
                None => std::env::remove_var(self.key),
            }
        }
    }

    fn write_docker_config(dir: &tempfile::TempDir, contents: &Value) -> PathBuf {
        let path = dir.path().join("config.json");
        std::fs::write(&path, contents.to_string()).expect("write docker config");
        dir.path().to_path_buf()
    }

    fn assert_basic(credential: Credential, username: &str, password: &str) {
        match credential {
            Credential::Basic {
                username: actual_user,
                password: actual_password,
            } => {
                assert_eq!(actual_user, username);
                assert_eq!(actual_password, password);
            }
            other => panic!("expected basic credentials, got {other:?}"),
        }
    }

    #[test]
    fn env_token_overrides_docker_config() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().expect("temp dir");
        let _docker = EnvVar::set(
            "DOCKER_CONFIG",
            write_docker_config(
                &dir,
                &serde_json::json!({"auths": {"ghcr.io": {"auth": BASE64.encode("alice:from-config")}}}),
            )
            .to_str()
            .expect("utf-8 path"),
        );
        let _token = EnvVar::set("GHCR_TOKEN", "ci-token");
        let _actor = EnvVar::set("GITHUB_ACTOR", "octocat");

        assert_basic(
            docker_credential("ghcr.io").expect("docker credential"),
            "octocat",
            "ci-token",
        );
    }

    #[test]
    fn github_token_falls_back_to_the_x_access_token_user() {
        let _guard = env_lock();
        let _ghcr = EnvVar::unset("GHCR_TOKEN");
        let _token = EnvVar::set("GITHUB_TOKEN", "actions-token");
        let _actor = EnvVar::unset("GITHUB_ACTOR");
        let _docker = EnvVar::unset("DOCKER_CONFIG");

        assert_basic(
            docker_credential("ghcr.io").expect("docker credential"),
            CI_TOKEN_USER,
            "actions-token",
        );
    }

    #[test]
    fn ci_tokens_only_override_the_docker_config_for_ghcr() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().expect("temp dir");
        let _docker = EnvVar::set(
            "DOCKER_CONFIG",
            write_docker_config(
                &dir,
                &serde_json::json!({"auths": {"registry.example": {"auth": BASE64.encode("bob:config-password")}}}),
            )
            .to_str()
            .expect("utf-8 path"),
        );
        let _token = EnvVar::set("GHCR_TOKEN", "ci-token");

        assert_basic(
            docker_credential("registry.example").expect("docker credential"),
            "bob",
            "config-password",
        );
    }

    #[test]
    fn docker_config_auth_is_decoded() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().expect("temp dir");
        let _docker = EnvVar::set(
            "DOCKER_CONFIG",
            write_docker_config(
                &dir,
                &serde_json::json!({
                    "auths": {
                        "https://registry.example/v1/": {
                            "auth": BASE64.encode("carol:s3cret")
                        }
                    }
                }),
            )
            .to_str()
            .expect("utf-8 path"),
        );

        assert_basic(
            docker_credential("registry.example").expect("docker credential"),
            "carol",
            "s3cret",
        );
    }

    #[test]
    fn docker_config_identity_token_is_a_bearer_credential() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().expect("temp dir");
        let _docker = EnvVar::set(
            "DOCKER_CONFIG",
            write_docker_config(
                &dir,
                &serde_json::json!({
                    "auths": {"registry.example": {"identitytoken": "issued-token"}}
                }),
            )
            .to_str()
            .expect("utf-8 path"),
        );

        match docker_credential("registry.example").expect("docker credential") {
            Credential::Bearer { token } => assert_eq!(token, "issued-token"),
            other => panic!("expected a bearer credential, got {other:?}"),
        }
    }

    #[test]
    fn credential_helper_entries_are_a_typed_error() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().expect("temp dir");
        let _docker = EnvVar::set(
            "DOCKER_CONFIG",
            write_docker_config(
                &dir,
                &serde_json::json!({
                    "credHelpers": {"registry.example": "secretservice"},
                    "auths": {"other.example": {"auth": BASE64.encode("x:y")}}
                }),
            )
            .to_str()
            .expect("utf-8 path"),
        );

        let error = docker_credential("registry.example").expect_err("helper must be refused");
        match error {
            AuthError::UnsupportedCredentialHelper { helper, .. } => {
                assert_eq!(helper, "secretservice");
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn a_missing_docker_config_means_anonymous() {
        let _guard = env_lock();
        let dir = tempfile::tempdir().expect("temp dir");
        let _docker = EnvVar::set("DOCKER_CONFIG", dir.path().to_str().expect("utf-8 path"));

        assert!(matches!(
            docker_credential("registry.example").expect("docker credential"),
            Credential::Anonymous
        ));
    }

    #[test]
    fn challenge_parser_respects_quoted_commas() {
        let challenge = Challenge::parse(
            r#"Bearer realm="https://ghcr.io/token",service="ghcr.io",scope="repository:a/b:pull,push""#,
        );

        assert_eq!(challenge.scheme, "bearer");
        assert_eq!(
            challenge.params.get("realm").map(String::as_str),
            Some("https://ghcr.io/token")
        );
        assert_eq!(
            challenge.params.get("service").map(String::as_str),
            Some("ghcr.io")
        );
        assert_eq!(
            challenge.params.get("scope").map(String::as_str),
            Some("repository:a/b:pull,push")
        );
    }

    #[test]
    fn challenge_parser_lowercases_the_scheme_and_unquotes_values() {
        let challenge = Challenge::parse("basic realm=registry");

        assert_eq!(challenge.scheme, "basic");
        assert_eq!(
            challenge.params.get("realm").map(String::as_str),
            Some("registry")
        );
    }

    #[test]
    fn debug_output_never_contains_credentials() {
        let basic = format!(
            "{:?}",
            OciAuth::Basic {
                username: "alice".to_string(),
                password: "s3cret".to_string(),
            }
        );
        let bearer = format!(
            "{:?}",
            OciAuth::Bearer {
                token: "t0ken".to_string(),
            }
        );

        assert!(!basic.contains("s3cret"), "{basic}");
        assert!(basic.contains("alice"));
        assert!(!bearer.contains("t0ken"), "{bearer}");
    }

    #[test]
    fn cleartext_registries_need_the_explicit_opt_in() {
        let error = registry_base("http://127.0.0.1:5000", false).expect_err("cleartext");
        assert!(matches!(error, OciError::Config { .. }));

        let local = registry_base("http://127.0.0.1:5000", true).expect("local registry");
        assert_eq!(local.scheme(), "http");

        let remote = registry_base("ghcr.io", false).expect("remote registry");
        assert_eq!(remote.as_str(), "https://ghcr.io/");
    }

    #[test]
    fn registry_paths_refuse_traversal() {
        let registry = Registry::new(OciConfig::new("ghcr.io", "ns")).expect("registry");

        for repo in ["../etc", "ns/../x", "ns//x", ""] {
            let error = registry
                .url_for(&["v2", repo, "blobs", "sha256:00"])
                .expect_err("traversal must be refused");
            assert!(
                matches!(error, OciError::Config { .. }),
                "{repo}: {error:?}"
            );
        }

        assert_eq!(
            registry
                .url_for(&["v2", "ns/cinc", "blobs", "sha256:aa"])
                .expect("url")
                .as_str(),
            "https://ghcr.io/v2/ns/cinc/blobs/sha256:aa"
        );
    }

    #[test]
    fn upload_locations_may_not_leave_the_registry() {
        let registry = Registry::new(OciConfig::new("ghcr.io", "ns")).expect("registry");

        assert!(registry
            .location_url("https://ghcr.io/v2/ns/blobs/uploads/1?_state=x")
            .is_ok());
        assert!(registry
            .location_url("/v2/ns/blobs/uploads/1?_state=x")
            .is_ok());
        assert!(registry
            .location_url("https://evil.example/upload/1")
            .is_err());
        assert!(registry.location_url("http://ghcr.io/upload/1").is_err());
    }

    #[test]
    fn package_layer_matching_covers_every_suffix() {
        for suffix in PACKAGE_SUFFIXES {
            let title = format!("cinc_19.4.46-1_amd64{suffix}").to_ascii_uppercase();
            let manifest = serde_json::json!({
                "layers": [
                    {"digest": "sha256:metadata", "annotations": {TITLE_ANNOTATION: "metadata.json"}},
                    {"digest": "sha256:package", "annotations": {TITLE_ANNOTATION: title}},
                ]
            });

            assert_eq!(
                package_layer_digest(&manifest).as_deref(),
                Some("sha256:package"),
                "suffix {suffix}"
            );
        }
    }

    #[test]
    fn package_layer_falls_back_to_the_first_layer() {
        let manifest = serde_json::json!({
            "layers": [{"digest": "sha256:first"}, {"digest": "sha256:second"}]
        });
        assert_eq!(
            package_layer_digest(&manifest).as_deref(),
            Some("sha256:first")
        );

        assert_eq!(
            package_layer_digest(&serde_json::json!({"layers": []})),
            None
        );
        assert_eq!(package_layer_digest(&serde_json::json!({})), None);
    }

    #[test]
    fn retryable_statuses_are_throttling_and_server_errors() {
        let status = |code| OciError::Status {
            method: "PUT".to_string(),
            url: "https://ghcr.io/v2/x".to_string(),
            status: code,
            body: String::new(),
        };

        for code in [429, 500, 502, 503] {
            assert!(status(code).is_retryable(), "status {code}");
        }
        for code in [400, 401, 403, 404] {
            assert!(!status(code).is_retryable(), "status {code}");
        }
        assert!(!OciError::Config {
            reason: "bad".to_string()
        }
        .is_retryable());
    }

    #[test]
    fn cached_tokens_expire() {
        let registry = Registry::new(OciConfig::new("ghcr.io", "ns")).expect("registry");
        let scope = push_scope("ns/cinc");

        registry.cache_token(
            "ns/cinc",
            &scope,
            "fresh",
            Instant::now() + Duration::from_secs(60),
        );
        assert_eq!(
            registry.cached_token("ns/cinc", &scope).as_deref(),
            Some("fresh")
        );

        registry.cache_token(
            "ns/cinc",
            &scope,
            "stale",
            Instant::now() + Duration::from_secs(1),
        );
        assert_eq!(registry.cached_token("ns/cinc", &scope), None);

        registry.forget_token("ns/cinc", &scope);
        assert_eq!(registry.cached_token("ns/cinc", &scope), None);
    }

    fn scratch_target(auth: TargetAuth, password_file: Option<PathBuf>) -> TargetConfig {
        TargetConfig {
            name: "scratch".to_string(),
            kind: TargetKind::Oci,
            enabled: true,
            registry: Some("registry.example".to_string()),
            namespace: Some("cinc-mirror".to_string()),
            url: None,
            auth,
            max_bandwidth: None,
            identity_file: None,
            password_file,
        }
    }

    #[test]
    fn from_target_reads_basic_credentials_from_the_environment() {
        let _guard = env_lock();
        let _user = EnvVar::set("CINC_MIRROR_SCRATCH_USER", "mirror");
        let _password = EnvVar::set("CINC_MIRROR_SCRATCH_PASSWORD", "env-password");

        let registry =
            Registry::from_target(&scratch_target(TargetAuth::Basic, None), &Config::default())
                .expect("registry");

        assert_basic(
            match registry.auth {
                OciAuth::Basic { username, password } => Credential::Basic { username, password },
                other => panic!("unexpected auth: {other:?}"),
            },
            "mirror",
            "env-password",
        );
    }

    #[test]
    fn from_target_reads_the_basic_password_from_a_file() {
        let _guard = env_lock();
        let _user = EnvVar::set("CINC_MIRROR_SCRATCH_USER", "mirror");
        let _password = EnvVar::unset("CINC_MIRROR_SCRATCH_PASSWORD");
        let dir = tempfile::tempdir().expect("temp dir");
        let path = dir.path().join("password");
        std::fs::write(&path, "file-password\n").expect("write password");

        let registry = Registry::from_target(
            &scratch_target(TargetAuth::Basic, Some(path)),
            &Config::default(),
        )
        .expect("registry");

        match registry.auth {
            OciAuth::Basic { username, password } => {
                assert_eq!(username, "mirror");
                assert_eq!(password, "file-password");
            }
            other => panic!("unexpected auth: {other:?}"),
        }
    }

    #[test]
    fn from_target_reports_missing_basic_credentials() {
        let _guard = env_lock();
        let _user = EnvVar::unset("CINC_MIRROR_SCRATCH_USER");
        let _password = EnvVar::unset("CINC_MIRROR_SCRATCH_PASSWORD");

        let error =
            Registry::from_target(&scratch_target(TargetAuth::Basic, None), &Config::default())
                .expect_err("credentials are missing");

        assert!(matches!(
            error,
            OciError::Auth(AuthError::MissingCredentials { .. })
        ));
    }

    #[test]
    fn from_target_reads_a_preissued_bearer_token() {
        let _guard = env_lock();
        let _token = EnvVar::set("CINC_MIRROR_SCRATCH_TOKEN", "preissued");

        let registry = Registry::from_target(
            &scratch_target(TargetAuth::Bearer, None),
            &Config::default(),
        )
        .expect("registry");

        match registry.auth {
            OciAuth::Bearer { token } => assert_eq!(token, "preissued"),
            other => panic!("unexpected auth: {other:?}"),
        }
    }

    #[test]
    fn from_target_refuses_a_non_oci_target() {
        let mut target = scratch_target(TargetAuth::Anonymous, None);
        target.kind = TargetKind::Rsync;

        let error = Registry::from_target(&target, &Config::default()).expect_err("not oci");
        assert!(matches!(error, OciError::Config { .. }));
    }

    #[test]
    fn empty_registries_are_refused() {
        let error = Registry::new(OciConfig::new("   ", "ns")).expect_err("empty registry");
        assert!(matches!(error, OciError::Config { .. }));
    }

    #[test]
    fn timeouts_default_and_must_be_positive() {
        let config = OciConfig::new("ghcr.io", "ns");
        assert_eq!(config.idle_read_timeout, DEFAULT_IDLE_READ_TIMEOUT);
        assert_eq!(config.request_timeout, DEFAULT_REQUEST_TIMEOUT);

        for config in [
            OciConfig {
                request_timeout: Duration::ZERO,
                ..OciConfig::new("ghcr.io", "ns")
            },
            OciConfig {
                idle_read_timeout: Duration::ZERO,
                ..OciConfig::new("ghcr.io", "ns")
            },
        ] {
            let error = Registry::new(config).expect_err("a zero timeout would fail everything");
            assert!(matches!(error, OciError::Config { .. }), "{error:?}");
        }
    }

    #[test]
    fn timeouts_are_retryable_transport_failures() {
        let error = OciError::Http {
            method: "PATCH".to_string(),
            url: "https://ghcr.io/v2/ns/blobs/uploads/1".to_string(),
            source: HttpFailure::Timeout {
                waited: Duration::from_millis(50),
                phase: "reading the response body",
            },
        };

        assert!(error.is_retryable());
        assert!(error.to_string().contains("timed out after 50ms"));
    }

    #[test]
    fn registry_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}

        // The OCI target shares one registry across upload workers.
        assert_send_sync::<Registry>();
    }
}
