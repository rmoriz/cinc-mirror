//! GitHub Packages API client.
//!
//! GHCR answers `405 UNSUPPORTED` to the distribution spec's own
//! `DELETE /v2/<repo>/manifests/<digest>`, so a package version can only be
//! deleted through the REST API that backs GitHub Packages. This module wraps
//! the calls that needs — list versions, delete a version by id and list the
//! package catalogue — and nothing else.
//!
//! # Owner kind
//!
//! GitHub serves container packages either under `/users/<owner>/` or under
//! `/orgs/<owner>/`. [`PackagesClient::owner_kind`] asks the versions route
//! under `/users/` once and caches the answer: a `404` means the owner is an
//! organisation, and every later call uses `/orgs/`. A `403` on the probe is
//! [`PruneError::Denied`] rather than a fallback, so a missing credential does
//! not look like a wrong owner. A `404` on **both** forms means the package does
//! not exist: [`PackagesClient::versions`] returns an empty list, not an error.
//! When a listing succeeds only under the other form, that form is cached too,
//! so a later delete does not go to the route that just `404`ed.
//!
//! The package path (`<repository>/<project>`) travels as **one** percent
//! encoded path segment, so the URLs are built through
//! [`Url::path_segments_mut`], which encodes the slash, and never by string
//! concatenation.
//!
//! # Paging
//!
//! Listings ask for [`PAGE_SIZE`] items per page, follow a `rel="next"` `Link`
//! when GitHub sends one, and otherwise advance `page` themselves while a full
//! page comes back, for at most [`MAX_PAGES`] pages. A page shorter than
//! [`PAGE_SIZE`] ends the listing: GitHub does not reliably send a `Link`. A
//! `Link` is followed as sent, even to another host, so the token travels with
//! it.
//!
//! # Secrets
//!
//! The token only ever travels as an `Authorization: Bearer` header, never as
//! part of a URL. Every [`PruneError`] `Display` runs through
//! [`redact_secrets`], so an `Authorization` header that a response body echoes
//! cannot leak it.

use std::fmt;
use std::time::Duration;

use chrono::{DateTime, Utc};
use reqwest::header::{ACCEPT, AUTHORIZATION, LINK, USER_AGENT};
use reqwest::{Client, Method, Response, StatusCode};
use serde::Deserialize;
use thiserror::Error;
use tokio::sync::OnceCell;
use url::Url;

use crate::report::redact_secrets;

/// Items requested per page.
const PAGE_SIZE: usize = 100;

/// Pages a listing follows before it stops.
const MAX_PAGES: usize = 100;

/// Budget for one request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// User agent GitHub asks clients to identify themselves with.
const USER_AGENT_VALUE: &str = "cinc-mirror";

/// `Accept` value that pins the REST API to the JSON representation.
const ACCEPT_VALUE: &str = "application/vnd.github+json";

/// Characters of a response body kept in an error message.
const BODY_LIMIT: usize = 300;

/// Errors raised by the packages client.
///
/// Every `Display` is formatted through [`redact_secrets`]. `registry` names the
/// API base the client talks to and `repo` the `<owner>/<package>` path.
#[derive(Debug, Error)]
pub enum PruneError {
    /// The endpoint does not offer the packages API.
    #[error(
        "{}",
        redact_secrets(&format!(
            "packages api at {registry} answered HTTP 405 for {repo}; the versions cannot be managed"
        ))
    )]
    Unsupported {
        /// API base the request went to.
        registry: String,
        /// `<owner>/<package>` path.
        repo: String,
    },

    /// The token is missing, expired or lacks the package scope.
    #[error(
        "{}",
        redact_secrets(&format!(
            "packages api at {registry} denied access to {repo}: {reason}"
        ))
    )]
    Denied {
        /// API base the request went to.
        registry: String,
        /// `<owner>/<package>` path.
        repo: String,
        /// Redacted status and response body.
        reason: String,
    },

    /// A listing, a delete or the owner probe failed with an unexpected status.
    #[error(
        "{}",
        redact_secrets(&format!("packages api at {registry} failed for {repo}: {source}"))
    )]
    List {
        /// API base the request went to.
        registry: String,
        /// `<owner>/<package>` path.
        repo: String,
        /// The status and body, or an unusable `Link`.
        #[source]
        source: ApiFailure,
    },

    /// The request could not be completed at all.
    #[error(
        "{}",
        redact_secrets(&format!("request to {registry} for {repo} failed: {source}"))
    )]
    Transport {
        /// API base the request went to.
        registry: String,
        /// `<owner>/<package>` path.
        repo: String,
        /// Underlying transport failure, including a timeout.
        #[source]
        source: reqwest::Error,
    },

    /// The client configuration is unusable.
    #[error("{}", redact_secrets(&format!("invalid packages api configuration: {reason}")))]
    Config {
        /// Why the configuration was rejected.
        reason: String,
    },
}

/// A failed packages API answer, already redacted.
///
/// A status of `0` means no answer was involved, for example an unusable
/// `Link` header.
#[derive(Debug, Error)]
#[error("{message}")]
pub struct ApiFailure {
    status: u16,
    message: String,
}

impl ApiFailure {
    /// The status the API answered with, or `0` when there was none.
    #[must_use]
    pub fn status(&self) -> u16 {
        self.status
    }
}

/// Which owner route serves the package.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerKind {
    /// A user account, under `/users/<owner>/`.
    User,
    /// An organisation, under `/orgs/<owner>/`.
    Org,
}

impl OwnerKind {
    /// Path segment that selects this owner form.
    fn segment(self) -> &'static str {
        match self {
            Self::User => "users",
            Self::Org => "orgs",
        }
    }

    /// The form to try when this one answers `404`.
    fn other(self) -> Self {
        match self {
            Self::User => Self::Org,
            Self::Org => Self::User,
        }
    }
}

/// One package version as GitHub reports it.
#[derive(Debug, Clone)]
pub struct RemoteVersion {
    /// Version id the delete route takes.
    pub id: u64,
    /// Manifest digest GitHub stores as the version `name`.
    pub digest: String,
    /// Container tags that point at this version.
    pub tags: Vec<String>,
    /// Creation time; a missing or malformed value becomes "now".
    pub created_at: DateTime<Utc>,
}

/// A packages client bound to one owner and package.
pub struct PackagesClient {
    registry: String,
    base: Url,
    owner: String,
    package: String,
    token: String,
    client: Client,
    kind: OnceCell<OwnerKind>,
}

impl fmt::Debug for PackagesClient {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PackagesClient")
            .field("registry", &self.registry)
            .field("owner", &self.owner)
            .field("package", &self.package)
            .field("token", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl PackagesClient {
    /// Build a client for `api_base`, `owner`, `package` and `token`.
    ///
    /// `package` is the GHCR package path `<repository>/<project>`; it becomes a
    /// single encoded URL path segment.
    ///
    /// # Errors
    ///
    /// Returns [`PruneError::Config`] when a field is empty, when `api_base` is
    /// not an `http` or `https` URL, or when the HTTP client cannot be built.
    pub fn new(
        api_base: &str,
        owner: &str,
        package: &str,
        token: String,
    ) -> Result<Self, PruneError> {
        let registry = api_base.trim().trim_end_matches('/').to_string();
        if registry.is_empty() {
            return Err(PruneError::Config {
                reason: "api_base must not be empty".to_string(),
            });
        }
        let owner = owner.trim().to_string();
        if owner.is_empty() {
            return Err(PruneError::Config {
                reason: "owner must not be empty".to_string(),
            });
        }
        let package = package.trim().to_string();
        if package.is_empty() {
            return Err(PruneError::Config {
                reason: "package must not be empty".to_string(),
            });
        }
        let token = token.trim().to_string();
        if token.is_empty() {
            return Err(PruneError::Config {
                reason: "token must not be empty".to_string(),
            });
        }

        let base = Url::parse(&registry).map_err(|error| PruneError::Config {
            reason: format!("`{registry}` is not a URL: {error}"),
        })?;
        if !matches!(base.scheme(), "http" | "https") {
            return Err(PruneError::Config {
                reason: format!("`{registry}` is not an http or https URL"),
            });
        }
        if base.host_str().is_none() {
            return Err(PruneError::Config {
                reason: format!("`{registry}` has no host"),
            });
        }

        let client = Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|error| PruneError::Config {
                reason: format!("cannot build the http client: {error}"),
            })?;

        Ok(Self {
            registry,
            base,
            owner,
            package,
            token,
            client,
            kind: OnceCell::new(),
        })
    }

    /// Which owner route serves the package, probing `/users/`.
    ///
    /// A `2xx` proves a user account and is cached at once. A `404` only says
    /// that the package is not there, so `Org` is a guess until a listing or a
    /// delete proves it; only a proven answer is cached, which is what lets a
    /// fallback correct the probe.
    ///
    /// # Errors
    ///
    /// Returns [`PruneError::Denied`] when the probe is refused (a `403` is not
    /// a fallback), [`PruneError::Unsupported`] on `405` and
    /// [`PruneError::Transport`] when the request cannot be completed.
    pub async fn owner_kind(&self) -> Result<OwnerKind, PruneError> {
        match self.kind.get() {
            Some(kind) => Ok(*kind),
            None => self.probe_owner().await,
        }
    }

    /// Every version of the package, newest first.
    ///
    /// The caller decides what to keep. A package that does not exist — a
    /// `404` on both owner forms — yields an empty list, not an error. A `404`
    /// after the first page ends the listing where it stands.
    ///
    /// # Errors
    ///
    /// Returns [`PruneError::Denied`] for a `403`, [`PruneError::Unsupported`]
    /// for a `405`, [`PruneError::List`] for any other unexpected status and
    /// [`PruneError::Transport`] when a request cannot be completed.
    pub async fn versions(&self) -> Result<Vec<RemoteVersion>, PruneError> {
        let mut kind = self.owner_kind().await?;
        let mut url = self.page_url(kind, &["versions"], 1)?;
        let mut versions = Vec::new();
        let mut page = 1;

        for _ in 0..MAX_PAGES {
            let (items, next) = match self.version_page(&url).await? {
                Page::Items(items, next) => (items, next),
                // The probe proved nothing about the package itself; a `404` on
                // the first page may be a wrong owner form or an absent
                // package. Ask the other form once, then stop either way.
                Page::Missing if page == 1 => {
                    let other = kind.other();
                    let other_url = self.page_url(other, &["versions"], 1)?;
                    match self.version_page(&other_url).await? {
                        Page::Items(items, next) => {
                            // The loop recomputes `url` from the corrected
                            // `kind`, so only that survives the fallback.
                            kind = other;
                            (items, next)
                        }
                        Page::Missing => return Ok(Vec::new()),
                    }
                }
                Page::Missing => break,
            };

            // Any page under a form proves it serves this owner.
            if page == 1 {
                let _ = self.kind.set(kind);
            }
            let full = items.len() == PAGE_SIZE;
            versions.extend(items);
            if !full {
                break;
            }
            page += 1;
            url = match next {
                Some(link) => self.resolve(&link)?,
                None => self.page_url(kind, &["versions"], page)?,
            };
        }

        Ok(versions)
    }

    /// Delete the version `version_id`.
    ///
    /// A `404` is success: the version is already gone.
    ///
    /// # Errors
    ///
    /// Returns [`PruneError::Denied`] for a `403`, [`PruneError::Unsupported`]
    /// for a `405`, [`PruneError::List`] for any other non-success status and
    /// [`PruneError::Transport`] when the request cannot be completed.
    pub async fn delete(&self, version_id: u64) -> Result<(), PruneError> {
        let kind = self.owner_kind().await?;
        let url = self.owner_url(kind, &["versions", &version_id.to_string()])?;
        let response = self.send(Method::DELETE, &url).await?;
        match response.status() {
            status if status.is_success() => {
                let _ = self.kind.set(kind);
                Ok(())
            }
            StatusCode::NOT_FOUND => Ok(()),
            StatusCode::FORBIDDEN => Err(self.denied(response).await),
            StatusCode::METHOD_NOT_ALLOWED => Err(self.unsupported()),
            _ => Err(self.list_status(response).await),
        }
    }

    /// Every container package of the owner, sorted as GitHub sends them.
    ///
    /// The probe answers for the package's versions route, which says nothing
    /// about the owner when that package does not exist. A `404` on the first
    /// page therefore retries the other owner form once and caches the
    /// corrected kind.
    ///
    /// # Errors
    ///
    /// Returns [`PruneError::Denied`] for a `403`, [`PruneError::Unsupported`]
    /// for a `405`, [`PruneError::List`] for any other unexpected status and
    /// [`PruneError::Transport`] when a request cannot be completed.
    pub async fn packages(&self) -> Result<Vec<String>, PruneError> {
        let mut kind = self.owner_kind().await?;
        let mut url = self.catalogue_url(kind, 1)?;
        let mut packages = Vec::new();
        let mut page = 1;

        for _ in 0..MAX_PAGES {
            let (items, next) = match self.package_page(&url).await? {
                Page::Items(items, next) => (items, next),
                // The probe discriminates on the versions route, so a `404`
                // here can mean the wrong owner form rather than an absent
                // package (a user whose package nobody mirrored yet, for
                // example). Ask the other form once and keep the correction.
                Page::Missing if page == 1 => {
                    let other = kind.other();
                    let other_url = self.catalogue_url(other, 1)?;
                    match self.package_page(&other_url).await? {
                        Page::Items(items, next) => {
                            // The loop recomputes `url` from the corrected
                            // `kind`, so only that survives the fallback.
                            kind = other;
                            (items, next)
                        }
                        Page::Missing => break,
                    }
                }
                Page::Missing => break,
            };
            if page == 1 {
                let _ = self.kind.set(kind);
            }
            let full = items.len() == PAGE_SIZE;
            packages.extend(items);
            if !full {
                break;
            }
            page += 1;
            url = match next {
                Some(link) => self.resolve(&link)?,
                None => self.catalogue_url(kind, page)?,
            };
        }

        Ok(packages)
    }

    // Requests ---------------------------------------------------------------

    async fn probe_owner(&self) -> Result<OwnerKind, PruneError> {
        let url = self.page_url(OwnerKind::User, &["versions"], 1)?;
        let response = self.send(Method::GET, &url).await?;
        match response.status() {
            status if status.is_success() => {
                let _ = self.kind.set(OwnerKind::User);
                Ok(OwnerKind::User)
            }
            StatusCode::NOT_FOUND => Ok(OwnerKind::Org),
            StatusCode::FORBIDDEN => Err(self.denied(response).await),
            StatusCode::METHOD_NOT_ALLOWED => Err(self.unsupported()),
            _ => Err(self.list_status(response).await),
        }
    }

    async fn version_page(&self, url: &Url) -> Result<Page<RemoteVersion>, PruneError> {
        let response = self.send(Method::GET, url).await?;
        match response.status() {
            status if status.is_success() => {
                let next = next_link(&response);
                let body: Vec<WireVersion> = response
                    .json()
                    .await
                    .map_err(|error| self.transport(error))?;
                Ok(Page::Items(
                    body.into_iter().map(RemoteVersion::from).collect(),
                    next,
                ))
            }
            StatusCode::NOT_FOUND => Ok(Page::Missing),
            StatusCode::FORBIDDEN => Err(self.denied(response).await),
            StatusCode::METHOD_NOT_ALLOWED => Err(self.unsupported()),
            _ => Err(self.list_status(response).await),
        }
    }

    async fn package_page(&self, url: &Url) -> Result<Page<String>, PruneError> {
        let response = self.send(Method::GET, url).await?;
        match response.status() {
            status if status.is_success() => {
                let next = next_link(&response);
                let body: Vec<WirePackage> = response
                    .json()
                    .await
                    .map_err(|error| self.transport(error))?;
                Ok(Page::Items(
                    body.into_iter().map(|package| package.name).collect(),
                    next,
                ))
            }
            StatusCode::NOT_FOUND => Ok(Page::Missing),
            StatusCode::FORBIDDEN => Err(self.denied(response).await),
            StatusCode::METHOD_NOT_ALLOWED => Err(self.unsupported()),
            _ => Err(self.list_status(response).await),
        }
    }

    async fn send(&self, method: Method, url: &Url) -> Result<Response, PruneError> {
        self.client
            .request(method, url.clone())
            .header(AUTHORIZATION, format!("Bearer {}", self.token))
            .header(ACCEPT, ACCEPT_VALUE)
            .header(USER_AGENT, USER_AGENT_VALUE)
            .send()
            .await
            .map_err(|error| self.transport(error))
    }

    // Errors -----------------------------------------------------------------

    fn repo(&self) -> String {
        format!("{}/{}", self.owner, self.package)
    }

    fn transport(&self, source: reqwest::Error) -> PruneError {
        PruneError::Transport {
            registry: self.registry.clone(),
            repo: self.repo(),
            source,
        }
    }

    fn unsupported(&self) -> PruneError {
        PruneError::Unsupported {
            registry: self.registry.clone(),
            repo: self.repo(),
        }
    }

    async fn denied(&self, response: Response) -> PruneError {
        let status = response.status();
        let body = self.body_text(response).await;
        let reason = if body.is_empty() {
            status.to_string()
        } else {
            format!("HTTP {status}: {body}")
        };
        PruneError::Denied {
            registry: self.registry.clone(),
            repo: self.repo(),
            reason,
        }
    }

    async fn list_status(&self, response: Response) -> PruneError {
        let status = response.status();
        let body = self.body_text(response).await;
        PruneError::List {
            registry: self.registry.clone(),
            repo: self.repo(),
            source: ApiFailure {
                status: status.as_u16(),
                message: format!("HTTP {status}: {body}"),
            },
        }
    }

    async fn body_text(&self, response: Response) -> String {
        let text = response.text().await.unwrap_or_default();
        let trimmed = text.trim();
        let mut kept = trimmed.chars().take(BODY_LIMIT).collect::<String>();
        if trimmed.chars().count() > BODY_LIMIT {
            kept.push('…');
        }
        redact_secrets(&kept)
    }

    // URLs -------------------------------------------------------------------

    fn owner_url(&self, kind: OwnerKind, tail: &[&str]) -> Result<Url, PruneError> {
        self.build_url(kind, Some(&self.package), tail)
    }

    fn page_url(&self, kind: OwnerKind, tail: &[&str], page: usize) -> Result<Url, PruneError> {
        let mut url = self.owner_url(kind, tail)?;
        append_paging(&mut url, page, None);
        Ok(url)
    }

    fn catalogue_url(&self, kind: OwnerKind, page: usize) -> Result<Url, PruneError> {
        let mut url = self.build_url(kind, None, &[])?;
        append_paging(&mut url, page, Some("container"));
        Ok(url)
    }

    fn build_url(
        &self,
        kind: OwnerKind,
        package: Option<&str>,
        tail: &[&str],
    ) -> Result<Url, PruneError> {
        let mut url = self.base.clone();
        url.set_query(None);
        url.set_fragment(None);
        {
            let mut segments = url.path_segments_mut().map_err(|()| PruneError::Config {
                reason: format!("`{}` cannot hold path segments", self.base),
            })?;
            segments.pop_if_empty();
            segments.push(kind.segment());
            segments.push(&self.owner);
            segments.push("packages");
            if let Some(package) = package {
                segments.push("container");
                // One segment, so `path_segments_mut` encodes the slash.
                segments.push(package);
            }
            for part in tail {
                segments.push(part);
            }
        }
        Ok(url)
    }

    /// Resolve a `Link` target, absolute or relative to the API base.
    fn resolve(&self, link: &str) -> Result<Url, PruneError> {
        if let Ok(url) = Url::parse(link) {
            return Ok(url);
        }
        self.base.join(link).map_err(|error| PruneError::List {
            registry: self.registry.clone(),
            repo: self.repo(),
            source: ApiFailure {
                status: 0,
                message: format!("unusable Link `{link}`: {error}"),
            },
        })
    }
}

/// One page of a listing, or the `404` that says there is nothing to page.
enum Page<T> {
    Items(Vec<T>, Option<String>),
    Missing,
}

/// A version as GitHub serialises it.
#[derive(Debug, Deserialize)]
struct WireVersion {
    id: u64,
    #[serde(default)]
    name: String,
    #[serde(default)]
    created_at: Option<String>,
    #[serde(default)]
    metadata: WireMetadata,
}

/// The metadata block of a version.
#[derive(Debug, Default, Deserialize)]
struct WireMetadata {
    #[serde(default)]
    container: WireContainer,
}

/// The container metadata of a version.
#[derive(Debug, Default, Deserialize)]
struct WireContainer {
    #[serde(default)]
    tags: Vec<String>,
}

/// A catalogue entry.
#[derive(Debug, Deserialize)]
struct WirePackage {
    name: String,
}

impl From<WireVersion> for RemoteVersion {
    fn from(wire: WireVersion) -> Self {
        Self {
            id: wire.id,
            digest: wire.name,
            tags: wire.metadata.container.tags,
            created_at: parse_created(wire.created_at.as_deref()),
        }
    }
}

/// Parse a creation stamp, replacing a missing or malformed one with "now".
fn parse_created(value: Option<&str>) -> DateTime<Utc> {
    value
        .and_then(|value| DateTime::parse_from_rfc3339(value).ok())
        .map_or_else(Utc::now, |parsed| parsed.with_timezone(&Utc))
}

/// Add the paging query to `url`.
fn append_paging(url: &mut Url, page: usize, package_type: Option<&str>) {
    let mut query = url.query_pairs_mut();
    if let Some(package_type) = package_type {
        query.append_pair("package_type", package_type);
    }
    query
        .append_pair("per_page", &PAGE_SIZE.to_string())
        .append_pair("page", &page.to_string());
}

/// The `rel="next"` target of a `Link` header, if there is one.
fn next_link(response: &Response) -> Option<String> {
    response
        .headers()
        .get_all(LINK)
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
