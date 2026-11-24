//! Upstream source access.
//!
//! Two upstream views are needed and both are HTTPS only:
//!
//! - the autoindex Apache serves for a directory, parsed into [`IndexEntry`]
//!   values by [`Source::list`];
//! - the `*.metadata.json` sibling beside every package, parsed by
//!   [`Source::metadata`].
//!
//! The mirror never falls back to cleartext. The request URL is checked before
//! anything is sent, a redirect to a non-HTTPS URL is refused before it is
//! followed, and the *final* URL is checked again after redirects as defense in
//! depth. Redirects are additionally limited to ten hops and to the configured
//! host, so a listed or metadata response cannot quietly move the crawl to a
//! third party.
//!
//! The client construction is not async; only [`Source::list`] and
//! [`Source::metadata`] perform I/O. Both read through [`Fetcher`], which keeps
//! the scheme enforcement in [`Source`] testable without a TLS server.

pub mod index;
pub mod metadata;

use std::fmt;
use std::sync::Arc;

use async_trait::async_trait;
use reqwest::redirect::Policy;
use reqwest::Client;
use thiserror::Error;
use url::Url;

use crate::config::{Config, TransportKind};
use crate::source::metadata::Metadata;

pub use index::{parse_index, IndexEntry};

/// Upstream HTTPS root for listings and metadata.
pub const DEFAULT_HTTPS_BASE: &str = "https://downloads.cinc.sh/files";
/// Upstream FTP host used by the payload transports.
pub const DEFAULT_FTP_HOST: &str = "ftp.osuosl.org";
/// Upstream FTP path below [`DEFAULT_FTP_HOST`].
pub const DEFAULT_FTP_BASE_PATH: &str = "pub/cinc/files";

/// Maximum number of redirects a source request may follow.
const MAX_REDIRECTS: usize = 10;

/// User agent sent with every upstream request.
const USER_AGENT: &str = concat!("cinc-mirror/", env!("CARGO_PKG_VERSION"));

/// Where upstream artifacts and metadata are read from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceConfig {
    /// HTTPS root, e.g. `https://downloads.cinc.sh/files`.
    pub https_base: Url,
    /// FTP host for payload transfers, e.g. `ftp.osuosl.org`.
    pub ftp_host: String,
    /// Path below the FTP host, e.g. `pub/cinc/files`.
    pub ftp_base_path: String,
    /// Payload transports in ladder order.
    pub transports: Vec<TransportKind>,
}

impl SourceConfig {
    /// Derive the source configuration from the mirror configuration.
    ///
    /// This performs no network access; the upstream base and FTP location are
    /// fixed constants. A configuration whose metadata transport is not HTTPS
    /// is rejected rather than silently downgraded.
    ///
    /// # Errors
    ///
    /// Returns [`SourceError::Config`] when `metadata_transport` is not
    /// `https`.
    pub fn from_config(config: &Config) -> Result<Self, SourceError> {
        if config.metadata_transport != TransportKind::Https {
            return Err(SourceError::Config {
                reason: "metadata_transport must be `https`".to_string(),
            });
        }

        let https_base = Url::parse(DEFAULT_HTTPS_BASE).map_err(|error| SourceError::Config {
            reason: format!("invalid built-in https base `{DEFAULT_HTTPS_BASE}`: {error}"),
        })?;

        Ok(Self {
            https_base,
            ftp_host: DEFAULT_FTP_HOST.to_string(),
            ftp_base_path: DEFAULT_FTP_BASE_PATH.to_string(),
            transports: config.transport.clone(),
        })
    }
}

/// A response body together with the URL it was finally read from.
///
/// The final URL differs from the request URL when a redirect was followed, and
/// is the value [`Source`] re-checks before the body is trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fetched {
    /// Response body as text.
    pub body: String,
    /// URL the response was actually served from.
    pub final_url: Url,
}

/// The transport [`Source`] reads through.
///
/// The trait exists so scheme enforcement can be tested without a TLS server:
/// production uses [`HttpFetcher`], tests substitute a fetcher that reports an
/// arbitrary final URL.
#[async_trait]
pub trait Fetcher: Send + Sync {
    /// Fetch `url` and return its body and final URL.
    async fn get(&self, url: &Url) -> Result<Fetched, SourceError>;
}

/// [`Fetcher`] backed by a `reqwest` client.
#[derive(Debug, Clone)]
pub struct HttpFetcher {
    client: Client,
}

impl HttpFetcher {
    /// Build the HTTPS client for `config`.
    ///
    /// The client is restricted to HTTPS redirect targets, at most
    /// [`MAX_REDIRECTS`] hops and the configured host.
    ///
    /// # Errors
    ///
    /// Returns [`SourceError::Config`] when the base URL has no host, and
    /// [`SourceError::Http`] when the HTTP client cannot be built.
    pub fn new(config: &SourceConfig) -> Result<Self, SourceError> {
        let host = config
            .https_base
            .host_str()
            .ok_or_else(|| SourceError::Config {
                reason: format!("https_base `{}` has no host", config.https_base),
            })?
            .to_string();

        let client = Client::builder()
            .user_agent(USER_AGENT)
            .redirect(redirect_policy(&host))
            .build()
            .map_err(|source| SourceError::Http {
                url: config.https_base.to_string(),
                source,
            })?;

        Ok(Self { client })
    }
}

#[async_trait]
impl Fetcher for HttpFetcher {
    async fn get(&self, url: &Url) -> Result<Fetched, SourceError> {
        let response = self
            .client
            .get(url.clone())
            .send()
            .await
            .map_err(|source| SourceError::Http {
                url: url.to_string(),
                source,
            })?;

        let final_url = response.url().clone();
        let status = response.status();
        if !status.is_success() {
            return Err(SourceError::HttpStatus {
                url: final_url.to_string(),
                status: status.as_u16(),
            });
        }

        let body = response.text().await.map_err(|source| SourceError::Http {
            url: final_url.to_string(),
            source,
        })?;

        Ok(Fetched { body, final_url })
    }
}

/// HTTPS access to the upstream index and metadata.
#[derive(Clone)]
pub struct Source {
    fetcher: Arc<dyn Fetcher>,
    https_base: Url,
}

impl fmt::Debug for Source {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Source")
            .field("https_base", &self.https_base)
            .finish_non_exhaustive()
    }
}

impl Source {
    /// Build a source client for `config`.
    ///
    /// The base scheme is not enforced here; every request URL and final URL is
    /// checked in [`Source::list`] and [`Source::metadata`], so a cleartext base
    /// is rejected before any bytes are sent.
    ///
    /// # Errors
    ///
    /// Returns [`SourceError::Config`] when the base URL has no host, and
    /// [`SourceError::Http`] when the HTTP client cannot be built.
    pub fn new(config: &SourceConfig) -> Result<Self, SourceError> {
        let fetcher = HttpFetcher::new(config)?;
        Ok(Self::with_fetcher(
            Arc::new(fetcher),
            config.https_base.clone(),
        ))
    }

    /// Build a source over an arbitrary fetcher.
    ///
    /// Used by tests to inject a final URL or body; production goes through
    /// [`Source::new`].
    pub(crate) fn with_fetcher(fetcher: Arc<dyn Fetcher>, https_base: Url) -> Self {
        Self {
            fetcher,
            https_base,
        }
    }

    /// List the entries directly below `dir`.
    ///
    /// `dir` is relative to the configured HTTPS base and may be written with or
    /// without surrounding slashes. The request always targets the directory
    /// URL with a trailing slash, which is what Apache needs to serve a listing
    /// instead of a redirect.
    ///
    /// # Errors
    ///
    /// Returns [`SourceError::Insecure`] before sending when the directory URL
    /// (or the final URL after redirects) is not HTTPS,
    /// [`SourceError::Http`] on a transport failure,
    /// [`SourceError::HttpStatus`] on a non-success status and
    /// [`SourceError::Index`] when the body is not a directory listing.
    pub async fn list(&self, dir: &str) -> Result<Vec<IndexEntry>, SourceError> {
        let url = ensure_https(join_path(&self.https_base, dir, true)?)?;
        let fetched = self.fetcher.get(&url).await?;
        ensure_https(fetched.final_url.clone())?;

        let anchors = index::parse_anchors(&fetched.body);
        if anchors.is_empty() {
            return Err(SourceError::Index {
                url: fetched.final_url.to_string(),
                reason: "response contains no <a> tags".to_string(),
            });
        }

        Ok(anchors
            .into_iter()
            .filter_map(index::entry_from_href)
            .collect())
    }

    /// Fetch and parse the metadata document at `path`.
    ///
    /// `path` is relative to the configured HTTPS base, e.g.
    /// `stable/cinc/19.4.46/debian/13/cinc_19.4.46-1_amd64.deb.metadata.json`.
    ///
    /// # Errors
    ///
    /// Returns [`SourceError::Insecure`] when the request or final URL is not
    /// HTTPS, [`SourceError::Http`] on a transport failure,
    /// [`SourceError::HttpStatus`] on a non-success status and
    /// [`SourceError::Metadata`] when the document cannot be parsed.
    pub async fn metadata(&self, path: &str) -> Result<Metadata, SourceError> {
        let url = ensure_https(join_path(&self.https_base, path, false)?)?;
        let fetched = self.fetcher.get(&url).await?;
        ensure_https(fetched.final_url.clone())?;

        metadata_from_body(&fetched.final_url, &fetched.body)
    }
}

/// Errors raised while reading listings or metadata.
#[derive(Debug, Error)]
pub enum SourceError {
    /// The request could not be completed.
    #[error("request to {url} failed: {source}")]
    Http {
        /// Request URL.
        url: String,
        /// Underlying transport error.
        #[source]
        source: reqwest::Error,
    },

    /// Upstream answered with a non-success status.
    #[error("request to {url} returned HTTP {status}")]
    HttpStatus {
        /// Request URL.
        url: String,
        /// Status code.
        status: u16,
    },

    /// A URL that is not HTTPS was about to be used.
    #[error("refusing insecure URL {url}: listings and metadata require https")]
    Insecure {
        /// The rejected URL.
        url: String,
    },

    /// The body was not a directory listing.
    #[error("cannot read directory listing from {url}: {reason}")]
    Index {
        /// Request URL.
        url: String,
        /// What was wrong with the body.
        reason: String,
    },

    /// The metadata document could not be parsed.
    #[error("cannot parse metadata from {url}: {source}")]
    Metadata {
        /// Request URL.
        url: String,
        /// Underlying parse error.
        #[source]
        source: metadata::MetadataError,
    },

    /// The source configuration is unusable.
    #[error("invalid source configuration: {reason}")]
    Config {
        /// Why the configuration was rejected.
        reason: String,
    },
}

/// Append `path` to `base`, optionally as a directory URL.
fn join_path(base: &Url, path: &str, trailing_slash: bool) -> Result<Url, SourceError> {
    let mut url = base.clone();
    url.set_query(None);
    url.set_fragment(None);

    {
        let mut segments = url.path_segments_mut().map_err(|()| SourceError::Config {
            reason: format!("`{base}` cannot be used as a base URL"),
        })?;
        segments.pop_if_empty();

        for segment in path.split('/').filter(|segment| !segment.is_empty()) {
            if segment == "." || segment == ".." {
                return Err(SourceError::Config {
                    reason: format!("path `{path}` must not contain traversal segments"),
                });
            }
            segments.push(segment);
        }

        if trailing_slash {
            segments.push("");
        }
    }

    Ok(url)
}

/// Reject a URL that is not HTTPS.
fn ensure_https(url: Url) -> Result<Url, SourceError> {
    if url.scheme() == "https" {
        Ok(url)
    } else {
        Err(SourceError::Insecure {
            url: url.to_string(),
        })
    }
}

/// Parse a metadata body, attributing failures to the URL it came from.
fn metadata_from_body(url: &Url, body: &str) -> Result<Metadata, SourceError> {
    Metadata::from_json(body).map_err(|source| SourceError::Metadata {
        url: url.to_string(),
        source,
    })
}

/// Redirect policy: at most [`MAX_REDIRECTS`] hops, same host only.
fn redirect_policy(allowed_host: &str) -> Policy {
    let allowed_host = allowed_host.to_string();

    Policy::custom(move |attempt| {
        match check_redirect(&allowed_host, attempt.previous().len(), attempt.url()) {
            Ok(()) => attempt.follow(),
            Err(reason) => attempt.error(reason),
        }
    })
}

/// Decide whether a redirect target may be followed.
///
/// A cleartext target is refused here, before the request is sent, so no
/// forbidden transfer takes place. The post-response scheme check in
/// [`Source::list`] and [`Source::metadata`] stays as defense in depth for a
/// fetcher that does not apply this policy.
fn check_redirect(allowed_host: &str, previous: usize, target: &Url) -> Result<(), &'static str> {
    if previous >= MAX_REDIRECTS {
        return Err("redirect limit exceeded");
    }
    if target.scheme() != "https" {
        return Err("refusing a redirect to a cleartext URL");
    }
    if target.host_str() != Some(allowed_host) {
        return Err("refusing a redirect to another host");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> SourceConfig {
        SourceConfig {
            https_base: Url::parse(DEFAULT_HTTPS_BASE).expect("base url"),
            ftp_host: DEFAULT_FTP_HOST.to_string(),
            ftp_base_path: DEFAULT_FTP_BASE_PATH.to_string(),
            transports: vec![TransportKind::Https],
        }
    }

    #[test]
    fn from_config_uses_the_upstream_defaults() {
        let config = SourceConfig::from_config(&Config::default()).expect("source config");

        assert_eq!(
            config.https_base.as_str(),
            "https://downloads.cinc.sh/files"
        );
        assert_eq!(config.ftp_host, "ftp.osuosl.org");
        assert_eq!(config.ftp_base_path, "pub/cinc/files");
        assert_eq!(config.transports, Config::default().transport);
    }

    #[test]
    fn from_config_rejects_a_cleartext_metadata_transport() {
        let config = Config {
            metadata_transport: TransportKind::Ftp,
            ..Config::default()
        };

        let error = SourceConfig::from_config(&config).expect_err("cleartext must be refused");

        assert!(matches!(error, SourceError::Config { .. }));
    }

    #[test]
    fn builds_directory_and_file_urls_below_the_base() {
        let source = Source::new(&config()).expect("source");

        assert_eq!(
            join_path(&source.https_base, "stable/cinc", true)
                .expect("url")
                .as_str(),
            "https://downloads.cinc.sh/files/stable/cinc/"
        );
        assert_eq!(
            join_path(
                &source.https_base,
                "/stable/cinc/19.4.46/debian/13/cinc_19.4.46-1_amd64.deb.metadata.json",
                false
            )
            .expect("url")
            .as_str(),
            "https://downloads.cinc.sh/files/stable/cinc/19.4.46/debian/13/\
             cinc_19.4.46-1_amd64.deb.metadata.json"
        );
    }

    #[test]
    fn a_base_without_a_trailing_slash_keeps_its_path() {
        let base = Url::parse("https://example.org/files").expect("base url");

        assert_eq!(
            join_path(&base, "stable", true).expect("url").as_str(),
            "https://example.org/files/stable/"
        );
    }

    #[test]
    fn rejects_traversal_segments_in_a_path() {
        let base = Url::parse(DEFAULT_HTTPS_BASE).expect("base url");

        for path in ["../etc/passwd", "stable/../../etc"] {
            let error = join_path(&base, path, false).expect_err("traversal must be rejected");
            assert!(matches!(error, SourceError::Config { .. }), "{error:?}");
        }
    }

    #[test]
    fn accepts_https_and_rejects_everything_else() {
        assert!(ensure_https(Url::parse("https://downloads.cinc.sh/files").expect("url")).is_ok());

        for insecure in ["http://downloads.cinc.sh/files", "ftp://example.org/x"] {
            let error = ensure_https(Url::parse(insecure).expect("url")).expect_err("must reject");
            assert!(matches!(error, SourceError::Insecure { .. }));
        }
    }

    #[test]
    fn redirects_must_stay_https_on_the_configured_host_and_within_the_limit() {
        let same_host = Url::parse("https://downloads.cinc.sh/files/x").expect("url");
        let cleartext = Url::parse("http://downloads.cinc.sh/files/x").expect("url");
        let foreign = Url::parse("https://evil.example/x").expect("url");

        assert!(check_redirect("downloads.cinc.sh", 0, &same_host).is_ok());
        assert!(
            check_redirect("downloads.cinc.sh", 0, &cleartext).is_err(),
            "a cleartext redirect target must never be followed"
        );
        assert!(check_redirect("downloads.cinc.sh", 0, &foreign).is_err());
        assert!(check_redirect("downloads.cinc.sh", MAX_REDIRECTS, &same_host).is_err());
    }

    /// A fetcher that returns a pre-baked response, including an arbitrary final
    /// URL. This is how the post-response scheme check is exercised without a
    /// TLS server.
    struct FakeFetcher {
        final_url: Url,
        body: String,
    }

    #[async_trait]
    impl Fetcher for FakeFetcher {
        async fn get(&self, _url: &Url) -> Result<Fetched, SourceError> {
            Ok(Fetched {
                body: self.body.clone(),
                final_url: self.final_url.clone(),
            })
        }
    }

    fn fake_source(final_url: &str, body: &str) -> Source {
        Source::with_fetcher(
            Arc::new(FakeFetcher {
                final_url: Url::parse(final_url).expect("final url"),
                body: body.to_string(),
            }),
            Url::parse(DEFAULT_HTTPS_BASE).expect("base url"),
        )
    }

    const TEST_METADATA: &str = r#"{
        "basename": "cinc_19.4.46-1_amd64.deb",
        "sha256": "83ad6e1b905a348909e1f312bc4f2f5061c566469a4ec77b041746378975d2a9",
        "platform": "debian",
        "platform_version": "13",
        "arch": "x86_64",
        "version": "19.4.46"
    }"#;

    #[tokio::test]
    async fn rejects_cleartext_final_url_from_fetcher() {
        let source = fake_source(
            "http://downloads.cinc.sh/files/x.metadata.json",
            TEST_METADATA,
        );

        let error = source
            .metadata("x.metadata.json")
            .await
            .expect_err("a cleartext final URL must be refused");

        assert!(
            matches!(error, SourceError::Insecure { .. }),
            "unexpected error: {error:?}"
        );
    }

    #[tokio::test]
    async fn list_rejects_cleartext_final_url_from_fetcher() {
        let source = fake_source(
            "http://downloads.cinc.sh/files/stable/cinc/",
            r#"<a href="19.4.46/">19.4.46/</a>"#,
        );

        let error = source
            .list("stable/cinc")
            .await
            .expect_err("a cleartext final URL must be refused");

        assert!(
            matches!(error, SourceError::Insecure { .. }),
            "unexpected error: {error:?}"
        );
    }

    #[tokio::test]
    async fn accepts_an_https_final_url_from_fetcher() {
        let source = fake_source(
            "https://downloads.cinc.sh/files/x.metadata.json",
            TEST_METADATA,
        );

        let metadata = source
            .metadata("x.metadata.json")
            .await
            .expect("https response is accepted");

        assert_eq!(metadata.basename, "cinc_19.4.46-1_amd64.deb");
    }

    #[test]
    fn metadata_parse_errors_carry_the_url() {
        let url = Url::parse("https://downloads.cinc.sh/files/x.metadata.json").expect("url");

        let error = metadata_from_body(&url, r#"{"basename":"x"}"#).expect_err("missing fields");

        match error {
            SourceError::Metadata {
                url: reported,
                source,
            } => {
                assert_eq!(reported, url.as_str());
                assert_eq!(source, metadata::MetadataError::MissingField("sha256"));
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
