//! Payload transport ladder tests.
//!
//! The ladder has two layers worth pinning separately:
//!
//! - the transports themselves (`HttpsTransport` against a real HTTP responder
//!   that speaks `Range`/`206`/`416`, `FtpTransport` against libunftp with
//!   `REST`), and
//! - the ladder (`Source::download`) with an injected fake transport, so resume,
//!   restart, fatal statuses, retries and exhaustion are exercised without a TLS
//!   mock.
//!
//! Every test asserts the bytes that ended up on disk and the final hashes, not
//! just an error variant: the point of the ladder is a verified file.

mod support;

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use cinc_mirror::config::TransportKind;
use cinc_mirror::hash::{hash_reader, ExpectedHashes};
use cinc_mirror::source::transport::{
    DownloadError, FtpTransport, HttpsTransport, PayloadTransport, RetryPolicy, TransportError,
};
use cinc_mirror::source::{Fetched, Fetcher, Source, SourceError};
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const REMOTE: &str = "payload/cinc_19.4.46-1_amd64.deb";

// Fixtures -------------------------------------------------------------------

fn expected_for(body: &[u8]) -> ExpectedHashes {
    let hashes = hash_reader(body).expect("hash fixture");
    ExpectedHashes {
        sha256: hashes.sha256,
        sha512: None,
        sha1: None,
        md5: None,
        size: Some(body.len() as u64),
    }
}

fn sha256_of(body: &[u8]) -> String {
    hash_reader(body).expect("hash fixture").sha256
}

fn append(dest: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(dest)?;
    file.write_all(bytes)
}

fn no_retry() -> RetryPolicy {
    RetryPolicy::new(3, Duration::ZERO)
}

fn temp_file(contents: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("payload.part");
    std::fs::write(&path, contents).expect("write partial");
    (dir, path)
}

fn empty_dest() -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("payload.part");
    (dir, path)
}

/// A `Fetcher` that must never be used: the download ladder does not read
/// listings or metadata.
struct UnusedFetcher;

#[async_trait]
impl Fetcher for UnusedFetcher {
    async fn get(&self, url: &Url) -> Result<Fetched, SourceError> {
        Err(SourceError::Config {
            reason: format!("ladder tests must not fetch {url}"),
        })
    }

    async fn head_len(&self, _url: &Url) -> Result<Option<u64>, SourceError> {
        Ok(None)
    }
}

fn source_with(transports: Vec<Arc<dyn PayloadTransport>>, retry: RetryPolicy) -> Source {
    Source::with_fetcher(
        Arc::new(UnusedFetcher),
        Url::parse("https://downloads.cinc.sh/files").expect("base url"),
    )
    .with_payload_transports(transports)
    .with_retry_policy(retry)
}

type Behaviour = Box<dyn Fn(usize, &Path, u64) -> Result<u64, TransportError> + Send + Sync>;
type StatusCheck = fn(&TransportError) -> bool;
type ErrorFactory = fn() -> TransportError;

/// An injected rung: records every `resume_from`, then delegates to a closure.
struct FakeTransport {
    kind: TransportKind,
    behaviour: Behaviour,
    calls: AtomicUsize,
    resumes: Mutex<Vec<u64>>,
}

impl FakeTransport {
    fn new(
        kind: TransportKind,
        behaviour: impl Fn(usize, &Path, u64) -> Result<u64, TransportError> + Send + Sync + 'static,
    ) -> Arc<Self> {
        Arc::new(Self {
            kind,
            behaviour: Box::new(behaviour),
            calls: AtomicUsize::new(0),
            resumes: Mutex::new(Vec::new()),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn resumes(&self) -> Vec<u64> {
        self.resumes.lock().expect("resume lock").clone()
    }
}

#[async_trait]
impl PayloadTransport for FakeTransport {
    fn kind(&self) -> TransportKind {
        self.kind
    }

    async fn fetch(
        &self,
        _remote_path: &str,
        dest: &Path,
        resume_from: u64,
    ) -> Result<u64, TransportError> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        self.resumes.lock().expect("resume lock").push(resume_from);
        (self.behaviour)(call, dest, resume_from)
    }
}

/// A rung that always serves `body`, appending from `resume_from`.
fn serving(kind: TransportKind, body: &'static [u8]) -> Arc<FakeTransport> {
    FakeTransport::new(kind, move |_call, dest, resume_from| {
        let start = usize::try_from(resume_from)
            .expect("offset")
            .min(body.len());
        append(dest, &body[start..]).map_err(local)?;
        Ok((body.len() - start) as u64)
    })
}

fn local(source: std::io::Error) -> TransportError {
    TransportError::Local {
        path: "fake".to_string(),
        source,
    }
}

fn retryable(reason: &str) -> TransportError {
    TransportError::Retryable {
        path: REMOTE.to_string(),
        reason: reason.to_string(),
    }
}

// An HTTP responder that understands Range ------------------------------------

/// Serves `body` honouring `Range: bytes=<start>-` with `206`/`416`, or ignores
/// the header and answers `200` with the whole body.
struct Ranged {
    body: Vec<u8>,
    honour_range: bool,
}

impl Ranged {
    fn honouring(body: &[u8]) -> Self {
        Self {
            body: body.to_vec(),
            honour_range: true,
        }
    }

    fn ignoring(body: &[u8]) -> Self {
        Self {
            body: body.to_vec(),
            honour_range: false,
        }
    }
}

impl Respond for Ranged {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let len = self.body.len();
        let requested = request
            .headers
            .get("range")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_range_start);

        match (requested, self.honour_range) {
            (Some(start), true) if start < len => ResponseTemplate::new(206)
                .insert_header("content-range", format!("bytes {start}-{}/{len}", len - 1))
                .set_body_bytes(self.body[start..].to_vec()),
            (Some(_), true) => {
                ResponseTemplate::new(416).insert_header("content-range", format!("bytes */{len}"))
            }
            _ => ResponseTemplate::new(200).set_body_bytes(self.body.clone()),
        }
    }
}

fn parse_range_start(value: &str) -> Option<usize> {
    value
        .strip_prefix("bytes=")?
        .split('-')
        .next()?
        .parse()
        .ok()
}

async fn mount_range_server(body: &[u8]) -> (MockServer, Vec<u8>) {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{REMOTE}")))
        .respond_with(Ranged::honouring(body))
        .mount(&server)
        .await;
    (server, body.to_vec())
}

// HTTPS transport -------------------------------------------------------------

#[tokio::test]
async fn resumes_http_download_from_partial_size() {
    let body = b"the quick brown fox";
    let prefix = 7;
    let (server, full) = mount_range_server(body).await;
    let transport = HttpsTransport::new(Url::parse(&server.uri()).expect("server url"));
    let (_dir, dest) = temp_file(&body[..prefix]);

    let outcome = source_with(vec![Arc::new(transport)], no_retry())
        .download(REMOTE, &dest, &expected_for(body))
        .await
        .expect("resume must succeed");

    assert_eq!(outcome.transport, TransportKind::Https);
    assert_eq!(outcome.resumed_from, prefix as u64);
    assert_eq!(outcome.hashes.sha256, sha256_of(body));
    assert_eq!(std::fs::read(&dest).expect("payload"), full);

    let requests = server.received_requests().await.expect("requests");
    assert_eq!(requests.len(), 1, "the range must be requested once");
    assert_eq!(
        requests[0]
            .headers
            .get("range")
            .and_then(|value| value.to_str().ok()),
        Some(format!("bytes={prefix}-").as_str())
    );
}

#[tokio::test]
async fn restarts_when_remote_is_shorter_than_partial() {
    let body = b"abc";
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{REMOTE}")))
        .respond_with(Ranged::honouring(body))
        .mount(&server)
        .await;
    let transport = HttpsTransport::new(Url::parse(&server.uri()).expect("server url"));
    let (_dir, dest) = temp_file(&[0x5a; 10]);

    let outcome = source_with(vec![Arc::new(transport)], no_retry())
        .download(REMOTE, &dest, &expected_for(body))
        .await
        .expect("a shorter remote must restart from zero");

    assert_eq!(outcome.resumed_from, 0, "the prefix was discarded");
    assert_eq!(outcome.hashes.sha256, sha256_of(body));
    assert_eq!(
        std::fs::read(&dest).expect("payload"),
        body,
        "the old partial must not survive the restart"
    );

    let requests = server.received_requests().await.expect("requests");
    assert_eq!(
        requests.len(),
        2,
        "a 416 must be followed by one full request"
    );
}

#[tokio::test]
async fn restarts_when_the_server_ignores_the_range() {
    let body = b"0123456789";
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{REMOTE}")))
        .respond_with(Ranged::ignoring(body))
        .mount(&server)
        .await;
    let transport = HttpsTransport::new(Url::parse(&server.uri()).expect("server url"));
    let (_dir, dest) = temp_file(&body[..4]);

    let outcome = source_with(vec![Arc::new(transport)], no_retry())
        .download(REMOTE, &dest, &expected_for(body))
        .await
        .expect("a 200 answer must be written from zero");

    assert_eq!(outcome.resumed_from, 0);
    assert_eq!(
        std::fs::read(&dest).expect("payload"),
        body,
        "a spliced 200 body would duplicate the prefix"
    );
}

#[tokio::test]
async fn https_fetch_maps_fatal_statuses_and_server_errors() {
    let cases: [(u16, StatusCheck); 5] = [
        (404, |error| {
            matches!(error, TransportError::NotFound { .. })
        }),
        (401, |error| matches!(error, TransportError::Auth { .. })),
        (403, |error| {
            matches!(error, TransportError::Forbidden { .. })
        }),
        (451, |error| {
            matches!(error, TransportError::Forbidden { .. })
        }),
        (503, |error| {
            matches!(error, TransportError::Retryable { .. })
        }),
    ];

    for (status, check) in cases {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path(format!("/{REMOTE}")))
            .respond_with(ResponseTemplate::new(status))
            .mount(&server)
            .await;
        let transport = HttpsTransport::new(Url::parse(&server.uri()).expect("server url"));
        let (_dir, dest) = empty_dest();

        let error = transport
            .fetch(REMOTE, &dest, 0)
            .await
            .expect_err("the status must be an error");

        assert!(check(&error), "HTTP {status} mapped to {error:?}");
    }
}

#[tokio::test]
async fn transports_refuse_path_traversal() {
    let http =
        HttpsTransport::new(Url::parse("https://downloads.cinc.sh/files").expect("base url"));
    let (_dir, dest) = empty_dest();

    let error = http
        .fetch("../etc/passwd", &dest, 0)
        .await
        .expect_err("traversal must be refused");
    assert!(
        matches!(error, TransportError::Protocol { .. }),
        "{error:?}"
    );
    assert!(!dest.exists(), "nothing may be created");

    let ftp = FtpTransport::new("127.0.0.1", 1, "pub/cinc/files");
    let error = ftp
        .fetch("stable/../../etc/passwd", &dest, 0)
        .await
        .expect_err("traversal must be refused");
    assert!(
        matches!(error, TransportError::Protocol { .. }),
        "{error:?}"
    );
    assert!(!dest.exists(), "nothing may be created");
}

// FTP transport ---------------------------------------------------------------

const FTP_PACKAGE: &str = "stable/cinc/19.4.46/debian/13/cinc_19.4.46-1_amd64.deb";

#[tokio::test]
async fn ftp_roundtrip_matches_bytes_and_hash() {
    let body: Vec<u8> = (0..64 * 1024 + 17)
        .map(|index| (index % 251) as u8)
        .collect();
    let root = tempfile::tempdir().expect("temp dir");
    let dir = root
        .path()
        .join("pub/cinc/files/stable/cinc/19.4.46/debian/13");
    std::fs::create_dir_all(&dir).expect("fixture dir");
    std::fs::write(dir.join("cinc_19.4.46-1_amd64.deb"), &body).expect("package fixture");

    let server = support::start_ftp(root.path().to_path_buf()).await;
    let transport = FtpTransport::new("127.0.0.1", server.port, "pub/cinc/files");
    let (_out_dir, dest) = empty_dest();

    let written = transport
        .fetch(FTP_PACKAGE, &dest, 0)
        .await
        .expect("ftp download");

    assert_eq!(written, body.len() as u64);
    assert_eq!(std::fs::read(&dest).expect("payload"), body);
    assert_eq!(
        hash_reader(std::fs::File::open(&dest).expect("open")).expect("hash"),
        hash_reader(&body[..]).expect("hash")
    );
}

#[tokio::test]
async fn ftp_resumes_from_the_partial_offset() {
    let body: Vec<u8> = (0..32 * 1024 + 5)
        .map(|index| (index % 249) as u8)
        .collect();
    let root = tempfile::tempdir().expect("temp dir");
    let dir = root
        .path()
        .join("pub/cinc/files/stable/cinc/19.4.46/debian/13");
    std::fs::create_dir_all(&dir).expect("fixture dir");
    std::fs::write(dir.join("cinc_19.4.46-1_amd64.deb"), &body).expect("package fixture");

    let server = support::start_ftp(root.path().to_path_buf()).await;
    let transport = FtpTransport::new("127.0.0.1", server.port, "pub/cinc/files");
    let resume_from = 20_000;
    let (_out_dir, dest) = temp_file(&body[..resume_from as usize]);

    let written = transport
        .fetch(FTP_PACKAGE, &dest, resume_from)
        .await
        .expect("ftp resume");

    assert_eq!(written, body.len() as u64 - resume_from);
    assert_eq!(
        std::fs::read(&dest).expect("payload"),
        body,
        "REST must continue from the partial offset"
    );
}

#[tokio::test]
async fn ftp_reports_a_missing_path_as_not_found() {
    let root = tempfile::tempdir().expect("temp dir");
    std::fs::create_dir_all(root.path().join("pub/cinc/files")).expect("fixture dir");
    let server = support::start_ftp(root.path().to_path_buf()).await;
    let transport = FtpTransport::new("127.0.0.1", server.port, "pub/cinc/files");
    let (_dir, dest) = empty_dest();

    let error = transport
        .fetch("stable/cinc/absent.deb", &dest, 0)
        .await
        .expect_err("a 550 must be a missing file");

    assert!(
        matches!(error, TransportError::NotFound { .. }),
        "{error:?}"
    );
}

// Ladder ----------------------------------------------------------------------

#[tokio::test]
async fn restart_when_partial_hash_differs_after_completion() {
    let wrong = b"HELLO";
    let right = b"hello";
    // The first server holds a complete but wrong object; the second rung must
    // be tried and its verified bytes must win.
    let first = serving(TransportKind::Ftp, wrong);
    let second = serving(TransportKind::Ftps, right);
    let (_dir, dest) = empty_dest();

    let outcome = source_with(vec![first.clone(), second.clone()], no_retry())
        .download(REMOTE, &dest, &expected_for(right))
        .await
        .expect("a later rung with the right bytes must win");

    assert_eq!(first.calls(), 1, "a corrupt completion is not retried");
    assert_eq!(second.calls(), 1, "the next rung must be tried");
    assert_eq!(outcome.transport, TransportKind::Ftps);
    assert_eq!(outcome.hashes.sha256, sha256_of(right));
    assert_eq!(std::fs::read(&dest).expect("payload"), right);
}

#[tokio::test]
async fn a_corrupt_rung_outranks_a_later_transport_failure() {
    let wrong = b"complete but wrong";
    let promised = b"what the metadata promised";
    let corrupt = serving(TransportKind::Ftp, wrong);
    let failing = FakeTransport::new(TransportKind::Ftps, |_call, _dest, _from| {
        Err(retryable("the later rung is down"))
    });
    let (_dir, dest) = empty_dest();

    let error = source_with(vec![corrupt.clone(), failing.clone()], no_retry())
        .download(REMOTE, &dest, &expected_for(promised))
        .await
        .expect_err("no rung verified the bytes");

    match error {
        DownloadError::Corrupt { expected, observed } => {
            assert_eq!(expected, sha256_of(promised));
            assert_eq!(
                observed.sha256,
                sha256_of(wrong),
                "the last corrupt completion must be reported"
            );
        }
        other => panic!("a corrupt rung must outrank a transport failure: {other:?}"),
    }
    assert_eq!(corrupt.calls(), 1);
    assert_eq!(failing.calls(), 3, "the later rung still retries");
    assert!(!dest.exists(), "the corrupt partial must be deleted");
}

#[tokio::test]
async fn retries_resume_from_the_bytes_already_on_disk() {
    let body = b"0123456789abcdef";
    // The first attempt appends four bytes and loses the connection; the retry
    // must continue at four, not restart.
    let rung = FakeTransport::new(TransportKind::Ftp, |call, dest, resume_from| {
        if call == 0 {
            append(dest, &body[..4]).map_err(local)?;
            return Err(retryable("connection reset"));
        }
        let start = usize::try_from(resume_from)
            .expect("offset")
            .min(body.len());
        append(dest, &body[start..]).map_err(local)?;
        Ok((body.len() - start) as u64)
    });
    let (_dir, dest) = empty_dest();

    let outcome = source_with(vec![rung.clone()], no_retry())
        .download(REMOTE, &dest, &expected_for(body))
        .await
        .expect("the retry must finish the file");

    assert_eq!(rung.resumes(), vec![0, 4]);
    assert_eq!(outcome.resumed_from, 4);
    assert_eq!(std::fs::read(&dest).expect("payload"), body);
}

#[tokio::test]
async fn falls_back_to_next_transport_on_5xx() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(format!("/{REMOTE}")))
        .respond_with(ResponseTemplate::new(503))
        .mount(&server)
        .await;

    let body = b"served by the second rung";
    let second = serving(TransportKind::Ftps, body);
    let first = Arc::new(HttpsTransport::new(
        Url::parse(&server.uri()).expect("server url"),
    ));
    let (_dir, dest) = empty_dest();

    let outcome = source_with(vec![first, second.clone()], no_retry())
        .download(REMOTE, &dest, &expected_for(body))
        .await
        .expect("the second rung must finish the download");

    assert_eq!(outcome.transport, TransportKind::Ftps);
    assert_eq!(outcome.resumed_from, 0);
    assert_eq!(std::fs::read(&dest).expect("payload"), body);
    assert_eq!(second.calls(), 1);
    assert_eq!(
        server.received_requests().await.expect("requests").len(),
        3,
        "3 attempts per transport before the ladder advances"
    );
}

#[tokio::test]
async fn auth_and_404_do_not_advance_transport() {
    let cases: [(&str, ErrorFactory); 4] = [
        ("not found", || TransportError::NotFound {
            path: REMOTE.to_string(),
        }),
        ("auth", || TransportError::Auth {
            path: REMOTE.to_string(),
            reason: "530 login incorrect".to_string(),
        }),
        ("403", || TransportError::Forbidden {
            path: REMOTE.to_string(),
            status: 403,
        }),
        ("451", || TransportError::Forbidden {
            path: REMOTE.to_string(),
            status: 451,
        }),
    ];

    for (reason, make) in cases {
        let first = FakeTransport::new(TransportKind::Ftp, move |_call, _dest, _from| Err(make()));
        let second = serving(TransportKind::Https, b"must not be fetched");
        let (_dir, dest) = empty_dest();

        let error = source_with(vec![first.clone(), second.clone()], no_retry())
            .download(REMOTE, &dest, &expected_for(b"must not be fetched"))
            .await
            .expect_err("a fatal status ends the ladder");

        assert!(matches!(error, DownloadError::Rejected { .. }), "{reason}");
        assert_eq!(first.calls(), 1, "a fatal status must not be retried");
        assert_eq!(
            second.calls(),
            0,
            "a fatal status must not advance the ladder"
        );
        assert!(!dest.exists());
    }
}

#[tokio::test]
async fn exhausted_ladder_reports_last_error_and_observed_hash() {
    let wrong = b"complete but wrong";
    // The first rung streams every byte and *then* fails its final
    // acknowledgement: the partial on disk is complete, the transfer is not.
    let first = FakeTransport::new(TransportKind::Ftp, |call, dest, resume_from| {
        if call == 0 {
            append(dest, wrong).map_err(local)?;
            let _ = resume_from;
        }
        Err(retryable(
            "426 data connection closed before the final reply",
        ))
    });
    let second = FakeTransport::new(TransportKind::Ftps, |_call, _dest, _from| {
        Err(retryable("second rung down"))
    });
    let (_dir, dest) = empty_dest();

    let error = source_with(
        vec![first.clone(), second.clone()],
        RetryPolicy::new(2, Duration::ZERO),
    )
    .download(REMOTE, &dest, &expected_for(b"what the metadata promised"))
    .await
    .expect_err("both rungs fail");

    match &error {
        DownloadError::Exhausted {
            last_transport,
            source,
            observed,
            ..
        } => {
            assert_eq!(*last_transport, TransportKind::Ftps);
            assert!(
                source.to_string().contains("second rung down"),
                "the last error must be reported: {source}"
            );
            let observed = observed.as_ref().expect("the partial must be hashed");
            assert_eq!(observed.sha256, sha256_of(wrong));
        }
        other => panic!("unexpected error: {other:?}"),
    }

    let message = error.to_string();
    assert!(
        message.contains(&sha256_of(wrong)),
        "the observed hash must be in the message: {message}"
    );
    assert!(
        dest.exists(),
        "an exhausted ladder keeps the partial so the next run can resume"
    );
}
