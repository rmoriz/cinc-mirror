//! An in-memory OCI distribution registry for integration tests.
//!
//! The mock speaks the subset of the distribution spec the mirror uses:
//!
//! - `GET /v2/` (optionally behind a bearer challenge),
//! - `GET /token`, the token endpoint a `Bearer` challenge points at,
//! - `HEAD`/`GET /v2/<name>/blobs/<digest>`,
//! - `POST /v2/<name>/blobs/uploads/` plus `PATCH` chunks and a final `PUT`
//!   with `?digest=`,
//! - `PUT`/`GET`/`HEAD`/`DELETE /v2/<name>/manifests/<reference>`,
//! - `GET /v2/<name>/tags/list` with `n`/`last` paging.
//!
//! State lives in a `HashMap`, so a test can assert the exact bytes that
//! arrived and how they were split. Counters make wire behaviour visible:
//! number of `PATCH` requests, token requests, upload starts, manifest writes
//! and manifest deletes. [`MockRegistry::answer_405`] refuses every manifest
//! delete, [`MockRegistry::deny_deletes`] answers `403` for one repository and
//! [`MockRegistry::fail_deletes_with`] refuses the next one with an arbitrary
//! status. The server binds `127.0.0.1:0`, so tests never leave the machine.

use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Query, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, get};
use axum::Router;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use serde_json::json;
use sha2::{Digest, Sha256};

/// How the mock registry authenticates requests.
#[derive(Debug, Clone)]
pub enum MockAuth {
    /// No credentials are required; every route answers.
    Anonymous,
    /// `GET /v2/` answers 401 with a bearer challenge; a token from `/token` is
    /// required on every other route.
    Bearer,
    /// Like [`MockAuth::Bearer`], but `/token` itself requires the configured
    /// basic credentials, which is how GHCR and friends behave.
    BearerWithBasic { user: String, password: String },
}

impl MockAuth {
    fn requires_token(&self) -> bool {
        !matches!(self, Self::Anonymous)
    }
}

/// One manifest stored by the mock.
#[derive(Debug, Clone)]
pub struct StoredManifest {
    /// Exact bytes that arrived.
    pub bytes: Vec<u8>,
    /// Digest the mock reported in `Docker-Content-Digest`.
    pub digest: String,
}

/// All state and counters behind one running mock.
#[derive(Debug)]
pub struct MockState {
    base_url: String,
    auth: MockAuth,
    port: u16,
    tokens: Mutex<HashSet<String>>,
    next_token: AtomicUsize,
    blobs: Mutex<HashMap<(String, String), Vec<u8>>>,
    uploads: Mutex<HashMap<String, Vec<u8>>>,
    manifests: Mutex<HashMap<(String, String), StoredManifest>>,
    patches: AtomicUsize,
    patch_sizes: Mutex<Vec<usize>>,
    upload_starts: AtomicUsize,
    upload_completes: AtomicUsize,
    token_requests: AtomicUsize,
    token_scopes: Mutex<Vec<String>>,
    token_services: Mutex<Vec<String>>,
    token_basic_headers: Mutex<Vec<Option<String>>>,
    manifest_puts: AtomicUsize,
    manifest_put_failures: AtomicUsize,
    manifest_deletes: AtomicUsize,
    manifest_delete_attempts: AtomicUsize,
    answer_405: AtomicUsize,
    fail_deletes: AtomicU16,
    fail_all_deletes: AtomicU16,
    denied_repos: Mutex<HashSet<String>>,
    blob_heads: AtomicUsize,
    stall_patch: AtomicU64,
    stall_patch_body: AtomicU64,
    requests: Mutex<Vec<(String, String)>>,
    authorizations: Mutex<Vec<Option<String>>>,
}

impl MockState {
    fn new(base_url: String, port: u16, auth: MockAuth) -> Self {
        Self {
            base_url,
            auth,
            port,
            tokens: Mutex::new(HashSet::new()),
            next_token: AtomicUsize::new(0),
            blobs: Mutex::new(HashMap::new()),
            uploads: Mutex::new(HashMap::new()),
            manifests: Mutex::new(HashMap::new()),
            patches: AtomicUsize::new(0),
            patch_sizes: Mutex::new(Vec::new()),
            upload_starts: AtomicUsize::new(0),
            upload_completes: AtomicUsize::new(0),
            token_requests: AtomicUsize::new(0),
            token_scopes: Mutex::new(Vec::new()),
            token_services: Mutex::new(Vec::new()),
            token_basic_headers: Mutex::new(Vec::new()),
            manifest_puts: AtomicUsize::new(0),
            manifest_put_failures: AtomicUsize::new(0),
            manifest_deletes: AtomicUsize::new(0),
            manifest_delete_attempts: AtomicUsize::new(0),
            answer_405: AtomicUsize::new(0),
            fail_deletes: AtomicU16::new(0),
            fail_all_deletes: AtomicU16::new(0),
            denied_repos: Mutex::new(HashSet::new()),
            blob_heads: AtomicUsize::new(0),
            stall_patch: AtomicU64::new(0),
            stall_patch_body: AtomicU64::new(0),
            requests: Mutex::new(Vec::new()),
            authorizations: Mutex::new(Vec::new()),
        }
    }

    fn record(&self, method: &Method, path: &str, headers: &HeaderMap) {
        lock(&self.requests).push((method.as_str().to_string(), path.to_string()));
        lock(&self.authorizations).push(authorization(headers).map(str::to_string));
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

fn authorization(headers: &HeaderMap) -> Option<&str> {
    headers.get(header::AUTHORIZATION)?.to_str().ok()
}

fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    authorization(headers)?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

fn sha256_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    format!("sha256:{hex}")
}

fn challenge(state: &MockState, repo: &str, actions: &str) -> Response {
    let value = format!(
        r#"Bearer realm="{}/token",service="mock-registry",scope="repository:{}:{}""#,
        state.base_url, repo, actions
    );
    let mut response = StatusCode::UNAUTHORIZED.into_response();
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        value.parse().expect("challenge header"),
    );
    response
}

// The error is a ready 401 response, which axum's `Response` makes large; the
// mock hands it straight back to the caller without boxing.
#[allow(clippy::result_large_err)]
fn authorize(
    state: &MockState,
    headers: &HeaderMap,
    repo: &str,
    actions: &str,
) -> Result<(), Response> {
    if !state.auth.requires_token() {
        return Ok(());
    }
    match bearer_token(headers) {
        Some(token) if lock(&state.tokens).contains(token) => Ok(()),
        _ => Err(challenge(state, repo, actions)),
    }
}

fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    let query = query?;
    url::form_urlencoded::parse(query.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

async fn token(
    State(state): State<Arc<MockState>>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> Response {
    state.token_requests.fetch_add(1, Ordering::SeqCst);
    lock(&state.token_scopes).push(params.get("scope").cloned().unwrap_or_default());
    lock(&state.token_services).push(params.get("service").cloned().unwrap_or_default());

    let basic = authorization(&headers).map(str::to_string);
    lock(&state.token_basic_headers).push(basic.clone());

    if let MockAuth::BearerWithBasic { user, password } = &state.auth {
        let expected = format!("Basic {}", BASE64.encode(format!("{user}:{password}")));
        if basic.as_deref() != Some(expected.as_str()) {
            return (StatusCode::UNAUTHORIZED, "bad basic credentials").into_response();
        }
    }

    let number = state.next_token.fetch_add(1, Ordering::SeqCst) + 1;
    let value = format!("mock-token-{number}");
    lock(&state.tokens).insert(value.clone());

    axum::Json(json!({"token": value, "expires_in": 300})).into_response()
}

async fn v2(
    State(state): State<Arc<MockState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let path = uri.path();
    state.record(&method, path, &headers);

    if path == "/v2" || path == "/v2/" {
        if method != Method::GET && method != Method::HEAD {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        if let Err(response) = authorize(&state, &headers, "", "pull") {
            return response;
        }
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            "{}",
        )
            .into_response();
    }

    let Some(rest) = path.strip_prefix("/v2/") else {
        return StatusCode::NOT_FOUND.into_response();
    };

    if let Some(repo) = rest.strip_suffix("/blobs/uploads/") {
        if method != Method::POST {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        if let Err(response) = authorize(&state, &headers, repo, "pull,push") {
            return response;
        }
        return start_upload(&state, repo);
    }

    if let Some((prefix, id)) = rest.rsplit_once('/') {
        if let Some(repo) = prefix.strip_suffix("/blobs/uploads") {
            if method != Method::PATCH && method != Method::PUT {
                return StatusCode::METHOD_NOT_ALLOWED.into_response();
            }
            if let Err(response) = authorize(&state, &headers, repo, "pull,push") {
                return response;
            }
            return match method {
                Method::PATCH => patch_upload(&state, repo, id, &body).await,
                _ => finish_upload(&state, repo, id, &body, uri.query()),
            };
        }
    }

    if let Some((repo, digest)) = rest.rsplit_once("/blobs/") {
        if method != Method::GET && method != Method::HEAD {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        if let Err(response) = authorize(&state, &headers, repo, "pull") {
            return response;
        }
        return blob_response(&state, repo, digest, &method);
    }

    if let Some(repo) = rest.strip_suffix("/tags/list") {
        if method != Method::GET {
            return StatusCode::METHOD_NOT_ALLOWED.into_response();
        }
        if let Err(response) = authorize(&state, &headers, repo, "pull") {
            return response;
        }
        return tags_list(&state, repo, uri.query());
    }

    if let Some((repo, reference)) = rest.rsplit_once("/manifests/") {
        if let Err(response) = authorize(&state, &headers, repo, "pull,push") {
            return response;
        }
        return match method {
            Method::PUT => put_manifest(&state, repo, reference, &body),
            Method::GET => manifest_response(&state, repo, reference, false),
            Method::HEAD => manifest_response(&state, repo, reference, true),
            Method::DELETE => delete_manifest(&state, repo, reference),
            _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        };
    }

    StatusCode::NOT_FOUND.into_response()
}

fn start_upload(state: &Arc<MockState>, repo: &str) -> Response {
    state.upload_starts.fetch_add(1, Ordering::SeqCst);
    let id = format!(
        "upload-{}",
        state.upload_completes.load(Ordering::SeqCst) + state.upload_starts.load(Ordering::SeqCst)
    );
    lock(&state.uploads).entry(id.clone()).or_default();
    let location = format!(
        "{}/v2/{}/blobs/uploads/{}?_state=session",
        state.base_url, repo, id
    );
    (
        StatusCode::ACCEPTED,
        [("location", location), ("range", "0-0".to_string())],
    )
        .into_response()
}

async fn patch_upload(state: &Arc<MockState>, repo: &str, id: &str, body: &[u8]) -> Response {
    state.patches.fetch_add(1, Ordering::SeqCst);
    lock(&state.patch_sizes).push(body.len());

    let stall = state.stall_patch.load(Ordering::SeqCst);
    if stall > 0 {
        // A registry that accepts the connection and then does not answer:
        // only a client-side request timeout can end this.
        tokio::time::sleep(Duration::from_millis(stall)).await;
    }

    let mut uploads = lock(&state.uploads);
    let Some(upload) = uploads.get_mut(id) else {
        return (StatusCode::NOT_FOUND, "unknown upload session").into_response();
    };
    upload.extend_from_slice(body);
    let total = upload.len();
    drop(uploads);

    let location = format!(
        "{}/v2/{}/blobs/uploads/{}?_state=session",
        state.base_url, repo, id
    );
    let range = format!("0-{}", total.saturating_sub(1));

    let stall_body = state.stall_patch_body.load(Ordering::SeqCst);
    if stall_body > 0 {
        // Headers arrive immediately, the body never does: only the client's
        // per-read timeout can end this.
        let stream = futures::stream::once(async move {
            tokio::time::sleep(Duration::from_millis(stall_body)).await;
            Ok::<Bytes, std::io::Error>(Bytes::from_static(b"{}"))
        });
        let mut response = Response::new(Body::from_stream(stream));
        *response.status_mut() = StatusCode::ACCEPTED;
        response
            .headers_mut()
            .insert("location", location.parse().expect("location header"));
        response
            .headers_mut()
            .insert("range", range.parse().expect("range header"));
        return response;
    }

    (
        StatusCode::ACCEPTED,
        [("location", location), ("range", range)],
    )
        .into_response()
}

fn finish_upload(
    state: &Arc<MockState>,
    repo: &str,
    id: &str,
    body: &[u8],
    query: Option<&str>,
) -> Response {
    let Some(digest) = query_param(query, "digest") else {
        return (StatusCode::BAD_REQUEST, "missing digest").into_response();
    };

    let mut uploads = lock(&state.uploads);
    let Some(upload) = uploads.remove(id) else {
        return (StatusCode::NOT_FOUND, "unknown upload session").into_response();
    };
    let mut bytes = upload;
    bytes.extend_from_slice(body);

    if sha256_digest(&bytes) != digest {
        return (StatusCode::BAD_REQUEST, "digest mismatch").into_response();
    }

    lock(&state.blobs).insert((repo.to_string(), digest.clone()), bytes);
    state.upload_completes.fetch_add(1, Ordering::SeqCst);

    let location = format!("{}/v2/{}/blobs/{}", state.base_url, repo, digest);
    (
        StatusCode::CREATED,
        [("location", location), ("docker-content-digest", digest)],
    )
        .into_response()
}

fn blob_response(state: &Arc<MockState>, repo: &str, digest: &str, method: &Method) -> Response {
    if method == Method::HEAD {
        state.blob_heads.fetch_add(1, Ordering::SeqCst);
    }
    let blobs = lock(&state.blobs);
    let Some(bytes) = blobs.get(&(repo.to_string(), digest.to_string())) else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let length = bytes.len().to_string();
    if method == Method::HEAD {
        return (
            StatusCode::OK,
            [
                ("content-length", length),
                ("content-type", "application/octet-stream".to_string()),
                ("docker-content-digest", digest.to_string()),
            ],
        )
            .into_response();
    }

    (
        StatusCode::OK,
        [
            ("content-length", length),
            ("content-type", "application/octet-stream".to_string()),
            ("docker-content-digest", digest.to_string()),
        ],
        bytes.clone(),
    )
        .into_response()
}

fn put_manifest(state: &Arc<MockState>, repo: &str, reference: &str, body: &[u8]) -> Response {
    if state.manifest_put_failures.load(Ordering::SeqCst) > 0 {
        state.manifest_put_failures.fetch_sub(1, Ordering::SeqCst);
        state.manifest_puts.fetch_add(1, Ordering::SeqCst);
        return (StatusCode::INTERNAL_SERVER_ERROR, "injected failure").into_response();
    }

    state.manifest_puts.fetch_add(1, Ordering::SeqCst);
    let digest = sha256_digest(body);
    lock(&state.manifests).insert(
        (repo.to_string(), reference.to_string()),
        StoredManifest {
            bytes: body.to_vec(),
            digest: digest.clone(),
        },
    );

    (
        StatusCode::CREATED,
        [
            ("docker-content-digest", digest.clone()),
            (
                "location",
                format!("{}/v2/{}/manifests/{}", state.base_url, repo, digest),
            ),
        ],
    )
        .into_response()
}

fn manifest_response(
    state: &Arc<MockState>,
    repo: &str,
    reference: &str,
    head_only: bool,
) -> Response {
    let manifests = lock(&state.manifests);
    let manifest = manifests
        .get(&(repo.to_string(), reference.to_string()))
        .or_else(|| {
            manifests
                .iter()
                .find(|((name, _), manifest)| name == repo && manifest.digest == reference)
                .map(|(_, manifest)| manifest)
        });
    let Some(manifest) = manifest else {
        return StatusCode::NOT_FOUND.into_response();
    };

    let headers = [
        (
            "content-type",
            "application/vnd.oci.image.manifest.v1+json".to_string(),
        ),
        ("docker-content-digest", manifest.digest.clone()),
        ("content-length", manifest.bytes.len().to_string()),
    ];

    if head_only {
        return (StatusCode::OK, headers).into_response();
    }

    (StatusCode::OK, headers, manifest.bytes.clone()).into_response()
}

fn delete_manifest(state: &Arc<MockState>, repo: &str, reference: &str) -> Response {
    state
        .manifest_delete_attempts
        .fetch_add(1, Ordering::SeqCst);
    if state.answer_405.load(Ordering::SeqCst) != 0 {
        return (StatusCode::METHOD_NOT_ALLOWED, "UNSUPPORTED").into_response();
    }
    if lock(&state.denied_repos).contains(repo) {
        return (StatusCode::FORBIDDEN, "denied").into_response();
    }
    if let Some(status) = take_delete_failure(&state.fail_deletes) {
        return (status, "injected delete failure").into_response();
    }
    let always = state.fail_all_deletes.load(Ordering::SeqCst);
    if always != 0 {
        let status = StatusCode::from_u16(always).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        return (status, "injected delete failure").into_response();
    }

    let mut manifests = lock(&state.manifests);
    let before = manifests.len();
    manifests.retain(|(name, key), manifest| {
        !(name == repo && (key == reference || manifest.digest == reference))
    });
    if manifests.len() == before {
        return StatusCode::NOT_FOUND.into_response();
    }
    drop(manifests);

    state.manifest_deletes.fetch_add(1, Ordering::SeqCst);
    StatusCode::ACCEPTED.into_response()
}

/// Answer a status once if a delete failure is armed, then disarm it.
fn take_delete_failure(cell: &AtomicU16) -> Option<StatusCode> {
    let status = cell.swap(0, Ordering::SeqCst);
    (status != 0).then(|| StatusCode::from_u16(status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
}

fn tags_list(state: &Arc<MockState>, repo: &str, query: Option<&str>) -> Response {
    let mut tags = lock(&state.manifests)
        .keys()
        .filter(|(name, reference)| name == repo && !reference.starts_with("sha256:"))
        .map(|(_, reference)| reference.clone())
        .collect::<Vec<_>>();
    tags.sort();
    tags.dedup();

    if let Some(last) = query_param(query, "last") {
        tags.retain(|tag| tag.as_str() > last.as_str());
    }
    // Two per page in the mock forces a client into the `Link` paging path.
    let limit = query_param(query, "n")
        .and_then(|n| n.parse::<usize>().ok())
        .map_or(2, |n| n.min(2));
    let more = tags.len() > limit;
    tags.truncate(limit);

    let mut response = axum::Json(json!({"name": repo, "tags": tags})).into_response();
    if more {
        let last = tags.last().cloned().unwrap_or_default();
        let link = format!(
            "<{}/v2/{}/tags/list?n={limit}&last={last}>; rel=\"next\"",
            state.base_url, repo
        );
        if let Ok(value) = link.parse() {
            response.headers_mut().insert(header::LINK, value);
        }
    }
    response
}

/// A running mock registry on a loopback port.
pub struct MockRegistry {
    base_url: String,
    state: Arc<MockState>,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for MockRegistry {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl MockRegistry {
    /// Start a registry with the given authentication behaviour.
    pub async fn start(auth: MockAuth) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock registry");
        let address = listener.local_addr().expect("local address");
        let base_url = format!("http://{address}");
        let state = Arc::new(MockState::new(base_url.clone(), address.port(), auth));

        let app = Router::new()
            .route("/token", get(token))
            .route("/v2", any(v2))
            .route("/v2/", any(v2))
            .route("/v2/*rest", any(v2))
            // Chunked upload tests send 4 MiB PATCH bodies; the default axum
            // body limit is smaller.
            .layer(DefaultBodyLimit::disable())
            .with_state(Arc::clone(&state));

        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        for _ in 0..200 {
            if tokio::net::TcpStream::connect(address).await.is_ok() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        }

        Self {
            base_url,
            state,
            handle,
        }
    }

    /// The registry as it appears in configuration: `host:port`.
    pub fn registry_name(&self) -> String {
        self.base_url
            .strip_prefix("http://")
            .unwrap_or(&self.base_url)
            .to_string()
    }

    /// Base URL of the mock.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Port the mock listens on.
    pub fn port(&self) -> u16 {
        self.state.port
    }

    /// Store a blob as if a previous run had uploaded it; returns its digest.
    pub fn put_blob(&self, repo: &str, bytes: &[u8]) -> String {
        let digest = sha256_digest(bytes);
        lock(&self.state.blobs).insert((repo.to_string(), digest.clone()), bytes.to_vec());
        digest
    }

    /// Read back a stored blob.
    pub fn blob(&self, repo: &str, digest: &str) -> Option<Vec<u8>> {
        lock(&self.state.blobs)
            .get(&(repo.to_string(), digest.to_string()))
            .cloned()
    }

    /// Store a manifest directly, as if a previous run had written it.
    pub fn store_manifest(&self, repo: &str, reference: &str, bytes: &[u8]) -> String {
        let digest = sha256_digest(bytes);
        lock(&self.state.manifests).insert(
            (repo.to_string(), reference.to_string()),
            StoredManifest {
                bytes: bytes.to_vec(),
                digest: digest.clone(),
            },
        );
        digest
    }

    /// Read back a stored manifest.
    pub fn manifest(&self, repo: &str, reference: &str) -> Option<StoredManifest> {
        lock(&self.state.manifests)
            .get(&(repo.to_string(), reference.to_string()))
            .cloned()
    }

    /// Number of `PATCH` requests seen.
    pub fn patch_count(&self) -> usize {
        self.state.patches.load(Ordering::SeqCst)
    }

    /// Body size of every `PATCH` request, in arrival order.
    pub fn patch_sizes(&self) -> Vec<usize> {
        lock(&self.state.patch_sizes).clone()
    }

    /// Number of `POST .../blobs/uploads/` requests seen.
    pub fn upload_starts(&self) -> usize {
        self.state.upload_starts.load(Ordering::SeqCst)
    }

    /// Number of uploads finalised with `PUT ...?digest=`.
    pub fn upload_completes(&self) -> usize {
        self.state.upload_completes.load(Ordering::SeqCst)
    }

    /// Number of token endpoint hits.
    pub fn token_requests(&self) -> usize {
        self.state.token_requests.load(Ordering::SeqCst)
    }

    /// Scope parameter of every token request, in arrival order.
    pub fn token_scopes(&self) -> Vec<String> {
        lock(&self.state.token_scopes).clone()
    }

    /// Service parameter of every token request, in arrival order.
    pub fn token_services(&self) -> Vec<String> {
        lock(&self.state.token_services).clone()
    }

    /// `Authorization` header of every token request, in arrival order.
    pub fn token_basic_headers(&self) -> Vec<Option<String>> {
        lock(&self.state.token_basic_headers).clone()
    }

    /// Number of manifest `PUT` requests seen, including injected failures.
    pub fn manifest_put_count(&self) -> usize {
        self.state.manifest_puts.load(Ordering::SeqCst)
    }

    /// Number of `HEAD` blob requests seen.
    pub fn blob_head_count(&self) -> usize {
        self.state.blob_heads.load(Ordering::SeqCst)
    }

    /// Make every `PATCH` handler wait before answering.
    pub fn stall_patches_for(&self, duration: Duration) {
        self.state
            .stall_patch
            .store(duration.as_millis() as u64, Ordering::SeqCst);
    }

    /// Make every `PATCH` send its headers and then stall the response body.
    pub fn stall_patch_bodies_for(&self, duration: Duration) {
        self.state
            .stall_patch_body
            .store(duration.as_millis() as u64, Ordering::SeqCst);
    }

    /// Fail the next `count` manifest writes with HTTP 500.
    pub fn fail_manifest_puts(&self, count: usize) {
        self.state
            .manifest_put_failures
            .store(count, Ordering::SeqCst);
    }

    /// Number of manifest `DELETE` requests that removed something.
    pub fn delete_count(&self) -> usize {
        self.state.manifest_deletes.load(Ordering::SeqCst)
    }

    /// Answer `405 UNSUPPORTED` to every manifest `DELETE`.
    pub fn answer_405(&self) {
        self.state.answer_405.store(1, Ordering::SeqCst);
    }

    /// Answer the next manifest `DELETE` with `status`, then accept again.
    pub fn fail_deletes_with(&self, status: u16) {
        self.state.fail_deletes.store(status, Ordering::SeqCst);
    }

    /// Answer every manifest `DELETE` with `status`.
    pub fn fail_all_deletes_with(&self, status: u16) {
        self.state.fail_all_deletes.store(status, Ordering::SeqCst);
    }

    /// Answer every manifest `DELETE` below `repo` with `403 FORBIDDEN`.
    pub fn deny_deletes(&self, repo: &str) {
        lock(&self.state.denied_repos).insert(repo.to_string());
    }

    /// Number of manifest `DELETE` requests seen, successful or not.
    pub fn delete_attempts(&self) -> usize {
        self.state.manifest_delete_attempts.load(Ordering::SeqCst)
    }

    /// Accept a bearer token the test invents, for a pre-issued token.
    pub fn allow_token(&self, token: &str) {
        lock(&self.state.tokens).insert(token.to_string());
    }

    /// Every `(method, path)` seen, in arrival order.
    pub fn request_log(&self) -> Vec<(String, String)> {
        lock(&self.state.requests).clone()
    }

    /// `Authorization` header of every `/v2` request, in arrival order.
    pub fn authorizations(&self) -> Vec<Option<String>> {
        lock(&self.state.authorizations).clone()
    }
}
