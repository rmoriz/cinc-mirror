//! An in-memory GitHub Packages API for integration tests.
//!
//! The mock serves the subset of the REST API the pruner uses:
//!
//! - `GET /users|orgs/<owner>/packages/container/<package>/versions` with
//!   `per_page`/`page` paging and a `Link: rel="next"` header,
//! - `DELETE /users|orgs/<owner>/packages/container/<package>/versions/<id>`,
//! - `GET /users|orgs/<owner>/packages?package_type=container`.
//!
//! The package name arrives percent-encoded (`cinc-mirror%2Fcinc`), because
//! `Url::path_segments_mut().push` encodes the slash exactly as GHCR expects, so
//! the mock decodes every path segment before matching.
//!
//! Switches make the awkward GitHub answers reproducible: [`MockPackages::deny`]
//! answers `403` everywhere and echoes the received `Authorization` header in
//! the body (so a client can be checked for leaking its token), and
//! [`MockPackages::owner_is_org`] marks the named owner as an organisation.
//!
//! Owners are users unless marked otherwise, and the owner routes follow the
//! real API: a user owner `404`s under `/orgs/`, an organisation `404`s under
//! `/users/`. A client cannot get away with guessing the form from the owner of
//! a package's versions route.

use std::cmp::Reverse;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use chrono::{DateTime, Utc};
use percent_encoding::percent_decode_str;
use serde_json::{json, Value};

/// One stored package version.
#[derive(Debug, Clone)]
struct SeededVersion {
    id: u64,
    created: Option<String>,
    tags: Vec<String>,
}

/// All state and counters behind one running mock.
#[derive(Debug)]
struct MockState {
    base_url: String,
    orgs: Mutex<BTreeSet<String>>,
    deny: AtomicBool,
    omit_links: AtomicBool,
    failure: AtomicU16,
    next_id: AtomicU64,
    packages: Mutex<BTreeSet<String>>,
    versions: Mutex<BTreeMap<String, Vec<SeededVersion>>>,
    deleted: Mutex<Vec<u64>>,
    requests: Mutex<Vec<(String, String)>>,
    authorizations: Mutex<Vec<Option<String>>>,
    accepts: Mutex<Vec<Option<String>>>,
    user_agents: Mutex<Vec<Option<String>>>,
}

impl MockState {
    fn new(base_url: String) -> Self {
        Self {
            base_url,
            orgs: Mutex::new(BTreeSet::new()),
            deny: AtomicBool::new(false),
            omit_links: AtomicBool::new(false),
            failure: AtomicU16::new(0),
            next_id: AtomicU64::new(1),
            packages: Mutex::new(BTreeSet::new()),
            versions: Mutex::new(BTreeMap::new()),
            deleted: Mutex::new(Vec::new()),
            requests: Mutex::new(Vec::new()),
            authorizations: Mutex::new(Vec::new()),
            accepts: Mutex::new(Vec::new()),
            user_agents: Mutex::new(Vec::new()),
        }
    }

    fn record(&self, method: &Method, path: &str, headers: &HeaderMap) {
        lock(&self.requests).push((method.as_str().to_string(), path.to_string()));
        lock(&self.authorizations).push(header_value(headers, header::AUTHORIZATION));
        lock(&self.accepts).push(header_value(headers, header::ACCEPT));
        lock(&self.user_agents).push(header_value(headers, header::USER_AGENT));
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|error| error.into_inner())
}

fn header_value(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .map(str::to_string)
}

/// The digest a version's `name` reports; deterministic from its id.
fn digest_for(id: u64) -> String {
    format!("sha256:{id:064x}")
}

fn query_param(query: Option<&str>, name: &str) -> Option<String> {
    url::form_urlencoded::parse(query?.as_bytes())
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
}

/// `(per_page, page)` from the query, GitHub's defaults and ceiling applied.
fn page_params(query: Option<&str>) -> (usize, usize) {
    let limit = query_param(query, "per_page")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(30)
        .clamp(1, 100);
    let page = query_param(query, "page")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(1)
        .max(1);
    (limit, page)
}

fn link_header(state: &MockState, path: &str, limit: usize, page: usize) -> Option<String> {
    if state.omit_links.load(Ordering::SeqCst) {
        return None;
    }
    Some(format!(
        "<{}{}?per_page={limit}&page={}>; rel=\"next\"",
        state.base_url,
        path,
        page + 1
    ))
}

/// Split a raw path into percent-decoded segments.
fn segments(path: &str) -> Vec<String> {
    path.trim_start_matches('/')
        .split('/')
        .map(|segment| percent_decode_str(segment).decode_utf8_lossy().into_owned())
        .collect()
}

async fn api(
    State(state): State<Arc<MockState>>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
) -> Response {
    let path = uri.path();
    state.record(&method, path, &headers);

    if state.deny.load(Ordering::SeqCst) {
        let echo = header_value(&headers, header::AUTHORIZATION).unwrap_or_default();
        return (StatusCode::FORBIDDEN, format!("Authorization: {echo}\n")).into_response();
    }

    let failure = state.failure.load(Ordering::SeqCst);
    if failure != 0 {
        return (
            StatusCode::from_u16(failure).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            "injected failure",
        )
            .into_response();
    }

    let parts = segments(path);
    let Some(kind) = parts.first().map(String::as_str) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if kind != "users" && kind != "orgs" {
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some(owner) = parts.get(1) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    // A user owner has no `/orgs/` route and an organisation no `/users/` one.
    let org_owner = lock(&state.orgs).contains(owner.as_str());
    if (kind == "users") == org_owner {
        return StatusCode::NOT_FOUND.into_response();
    }
    if parts.len() < 3 || parts[2] != "packages" {
        return StatusCode::NOT_FOUND.into_response();
    }

    if parts.len() == 3 {
        return match method {
            Method::GET => catalogue(&state, uri.query(), path),
            _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        };
    }

    if parts.len() < 6 || parts[3] != "container" {
        return StatusCode::NOT_FOUND.into_response();
    }
    let package = parts[4].as_str();

    match (parts.len(), parts.get(5).map(String::as_str)) {
        (6, Some("versions")) => match method {
            Method::GET => versions(&state, package, uri.query(), path),
            _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        },
        (7, Some("versions")) => match method {
            Method::DELETE => {
                let id = parts[6].parse::<u64>().ok();
                match id {
                    Some(id) => delete(&state, package, id),
                    None => StatusCode::NOT_FOUND.into_response(),
                }
            }
            _ => StatusCode::METHOD_NOT_ALLOWED.into_response(),
        },
        _ => StatusCode::NOT_FOUND.into_response(),
    }
}

fn catalogue(state: &Arc<MockState>, query: Option<&str>, path: &str) -> Response {
    let packages = lock(&state.packages)
        .iter()
        .cloned()
        .collect::<Vec<String>>();
    let (limit, page) = page_params(query);
    let start = (page - 1) * limit;
    let slice = packages.iter().skip(start).take(limit);
    let items: Vec<Value> = slice
        .map(|name| json!({"name": name, "package_type": "container"}))
        .collect();
    let more = packages.len() > start + items.len();

    let mut response = axum::Json(Value::Array(items)).into_response();
    if more {
        if let Some(link) = link_header(state, path, limit, page) {
            if let Ok(value) = link.parse() {
                response.headers_mut().insert(header::LINK, value);
            }
        }
    }
    response
}

fn versions(state: &Arc<MockState>, package: &str, query: Option<&str>, path: &str) -> Response {
    let mut seeded = lock(&state.versions)
        .get(package)
        .cloned()
        .unwrap_or_default();
    if seeded.is_empty() && !lock(&state.packages).contains(package) {
        return StatusCode::NOT_FOUND.into_response();
    }

    // GitHub answers newest first.
    seeded.sort_by_key(|version| Reverse(version.id));

    let (limit, page) = page_params(query);
    let start = (page - 1) * limit;
    let slice = seeded.iter().skip(start).take(limit);
    let items: Vec<Value> = slice
        .map(|version| {
            json!({
                "id": version.id,
                "name": digest_for(version.id),
                "metadata": {"container": {"tags": version.tags}},
                "created_at": version.created,
            })
        })
        .collect();
    let more = seeded.len() > start + items.len();

    let mut response = axum::Json(Value::Array(items)).into_response();
    if more {
        if let Some(link) = link_header(state, path, limit, page) {
            if let Ok(value) = link.parse() {
                response.headers_mut().insert(header::LINK, value);
            }
        }
    }
    response
}

fn delete(state: &Arc<MockState>, package: &str, id: u64) -> Response {
    let mut versions = lock(&state.versions);

    // Version ids are unique across the owner, so a test may seed the version
    // in a package other than the client's.
    let holder = match versions.get_mut(package) {
        Some(list) if list.iter().any(|version| version.id == id) => Some(package.to_string()),
        _ => versions
            .iter()
            .find(|(_, list)| list.iter().any(|version| version.id == id))
            .map(|(name, _)| name.clone()),
    };
    let Some(holder) = holder else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let Some(list) = versions.get_mut(&holder) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    list.retain(|version| version.id != id);
    drop(versions);

    lock(&state.deleted).push(id);
    StatusCode::NO_CONTENT.into_response()
}

/// A running mock packages API on a loopback port.
pub struct MockPackages {
    base_url: String,
    state: Arc<MockState>,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for MockPackages {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl MockPackages {
    /// Start a mock on a free loopback port.
    pub async fn start() -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind mock packages api");
        let address = listener.local_addr().expect("local address");
        let base_url = format!("http://{address}");
        let state = Arc::new(MockState::new(base_url.clone()));

        let app = Router::new()
            .route("/users/*rest", any(api))
            .route("/orgs/*rest", any(api))
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

    /// Base URL of the mock, as handed to the client.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// Treat `owner` as an organisation.
    ///
    /// Unmarked owners are users, and each owner only answers under its own
    /// route: `/users/` `404`s for an organisation, `/orgs/` for a user.
    pub fn owner_is_org(&self, owner: &str) {
        lock(&self.state.orgs).insert(owner.to_string());
    }

    /// Answer `403` to every request, echoing the `Authorization` header.
    pub fn deny(&self) {
        self.state.deny.store(true, Ordering::SeqCst);
    }

    /// Stop sending `Link` headers, so only client-side paging advances.
    pub fn omit_links(&self) {
        self.state.omit_links.store(true, Ordering::SeqCst);
    }

    /// Answer every request with `status`.
    pub fn fail_with(&self, status: u16) {
        self.state.failure.store(status, Ordering::SeqCst);
    }

    /// Register a package without any version.
    pub fn add_package(&self, package: &str) {
        lock(&self.state.packages).insert(package.to_string());
    }

    /// Store a version of `package`; returns its id.
    pub fn seed_version(&self, package: &str, tags: &[&str], created: DateTime<Utc>) -> u64 {
        self.seed_version_raw(package, tags, Some(&created.to_rfc3339()))
    }

    /// Store a version with the raw `created_at` string GitHub would send.
    pub fn seed_version_raw(&self, package: &str, tags: &[&str], created: Option<&str>) -> u64 {
        let id = self.state.next_id.fetch_add(1, Ordering::SeqCst);
        lock(&self.state.packages).insert(package.to_string());
        lock(&self.state.versions)
            .entry(package.to_string())
            .or_default()
            .push(SeededVersion {
                id,
                created: created.map(str::to_string),
                tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
            });
        id
    }

    /// Tags seeded for `package`, newest version first.
    pub fn versions_for(&self, package: &str) -> Vec<String> {
        let mut seeded = lock(&self.state.versions)
            .get(package)
            .cloned()
            .unwrap_or_default();
        seeded.sort_by_key(|version| Reverse(version.id));
        seeded
            .into_iter()
            .flat_map(|version| version.tags)
            .collect()
    }

    /// Ids of the versions that a `DELETE` actually removed, in arrival order.
    pub fn deleted(&self) -> Vec<u64> {
        lock(&self.state.deleted).clone()
    }

    /// Every `(method, path)` seen, in arrival order.
    pub fn request_log(&self) -> Vec<(String, String)> {
        lock(&self.state.requests).clone()
    }

    /// `Authorization` header of every request, in arrival order.
    pub fn authorizations(&self) -> Vec<Option<String>> {
        lock(&self.state.authorizations).clone()
    }

    /// `Accept` header of every request, in arrival order.
    pub fn accepts(&self) -> Vec<Option<String>> {
        lock(&self.state.accepts).clone()
    }

    /// `User-Agent` header of every request, in arrival order.
    pub fn user_agents(&self) -> Vec<Option<String>> {
        lock(&self.state.user_agents).clone()
    }
}
