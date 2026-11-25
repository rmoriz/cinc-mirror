//! OCI distribution client tests.
//!
//! Every test runs against the in-memory registry in `tests/common/registry.rs`
//! and asserts what crossed the wire: the bearer challenge and token exchange,
//! token reuse, the number of `PATCH` requests for a 10 MiB layer, the exact
//! bytes the registry stored, and the manifest digest the client returned.

mod common;

use std::ffi::OsString;
use std::sync::{Mutex, MutexGuard};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;
use cinc_mirror::config::{TargetAuth, TargetConfig, TargetKind};
use cinc_mirror::oci::{AuthError, HttpFailure, OciAuth, OciConfig, OciError, Registry};
use common::registry::{MockAuth, MockRegistry};
use serde_json::json;
use sha2::{Digest, Sha256};

/// Serialises tests that change process-wide environment variables.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn lock_env() -> MutexGuard<'static, ()> {
    ENV_LOCK.lock().unwrap_or_else(|error| error.into_inner())
}

/// Sets an environment variable and restores the previous value on drop.
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
}

impl Drop for EnvVar {
    fn drop(&mut self) {
        match &self.previous {
            Some(value) => std::env::set_var(self.key, value),
            None => std::env::remove_var(self.key),
        }
    }
}

const REPO: &str = "cinc-mirror/cinc";

fn registry_for(mock: &MockRegistry, auth: OciAuth) -> Registry {
    Registry::new(OciConfig {
        registry: mock.registry_name(),
        namespace: "cinc-mirror".to_string(),
        auth,
        insecure_http: true,
        ..OciConfig::default()
    })
    .expect("mock registry")
    // The production backoff is 0.5/1/2 s; the tests assert counts, not waits.
    .with_retry_base(Duration::ZERO)
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

fn write_layer(bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("layer.bin");
    std::fs::write(&path, bytes).expect("write layer");
    (dir, path)
}

#[tokio::test]
async fn anonymous_pull_uses_token_endpoint() {
    let mock = MockRegistry::start(MockAuth::Bearer).await;
    let digest = mock.put_blob(REPO, b"verified layer bytes");
    let registry = registry_for(&mock, OciAuth::Anonymous);

    assert!(
        registry.head_blob(REPO, &digest).await.expect("head blob"),
        "the preloaded blob must be found after the token exchange"
    );

    assert_eq!(
        mock.token_requests(),
        1,
        "the 401 must trigger one token fetch"
    );
    let scopes = mock.token_scopes();
    assert!(
        scopes[0].contains(&format!("repository:{REPO}:pull")),
        "unexpected token scope: {:?}",
        scopes[0]
    );
    assert!(
        mock.authorizations()
            .iter()
            .flatten()
            .any(|header| header.starts_with("Bearer mock-token-")),
        "the retried request must carry the issued bearer token: {:?}",
        mock.authorizations()
    );
}

#[tokio::test]
// The guard serialises the whole test, including its awaits: the environment is
// process-wide and several tests change it.
#[allow(clippy::await_holding_lock)]
async fn docker_config_credentials_are_used() {
    let _guard = lock_env();
    let mock = MockRegistry::start(MockAuth::BearerWithBasic {
        user: "alice".to_string(),
        password: "s3cret".to_string(),
    })
    .await;

    let dir = tempfile::tempdir().expect("temp dir");
    let auth = BASE64.encode("alice:s3cret");
    std::fs::write(
        dir.path().join("config.json"),
        json!({"auths": { mock.registry_name(): { "auth": auth } }}).to_string(),
    )
    .expect("write docker config");
    let _config = EnvVar::set(
        "DOCKER_CONFIG",
        dir.path().to_str().expect("utf-8 temp path"),
    );

    let registry = registry_for(&mock, OciAuth::Docker);
    let digest = mock.put_blob(REPO, b"layer");

    assert!(
        registry.head_blob(REPO, &digest).await.expect("head blob"),
        "the credentials from the docker config must authenticate the token request"
    );

    let expected = format!("Basic {}", BASE64.encode("alice:s3cret"));
    assert_eq!(
        mock.token_basic_headers()[0].as_deref(),
        Some(expected.as_str()),
        "the token request must carry the docker-config credentials"
    );
}

#[tokio::test]
async fn basic_credentials_authenticate_the_token_request() {
    let mock = MockRegistry::start(MockAuth::BearerWithBasic {
        user: "bob".to_string(),
        password: "hunter2".to_string(),
    })
    .await;
    let digest = mock.put_blob(REPO, b"layer");
    let registry = registry_for(
        &mock,
        OciAuth::Basic {
            username: "bob".to_string(),
            password: "hunter2".to_string(),
        },
    );

    assert!(registry.head_blob(REPO, &digest).await.expect("head blob"));

    let expected = format!("Basic {}", BASE64.encode("bob:hunter2"));
    assert_eq!(
        mock.token_basic_headers()[0].as_deref(),
        Some(expected.as_str())
    );
}

#[tokio::test]
async fn preissued_bearer_token_is_sent_without_a_challenge() {
    let mock = MockRegistry::start(MockAuth::Bearer).await;
    mock.allow_token("preissued");
    let digest = mock.put_blob(REPO, b"layer");
    let registry = registry_for(
        &mock,
        OciAuth::Bearer {
            token: "preissued".to_string(),
        },
    );

    assert!(registry.head_blob(REPO, &digest).await.expect("head blob"));

    assert_eq!(
        mock.token_requests(),
        0,
        "a pre-issued token must not be exchanged again"
    );
    assert!(mock
        .authorizations()
        .iter()
        .flatten()
        .any(|header| header == "Bearer preissued"));
}

#[tokio::test]
async fn upload_streams_without_buffering_whole_file() {
    let mock = MockRegistry::start(MockAuth::Bearer).await;
    let registry = registry_for(&mock, OciAuth::Anonymous);

    let bytes: Vec<u8> = (0..10 * 1024 * 1024)
        .map(|index| (index % 251) as u8)
        .collect();
    let digest = sha256_digest(&bytes);
    let (_dir, path) = write_layer(&bytes);

    registry
        .upload_blob(REPO, &path, &digest)
        .await
        .expect("upload");

    assert!(
        mock.patch_count() > 1,
        "a 10 MiB layer must arrive in more than one PATCH, got {}",
        mock.patch_count()
    );
    let sizes = mock.patch_sizes();
    assert_eq!(
        sizes.iter().sum::<usize>(),
        bytes.len(),
        "the chunks must sum to the layer size: {sizes:?}"
    );
    assert!(
        sizes.iter().all(|size| *size <= 4 * 1024 * 1024),
        "no chunk may exceed the streaming buffer: {sizes:?}"
    );
    assert_eq!(
        mock.blob(REPO, &digest).as_deref(),
        Some(bytes.as_slice()),
        "the registry must hold the exact file bytes"
    );
    assert_eq!(mock.upload_starts(), 1);
    assert_eq!(mock.upload_completes(), 1);
}

#[tokio::test]
async fn upload_of_an_empty_layer_finalises_without_a_patch() {
    let mock = MockRegistry::start(MockAuth::Bearer).await;
    let registry = registry_for(&mock, OciAuth::Anonymous);
    let digest = sha256_digest(b"");
    let (_dir, path) = write_layer(b"");

    registry
        .upload_blob(REPO, &path, &digest)
        .await
        .expect("upload");

    assert_eq!(mock.patch_count(), 0);
    assert_eq!(mock.upload_completes(), 1);
    assert_eq!(mock.blob(REPO, &digest), Some(Vec::new()));
}

#[tokio::test]
async fn a_stalled_patch_times_out_instead_of_hanging() {
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    mock.stall_patches_for(Duration::from_secs(30));

    let registry = Registry::new(OciConfig {
        registry: mock.registry_name(),
        namespace: "cinc-mirror".to_string(),
        auth: OciAuth::Anonymous,
        insecure_http: true,
        request_timeout: Duration::from_millis(100),
        idle_read_timeout: Duration::from_millis(50),
    })
    .expect("mock registry")
    .with_retry_base(Duration::ZERO);

    let bytes: Vec<u8> = (0..8 * 1024 * 1024)
        .map(|index| (index % 251) as u8)
        .collect();
    let digest = sha256_digest(&bytes);
    let (_dir, path) = write_layer(&bytes);

    let started = Instant::now();
    let error = registry
        .upload_blob(REPO, &path, &digest)
        .await
        .expect_err("the stall must surface as an error, not hang");
    let elapsed = started.elapsed();

    assert!(error.is_retryable(), "a timeout must retry, got {error:?}");
    match &error {
        OciError::Http {
            source: HttpFailure::Timeout { .. },
            ..
        } => {}
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(
        elapsed < Duration::from_secs(3),
        "the client hung for {elapsed:?}"
    );
    assert_eq!(
        mock.upload_starts(),
        4,
        "the whole upload session retries four times"
    );
    assert_eq!(mock.patch_count(), 4, "one timed-out PATCH per attempt");
    assert_eq!(mock.upload_completes(), 0);
}

#[tokio::test]
async fn a_stalled_patch_response_body_hits_the_idle_read_timeout() {
    let mock = MockRegistry::start(MockAuth::Anonymous).await;
    mock.stall_patch_bodies_for(Duration::from_secs(30));

    let registry = Registry::new(OciConfig {
        registry: mock.registry_name(),
        namespace: "cinc-mirror".to_string(),
        auth: OciAuth::Anonymous,
        insecure_http: true,
        // Generous request budget so the per-read budget is what fires.
        request_timeout: Duration::from_secs(5),
        idle_read_timeout: Duration::from_millis(50),
    })
    .expect("mock registry")
    .with_retry_base(Duration::ZERO);

    let bytes: Vec<u8> = (0..4 * 1024 * 1024)
        .map(|index| (index % 251) as u8)
        .collect();
    let digest = sha256_digest(&bytes);
    let (_dir, path) = write_layer(&bytes);

    let started = Instant::now();
    let error = registry
        .upload_blob(REPO, &path, &digest)
        .await
        .expect_err("the stalled body must surface as an error, not hang");
    let elapsed = started.elapsed();

    match &error {
        OciError::Http {
            source: HttpFailure::Timeout { waited, phase, .. },
            ..
        } => {
            assert_eq!(*waited, Duration::from_millis(50));
            assert_eq!(*phase, "reading the response body");
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert!(error.is_retryable(), "{error:?}");
    assert!(
        elapsed < Duration::from_secs(3),
        "the client hung for {elapsed:?}"
    );
    assert_eq!(mock.upload_starts(), 4);
}

#[tokio::test]
async fn existing_blob_skips_upload() {
    let mock = MockRegistry::start(MockAuth::Bearer).await;
    let digest = mock.put_blob(REPO, b"already mirrored");
    let registry = registry_for(&mock, OciAuth::Anonymous);

    assert!(registry.head_blob(REPO, &digest).await.expect("head blob"));
    assert_eq!(
        mock.upload_starts(),
        0,
        "a HEAD hit must not start an upload"
    );

    let missing = sha256_digest(b"not there");
    assert!(
        !registry.head_blob(REPO, &missing).await.expect("head blob"),
        "a missing blob reports false so the caller can upload it"
    );
}

#[tokio::test]
async fn manifest_put_returns_digest_and_is_retried_on_5xx() {
    let mock = MockRegistry::start(MockAuth::Bearer).await;
    mock.fail_manifest_puts(2);
    let registry = registry_for(&mock, OciAuth::Anonymous);

    let manifest = json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {"mediaType": "application/vnd.oci.empty.v1+json", "digest": "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a", "size": 2},
        "layers": [
            {"mediaType": "application/octet-stream", "digest": "sha256:aa", "size": 1}
        ]
    });

    let digest = registry
        .put_manifest(REPO, "19.4.46-debian-13-amd64", &manifest)
        .await
        .expect("put manifest");

    let expected = sha256_digest(&serde_json::to_vec(&manifest).expect("serialise"));
    assert_eq!(
        digest, expected,
        "the returned digest is the manifest digest"
    );
    assert_eq!(
        mock.manifest_put_count(),
        3,
        "two 500s then a success means three PUTs"
    );
    let stored = mock
        .manifest(REPO, "19.4.46-debian-13-amd64")
        .expect("stored manifest");
    assert_eq!(
        stored.bytes,
        serde_json::to_vec(&manifest).expect("serialise"),
        "the registry must receive the exact serialised bytes"
    );
}

#[tokio::test]
async fn token_cache_reuses_unexpired_token() {
    let mock = MockRegistry::start(MockAuth::Bearer).await;
    let digest = mock.put_blob(REPO, b"layer");
    let registry = registry_for(&mock, OciAuth::Anonymous);

    for _ in 0..3 {
        assert!(registry.head_blob(REPO, &digest).await.expect("head blob"));
    }

    assert_eq!(
        mock.token_requests(),
        1,
        "the cached token must serve every later request"
    );
}

#[tokio::test]
async fn get_manifest_returns_value_and_digest() {
    let mock = MockRegistry::start(MockAuth::Bearer).await;
    let registry = registry_for(&mock, OciAuth::Anonymous);
    let manifest = json!({
        "schemaVersion": 2,
        "layers": [{"digest": "sha256:aa", "size": 1}]
    });

    let digest = registry
        .put_manifest(REPO, "latest", &manifest)
        .await
        .expect("put manifest");
    let (read, read_digest) = registry.get_manifest(REPO, "latest").await.expect("get");

    assert_eq!(read, manifest);
    assert_eq!(read_digest, digest);
}

#[tokio::test]
async fn package_digest_for_tag_selects_the_package_layer() {
    let mock = MockRegistry::start(MockAuth::Bearer).await;
    let registry = registry_for(&mock, OciAuth::Anonymous);
    let manifest = json!({
        "schemaVersion": 2,
        "layers": [
            {
                "mediaType": "application/json",
                "digest": "sha256:1111",
                "size": 2,
                "annotations": {"org.opencontainers.image.title": "metadata.json"}
            },
            {
                "mediaType": "application/octet-stream",
                "digest": "sha256:2222",
                "size": 3,
                "annotations": {"org.opencontainers.image.title": "cinc_19.4.46-1_amd64.deb"}
            }
        ]
    });

    registry
        .put_manifest(REPO, "19.4.46", &manifest)
        .await
        .expect("put manifest");

    assert_eq!(
        registry
            .package_digest_for_tag(REPO, "19.4.46")
            .await
            .expect("package digest")
            .as_deref(),
        Some("sha256:2222")
    );
    assert_eq!(
        registry
            .package_digest_for_tag(REPO, "missing")
            .await
            .expect("missing tag"),
        None,
        "a missing tag is not an error, it is an absent package"
    );
}

#[tokio::test]
async fn package_digest_falls_back_to_the_first_layer() {
    let mock = MockRegistry::start(MockAuth::Bearer).await;
    let registry = registry_for(&mock, OciAuth::Anonymous);
    let manifest = json!({
        "schemaVersion": 2,
        "layers": [
            {"digest": "sha256:3333", "size": 2},
            {"digest": "sha256:4444", "size": 3}
        ]
    });

    registry
        .put_manifest(REPO, "unannotated", &manifest)
        .await
        .expect("put manifest");

    assert_eq!(
        registry
            .package_digest_for_tag(REPO, "unannotated")
            .await
            .expect("package digest")
            .as_deref(),
        Some("sha256:3333")
    );
}

#[tokio::test]
async fn probe_fetches_push_pull_token_without_writing() {
    let mock = MockRegistry::start(MockAuth::Bearer).await;
    let registry = registry_for(&mock, OciAuth::Anonymous);

    registry.probe().await.expect("probe");

    assert_eq!(mock.token_requests(), 1);
    let scopes = mock.token_scopes();
    assert!(
        scopes[0].contains("push"),
        "the probe must ask for write access: {:?}",
        scopes[0]
    );
    assert!(
        scopes[0].contains("pull"),
        "and read access: {:?}",
        scopes[0]
    );
    assert_eq!(mock.upload_starts(), 0, "a probe must not start an upload");
    assert_eq!(mock.patch_count(), 0, "a probe must not upload any bytes");
    assert_eq!(
        mock.manifest_put_count(),
        0,
        "a probe must not write a manifest"
    );
}

#[tokio::test]
// See `docker_config_credentials_are_used` for why the guard is held across awaits.
#[allow(clippy::await_holding_lock)]
async fn credential_helpers_are_a_typed_error() {
    let _guard = lock_env();
    let mock = MockRegistry::start(MockAuth::Bearer).await;

    let dir = tempfile::tempdir().expect("temp dir");
    std::fs::write(
        dir.path().join("config.json"),
        json!({"credsStore": "desktop"}).to_string(),
    )
    .expect("write docker config");
    let _config = EnvVar::set(
        "DOCKER_CONFIG",
        dir.path().to_str().expect("utf-8 temp path"),
    );

    let registry = registry_for(&mock, OciAuth::Docker);
    let error = registry
        .head_blob(REPO, "sha256:0000")
        .await
        .expect_err("a credential helper cannot be read by this client");

    match error {
        OciError::Auth(AuthError::UnsupportedCredentialHelper { helper, .. }) => {
            assert_eq!(helper, "desktop");
        }
        other => panic!("unexpected error: {other:?}"),
    }
    assert_eq!(
        mock.token_requests(),
        0,
        "no request may be sent before credentials are resolved"
    );
}

#[test]
fn from_target_maps_an_explicit_cleartext_registry() {
    let target = TargetConfig {
        name: "scratch".to_string(),
        kind: TargetKind::Oci,
        enabled: true,
        registry: Some("http://127.0.0.1:5000".to_string()),
        namespace: Some("cinc-mirror".to_string()),
        url: None,
        auth: TargetAuth::Anonymous,
        max_bandwidth: None,
        identity_file: None,
        password_file: None,
    };

    let registry = Registry::from_target(&target, &cinc_mirror::config::Config::default())
        .expect("target registry");

    assert_eq!(registry.registry(), "127.0.0.1:5000");
    assert_eq!(registry.namespace(), "cinc-mirror");
}
