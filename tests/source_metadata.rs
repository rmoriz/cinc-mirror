//! HTTPS metadata client tests.
//!
//! Metadata is the digest source of truth, so a cleartext fetch must never
//! happen and a document without a `sha256` must not produce an artifact. The
//! fixture mirrors the real upstream document, including fields the mirror
//! ignores and the numeric `iteration`.

use cinc_mirror::config::TransportKind;
use cinc_mirror::source::metadata::{Metadata, MetadataError};
use cinc_mirror::source::{Source, SourceConfig, SourceError};
use url::Url;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The real `cinc_19.4.46-1_amd64.deb.metadata.json`, reduced to one plausible
/// line per field. Unknown fields are kept on purpose: upstream publishes many
/// more and the client must tolerate them.
const METADATA: &str = r#"{
  "basename": "cinc_19.4.46-1_amd64.deb",
  "md5": "33db1d1be1d5cd535d8b7dcfd2ec7ee0",
  "sha1": "c6d023b4f8fc5097e5a44625e639d1adfa4d1c04",
  "sha256": "83ad6e1b905a348909e1f312bc4f2f5061c566469a4ec77b041746378975d2a9",
  "sha512": "cdbbdd1d4be7454adc4c819dd5a0cb9d499b46913b7f4eb00910199d880632114006230221acfeea17b8f59da9bf62c00987d444bab3004b3e62914df292992a",
  "platform": "debian",
  "platform_version": "13",
  "arch": "x86_64",
  "name": "cinc",
  "friendly_name": "Cinc Client",
  "homepage": "https://www.cinc.sh",
  "version": "19.4.46",
  "iteration": 2,
  "license": "Apache-2.0"
}"#;

const METADATA_PATH: &str = "stable/cinc/19.4.46/debian/13/cinc_19.4.46-1_amd64.deb.metadata.json";

fn source_config(base: &str) -> SourceConfig {
    SourceConfig {
        https_base: Url::parse(base).expect("base url"),
        ftp_host: "ftp.osuosl.org".to_string(),
        ftp_port: 21,
        ftp_base_path: "pub/cinc/files".to_string(),
        transports: vec![TransportKind::Https],
    }
}

#[test]
fn metadata_parses_required_fields() {
    let metadata = Metadata::from_json(METADATA).expect("valid metadata");

    assert_eq!(metadata.basename, "cinc_19.4.46-1_amd64.deb");
    assert_eq!(
        metadata.sha256,
        "83ad6e1b905a348909e1f312bc4f2f5061c566469a4ec77b041746378975d2a9"
    );
    assert_eq!(metadata.platform, "debian");
    assert_eq!(metadata.platform_version, "13");
    assert_eq!(metadata.arch, "x86_64");
    assert_eq!(metadata.version, "19.4.46");
    assert_eq!(metadata.iteration.as_deref(), Some("2"));
}

#[test]
fn metadata_maps_to_artifact_input() {
    let input = Metadata::from_json(METADATA)
        .expect("valid metadata")
        .to_input();

    assert_eq!(input.basename, "cinc_19.4.46-1_amd64.deb");
    assert_eq!(
        input.sha256,
        "83ad6e1b905a348909e1f312bc4f2f5061c566469a4ec77b041746378975d2a9"
    );
    assert_eq!(input.platform, "debian");
    assert_eq!(input.platform_version, "13");
    assert_eq!(input.version, "19.4.46");
    assert_eq!(input.iteration.as_deref(), Some("2"));
    assert_eq!(input.raw_arch, "x86_64");
}

#[test]
fn metadata_missing_sha256_is_an_error() {
    let mut document: serde_json::Value = serde_json::from_str(METADATA).expect("json");
    document.as_object_mut().expect("object").remove("sha256");

    let error = Metadata::from_json(&document.to_string()).expect_err("sha256 is required");

    assert_eq!(error, MetadataError::MissingField("sha256"));
}

#[tokio::test]
async fn rejects_a_cleartext_metadata_request() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(METADATA))
        .mount(&server)
        .await;

    let source = Source::new(&source_config(&server.uri())).expect("source");
    let error = source
        .metadata(METADATA_PATH)
        .await
        .expect_err("a cleartext metadata fetch must be refused");

    assert!(
        matches!(error, SourceError::Insecure { .. }),
        "unexpected error: {error:?}"
    );
    assert!(
        server
            .received_requests()
            .await
            .unwrap_or_default()
            .is_empty(),
        "no request may leave the process for a cleartext URL"
    );
}
