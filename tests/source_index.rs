//! HTTPS directory index tests.
//!
//! The line between "a listing we can trust" and "a page that merely looks like
//! one" is narrow: the real upstream autoindex is wrapped in OSU OSL navigation,
//! sort links and a `Parent Directory` link that points at an absolute path.
//! These tests pin the two behaviours that matter — which entries survive the
//! scan, and that a cleartext URL is refused before any request is sent.

use cinc_mirror::config::TransportKind;
use cinc_mirror::source::index::{parse_index, IndexEntry};
use cinc_mirror::source::{Source, SourceConfig, SourceError};
use url::Url;
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

/// A representative slice of the real Apache autoindex served by
/// `downloads.cinc.sh`: OSU OSL navigation, the `<link>` header, sort links, an
/// absolute `Parent Directory` and a directory/file mix.
const LISTING: &str = r#"<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html><head>
  <link rel="stylesheet" type="text/css" media="screen" href="/header-inc/style.css">
</head><body id="others">
  <ul id="tabnav">
    <li><a href="https://ftp.osuosl.org/pub/">Others</a></li>
    <li><a href="https://ftp2.osuosl.org/pub/">Ftp2</a></li>
  </ul>
  <table>
   <tr><th><a href="?C=N;O=D">Name</a></th><th><a href="?C=M;O=A">Last modified</a></th></tr>
<tr><td><a href="/files/stable/cinc/">Parent Directory</a></td></tr>
<tr><td><a href="19.4.46/">19.4.46/</a></td></tr>
<tr><td><a href="19.3.14/">19.3.14/</a></td></tr>
<tr><td><a href="cinc_19.4.46-1_amd64.deb">cinc_19.4.46-1_amd64.deb</a></td></tr>
<tr><td><a href="cinc_19.4.46-1_amd64.deb.metadata.json">cinc_19.4.46-1_amd64.deb.metadata.json</a></td></tr>
  </table>
</body></html>
"#;

fn entry(name: &str, is_dir: bool) -> IndexEntry {
    IndexEntry {
        name: name.to_string(),
        is_dir,
    }
}

fn source_config(base: &str) -> SourceConfig {
    SourceConfig {
        https_base: Url::parse(base).expect("base url"),
        ftp_host: "ftp.osuosl.org".to_string(),
        ftp_port: 21,
        ftp_base_path: "pub/cinc/files".to_string(),
        transports: vec![TransportKind::Https],
    }
}

// Parsing -------------------------------------------------------------------

#[test]
fn parses_apache_autoindex() {
    assert_eq!(
        parse_index(LISTING),
        vec![
            entry("19.4.46", true),
            entry("19.3.14", true),
            entry("cinc_19.4.46-1_amd64.deb", false),
            entry("cinc_19.4.46-1_amd64.deb.metadata.json", false),
        ]
    );
}

#[test]
fn ignores_sort_links_parent_and_absolute_hrefs() {
    let entries = parse_index(LISTING);
    let names: Vec<&str> = entries.iter().map(|entry| entry.name.as_str()).collect();

    assert_eq!(names.len(), 4, "only real entries survive: {names:?}");
    for unwanted in [
        "Name",
        "Last modified",
        "Parent Directory",
        "Others",
        "Ftp2",
        "?C=N;O=D",
        "style.css",
    ] {
        assert!(
            !names.contains(&unwanted),
            "`{unwanted}` must not be treated as a listing entry"
        );
    }
}

#[test]
fn drops_traversal_and_foreign_urls() {
    let html = concat!(
        r#"<a href="../">..</a>"#,
        r#"<a href="./">.</a>"#,
        r#"<a href="%2E%2E/">..</a>"#,
        r#"<a href="http://evil.example/x.deb">x</a>"#,
        r#"<a href="//evil.example/x.deb">x</a>"#,
        r#"<a href="nested%2Ffile.deb">n</a>"#,
        r#"<a href="keep.deb">keep</a>"#,
    );

    assert_eq!(parse_index(html), vec![entry("keep.deb", false)]);
}

#[test]
fn decodes_percent_encoded_names() {
    assert_eq!(
        parse_index(r#"<a href="cinc%20client%2Bdebug.deb">x</a>"#),
        vec![entry("cinc client+debug.deb", false)]
    );
}

// HTTPS enforcement ---------------------------------------------------------

#[tokio::test]
async fn rejects_a_cleartext_listing_before_sending_anything() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_string(LISTING))
        .mount(&server)
        .await;

    let source = Source::new(&source_config(&server.uri())).expect("source");
    let error = source
        .list("stable/cinc")
        .await
        .expect_err("a cleartext listing must be refused");

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
