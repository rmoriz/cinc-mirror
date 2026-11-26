//! GitHub Packages API client tests.
//!
//! Every test talks to the in-memory API in `tests/common/packages.rs` and
//! asserts what crossed the wire: the encoded package path, the bearer
//! credential, the `Accept` header and the pages requested. GHCR answers `405`
//! to the distribution spec's own `DELETE`, so this client is the only deletion
//! route there.

mod common;

use chrono::{TimeZone, Utc};
use cinc_mirror::packages_api::{OwnerKind, PackagesClient, PruneError};
use common::packages::MockPackages;

const OWNER: &str = "rmoriz";
const PACKAGE: &str = "cinc-mirror/cinc";
const ENCODED_PACKAGE: &str = "cinc-mirror%2Fcinc";
const TOKEN: &str = "ghp_test_token_value";

fn client(mock: &MockPackages) -> PackagesClient {
    PackagesClient::new(mock.base_url(), OWNER, PACKAGE, TOKEN.to_string()).expect("client")
}

fn sorted(mut values: Vec<u64>) -> Vec<u64> {
    values.sort_unstable();
    values
}

#[tokio::test]
async fn versions_are_paged_until_a_short_page() {
    let mock = MockPackages::start().await;
    let mut ids = Vec::new();
    for index in 0..150 {
        ids.push(mock.seed_version(PACKAGE, &[&format!("tag-{index}")], Utc::now()));
    }

    let versions = client(&mock).versions().await.expect("list");

    assert_eq!(versions.len(), 150);
    assert_eq!(
        sorted(versions.iter().map(|version| version.id).collect()),
        sorted(ids)
    );
    // The probe plus the two version pages; GitHub's `Link` and the page
    // counter both name page 2, so this also proves the extra page is asked for.
    assert_eq!(mock.request_log().len(), 3);
    // The digest is GitHub's version name and the tags come from the metadata.
    assert!(versions[0].digest.starts_with("sha256:"));
    assert_eq!(versions[0].tags.len(), 1);
}

#[tokio::test]
async fn paging_advances_without_a_link_header() {
    let mock = MockPackages::start().await;
    mock.omit_links();
    for index in 0..105 {
        mock.seed_version(PACKAGE, &[&format!("tag-{index}")], Utc::now());
    }

    let versions = client(&mock).versions().await.expect("list");

    assert_eq!(versions.len(), 105);
    // The probe is the first request and shares the route; the listing follows.
    let pages: Vec<String> = mock
        .request_log()
        .into_iter()
        .skip(1)
        .filter(|(_, path)| path.ends_with("/versions"))
        .map(|(_, path)| path)
        .collect();
    assert_eq!(pages.len(), 2, "a full page must advance: {pages:?}");
}

#[tokio::test]
async fn requests_carry_the_encoded_package_and_the_github_headers() {
    let mock = MockPackages::start().await;
    mock.seed_version(PACKAGE, &["19.4.46"], Utc::now());

    client(&mock).versions().await.expect("list");

    let log = mock.request_log();
    assert!(
        log.iter().all(|(_, path)| path.contains(ENCODED_PACKAGE)),
        "the package must travel as one encoded segment: {log:?}"
    );
    assert_eq!(
        mock.authorizations()[0].as_deref(),
        Some(format!("Bearer {TOKEN}").as_str())
    );
    assert_eq!(
        mock.accepts()[0].as_deref(),
        Some("application/vnd.github+json")
    );
    assert_eq!(mock.user_agents()[0].as_deref(), Some("cinc-mirror"));
}

#[tokio::test]
async fn a_user_404_falls_back_to_orgs_and_the_probe_is_cached() {
    let mock = MockPackages::start().await;
    mock.owner_is_org();
    mock.seed_version(PACKAGE, &["19.4.46"], Utc::now());
    let client = client(&mock);

    assert_eq!(client.owner_kind().await.expect("probe"), OwnerKind::Org);
    assert_eq!(client.versions().await.expect("list").len(), 1);
    assert_eq!(client.owner_kind().await.expect("cached"), OwnerKind::Org);

    let log = mock.request_log();
    let users = log
        .iter()
        .filter(|(_, path)| path.starts_with("/users/"))
        .count();
    assert_eq!(users, 1, "the owner form is probed once: {log:?}");
    // Every real call after the probe uses the organisation route.
    assert!(
        log.iter()
            .skip(1)
            .all(|(_, path)| path.starts_with("/orgs/")),
        "{log:?}"
    );
}

#[tokio::test]
async fn a_missing_package_lists_nothing() {
    // The owner exists but has no such package: `/users/` 404s on the probe and
    // the organisation route 404s on the versions.
    let org_owner = MockPackages::start().await;
    org_owner.owner_is_org();
    assert!(client(&org_owner)
        .versions()
        .await
        .expect("empty")
        .is_empty());

    // Neither route knows the owner at all.
    let unknown = MockPackages::start().await;
    assert!(client(&unknown).versions().await.expect("empty").is_empty());
}

#[tokio::test]
async fn a_403_on_the_probe_is_denied() {
    let mock = MockPackages::start().await;
    mock.deny();

    let error = client(&mock).versions().await.unwrap_err();

    assert!(matches!(error, PruneError::Denied { .. }), "{error}");
    assert_eq!(mock.request_log().len(), 1, "no fallback after a 403");
}

#[tokio::test]
async fn a_403_on_delete_is_denied() {
    let mock = MockPackages::start().await;
    let id = mock.seed_version(PACKAGE, &["19.4.46"], Utc::now());
    let client = client(&mock);
    client.owner_kind().await.expect("probe");
    mock.deny();

    let error = client.delete(id).await.unwrap_err();

    assert!(matches!(error, PruneError::Denied { .. }), "{error}");
}

#[tokio::test]
async fn a_403_on_the_catalogue_is_denied() {
    let mock = MockPackages::start().await;
    let client = client(&mock);
    client.owner_kind().await.expect("probe");
    mock.deny();

    let error = client.packages().await.unwrap_err();

    assert!(matches!(error, PruneError::Denied { .. }), "{error}");
}

#[tokio::test]
async fn deleting_an_unknown_version_is_success() {
    let mock = MockPackages::start().await;
    mock.add_package(PACKAGE);

    client(&mock).delete(9_999).await.expect("404 is success");

    assert!(mock.deleted().is_empty());
}

#[tokio::test]
async fn deleting_a_version_removes_it() {
    let mock = MockPackages::start().await;
    let keep = mock.seed_version(PACKAGE, &["19.4.46"], Utc::now());
    let drop = mock.seed_version(PACKAGE, &["19.4.47"], Utc::now());
    let client = client(&mock);

    client.delete(drop).await.expect("delete");

    assert_eq!(mock.deleted(), vec![drop]);
    assert_eq!(mock.versions_for(PACKAGE), vec!["19.4.46".to_string()]);
    let remaining = client.versions().await.expect("list");
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].id, keep);
}

#[tokio::test]
async fn a_server_error_is_a_list_failure() {
    let mock = MockPackages::start().await;
    mock.seed_version(PACKAGE, &["19.4.46"], Utc::now());
    let client = client(&mock);
    client.owner_kind().await.expect("probe");
    mock.fail_with(500);

    let error = client.versions().await.unwrap_err();

    match &error {
        PruneError::List { source, .. } => {
            assert!(source.to_string().contains("500"), "{error}");
        }
        other => panic!("expected a list failure, got {other}"),
    }
}

#[tokio::test]
async fn a_405_is_unsupported() {
    let mock = MockPackages::start().await;
    mock.seed_version(PACKAGE, &["19.4.46"], Utc::now());
    let client = client(&mock);
    client.owner_kind().await.expect("probe");
    mock.fail_with(405);

    let error = client.versions().await.unwrap_err();

    assert!(matches!(error, PruneError::Unsupported { .. }), "{error}");
}

#[tokio::test]
async fn a_transport_failure_is_reported() {
    // Port 1 is reserved and closed, so the connection is refused.
    let client = PackagesClient::new("http://127.0.0.1:1", OWNER, PACKAGE, TOKEN.to_string())
        .expect("client");

    let error = client.versions().await.unwrap_err();

    assert!(matches!(error, PruneError::Transport { .. }), "{error}");
}

#[tokio::test]
async fn the_token_never_reaches_a_formatted_error() {
    let mock = MockPackages::start().await;
    mock.seed_version(PACKAGE, &["19.4.46"], Utc::now());
    mock.deny();

    let error = client(&mock).versions().await.unwrap_err();
    let text = format!("{error} {error:?}");

    assert!(!text.contains(TOKEN), "{text}");
    assert!(text.contains("***"), "{text}");
}

#[tokio::test]
async fn a_missing_or_broken_created_at_falls_back_to_now() {
    let mock = MockPackages::start().await;
    mock.seed_version_raw(PACKAGE, &["dated"], Some("2001-02-03T04:05:06Z"));
    mock.seed_version_raw(PACKAGE, &["broken"], Some("not a timestamp"));
    mock.seed_version_raw(PACKAGE, &["absent"], None);
    let before = Utc::now();

    let versions = client(&mock).versions().await.expect("list");
    let created = |tag: &str| {
        versions
            .iter()
            .find(|version| version.tags == [tag.to_string()])
            .expect("seeded tag")
            .created_at
    };

    assert_eq!(
        created("dated"),
        Utc.with_ymd_and_hms(2001, 2, 3, 4, 5, 6).unwrap()
    );
    assert!(created("broken") >= before, "malformed stamp is replaced");
    assert!(created("absent") >= before, "absent stamp is replaced");
}

#[tokio::test]
async fn the_catalogue_is_paged_and_listed() {
    let mock = MockPackages::start().await;
    for index in 0..120 {
        mock.add_package(&format!("cinc-mirror/project-{index:03}"));
    }

    let packages = client(&mock).packages().await.expect("catalogue");

    assert_eq!(packages.len(), 120);
    assert!(packages.contains(&"cinc-mirror/project-000".to_string()));
    assert!(packages.contains(&"cinc-mirror/project-119".to_string()));
}

#[test]
fn construction_rejects_the_unusable() {
    let config = |base: &str, owner: &str, package: &str, token: &str| {
        PackagesClient::new(base, owner, package, token.to_string())
    };

    assert!(matches!(
        config("http://127.0.0.1:1", "", PACKAGE, TOKEN),
        Err(PruneError::Config { .. })
    ));
    assert!(matches!(
        config("http://127.0.0.1:1", OWNER, "", TOKEN),
        Err(PruneError::Config { .. })
    ));
    assert!(matches!(
        config("http://127.0.0.1:1", OWNER, PACKAGE, ""),
        Err(PruneError::Config { .. })
    ));
    assert!(matches!(
        config("not a url", OWNER, PACKAGE, TOKEN),
        Err(PruneError::Config { .. })
    ));
    assert!(matches!(
        config("ftp://127.0.0.1/", OWNER, PACKAGE, TOKEN),
        Err(PruneError::Config { .. })
    ));
    assert!(config("http://127.0.0.1:1", OWNER, PACKAGE, TOKEN).is_ok());
}
