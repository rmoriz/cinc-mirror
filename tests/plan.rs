//! Size resolution and `plan` tests.
//!
//! Sizes are advisory: upstream metadata has no size field, so they come from
//! `MLSD`, `SIZE`, or an HTTPS `HEAD`. These tests pin the fallback ladder with a
//! fake fetcher and one libunftp-backed `SIZE` round trip, then pin the plan
//! totals, grouping, free-space report, projected duration and JSON shape.

mod support;

use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

use async_trait::async_trait;
use cinc_mirror::config::{Config, ProjectPolicy, TargetAuth, TargetConfig, TargetKind};
use cinc_mirror::crawl::crawl;
use cinc_mirror::plan::build;
use cinc_mirror::source::size::parse_mlsd;
use cinc_mirror::source::{Fetched, Fetcher, Source, SourceError};
use cinc_mirror::{ResolvedScope, ScopeArgs};
use url::Url;

const SHA_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const SHA_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const SHA_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const SHA_D: &str = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

const HTTPS_BASE: &str = "https://downloads.cinc.sh/files";

/// A fake HTTPS upstream keyed by the URL path below the base.
///
/// `get` serves bodies, `head_len` serves `Content-Length`, and `seen` records
/// what was asked for so a test can prove which rung of the ladder ran.
struct FakeUpstream {
    pages: HashMap<String, String>,
    lengths: HashMap<String, u64>,
    seen: Mutex<Vec<String>>,
}

impl FakeUpstream {
    fn new(pages: HashMap<String, String>, lengths: HashMap<String, u64>) -> Self {
        Self {
            pages,
            lengths,
            seen: Mutex::new(Vec::new()),
        }
    }

    fn seen(&self) -> Vec<String> {
        self.seen.lock().expect("seen lock").clone()
    }
}

#[async_trait]
impl Fetcher for FakeUpstream {
    async fn get(&self, url: &Url) -> Result<Fetched, SourceError> {
        let key = url.path().trim_start_matches('/').to_string();
        self.seen
            .lock()
            .expect("seen lock")
            .push(format!("GET {key}"));

        match self.pages.get(&key) {
            Some(body) => Ok(Fetched {
                body: body.clone(),
                final_url: url.clone(),
            }),
            None => Err(SourceError::HttpStatus {
                url: url.to_string(),
                status: 404,
            }),
        }
    }

    async fn head_len(&self, url: &Url) -> Result<Option<u64>, SourceError> {
        let key = url.path().trim_start_matches('/').to_string();
        self.seen
            .lock()
            .expect("seen lock")
            .push(format!("HEAD {key}"));
        Ok(self.lengths.get(&key).copied())
    }
}

/// A source over the fake HTTPS upstream and an unreachable FTP host, so every
/// size lookup falls back to HTTPS `HEAD`.
fn source_over(fake: FakeUpstream) -> Source {
    Source::with_fetcher(
        std::sync::Arc::new(fake),
        Url::parse(HTTPS_BASE).expect("base url"),
    )
    .with_ftp("127.0.0.1", 1, "pub/cinc/files")
}

fn listing(entries: &[&str]) -> String {
    let mut body = String::from("<html><body><table>");
    for entry in entries {
        body.push_str(&format!(
            r#"<tr><td><a href="{entry}">{entry}</a></td></tr>"#
        ));
    }
    body.push_str("</table></body></html>");
    body
}

fn metadata(
    basename: &str,
    sha: &str,
    platform: &str,
    platform_version: &str,
    version: &str,
    arch: &str,
) -> String {
    serde_json::json!({
        "basename": basename,
        "sha256": sha,
        "platform": platform,
        "platform_version": platform_version,
        "arch": arch,
        "version": version,
        "iteration": 1,
        "unknown_field": "tolerated",
    })
    .to_string()
}

/// Two versions, two platforms and two architectures, listed out of order.
///
/// Sizes: 1000 (19.4.46/debian/13/amd64), 2000 (19.4.46/debian/13/arm64),
/// 4000 (19.4.46/ubuntu/24.04/amd64), 3000 (19.3.14/debian/12/amd64).
fn fixture() -> FakeUpstream {
    let mut pages = HashMap::new();
    let mut lengths = HashMap::new();

    pages.insert(
        "files/stable/cinc/".to_string(),
        listing(&["19.3.14/", "19.4.46/"]),
    );
    pages.insert(
        "files/stable/cinc/19.4.46/".to_string(),
        listing(&["ubuntu/", "debian/"]),
    );
    pages.insert(
        "files/stable/cinc/19.4.46/debian/".to_string(),
        listing(&["13/"]),
    );
    pages.insert(
        "files/stable/cinc/19.4.46/debian/13/".to_string(),
        listing(&[
            "cinc_19.4.46-1_arm64.deb.metadata.json",
            "cinc_19.4.46-1_amd64.deb.metadata.json",
            "cinc_19.4.46-1_arm64.deb",
            "cinc_19.4.46-1_amd64.deb",
        ]),
    );
    pages.insert(
        "files/stable/cinc/19.4.46/debian/13/cinc_19.4.46-1_amd64.deb.metadata.json".to_string(),
        metadata(
            "cinc_19.4.46-1_amd64.deb",
            SHA_A,
            "debian",
            "13",
            "19.4.46",
            "x86_64",
        ),
    );
    pages.insert(
        "files/stable/cinc/19.4.46/debian/13/cinc_19.4.46-1_arm64.deb.metadata.json".to_string(),
        metadata(
            "cinc_19.4.46-1_arm64.deb",
            SHA_B,
            "debian",
            "13",
            "19.4.46",
            "aarch64",
        ),
    );
    lengths.insert(
        "files/stable/cinc/19.4.46/debian/13/cinc_19.4.46-1_amd64.deb".to_string(),
        1000,
    );
    lengths.insert(
        "files/stable/cinc/19.4.46/debian/13/cinc_19.4.46-1_arm64.deb".to_string(),
        2000,
    );

    pages.insert(
        "files/stable/cinc/19.4.46/ubuntu/".to_string(),
        listing(&["24.04/"]),
    );
    pages.insert(
        "files/stable/cinc/19.4.46/ubuntu/24.04/".to_string(),
        listing(&[
            "cinc_19.4.46-1_amd64.deb",
            "cinc_19.4.46-1_amd64.deb.metadata.json",
        ]),
    );
    pages.insert(
        "files/stable/cinc/19.4.46/ubuntu/24.04/cinc_19.4.46-1_amd64.deb.metadata.json".to_string(),
        metadata(
            "cinc_19.4.46-1_amd64.deb",
            SHA_D,
            "ubuntu",
            "24.04",
            "19.4.46",
            "x86_64",
        ),
    );
    lengths.insert(
        "files/stable/cinc/19.4.46/ubuntu/24.04/cinc_19.4.46-1_amd64.deb".to_string(),
        4000,
    );

    pages.insert(
        "files/stable/cinc/19.3.14/".to_string(),
        listing(&["debian/"]),
    );
    pages.insert(
        "files/stable/cinc/19.3.14/debian/".to_string(),
        listing(&["12/"]),
    );
    pages.insert(
        "files/stable/cinc/19.3.14/debian/12/".to_string(),
        listing(&[
            "cinc_19.3.14-1_amd64.deb.metadata.json",
            "cinc_19.3.14-1_amd64.deb",
        ]),
    );
    pages.insert(
        "files/stable/cinc/19.3.14/debian/12/cinc_19.3.14-1_amd64.deb.metadata.json".to_string(),
        metadata(
            "cinc_19.3.14-1_amd64.deb",
            SHA_C,
            "debian",
            "12",
            "19.3.14",
            "x86_64",
        ),
    );
    lengths.insert(
        "files/stable/cinc/19.3.14/debian/12/cinc_19.3.14-1_amd64.deb".to_string(),
        3000,
    );

    FakeUpstream::new(pages, lengths)
}

/// A fixture with a single artifact of exactly `size` bytes.
fn single_artifact(size: u64) -> FakeUpstream {
    let mut pages = HashMap::new();
    let mut lengths = HashMap::new();

    pages.insert("files/stable/cinc/".to_string(), listing(&["19.4.46/"]));
    pages.insert(
        "files/stable/cinc/19.4.46/".to_string(),
        listing(&["debian/"]),
    );
    pages.insert(
        "files/stable/cinc/19.4.46/debian/".to_string(),
        listing(&["13/"]),
    );
    pages.insert(
        "files/stable/cinc/19.4.46/debian/13/".to_string(),
        listing(&[
            "cinc_19.4.46-1_amd64.deb",
            "cinc_19.4.46-1_amd64.deb.metadata.json",
        ]),
    );
    pages.insert(
        "files/stable/cinc/19.4.46/debian/13/cinc_19.4.46-1_amd64.deb.metadata.json".to_string(),
        metadata(
            "cinc_19.4.46-1_amd64.deb",
            SHA_A,
            "debian",
            "13",
            "19.4.46",
            "x86_64",
        ),
    );
    lengths.insert(
        "files/stable/cinc/19.4.46/debian/13/cinc_19.4.46-1_amd64.deb".to_string(),
        size,
    );

    FakeUpstream::new(pages, lengths)
}

fn policy() -> ProjectPolicy {
    let mut policy = ProjectPolicy::new("cinc-stable");
    policy.project = "cinc".to_string();
    policy.channel = "stable".to_string();
    policy.min_version = Some("19.0.0".to_string());
    policy
}

fn oci_target(name: &str, enabled: bool) -> TargetConfig {
    TargetConfig {
        name: name.to_string(),
        kind: TargetKind::Oci,
        enabled,
        registry: Some("ghcr.io".to_string()),
        namespace: Some("rmoriz/cinc-mirror".to_string()),
        url: None,
        auth: TargetAuth::Docker,
        max_bandwidth: None,
        identity_file: None,
        password_file: None,
    }
}

fn rsync_target(name: &str) -> TargetConfig {
    TargetConfig {
        name: name.to_string(),
        kind: TargetKind::Rsync,
        enabled: true,
        registry: None,
        namespace: None,
        url: Some("ssh://mirror@example.org/srv/cinc-mirror".to_string()),
        auth: TargetAuth::SshKey,
        max_bandwidth: None,
        identity_file: None,
        password_file: None,
    }
}

fn config(state_dir: &std::path::Path, max_bandwidth: &str) -> Config {
    Config {
        state_dir: state_dir.to_path_buf(),
        max_bandwidth: max_bandwidth.to_string(),
        projects: vec![policy()],
        targets: vec![
            oci_target("ghcr", true),
            rsync_target("backup"),
            oci_target("disabled", false),
        ],
        ..Config::default()
    }
}

fn scope(config: &Config) -> ResolvedScope {
    config
        .resolve(&ScopeArgs::default())
        .expect("resolve the default scope")
}

// MLSD parsing ---------------------------------------------------------------

#[test]
fn parses_mlsd_lines() {
    let lines = [
        "type=file;size=51993096;modify=20241102093012;perm=adfr; cinc_19.4.46-1_amd64.deb",
        "type=dir;modify=20241102093012;perm=el; debian",
        "type=file;modify=20241102093012; cinc_without_size.deb",
        "type=file;size=12; cinc with spaces.deb",
        "unparseable",
    ];

    let sizes = parse_mlsd(
        &lines
            .iter()
            .map(|line| line.to_string())
            .collect::<Vec<_>>(),
    );

    assert_eq!(sizes.get("cinc_19.4.46-1_amd64.deb"), Some(&51_993_096));
    assert_eq!(sizes.get("cinc with spaces.deb"), Some(&12));
    assert_eq!(
        sizes.len(),
        2,
        "directories and sizeless records are skipped"
    );
}

// Size resolution ------------------------------------------------------------

#[tokio::test]
async fn size_falls_back_to_head_when_mlsd_missing() {
    let fake = std::sync::Arc::new(fixture());
    let source = Source::with_fetcher(fake.clone(), Url::parse(HTTPS_BASE).expect("base url"))
        .with_ftp("127.0.0.1", 1, "pub/cinc/files");

    let sizes = source
        .sizes("stable/cinc/19.4.46/debian/13")
        .await
        .expect("sizes");

    assert_eq!(
        sizes.get("cinc_19.4.46-1_amd64.deb"),
        Some(&1000),
        "the amd64 package size comes from HEAD Content-Length"
    );
    assert_eq!(sizes.get("cinc_19.4.46-1_arm64.deb"), Some(&2000));

    let seen = fake.seen();
    assert!(
        seen.iter().any(|request| request
            == "HEAD files/stable/cinc/19.4.46/debian/13/cinc_19.4.46-1_amd64.deb"),
        "the unreachable FTP host must send the lookup to HEAD: {seen:?}"
    );
}

#[tokio::test]
async fn ftp_size_fallback_resolves_sizes() {
    let root = tempfile::tempdir().expect("temp dir");
    let dir = root.path().join("stable/cinc/19.4.46/debian/13");
    std::fs::create_dir_all(&dir).expect("fixture dir");
    let package = "cinc_19.4.46-1_amd64.deb";
    std::fs::write(dir.join(package), vec![0_u8; 1234]).expect("package fixture");
    std::fs::write(dir.join(format!("{package}.metadata.json")), "{}").expect("metadata fixture");

    let server = support::start_ftp(root.path().to_path_buf()).await;
    let fake = fixture();
    let source = Source::with_fetcher(
        std::sync::Arc::new(fake),
        Url::parse(HTTPS_BASE).expect("base url"),
    )
    .with_ftp("127.0.0.1", server.port, "");

    let sizes = source
        .sizes("stable/cinc/19.4.46/debian/13")
        .await
        .expect("sizes");

    assert_eq!(
        sizes.get(package),
        Some(&1234),
        "libunftp does not implement MLSD, so SIZE must answer"
    );
}

// Crawl ----------------------------------------------------------------------

#[tokio::test]
async fn crawl_orders_versions_platforms_arches_and_basenames() {
    let source = source_over(fixture());
    let config = config(std::path::Path::new("/tmp"), "0");

    let outcome = crawl(&source, &scope(&config).policies[0])
        .await
        .expect("crawl");

    let keys: Vec<String> = outcome
        .artifacts
        .iter()
        .map(|artifact| artifact.key())
        .collect();
    assert_eq!(
        keys,
        vec![
            format!("stable/cinc/19.4.46/debian/13/amd64/{SHA_A}"),
            format!("stable/cinc/19.4.46/debian/13/arm64/{SHA_B}"),
            format!("stable/cinc/19.4.46/ubuntu/24.04/amd64/{SHA_D}"),
            format!("stable/cinc/19.3.14/debian/12/amd64/{SHA_C}"),
        ],
        "order is version descending, then platform, platform_version, arch, basename"
    );
    assert!(
        outcome.collisions.is_empty(),
        "the fixture has no tag collisions: {:?}",
        outcome.collisions
    );
    assert_eq!(
        outcome.artifacts[0].metadata_json,
        metadata(
            "cinc_19.4.46-1_amd64.deb",
            SHA_A,
            "debian",
            "13",
            "19.4.46",
            "x86_64",
        ),
        "crawl must carry the upstream document through unchanged"
    );
}

#[tokio::test]
async fn crawl_reports_two_digests_under_one_tag_as_a_collision() {
    let mut pages = HashMap::new();
    let js = |name: &str| format!("files/stable/cinc/19.4.46/debian/13/{name}.metadata.json");
    pages.insert("files/stable/cinc/".to_string(), listing(&["19.4.46/"]));
    pages.insert(
        "files/stable/cinc/19.4.46/".to_string(),
        listing(&["debian/"]),
    );
    pages.insert(
        "files/stable/cinc/19.4.46/debian/".to_string(),
        listing(&["13/"]),
    );
    pages.insert(
        "files/stable/cinc/19.4.46/debian/13/".to_string(),
        listing(&[
            "cinc_19.4.46-1_amd64.deb",
            "cinc_19.4.46-1_amd64.deb.metadata.json",
            "cinc-debug_19.4.46-1_amd64.deb",
            "cinc-debug_19.4.46-1_amd64.deb.metadata.json",
        ]),
    );
    pages.insert(
        js("cinc_19.4.46-1_amd64.deb"),
        metadata(
            "cinc_19.4.46-1_amd64.deb",
            SHA_A,
            "debian",
            "13",
            "19.4.46",
            "x86_64",
        ),
    );
    pages.insert(
        js("cinc-debug_19.4.46-1_amd64.deb"),
        metadata(
            "cinc-debug_19.4.46-1_amd64.deb",
            SHA_B,
            "debian",
            "13",
            "19.4.46",
            "x86_64",
        ),
    );

    let source = source_over(FakeUpstream::new(pages, HashMap::new()));
    let config = config(std::path::Path::new("/tmp"), "0");
    let outcome = crawl(&source, &scope(&config).policies[0])
        .await
        .expect("a collision is collected, not an error");

    // `cinc-debug_...` sorts before `cinc_...`, so it is the kept artifact.
    assert_eq!(outcome.artifacts.len(), 1);
    assert_eq!(outcome.artifacts[0].sha256, SHA_B);
    assert_eq!(outcome.collisions.len(), 1);
    let collision = &outcome.collisions[0];
    assert_eq!(collision.first.sha256, SHA_B, "the first artifact is kept");
    assert_eq!(collision.conflicting.sha256, SHA_A);
    assert_eq!(collision.tag, "19.4.46-debian-13-amd64");
    assert_eq!(
        collision.upstream_path,
        "stable/cinc/19.4.46/debian/13/cinc_19.4.46-1_amd64.deb"
    );
}

#[tokio::test]
async fn plan_excludes_colliding_artifacts_and_reports_them() {
    let mut pages = HashMap::new();
    let js = |name: &str| format!("files/stable/cinc/19.4.46/debian/13/{name}.metadata.json");
    pages.insert("files/stable/cinc/".to_string(), listing(&["19.4.46/"]));
    pages.insert(
        "files/stable/cinc/19.4.46/".to_string(),
        listing(&["debian/"]),
    );
    pages.insert(
        "files/stable/cinc/19.4.46/debian/".to_string(),
        listing(&["13/"]),
    );
    pages.insert(
        "files/stable/cinc/19.4.46/debian/13/".to_string(),
        listing(&[
            "cinc_19.4.46-1_aarch64.deb",
            "cinc_19.4.46-1_aarch64.deb.metadata.json",
            "cinc_19.4.46-1_arm64.deb",
            "cinc_19.4.46-1_arm64.deb.metadata.json",
        ]),
    );
    // Two raw arches mapping to one public arm64 with different bytes.
    pages.insert(
        js("cinc_19.4.46-1_aarch64.deb"),
        metadata(
            "cinc_19.4.46-1_aarch64.deb",
            SHA_B,
            "debian",
            "13",
            "19.4.46",
            "aarch64",
        ),
    );
    pages.insert(
        js("cinc_19.4.46-1_arm64.deb"),
        metadata(
            "cinc_19.4.46-1_arm64.deb",
            SHA_C,
            "debian",
            "13",
            "19.4.46",
            "arm64",
        ),
    );

    let state_dir = tempfile::tempdir().expect("temp dir");
    let config = config(state_dir.path(), "0");
    let mut lengths = HashMap::new();
    lengths.insert(
        "files/stable/cinc/19.4.46/debian/13/cinc_19.4.46-1_aarch64.deb".to_string(),
        2000,
    );
    lengths.insert(
        "files/stable/cinc/19.4.46/debian/13/cinc_19.4.46-1_arm64.deb".to_string(),
        3000,
    );

    let plan = build(
        &source_over(FakeUpstream::new(pages, lengths)),
        &config,
        &scope(&config),
        &HashSet::new(),
    )
    .await
    .expect("a collision does not fail the plan");

    assert_eq!(plan.collisions, 1);
    assert_eq!(
        plan.artifacts, 1,
        "the conflicting artifact is excluded from the totals"
    );
    assert_eq!(plan.total_bytes, 2000, "only the kept artifact is counted");
    assert!(plan.to_json().contains("\"collisions\": 1"));
}

// Plan totals and grouping ---------------------------------------------------

#[tokio::test]
async fn totals_group_by_project_platform_arch_and_target() {
    let state_dir = tempfile::tempdir().expect("temp dir");
    let config = config(state_dir.path(), "0");
    let source = source_over(fixture());
    let satisfied = HashSet::new();

    let plan = build(&source, &config, &scope(&config), &satisfied)
        .await
        .expect("plan");

    assert_eq!(plan.artifacts, 4);
    assert_eq!(plan.total_bytes, 10_000);
    assert_eq!(plan.satisfied_bytes, 0);

    let project = &plan.by_project["cinc"];
    assert_eq!((project.artifacts, project.bytes), (4, 10_000));
    assert_eq!(project.satisfied_bytes, 0);

    let debian = &plan.by_platform["debian"];
    assert_eq!((debian.artifacts, debian.bytes), (3, 6_000));
    let ubuntu = &plan.by_platform["ubuntu"];
    assert_eq!((ubuntu.artifacts, ubuntu.bytes), (1, 4_000));

    let amd64 = &plan.by_arch["amd64"];
    assert_eq!((amd64.artifacts, amd64.bytes), (3, 8_000));
    let arm64 = &plan.by_arch["arm64"];
    assert_eq!((arm64.artifacts, arm64.bytes), (1, 2_000));

    assert_eq!(plan.by_target.len(), 2, "only enabled targets are grouped");
    for name in ["ghcr", "backup"] {
        let target = &plan.by_target[name];
        assert_eq!((target.artifacts, target.bytes), (4, 10_000));
    }
    assert!(!plan.by_target.contains_key("disabled"));

    assert_eq!(
        plan.largest,
        vec![
            (
                format!("stable/cinc/19.4.46/ubuntu/24.04/amd64/{SHA_D}"),
                4_000
            ),
            (
                format!("stable/cinc/19.3.14/debian/12/amd64/{SHA_C}"),
                3_000
            ),
            (
                format!("stable/cinc/19.4.46/debian/13/arm64/{SHA_B}"),
                2_000
            ),
            (
                format!("stable/cinc/19.4.46/debian/13/amd64/{SHA_A}"),
                1_000
            ),
        ],
        "largest artifacts are ordered by size descending"
    );
}

#[tokio::test]
async fn satisfied_artifacts_count_separately() {
    let state_dir = tempfile::tempdir().expect("temp dir");
    let config = config(state_dir.path(), "0");
    let source = source_over(fixture());
    let satisfied: HashSet<String> =
        HashSet::from([format!("stable/cinc/19.3.14/debian/12/amd64/{SHA_C}")]);

    let plan = build(&source, &config, &scope(&config), &satisfied)
        .await
        .expect("plan");

    assert_eq!(plan.artifacts, 4);
    assert_eq!(plan.total_bytes, 10_000);
    assert_eq!(
        plan.satisfied_bytes, 3_000,
        "a satisfied artifact still counts in the total but not as pending"
    );

    assert_eq!(plan.by_arch["amd64"].satisfied_bytes, 3_000);
    assert_eq!(plan.by_arch["arm64"].satisfied_bytes, 0);
    assert_eq!(plan.by_platform["debian"].satisfied_bytes, 3_000);
    assert_eq!(plan.by_target["ghcr"].satisfied_bytes, 3_000);
}

// Free space -----------------------------------------------------------------

#[tokio::test]
async fn reports_whether_the_state_dir_has_room_without_failing() {
    let state_dir = tempfile::tempdir().expect("temp dir");
    let config = config(state_dir.path(), "0");
    let source = source_over(fixture());

    let plan = build(&source, &config, &scope(&config), &HashSet::new())
        .await
        .expect("plan");

    assert_eq!(plan.space.required_bytes, 10_000);
    assert!(
        plan.space.free_bytes.is_some(),
        "an existing state dir must report its free space"
    );
    assert_eq!(plan.space.fits, Some(true));

    let huge = single_artifact(u64::MAX / 2);
    let huge_plan = build(
        &source_over(huge),
        &config,
        &scope(&config),
        &HashSet::new(),
    )
    .await
    .expect("a plan larger than the disk still succeeds");

    assert_eq!(huge_plan.space.fits, Some(false));
}

// Projected duration ---------------------------------------------------------

#[tokio::test]
async fn projected_duration_uses_max_bandwidth() {
    let state_dir = tempfile::tempdir().expect("temp dir");
    let limited = config(state_dir.path(), "10MiB/s");
    let source = source_over(single_artifact(100 * 1024 * 1024));

    let plan = build(&source, &limited, &scope(&limited), &HashSet::new())
        .await
        .expect("plan");

    assert_eq!(plan.total_bytes, 104_857_600);
    assert_eq!(plan.projected_seconds, Some(10), "100 MiB at 10 MiB/s");

    let unlimited = config(state_dir.path(), "0");
    let plan = build(
        &source_over(single_artifact(1024)),
        &unlimited,
        &scope(&unlimited),
        &HashSet::new(),
    )
    .await
    .expect("plan");
    assert_eq!(plan.projected_seconds, None, "0 means unlimited");
}

// JSON -----------------------------------------------------------------------

#[tokio::test]
async fn json_embeds_effective_policy_and_is_stable() {
    let state_dir = tempfile::tempdir().expect("temp dir");
    let config = config(state_dir.path(), "0");
    let source = source_over(fixture());

    let plan = build(&source, &config, &scope(&config), &HashSet::new())
        .await
        .expect("plan");

    let json = plan.to_json();
    assert_eq!(json, plan.to_json(), "serialisation must be repeatable");

    let mut cursor = 0;
    for key in [
        "\"artifacts\"",
        "\"total_bytes\"",
        "\"satisfied_bytes\"",
        "\"collisions\"",
        "\"by_project\"",
        "\"by_platform\"",
        "\"by_arch\"",
        "\"by_target\"",
        "\"largest\"",
        "\"space\"",
        "\"effective_policy\"",
        "\"projected_seconds\"",
    ] {
        let offset = json[cursor..]
            .find(key)
            .unwrap_or_else(|| panic!("`{key}` missing or out of order in {json}"));
        cursor += offset + key.len();
    }

    let value: serde_json::Value = serde_json::from_str(&json).expect("valid json");
    assert_eq!(value["collisions"], serde_json::json!(0));
    let policies = value["effective_policy"]
        .as_array()
        .expect("effective_policy is an array");
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0]["id"], "cinc-stable");
    assert_eq!(policies[0]["project"], "cinc");
    assert_eq!(policies[0]["channel"], "stable");
    assert_eq!(policies[0]["min_version"], "19.0.0");
    assert_eq!(policies[0]["max_version"], serde_json::Value::Null);
    assert_eq!(policies[0]["versions"], serde_json::json!([]));
    assert_eq!(policies[0]["platforms"], "*");
    assert_eq!(policies[0]["arches"], "*");

    let archs = value["by_arch"].as_object().expect("by_arch object");
    let names: Vec<&String> = archs.keys().collect();
    assert_eq!(names, vec!["amd64", "arm64"], "groups are sorted");
}

#[tokio::test]
async fn writes_the_plan_json_to_a_file() {
    let state_dir = tempfile::tempdir().expect("temp dir");
    let config = config(state_dir.path(), "0");
    let plan = build(
        &source_over(fixture()),
        &config,
        &scope(&config),
        &HashSet::new(),
    )
    .await
    .expect("plan");

    let path = state_dir.path().join("plan-test.json");
    plan.write(&path).expect("write plan");

    assert_eq!(
        std::fs::read_to_string(&path).expect("read plan"),
        plan.to_json()
    );
}
