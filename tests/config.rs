//! Configuration model, validation and `--set` override tests.

use std::io::Write;
use std::path::Path;

use assert_cmd::Command;
use cinc_mirror::config::{
    Config, ConfigError, DeleteMode, ProjectPolicy, Selection, TargetAuth, TargetKind,
    TransportKind,
};
use predicates::prelude::*;

fn load_str(source: &str) -> Result<Config, ConfigError> {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    file.write_all(source.as_bytes()).expect("write config");
    Config::load(Some(file.path()))
}

fn validated(source: &str) -> Result<Config, ConfigError> {
    let config = load_str(source)?;
    config.validate()?;
    Ok(config)
}

fn policy(id: &str, project: &str, channel: &str) -> ProjectPolicy {
    ProjectPolicy::new(id)
        .with_project(project)
        .with_channel(channel)
}

fn overrides(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| value.to_string()).collect()
}

/// The test binary Cargo built for this integration test.
fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_cinc-mirror"))
}

#[test]
fn parses_projects_whose_arch_collisions_are_ignored() {
    let config = validated(
        r#"
        [incident]
        ignore_arch_collisions = ["omnibus-toolchain"]
        "#,
    )
    .expect("valid config");

    assert_eq!(
        config.incident.ignore_arch_collisions,
        vec!["omnibus-toolchain".to_string()]
    );
}

#[test]
fn rejects_duplicate_policy_ids() {
    let error = validated(
        r#"
        [[projects]]
        id = "cinc"
        project = "cinc"
        channel = "stable"

        [[projects]]
        id = "cinc"
        project = "cinc"
        channel = "unstable"
        "#,
    )
    .expect_err("duplicate ids must be rejected");

    assert!(
        matches!(error, ConfigError::DuplicatePolicyId(ref id) if id == "cinc"),
        "unexpected error: {error}"
    );
}

#[test]
fn rejects_platform_version_for_unlisted_platform() {
    let error = validated(
        r#"
        [[projects]]
        id = "cinc"
        project = "cinc"
        channel = "stable"
        platforms = ["ubuntu"]
        platform_versions = { debian = ["13"] }
        "#,
    )
    .expect_err("platform_versions must be limited to listed platforms");

    assert!(
        matches!(
            error,
            ConfigError::PlatformVersionForUnlistedPlatform {
                ref policy_id,
                ref platform,
            } if policy_id == "cinc" && platform == "debian"
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn wildcard_platforms_accept_platform_versions() {
    let config = validated(
        r#"
        [[projects]]
        id = "cinc"
        project = "cinc"
        channel = "stable"
        platforms = "*"
        platform_versions = { debian = ["13"] }
        "#,
    )
    .expect("wildcard platforms allow platform_versions");

    assert_eq!(config.projects[0].platforms, Selection::All);
}

#[test]
fn rejects_min_above_max() {
    let error = validated(
        r#"
        [[projects]]
        id = "cinc"
        project = "cinc"
        channel = "stable"
        min_version = "20"
        max_version = "19"
        "#,
    )
    .expect_err("min above max must be rejected");

    assert!(
        matches!(error, ConfigError::MinAboveMax { ref min, ref max, .. } if min == "20" && max == "19"),
        "unexpected error: {error}"
    );
}

#[test]
fn compares_version_bounds_numerically() {
    let error = validated(
        r#"
        [[projects]]
        id = "cinc"
        project = "cinc"
        channel = "stable"
        min_version = "19.10.0"
        max_version = "19.4.46"
        "#,
    )
    .expect_err("19.10.0 is greater than 19.4.46");

    assert!(
        matches!(error, ConfigError::MinAboveMax { .. }),
        "unexpected error: {error}"
    );

    validated(
        r#"
        [[projects]]
        id = "cinc"
        project = "cinc"
        channel = "stable"
        min_version = "19.4.46"
        max_version = "19.10.0"
        "#,
    )
    .expect("numeric segment order must accept 19.4.46 <= 19.10.0");
}

#[test]
fn policy_max_below_global_floor_is_rejected() {
    let error = validated(
        r#"
        min_version = "20"

        [[projects]]
        id = "cinc"
        project = "cinc"
        channel = "stable"
        max_version = "19"
        "#,
    )
    .expect_err("the global floor applies to policies without their own floor");

    assert!(
        matches!(error, ConfigError::MinAboveMax { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn all_versions_policy_may_sit_below_the_global_floor() {
    validated(
        r#"
        min_version = "18"

        [[projects]]
        id = "omnibus-toolchain"
        project = "omnibus-toolchain"
        channel = "stable"
        all_versions = true
        max_version = "17"
        "#,
    )
    .expect("all_versions removes the global floor, so the bound is consistent");
}

#[test]
fn rejects_malformed_version_bounds() {
    for bound in ["", "19..0", "19.x", "-1", "19 .0"] {
        let error = validated(&format!(
            r#"
            [[projects]]
            id = "cinc"
            project = "cinc"
            channel = "stable"
            min_version = "{bound}"
            "#
        ))
        .expect_err("malformed bound must be rejected by validation");

        assert!(
            matches!(error, ConfigError::InvalidVersionBound { .. }),
            "bound {bound:?} produced {error}"
        );
    }
}

#[test]
fn rejects_malformed_version_globs() {
    for glob in ["", "19..*", "19.x", "19.*x"] {
        let error = validated(&format!(
            r#"
            [[projects]]
            id = "cinc"
            project = "cinc"
            channel = "stable"
            versions = ["{glob}"]
            "#
        ))
        .expect_err("malformed version glob must be rejected by validation");

        assert!(
            matches!(error, ConfigError::InvalidVersionGlob { ref value } if value == glob),
            "glob {glob:?} produced {error}"
        );
    }

    validated(
        r#"
        [[projects]]
        id = "cinc"
        project = "cinc"
        channel = "stable"
        versions = ["18.8.*", "19.?.0", "19.4.46"]
        "#,
    )
    .expect("numeric segments, `*` and `?` are valid globs");
}

#[test]
fn set_rejects_malformed_version_globs() {
    let mut config = Config::default();
    config
        .projects
        .push(policy("cinc-stable", "cinc", "stable"));

    let error = config
        .apply_overrides(&overrides(&["cinc-stable.versions=19.*,19..*"]))
        .expect_err("a malformed glob in --set must not be stored");

    assert!(
        matches!(error, ConfigError::InvalidVersionGlob { ref value } if value == "19..*"),
        "unexpected error: {error}"
    );

    config
        .apply_overrides(&overrides(&["cinc-stable.versions=19.*,18.8.?"]))
        .expect("valid globs apply");
    assert_eq!(
        config.projects[0].versions,
        vec!["19.*".to_string(), "18.8.?".to_string()]
    );
}

#[test]
fn empty_config_uses_documented_defaults() {
    let config = Config::default();
    config.validate().expect("defaults are valid");

    assert_eq!(
        config.state_dir,
        Path::new("~/.local/state/cinc-mirror").to_path_buf()
    );
    assert_eq!(config.concurrency, 4);
    assert_eq!(config.upload_concurrency, 2);
    assert_eq!(config.max_bandwidth, "0");
    assert_eq!(
        config.transport,
        vec![
            TransportKind::Ftp,
            TransportKind::Ftps,
            TransportKind::Https
        ]
    );
    assert_eq!(config.metadata_transport, TransportKind::Https);
    assert_eq!(config.min_version, None);
    assert!(config.projects.is_empty());
    assert!(config.targets.is_empty());
    assert_eq!(config.ledger.branch, "ledger");
    assert_eq!(config.ledger.remote, "origin");

    let empty = validated("").expect("an empty config file is valid");
    assert!(empty.projects.is_empty());
}

#[test]
fn parses_transports_and_wildcards() {
    let config = validated(
        r#"
        transport = ["https", "ftp"]
        metadata_transport = "https"
        min_version = "18"

        [[projects]]
        id = "cinc"
        project = "cinc"
        channel = "stable"
        platforms = "*"
        arches = ["amd64", "arm64"]
        "#,
    )
    .expect("valid config");

    assert_eq!(
        config.transport,
        vec![TransportKind::Https, TransportKind::Ftp]
    );
    assert_eq!(config.min_version.as_deref(), Some("18"));
    assert_eq!(config.projects[0].platforms, Selection::All);
    assert_eq!(
        config.projects[0].arches,
        Selection::Only(vec!["amd64".to_string(), "arm64".to_string()])
    );

    let error = load_str(
        r#"
        [[projects]]
        id = "cinc"
        project = "cinc"
        channel = "stable"
        platforms = "debian"
        "#,
    )
    .expect_err("a bare string is not a valid selection");
    assert!(
        matches!(
            error,
            ConfigError::Parse { ref source, .. }
                if source.to_string().contains("array of names")
        ),
        "expected the Selection visitor to reject the bare string, got: {error}"
    );
}

#[test]
fn rejects_metadata_over_plain_transport() {
    let error = load_str(r#"metadata_transport = "ftp""#)
        .and_then(|config| config.validate())
        .expect_err("metadata must use https");

    assert!(
        matches!(error, ConfigError::MetadataTransportNotHttps),
        "unexpected error: {error}"
    );
}

#[test]
fn rejects_zero_concurrency() {
    let error = load_str("concurrency = 0")
        .and_then(|config| config.validate())
        .expect_err("zero downloads cannot make progress");

    assert!(
        matches!(
            error,
            ConfigError::ZeroValue {
                field: "concurrency"
            }
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn parses_oci_and_rsync_targets() {
    let config = validated(
        r#"
        [[targets]]
        name = "ghcr"
        kind = "oci"
        registry = "ghcr.io"
        namespace = "rmoriz/cinc-mirror"
        auth = "docker"

        [[targets]]
        name = "rsync"
        kind = "rsync"
        url = "ssh://mirror@backup.example.org/srv/cinc-mirror"
        auth = "ssh-key"
        enabled = false
        "#,
    )
    .expect("valid targets");

    assert_eq!(config.targets[0].kind, TargetKind::Oci);
    assert_eq!(config.targets[0].auth, TargetAuth::Docker);
    assert!(config.targets[0].enabled);
    assert_eq!(config.targets[1].auth, TargetAuth::SshKey);
    assert!(!config.targets[1].enabled);
}

#[test]
fn accepts_a_local_rsync_path() {
    let config = validated(
        r#"
        [[targets]]
        name = "local"
        kind = "rsync"
        url = "/srv/cinc-mirror"
        "#,
    )
    .expect("a local filesystem path is a valid rsync target");
    assert_eq!(config.targets[0].kind, TargetKind::Rsync);
    assert_eq!(config.targets[0].auth, TargetAuth::Anonymous);

    let wrong_auth = load_str(
        r#"
        [[targets]]
        name = "local"
        kind = "rsync"
        url = "/srv/cinc-mirror"
        auth = "ssh-key"
        "#,
    )
    .and_then(|config| config.validate())
    .expect_err("a local path does not use ssh-key auth");
    assert!(
        matches!(wrong_auth, ConfigError::InvalidTarget { .. }),
        "unexpected error: {wrong_auth}"
    );
}

#[test]
fn rejects_invalid_targets() {
    let missing_registry = load_str(
        r#"
        [[targets]]
        name = "ghcr"
        kind = "oci"
        namespace = "rmoriz/cinc-mirror"
        "#,
    )
    .and_then(|config| config.validate())
    .expect_err("oci requires a registry");
    assert!(
        matches!(missing_registry, ConfigError::InvalidTarget { .. }),
        "unexpected error: {missing_registry}"
    );

    let wrong_rsync_auth = load_str(
        r#"
        [[targets]]
        name = "rsync"
        kind = "rsync"
        url = "rsync://backup.example.org/cinc"
        auth = "ssh-key"
        "#,
    )
    .and_then(|config| config.validate())
    .expect_err("a daemon address needs daemon auth");
    assert!(
        matches!(wrong_rsync_auth, ConfigError::InvalidTarget { .. }),
        "unexpected error: {wrong_rsync_auth}"
    );

    let duplicate_names = load_str(
        r#"
        [[targets]]
        name = "ghcr"
        kind = "oci"
        registry = "ghcr.io"
        namespace = "a/b"

        [[targets]]
        name = "ghcr"
        kind = "oci"
        registry = "ghcr.io"
        namespace = "c/d"
        "#,
    )
    .and_then(|config| config.validate())
    .expect_err("target names must be unique");
    assert!(
        matches!(duplicate_names, ConfigError::DuplicateTargetName(ref name) if name == "ghcr"),
        "unexpected error: {duplicate_names}"
    );
}

#[test]
fn apply_overrides_replaces_field_and_adds_policy() {
    let mut config = Config::default();
    config
        .projects
        .push(policy("cinc-stable", "cinc", "stable"));
    config.projects[0].min_version = Some("19.0.0".to_string());

    config
        .apply_overrides(&overrides(&[
            "cinc-stable.min_version=19.2.0",
            "extra.project=foo",
        ]))
        .expect("overrides apply");

    assert_eq!(config.projects[0].id, "cinc-stable");
    assert_eq!(config.projects[0].min_version.as_deref(), Some("19.2.0"));
    assert_eq!(config.projects[1].id, "extra");
    assert_eq!(config.projects[1].project, "foo");
    assert_eq!(config.projects[1].channel, "");
    assert!(config.projects[1].enabled);
    assert_eq!(config.projects[1].platforms, Selection::All);

    config
        .apply_overrides(&overrides(&["extra.channel=stable"]))
        .expect("channel override applies");
    config.validate().expect("completed policy is now valid");
}

#[test]
fn apply_overrides_handles_global_keys_and_arrays() {
    let mut config = Config::default();

    config
        .apply_overrides(&overrides(&[
            "concurrency=8",
            "upload_concurrency=3",
            "state_dir=/var/lib/cinc",
            "transport=https,ftp",
            "metadata_transport=https",
            "min_version=18",
            "ledger.branch=mirror-ledger",
            "ledger.remote=upstream",
        ]))
        .expect("global overrides apply");

    assert_eq!(config.concurrency, 8);
    assert_eq!(config.upload_concurrency, 3);
    assert_eq!(config.state_dir, Path::new("/var/lib/cinc"));
    assert_eq!(
        config.transport,
        vec![TransportKind::Https, TransportKind::Ftp]
    );
    assert_eq!(config.min_version.as_deref(), Some("18"));
    assert_eq!(config.ledger.branch, "mirror-ledger");
    assert_eq!(config.ledger.remote, "upstream");
}

#[test]
fn apply_overrides_rejects_unknown_keys_and_bad_values() {
    let mut config = Config::default();
    config
        .projects
        .push(policy("cinc-stable", "cinc", "stable"));

    let unknown = config
        .apply_overrides(&overrides(&["cinc-stable.bogus=1"]))
        .expect_err("unknown policy field");
    assert!(
        matches!(unknown, ConfigError::UnknownSetKey(ref key) if key == "cinc-stable.bogus"),
        "unexpected error: {unknown}"
    );

    let unknown_global = config
        .apply_overrides(&overrides(&["bogus=1"]))
        .expect_err("unknown global key");
    assert!(
        matches!(unknown_global, ConfigError::UnknownSetKey(ref key) if key == "bogus"),
        "unexpected error: {unknown_global}"
    );

    let malformed = config
        .apply_overrides(&overrides(&["concurrency"]))
        .expect_err("missing value");
    assert!(
        matches!(malformed, ConfigError::InvalidOverride(ref raw) if raw == "concurrency"),
        "unexpected error: {malformed}"
    );

    let bad_bool = config
        .apply_overrides(&overrides(&["cinc-stable.all_versions=yes"]))
        .expect_err("booleans are true or false");
    assert!(
        matches!(bad_bool, ConfigError::InvalidSetValue { .. }),
        "unexpected error: {bad_bool}"
    );

    let bad_bound = config
        .apply_overrides(&overrides(&["cinc-stable.min_version=19.x"]))
        .expect_err("bad version bound");
    assert!(
        matches!(bad_bound, ConfigError::InvalidVersionBound { .. }),
        "unexpected error: {bad_bound}"
    );

    let bad_transport = config
        .apply_overrides(&overrides(&["transport=sftp"]))
        .expect_err("unknown transport");
    assert!(
        matches!(bad_transport, ConfigError::InvalidTransport(ref value) if value == "sftp"),
        "unexpected error: {bad_transport}"
    );

    let empty_array = config
        .apply_overrides(&overrides(&["transport="]))
        .expect_err("empty array");
    assert!(
        matches!(empty_array, ConfigError::InvalidSetValue { .. }),
        "unexpected error: {empty_array}"
    );
}

#[test]
fn overridden_bounds_are_validated_before_resolution() {
    let mut config = load_str(
        r#"
        [[projects]]
        id = "cinc-stable"
        project = "cinc"
        channel = "stable"
        max_version = "19"
        "#,
    )
    .expect("loads");

    config
        .apply_overrides(&overrides(&["cinc-stable.min_version=20"]))
        .expect("bound syntax is valid");

    let error = config
        .validate()
        .expect_err("override produced min above max");
    assert!(
        matches!(error, ConfigError::MinAboveMax { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn unknown_toml_key_is_an_error() {
    let error = load_str("concurreny = 4").expect_err("typos must not be ignored");

    assert!(
        matches!(error, ConfigError::Parse { .. }),
        "unexpected error: {error}"
    );

    let nested = load_str(
        r#"
        [[projects]]
        id = "cinc"
        project = "cinc"
        channel = "stable"
        platform_version = { debian = ["13"] }
        "#,
    )
    .expect_err("unknown nested key must not be ignored");
    assert!(matches!(nested, ConfigError::Parse { .. }), "{nested}");
}

#[test]
fn retention_defaults_are_off_and_automatic() {
    let config = Config::default();
    assert!(!config.retention.prune);
    assert_eq!(config.retention.delete, DeleteMode::Auto);
    assert_eq!(config.retention.max_deletions, 2000);
    assert_eq!(config.retention.api_base, "https://api.github.com");
}

#[test]
fn retention_delete_modes_parse_and_serialise() {
    for (text, mode) in [
        ("auto", DeleteMode::Auto),
        ("registry", DeleteMode::Registry),
        ("packages-api", DeleteMode::PackagesApi),
    ] {
        let config = validated(&format!("[retention]\ndelete = \"{text}\"\n"))
            .expect("the delete mode must parse");
        assert_eq!(config.retention.delete, mode);
        assert_eq!(mode.to_string(), text);
        let serialised = serde_json::to_value(&config.retention).expect("retention must serialise");
        assert_eq!(serialised["delete"], text);
    }
}

#[test]
fn retention_rejects_an_unknown_delete_mode_and_a_zero_budget() {
    for body in [
        "[retention]\ndelete = \"s3\"\n",
        "[retention]\nkeep_days = 3\n",
    ] {
        assert!(load_str(body).is_err(), "`{body}` must be rejected");
    }
    for body in [
        "[retention]\nmax_deletions = 0\n",
        "[retention]\napi_base = \" \"\n",
    ] {
        assert!(validated(body).is_err(), "`{body}` must be rejected");
    }
}

#[test]
fn missing_config_file_is_a_read_error() {
    let error = Config::load(Some(Path::new("definitely-not-a-config.toml")))
        .expect_err("an explicit config path must exist");

    assert!(matches!(error, ConfigError::Read { .. }), "{error}");
}

#[test]
fn loads_the_shipped_example_config() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("mirror.toml.example");

    let config = Config::load(Some(&path)).expect("example config parses");
    config.validate().expect("example config is valid");

    assert!(!config.projects.is_empty());
    assert!(!config.targets.is_empty());
}

#[test]
fn the_ci_config_follows_one_major_line_per_project() {
    // The scheduled backfill mirrors the current major of every project, not the
    // whole history. A missing or widened glob here silently re-adds thousands
    // of old artifacts.
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("mirror.ci.toml");

    let config = Config::load(Some(&path)).expect("CI config parses");
    config.validate().expect("CI config is valid");
    assert_eq!(config.projects.len(), 6);

    for policy in &config.projects {
        assert!(
            !policy.all_versions,
            "{}: a wide open policy would crawl every version",
            policy.id
        );
        assert_eq!(
            policy.versions.len(),
            1,
            "{}: exactly one major glob",
            policy.id
        );
        let raw = &policy.versions[0];
        let major: u64 = raw
            .trim_end_matches(".*")
            .parse()
            .unwrap_or_else(|_| panic!("{}: `{raw}` must be `<major>.*`", policy.id));
        let glob: cinc_mirror::VersionGlob = raw.parse().expect("valid glob");
        let probe = |version: &str| glob.matches(&version.parse().expect("probe version"));
        assert!(probe(&format!("{major}.99.99")), "{}: own line", policy.id);
        assert!(
            !probe(&format!("{}.0.0", major - 1)),
            "{}: previous major must be out",
            policy.id
        );
        assert!(
            !probe(&format!("{}.0.0", major + 1)),
            "{}: next major must be out",
            policy.id
        );
    }
}

// CLI behaviour: exit codes are part of the contract even while commands are
// stubs.

#[test]
fn config_check_prints_policies_without_secrets() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("mirror.toml.example");

    binary()
        .args(["config", "check", "--config"])
        .arg(&path)
        .assert()
        .success()
        .stdout(predicate::str::contains("cinc-stable"))
        .stdout(predicate::str::contains("ghcr"))
        .stdout(predicate::str::contains(
            "retention: prune false, delete auto, max_deletions 2000",
        ))
        .stdout(predicate::str::contains("password").not())
        .stdout(predicate::str::contains("token").not());
}

#[test]
fn config_check_works_without_a_config_file() {
    let dir = tempfile::tempdir().expect("temp dir");

    binary()
        .current_dir(dir.path())
        .args(["config", "check"])
        .assert()
        .success()
        .stdout(predicate::str::contains("none (built-in defaults)"));
}

#[test]
fn config_errors_exit_with_code_5() {
    let mut file = tempfile::NamedTempFile::new().expect("temp file");
    write!(
        file,
        r#"
        [[projects]]
        id = "cinc"
        project = "cinc"
        channel = "stable"

        [[projects]]
        id = "cinc"
        project = "cinc"
        channel = "unstable"
        "#
    )
    .expect("write config");

    binary()
        .args(["config", "check", "--config"])
        .arg(file.path())
        .assert()
        .code(5);
}

#[test]
fn usage_errors_exit_with_code_64() {
    binary().assert().code(64);

    binary().args(["config", "bogus"]).assert().code(64);
}

#[test]
fn prune_names_a_target_that_is_not_an_oci_target() {
    let root = tempfile::tempdir().expect("root");
    let state = root.path().join("state");
    std::fs::create_dir_all(&state).expect("state dir");
    let target_root = root.path().join("rsync");
    std::fs::create_dir_all(&target_root).expect("target root");
    let config = root.path().join("mirror.toml");
    write!(
        std::fs::File::create(&config).expect("config file"),
        r#"state_dir = {state:?}

[ledger]
branch = "ledger"
remote = "git@example.invalid:ledger.git"

[[targets]]
name = "rsync"
kind = "rsync"
url = {target_root:?}
auth = "anonymous"
"#
    )
    .expect("write config");

    binary()
        .arg("--config")
        .arg(&config)
        .args(["prune", "--target", "rsync"])
        .env_remove("CI")
        .env_remove("GITHUB_ACTIONS")
        .assert()
        .code(64)
        .stderr(
            predicate::str::contains("rsync").and(predicate::str::contains("not an oci target")),
        );
}

#[test]
fn help_exits_with_code_0() {
    binary()
        .arg("--help")
        .assert()
        .code(0)
        .stdout(predicate::str::contains("config"));
}
