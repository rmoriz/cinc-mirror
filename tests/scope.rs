//! Version semantics and scope resolution tests.
//!
//! Resolution is always: config -> `--set` (already stored on `Config`) -> CLI
//! filters -> intersection. Only `all_versions` widens.

use std::collections::BTreeMap;

use cinc_mirror::config::{Config, ProjectPolicy, Selection};
use cinc_mirror::scope::{ScopeArgs, ScopeError};
use cinc_mirror::version::{Version, VersionError, VersionGlob, VersionGlobError};

fn v(text: &str) -> Version {
    text.parse().expect("valid version")
}

fn g(text: &str) -> VersionGlob {
    text.parse().expect("valid version glob")
}

fn policy(id: &str, project: &str, channel: &str) -> ProjectPolicy {
    ProjectPolicy::new(id)
        .with_project(project)
        .with_channel(channel)
}

fn config_with(projects: Vec<ProjectPolicy>, global_min: Option<&str>) -> Config {
    Config {
        min_version: global_min.map(ToString::to_string),
        projects,
        ..Config::default()
    }
}

fn only(values: &[&str]) -> Selection {
    Selection::Only(values.iter().map(ToString::to_string).collect())
}

// Version semantics ---------------------------------------------------------

#[test]
fn numeric_segments_not_lexicographic() {
    assert!(v("19.10.0") > v("19.4.46"));
    assert!(v("19.4.46") > v("19.4.9"));
    assert!(v("20.0.0") > v("19.99.99"));
    assert!(v("19.4.46") < v("19.10.0"));
}

#[test]
fn missing_segments_compare_as_zero() {
    assert_eq!(v("19.4"), v("19.4.0"));
    assert_eq!(v("19"), v("19.0.0"));
    assert!(v("19.4") < v("19.4.1"));
}

#[test]
fn version_parses_strictly() {
    for bad in [
        "",
        "19..0",
        "19.x",
        "-1",
        "19 .0",
        "19.0.",
        ".19",
        "19.-1",
        "18446744073709551616",
    ] {
        assert!(
            bad.parse::<Version>().is_err(),
            "{bad:?} must not parse as a version"
        );
    }

    let error = "19.x".parse::<Version>().expect_err("non-numeric segment");
    assert!(
        matches!(
            error,
            VersionError::InvalidSegment { ref value, ref segment }
                if value == "19.x" && segment == "x"
        ),
        "unexpected error: {error}"
    );

    assert_eq!(v("19.4.46").to_string(), "19.4.46");
}

#[test]
fn globs_match_whole_segments() {
    assert!(g("18.8.*").matches(&v("18.8.11")));
    assert!(g("18.8.*").matches(&v("18.8.0")));
    assert!(!g("18.8.*").matches(&v("18.9.1")));
    assert!(!g("18.8.*").matches(&v("19.8.11")));
    assert!(g("18.8.*").matches(&v("18.8")));
    assert!(g("19.*").matches(&v("19.4.46")));

    // A glob cannot match only part of a segment, but a shorter glob leaves the
    // remaining version segments unconstrained.
    assert!(g("18.*").matches(&v("18.8.11")));
    assert!(g("18.*").matches(&v("18.8.0")));
    assert!(!g("18.*").matches(&v("19.8.11")));
    assert!(g("18.8.*").matches(&v("18.8.11.2")));

    // `?` matches a single-digit segment, not a multi-digit one.
    assert!(g("18.8.?").matches(&v("18.8.3")));
    assert!(!g("18.8.?").matches(&v("18.8.11")));

    assert_eq!(g("18.8.*").to_string(), "18.8.*");
}

#[test]
fn glob_parsing_rejects_junk() {
    for bad in ["", "18..*", "18.8.x", "18.*x", "18.8.-1"] {
        assert!(
            bad.parse::<VersionGlob>().is_err(),
            "{bad:?} must not parse as a version glob"
        );
    }

    let error = "18.x".parse::<VersionGlob>().expect_err("bad glob segment");
    assert!(
        matches!(error, VersionGlobError::InvalidSegment { .. }),
        "unexpected error: {error}"
    );
}

// Resolver ------------------------------------------------------------------

#[test]
fn all_versions_clears_global_floor() {
    let mut config = config_with(
        vec![policy("omnibus-toolchain", "omnibus-toolchain", "stable")],
        Some("18"),
    );
    config.projects[0].all_versions = true;

    let scope = config.resolve(&ScopeArgs::default()).expect("resolves");
    let resolved = &scope.policies[0];

    assert_eq!(resolved.min_version, None);
    assert!(resolved.all_versions);
    assert!(resolved.allows_version(&v("17.1.0")));
    assert!(resolved.allows_version(&v("10.0.0")));

    // Without the flag the same policy keeps the global floor.
    let mut strict = config.clone();
    strict.projects[0].all_versions = false;
    let scope = strict.resolve(&ScopeArgs::default()).expect("resolves");
    assert!(!scope.policies[0].allows_version(&v("17.1.0")));
    assert!(scope.policies[0].allows_version(&v("18.0.0")));
}

#[test]
fn own_floor_survives_all_versions_and_beats_the_global_floor() {
    let mut config = config_with(vec![policy("cinc-stable", "cinc", "stable")], Some("18"));
    config.projects[0].all_versions = true;
    config.projects[0].min_version = Some("17".to_string());

    let scope = config.resolve(&ScopeArgs::default()).expect("resolves");
    let resolved = &scope.policies[0];

    assert_eq!(resolved.min_version, Some(v("17")));
    assert!(resolved.allows_version(&v("17.0.0")));
    assert!(!resolved.allows_version(&v("16.9.0")));
}

#[test]
fn cli_min_version_narrows_only() {
    let config = config_with(vec![policy("cinc-stable", "cinc", "stable")], Some("18"));
    let mut project = config.clone();
    project.projects[0].min_version = Some("19".to_string());

    let raised = project
        .resolve(&ScopeArgs {
            min_version: Some("19.2".to_string()),
            ..ScopeArgs::default()
        })
        .expect("resolves");
    assert_eq!(raised.policies[0].min_version, Some(v("19.2")));
    assert!(!raised.policies[0].allows_version(&v("19.1.0")));
    assert!(raised.policies[0].allows_version(&v("19.2.0")));

    let lowered = project
        .resolve(&ScopeArgs {
            min_version: Some("18".to_string()),
            ..ScopeArgs::default()
        })
        .expect("resolves");
    assert_eq!(lowered.policies[0].min_version, Some(v("19")));

    let own_floor = project
        .resolve(&ScopeArgs {
            min_version: Some("19.1".to_string()),
            ..ScopeArgs::default()
        })
        .expect("resolves");
    assert_eq!(own_floor.policies[0].min_version, Some(v("19.1")));
}

#[test]
fn cli_all_versions_clears_bounds() {
    let mut config = config_with(vec![policy("cinc-stable", "cinc", "stable")], Some("18"));
    config.projects[0].min_version = Some("19".to_string());
    config.projects[0].max_version = Some("19.10.0".to_string());

    let scope = config
        .resolve(&ScopeArgs {
            all_versions: true,
            ..ScopeArgs::default()
        })
        .expect("resolves");
    let resolved = &scope.policies[0];

    assert_eq!(resolved.min_version, None);
    assert_eq!(resolved.max_version, None);
    assert!(resolved.all_versions);
    assert!(resolved.allows_version(&v("10.0.0")));
    assert!(resolved.allows_version(&v("20.0.0")));
}

#[test]
fn everything_plus_project_is_usage_error() {
    let config = config_with(vec![policy("cinc-stable", "cinc", "stable")], None);

    let error = config
        .resolve(&ScopeArgs {
            everything: true,
            projects: vec!["cinc".to_string()],
            ..ScopeArgs::default()
        })
        .expect_err("--everything and --project are mutually exclusive");

    assert!(
        matches!(error, ScopeError::EverythingWithProject { ref project } if project == "cinc"),
        "unexpected error: {error}"
    );
}

#[test]
fn project_name_selects_all_its_policies() {
    let config = config_with(
        vec![
            policy("cinc-stable", "cinc", "stable"),
            policy("cinc-auditor", "cinc-auditor", "stable"),
            policy("cinc-unstable", "cinc", "unstable"),
        ],
        None,
    );

    let scope = config
        .resolve(&ScopeArgs {
            projects: vec!["cinc".to_string()],
            ..ScopeArgs::default()
        })
        .expect("resolves");

    let ids: Vec<_> = scope.policies.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["cinc-stable", "cinc-unstable"]);

    let scope = config
        .resolve(&ScopeArgs {
            projects: vec!["cinc-auditor".to_string()],
            ..ScopeArgs::default()
        })
        .expect("resolves");
    let ids: Vec<_> = scope.policies.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["cinc-auditor"]);
}

#[test]
fn policy_id_match_wins_over_a_project_name() {
    let config = config_with(
        vec![
            policy("cinc", "legacy", "stable"),
            policy("other", "cinc", "stable"),
        ],
        None,
    );

    let scope = config
        .resolve(&ScopeArgs {
            projects: vec!["cinc".to_string()],
            ..ScopeArgs::default()
        })
        .expect("resolves");

    let ids: Vec<_> = scope.policies.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["cinc"]);
}

#[test]
fn unknown_project_selector_is_an_error() {
    let config = config_with(vec![policy("cinc-stable", "cinc", "stable")], None);

    let error = config
        .resolve(&ScopeArgs {
            projects: vec!["nope".to_string()],
            ..ScopeArgs::default()
        })
        .expect_err("a typo must not resolve to nothing silently");

    assert!(
        matches!(error, ScopeError::UnknownProject { ref selector } if selector == "nope"),
        "unexpected error: {error}"
    );
}

#[test]
fn set_applies_before_cli_intersection() {
    let mut config = config_with(vec![policy("cinc-stable", "cinc", "stable")], None);
    config
        .apply_overrides(&["cinc-stable.min_version=19.5".to_string()])
        .expect("override applies");

    let scope = config
        .resolve(&ScopeArgs {
            min_version: Some("19.2".to_string()),
            ..ScopeArgs::default()
        })
        .expect("resolves");

    assert_eq!(scope.policies[0].min_version, Some(v("19.5")));
}

#[test]
fn cli_filters_intersect_versions_platforms_and_arches() {
    let mut config = config_with(vec![policy("cinc-stable", "cinc", "stable")], None);
    config.projects[0].versions = vec!["19.*".to_string()];
    config.projects[0].platforms = only(&["debian", "ubuntu"]);
    config.projects[0].arches = only(&["amd64", "arm64"]);

    let scope = config
        .resolve(&ScopeArgs {
            versions: vec!["19.4.*".to_string()],
            platforms: vec!["ubuntu".to_string()],
            arches: vec!["arm64".to_string()],
            ..ScopeArgs::default()
        })
        .expect("resolves");
    let resolved = &scope.policies[0];

    assert!(resolved.allows_version(&v("19.4.46")));
    assert!(!resolved.allows_version(&v("19.10.0")));
    assert!(!resolved.allows_version(&v("18.4.0")));
    assert_eq!(resolved.platforms, only(&["ubuntu"]));
    assert!(resolved.allows_platform("ubuntu"));
    assert!(!resolved.allows_platform("debian"));
    assert_eq!(resolved.arches, only(&["arm64"]));
    assert!(resolved.allows_arch("arm64"));
    assert!(!resolved.allows_arch("amd64"));
}

#[test]
fn cli_filter_can_empty_a_selection() {
    let mut config = config_with(vec![policy("cinc-stable", "cinc", "stable")], None);
    config.projects[0].platforms = only(&["debian", "ubuntu"]);

    let scope = config
        .resolve(&ScopeArgs {
            platforms: vec!["windows".to_string()],
            ..ScopeArgs::default()
        })
        .expect("resolves");

    assert_eq!(scope.policies[0].platforms, only(&[]));
    assert!(!scope.policies[0].allows_platform("debian"));
}

#[test]
fn platform_versions_intersect() {
    let mut config = config_with(vec![policy("cinc-stable", "cinc", "stable")], None);
    config.projects[0].platforms = Selection::All;
    config.projects[0].platform_versions = BTreeMap::from([(
        "debian".to_string(),
        vec!["12".to_string(), "13".to_string()],
    )]);

    let scope = config
        .resolve(&ScopeArgs {
            platform_versions: vec!["debian/13".to_string(), "ubuntu/22.04".to_string()],
            ..ScopeArgs::default()
        })
        .expect("resolves");
    let resolved = &scope.policies[0];

    assert!(resolved.allows_platform_version("debian", "13"));
    assert!(!resolved.allows_platform_version("debian", "12"));
    assert!(resolved.allows_platform_version("ubuntu", "22.04"));
    assert!(!resolved.allows_platform_version("ubuntu", "20.04"));
    assert!(!resolved.allows_platform_version("el", "9"));

    // Without the CLI filter the policy map is the only restriction.
    let scope = config.resolve(&ScopeArgs::default()).expect("resolves");
    let resolved = &scope.policies[0];
    assert!(resolved.allows_platform_version("debian", "12"));
    assert!(resolved.allows_platform_version("el", "9"));
}

#[test]
fn bare_platform_version_filter_matches_any_platform() {
    let mut config = config_with(vec![policy("cinc-stable", "cinc", "stable")], None);
    config.projects[0].platform_versions = BTreeMap::from([(
        "debian".to_string(),
        vec!["12".to_string(), "13".to_string()],
    )]);

    let scope = config
        .resolve(&ScopeArgs {
            platform_versions: vec!["13".to_string()],
            ..ScopeArgs::default()
        })
        .expect("resolves");
    let resolved = &scope.policies[0];

    assert!(resolved.allows_platform_version("debian", "13"));
    assert!(resolved.allows_platform_version("ubuntu", "13"));
    assert!(!resolved.allows_platform_version("debian", "12"));
}

#[test]
fn malformed_platform_version_filter_is_an_error() {
    let config = config_with(vec![policy("cinc-stable", "cinc", "stable")], None);

    let error = config
        .resolve(&ScopeArgs {
            platform_versions: vec!["debian/".to_string()],
            ..ScopeArgs::default()
        })
        .expect_err("an empty version is not a filter");

    assert!(
        matches!(
            error,
            ScopeError::InvalidPlatformVersion { ref value } if value == "debian/"
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn cli_floor_above_policy_ceiling_is_an_error() {
    let mut config = config_with(vec![policy("cinc-stable", "cinc", "stable")], None);
    config.projects[0].max_version = Some("19.10.0".to_string());

    let error = config
        .resolve(&ScopeArgs {
            min_version: Some("20".to_string()),
            ..ScopeArgs::default()
        })
        .expect_err("a floor above the ceiling selects nothing by mistake");

    assert!(
        matches!(
            error,
            ScopeError::MinAboveMax { ref policy_id, ref min, ref max }
                if policy_id == "cinc-stable" && min == "20" && max == "19.10.0"
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn disabled_policies_are_skipped_unless_named() {
    let mut config = config_with(
        vec![
            policy("cinc-stable", "cinc", "stable"),
            policy("cinc-auditor", "cinc-auditor", "stable"),
        ],
        None,
    );
    config.projects[0].enabled = false;

    let default_scope = config.resolve(&ScopeArgs::default()).expect("resolves");
    let ids: Vec<_> = default_scope
        .policies
        .iter()
        .map(|p| p.id.as_str())
        .collect();
    assert_eq!(ids, ["cinc-auditor"]);

    let everything = config
        .resolve(&ScopeArgs {
            everything: true,
            ..ScopeArgs::default()
        })
        .expect("resolves");
    let ids: Vec<_> = everything.policies.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["cinc-auditor"]);

    let named = config
        .resolve(&ScopeArgs {
            projects: vec!["cinc-stable".to_string()],
            ..ScopeArgs::default()
        })
        .expect("explicit selection reaches a disabled policy");
    let ids: Vec<_> = named.policies.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["cinc-stable"]);
}

#[test]
fn resolution_keeps_config_order() {
    let config = config_with(
        vec![
            policy("zulu", "zulu", "stable"),
            policy("alpha", "alpha", "stable"),
            policy("mike", "mike", "stable"),
        ],
        None,
    );

    let scope = config
        .resolve(&ScopeArgs {
            everything: true,
            ..ScopeArgs::default()
        })
        .expect("resolves");

    let ids: Vec<_> = scope.policies.iter().map(|p| p.id.as_str()).collect();
    assert_eq!(ids, ["zulu", "alpha", "mike"]);
}

#[test]
fn max_version_bounds_versions() {
    let mut config = config_with(vec![policy("cinc-stable", "cinc", "stable")], None);
    config.projects[0].max_version = Some("19.10.0".to_string());

    let scope = config.resolve(&ScopeArgs::default()).expect("resolves");
    let resolved = &scope.policies[0];

    assert_eq!(resolved.max_version, Some(v("19.10.0")));
    assert!(resolved.allows_version(&v("19.10.0")));
    assert!(!resolved.allows_version(&v("19.10.1")));
}

#[test]
fn resolve_reports_malformed_policy_globs() {
    let mut config = config_with(vec![policy("cinc-stable", "cinc", "stable")], None);
    config.projects[0].versions = vec!["19..*".to_string()];

    let error = config
        .resolve(&ScopeArgs::default())
        .expect_err("an unvalidated glob is still an error at resolution");

    assert!(
        matches!(
            error,
            ScopeError::InvalidVersionGlob(VersionGlobError::EmptySegment { ref value })
                if value == "19..*"
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn policy_versions_globs_still_apply_without_cli_filters() {
    let mut config = config_with(vec![policy("cinc-stable", "cinc", "stable")], None);
    config.projects[0].versions = vec!["18.8.*".to_string()];

    let scope = config.resolve(&ScopeArgs::default()).expect("resolves");
    let resolved = &scope.policies[0];

    assert!(resolved.allows_version(&v("18.8.11")));
    assert!(!resolved.allows_version(&v("18.9.1")));
}
