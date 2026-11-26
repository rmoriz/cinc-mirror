//! Artifact identity, tag and rsync path tests.
//!
//! The artifact is the unit every later layer keys on: the ledger, the store,
//! the OCI tag and the rsync path all derive from these values, so the tests
//! pin the exact upstream names (`cinc_19.4.46-1_amd64.deb`,
//! `cinc-19.4.46-2-x64.msi`) rather than approximations.

use cinc_mirror::artifact::{
    mapped_arch, sanitize_component, Artifact, ArtifactContext, ArtifactError, ArtifactInput,
    ARTIFACT_TYPE,
};

const SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const OTHER_SHA: &str = "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210";
const SHA12: &str = "0123456789ab";

fn context(version: &str, platform: &str, platform_version: &str) -> ArtifactContext {
    ArtifactContext {
        channel: "stable".to_string(),
        project: "cinc".to_string(),
        version: version.to_string(),
        platform: platform.to_string(),
        platform_version: platform_version.to_string(),
    }
}

fn input(basename: &str, sha256: &str, raw_arch: &str, iteration: Option<&str>) -> ArtifactInput {
    ArtifactInput {
        basename: basename.to_string(),
        sha256: sha256.to_string(),
        metadata_json: format!(r#"{{"basename":"{basename}","sha256":"{sha256}","iteration":1}}"#),
        platform: "debian".to_string(),
        platform_version: "13".to_string(),
        version: "19.4.46".to_string(),
        iteration: iteration.map(ToString::to_string),
        raw_arch: raw_arch.to_string(),
    }
}

fn debian_artifact(sha256: &str, iteration: Option<&str>) -> Artifact {
    Artifact::new(
        &context("19.4.46", "debian", "13"),
        input("cinc_19.4.46-1_amd64.deb", sha256, "x86_64", iteration),
    )
    .expect("valid artifact")
}

// Metadata document ---------------------------------------------------------

#[test]
fn keeps_the_exact_upstream_metadata_document() {
    let raw = r#"{
  "basename": "cinc_19.4.46-1_amd64.deb",
  "sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "sha512": "cross-check",
  "unknown": {"nested": [1, 2]},
  "iteration": 1
}"#;
    let artifact = Artifact::new(
        &context("19.4.46", "debian", "13"),
        ArtifactInput {
            metadata_json: raw.to_string(),
            ..input("cinc_19.4.46-1_amd64.deb", SHA, "x86_64", Some("1"))
        },
    )
    .expect("valid artifact");

    assert_eq!(artifact.metadata_json, raw);
}

// Arch mapping --------------------------------------------------------------

#[test]
fn maps_raw_arches() {
    assert_eq!(mapped_arch("x86_64"), "amd64");
    assert_eq!(mapped_arch("aarch64"), "arm64");
    assert_eq!(mapped_arch("armv7l"), "armv7");
    assert_eq!(mapped_arch("armv7hl"), "armv7");
    assert_eq!(mapped_arch("i386"), "386");
    assert_eq!(mapped_arch("i686"), "386");
}

#[test]
fn unknown_arches_pass_through_sanitised() {
    assert_eq!(mapped_arch("ppc64le"), "ppc64le");
    assert_eq!(mapped_arch("s390x"), "s390x");
    assert_eq!(mapped_arch("riscv64"), "riscv64");
    assert_eq!(mapped_arch("Weird Arch"), "weird_arch");
}

#[test]
fn sanitize_component_keeps_the_public_character_set() {
    assert_eq!(sanitize_component("Ubuntu"), "ubuntu");
    assert_eq!(sanitize_component("19.4.46+build:7"), "19.4.46_build_7");
    assert_eq!(sanitize_component("22.04-LTS_x"), "22.04-lts_x");
    assert_eq!(sanitize_component("a b\tc"), "a_b_c");
}

// Tags ----------------------------------------------------------------------

#[test]
fn iteration_one_keeps_legacy_tag() {
    let artifact = debian_artifact(SHA, Some("1"));
    assert_eq!(artifact.tag(), "19.4.46-debian-13-amd64");
}

#[test]
fn iteration_one_is_also_the_absent_iteration() {
    for iteration in [None, Some("0"), Some(""), Some(" "), Some("not-a-number")] {
        let artifact = debian_artifact(SHA, iteration);
        assert_eq!(
            artifact.tag(),
            "19.4.46-debian-13-amd64",
            "iteration {iteration:?} must not add a suffix"
        );
    }
}

#[test]
fn iteration_two_gets_suffix() {
    let artifact = Artifact::new(
        &context("19.4.46", "windows", "2022"),
        ArtifactInput {
            basename: "cinc-19.4.46-2-x64.msi".to_string(),
            sha256: SHA.to_string(),
            metadata_json: "{}".to_string(),
            platform: "windows".to_string(),
            platform_version: "2022".to_string(),
            version: "19.4.46".to_string(),
            iteration: Some("2".to_string()),
            raw_arch: "x86_64".to_string(),
        },
    )
    .expect("valid artifact");

    assert_eq!(artifact.tag(), "19.4.46-windows-2022-amd64-r2");
}

#[test]
fn superseded_tag_appends_the_marker() {
    let artifact = debian_artifact(SHA, Some("1"));
    assert_eq!(
        artifact.superseded_tag(),
        "19.4.46-debian-13-amd64-superseded"
    );
}

#[test]
fn a_digest_qualified_tag_keeps_the_prefix_and_ends_with_the_digest() {
    let mut artifact = debian_artifact(SHA, Some("1"));
    artifact.qualify_tag_with_digest();

    assert_eq!(
        artifact.tag(),
        format!("19.4.46-debian-13-amd64-{SHA12}"),
        "the readable prefix stays and the digest follows it"
    );
    assert_eq!(
        artifact.superseded_tag(),
        format!("19.4.46-debian-13-amd64-{SHA12}-superseded")
    );
    // The identity does not change with the publication reference.
    assert_eq!(artifact.key(), debian_artifact(SHA, Some("1")).key());
}

#[test]
fn sanitizes_and_caps_tag_length() {
    let artifact = Artifact::new(
        &context("19.4.46+build:7", "Debian GNU Linux", "13"),
        ArtifactInput {
            basename: "cinc_19.4.46-1_amd64.deb".to_string(),
            sha256: SHA.to_string(),
            metadata_json: "{}".to_string(),
            platform: "Debian GNU Linux".to_string(),
            platform_version: "13".to_string(),
            version: "19.4.46+build:7".to_string(),
            iteration: None,
            raw_arch: "x86_64".to_string(),
        },
    )
    .expect("valid artifact");

    assert_eq!(artifact.tag(), "19.4.46_build_7-debian_gnu_linux-13-amd64");

    let long = Artifact::new(
        &context("19.4.46", &"platform".repeat(40), "13"),
        ArtifactInput {
            basename: "cinc_19.4.46-1_amd64.deb".to_string(),
            sha256: SHA.to_string(),
            metadata_json: "{}".to_string(),
            platform: "platform".repeat(40),
            platform_version: "13".to_string(),
            version: "19.4.46".to_string(),
            iteration: None,
            raw_arch: "x86_64".to_string(),
        },
    )
    .expect("valid artifact");

    let tag = long.tag();
    assert_eq!(tag.len(), 128, "cap must keep exactly 128 bytes: {tag}");
    assert!(
        tag.ends_with(&format!("-{SHA12}")),
        "capped tag must keep the sha suffix: {tag}"
    );
    assert!(
        tag.chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || "._-".contains(ch)),
        "capped tag must stay in the public character set: {tag}"
    );
    assert!(long.superseded_tag().len() <= 128);
}

// Basenames, digests and context -------------------------------------------

#[test]
fn rejects_hostile_basename() {
    for basename in ["", ".", "..", "../../etc/passwd", "a/b.deb", "a\\b.deb"] {
        let error = Artifact::new(
            &context("19.4.46", "debian", "13"),
            input(basename, SHA, "x86_64", None),
        )
        .expect_err("hostile basename must be rejected");

        assert!(
            matches!(error, ArtifactError::InvalidBasename { .. }),
            "unexpected error for {basename:?}: {error}"
        );
    }
}

#[test]
fn digest_must_be_64_hex_and_is_lowercased() {
    for bad in ["", "abc", &"g".repeat(64), &SHA[..63], &format!("{SHA}0")] {
        let error = Artifact::new(
            &context("19.4.46", "debian", "13"),
            input("cinc_19.4.46-1_amd64.deb", bad, "x86_64", None),
        )
        .expect_err("invalid digest must be rejected");

        assert!(
            matches!(error, ArtifactError::InvalidSha256 { .. }),
            "unexpected error for {bad:?}: {error}"
        );
    }

    let artifact = debian_artifact(&SHA.to_uppercase(), None);
    assert_eq!(artifact.sha256, SHA);
}

#[test]
fn rejects_component_that_does_not_match_the_context() {
    for (field, input) in [
        (
            "platform",
            ArtifactInput {
                platform: "ubuntu".to_string(),
                ..input("cinc_19.4.46-1_amd64.deb", SHA, "x86_64", None)
            },
        ),
        (
            "platform_version",
            ArtifactInput {
                platform_version: "12".to_string(),
                ..input("cinc_19.4.46-1_amd64.deb", SHA, "x86_64", None)
            },
        ),
        (
            "version",
            ArtifactInput {
                version: "19.4.47".to_string(),
                ..input("cinc_19.4.46-1_amd64.deb", SHA, "x86_64", None)
            },
        ),
    ] {
        let error = Artifact::new(&context("19.4.46", "debian", "13"), input)
            .expect_err("mismatch must be rejected");

        assert!(
            matches!(error, ArtifactError::ContextMismatch { field: reported, .. } if reported == field),
            "unexpected error for field {field}: {error}"
        );
    }
}

#[test]
fn rejects_unsafe_context_components() {
    for (field, context) in [
        (
            "channel",
            ArtifactContext {
                channel: "../stable".to_string(),
                ..context("19.4.46", "debian", "13")
            },
        ),
        (
            "project",
            ArtifactContext {
                project: String::new(),
                ..context("19.4.46", "debian", "13")
            },
        ),
        (
            "platform_version",
            ArtifactContext {
                platform_version: "13/14".to_string(),
                ..context("19.4.46", "debian", "13")
            },
        ),
    ] {
        let error = Artifact::new(
            &context,
            input("cinc_19.4.46-1_amd64.deb", SHA, "x86_64", None),
        )
        .expect_err("unsafe component must be rejected");

        assert!(
            matches!(error, ArtifactError::InvalidComponent { field: reported, .. } if reported == field),
            "unexpected error for field {field}: {error}"
        );
    }
}

// Key and rsync path --------------------------------------------------------

#[test]
fn key_is_channel_project_version_platform_arch_sha() {
    let artifact = debian_artifact(SHA, None);
    assert_eq!(
        artifact.key(),
        format!("stable/cinc/19.4.46/debian/13/amd64/{SHA}")
    );
}

#[test]
fn rsync_relpath_is_upstream_shaped() {
    let artifact = debian_artifact(SHA, Some("1"));
    assert_eq!(
        artifact.rsync_relpath(),
        "stable/cinc/19.4.46/debian/13/cinc_19.4.46-1_amd64.deb"
    );

    let windows = Artifact::new(
        &context("19.4.46", "windows", "2022"),
        ArtifactInput {
            basename: "cinc-19.4.46-2-x64.msi".to_string(),
            sha256: SHA.to_string(),
            metadata_json: "{}".to_string(),
            platform: "windows".to_string(),
            platform_version: "2022".to_string(),
            version: "19.4.46".to_string(),
            iteration: Some("2".to_string()),
            raw_arch: "x86_64".to_string(),
        },
    )
    .expect("valid artifact");

    assert_eq!(
        windows.rsync_relpath(),
        "stable/cinc/19.4.46/windows/2022/cinc-19.4.46-2-x64.msi"
    );
}

#[test]
fn artifact_type_names_the_package_manifest() {
    assert_eq!(ARTIFACT_TYPE, "application/vnd.cinc.package.v1+json");
}

// Collisions ----------------------------------------------------------------

#[test]
fn detects_tag_collision_between_two_artifacts() {
    let first = debian_artifact(SHA, None);
    let second = Artifact::new(
        &context("19.4.46", "debian", "13"),
        input("cinc_19.4.46-1_amd64.deb", OTHER_SHA, "x86_64", None),
    )
    .expect("valid artifact");

    let error = first
        .check_tag_collision(&second)
        .expect_err("same tag with different bytes must collide");
    assert!(
        matches!(error, ArtifactError::TagCollision { .. }),
        "unexpected error: {error}"
    );

    first
        .check_tag_collision(&debian_artifact(SHA, None))
        .expect("same tag and same bytes is a no-op");
    first
        .check_tag_collision(&debian_artifact(SHA, Some("2")))
        .expect("different tags never collide");
}
