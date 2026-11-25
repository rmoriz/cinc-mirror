//! rsync target tests.
//!
//! The address and argv tests are pure: they pin exactly what would be
//! executed, so a missing `-e`, host-key option or identity file fails here
//! rather than on a production mirror. The upload tests drive the real `rsync`
//! binary against a local temporary directory, because the interesting
//! behaviour is what rsync actually writes: the package, the verbatim
//! `metadata.json` and the `<basename>.sha256` commit marker.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

use cinc_mirror::artifact::{Artifact, ArtifactContext, ArtifactInput};
use cinc_mirror::config::{Config, TargetAuth, TargetConfig, TargetKind};
use cinc_mirror::targets::{
    RsyncAddress, RsyncConfig, RsyncTarget, Target, TargetError, TargetSet,
};
use sha2::{Digest, Sha256};

const BASENAME: &str = "cinc_19.4.46-1_amd64.deb";

/// Fail loudly when the machine has no `rsync`; a silently skipped integration
/// test would let the upload path rot.
fn require_rsync() {
    match Command::new("rsync").arg("--version").output() {
        Ok(output) if output.status.success() => {}
        Ok(output) => panic!(
            "rsync is required for the rsync target tests but `rsync --version` failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ),
        Err(error) => panic!("rsync is required for the rsync target tests: {error}"),
    }
}

fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

fn artifact_for(bytes: &[u8]) -> Artifact {
    artifact_with_basename(bytes, BASENAME)
}

fn artifact_with_basename(bytes: &[u8], basename: &str) -> Artifact {
    let sha256 = sha256_hex(bytes);
    let metadata = format!(
        r#"{{
  "basename": "{basename}",
  "sha256": "{sha256}",
  "platform": "debian",
  "platform_version": "13",
  "arch": "x86_64",
  "version": "19.4.46",
  "iteration": 1
}}"#
    );
    Artifact::new(
        &ArtifactContext {
            channel: "stable".to_string(),
            project: "cinc".to_string(),
            version: "19.4.46".to_string(),
            platform: "debian".to_string(),
            platform_version: "13".to_string(),
        },
        ArtifactInput {
            basename: basename.to_string(),
            sha256,
            metadata_json: metadata,
            platform: "debian".to_string(),
            platform_version: "13".to_string(),
            version: "19.4.46".to_string(),
            iteration: Some("1".to_string()),
            raw_arch: "x86_64".to_string(),
        },
    )
    .expect("artifact")
}

fn write_package(dir: &Path, bytes: &[u8]) -> PathBuf {
    let path = dir.join(BASENAME);
    std::fs::write(&path, bytes).expect("write package");
    path
}

fn local_target(root: &Path) -> RsyncTarget {
    RsyncTarget::new(RsyncConfig {
        name: "local".to_string(),
        url: root.to_string_lossy().into_owned(),
        auth: TargetAuth::Anonymous,
        identity_file: None,
        password_file: None,
    })
    .expect("local rsync target")
}

fn ssh_target(identity: Option<&Path>) -> RsyncTarget {
    RsyncTarget::new(RsyncConfig {
        name: "ssh".to_string(),
        url: "ssh://mirror@backup.example.org:2222/srv/cinc-mirror".to_string(),
        auth: TargetAuth::SshKey,
        identity_file: identity.map(Path::to_path_buf),
        password_file: None,
    })
    .expect("ssh rsync target")
}

fn daemon_target() -> RsyncTarget {
    RsyncTarget::new(RsyncConfig {
        name: "daemon".to_string(),
        url: "rsync://backup.example.org:873/cinc".to_string(),
        auth: TargetAuth::Daemon,
        identity_file: None,
        password_file: None,
    })
    .expect("daemon rsync target")
}

fn relative_dir(artifact: &Artifact) -> String {
    let relpath = artifact.rsync_relpath();
    relpath
        .rsplit_once('/')
        .map(|(dir, _)| dir.to_string())
        .expect("relpath has a directory")
}

fn published_dir(root: &Path, artifact: &Artifact) -> PathBuf {
    root.join(relative_dir(artifact))
}

fn sidecar_path(root: &Path, artifact: &Artifact) -> PathBuf {
    published_dir(root, artifact).join(format!("{BASENAME}.sha256"))
}

fn modified(path: &Path) -> SystemTime {
    std::fs::metadata(path)
        .unwrap_or_else(|error| panic!("metadata for {}: {error}", path.display()))
        .modified()
        .expect("mtime")
}

// Address parsing -----------------------------------------------------------

#[test]
fn parses_ssh_and_daemon_addresses() {
    assert_eq!(
        RsyncAddress::parse("ssh://u@h:22/p").expect("ssh address"),
        RsyncAddress::Ssh {
            user: Some("u".to_string()),
            host: "h".to_string(),
            port: Some(22),
            path: "/p".to_string(),
        }
    );

    assert_eq!(
        RsyncAddress::parse("rsync://h/mod").expect("daemon address"),
        RsyncAddress::Daemon {
            host: "h".to_string(),
            port: None,
            module: "mod".to_string(),
            path: String::new(),
        }
    );

    assert_eq!(
        RsyncAddress::parse("/srv/cinc").expect("local address"),
        RsyncAddress::Local {
            path: PathBuf::from("/srv/cinc"),
        }
    );
}

#[test]
fn rejects_addresses_it_cannot_use() {
    for bad in [
        "ftp://h/p",
        "ssh://h",
        "rsync://h",
        "ssh://user:secret@h/p",
        "ssh://h/p?query=1",
    ] {
        let error = RsyncAddress::parse(bad).expect_err(bad);
        assert!(
            matches!(error, TargetError::InvalidAddress { .. }),
            "{bad}: expected InvalidAddress, got {error:?}"
        );
    }
}

// Argv construction ---------------------------------------------------------

#[test]
fn ssh_address_uses_strict_host_key_and_batch_mode() {
    let artifact = artifact_for(b"package bytes");
    let target = ssh_target(Some(Path::new("/keys/id_ed25519")));

    let args = target.rsync_args(&artifact);

    let rsh = args
        .iter()
        .position(|arg| arg == "-e")
        .map(|index| args.get(index + 1).expect("value after -e"))
        .expect("ssh form must pass -e");
    for expected in [
        "ssh",
        "-p 2222",
        "-o BatchMode=yes",
        "-o StrictHostKeyChecking=yes",
        "-i '/keys/id_ed25519'",
    ] {
        assert!(
            rsh.contains(expected),
            "`-e` value `{rsh}` lacks `{expected}`"
        );
    }

    assert!(
        args.iter().any(|arg| arg == "-s"),
        "the remote path must be protected from the remote shell: {args:?}"
    );
    assert!(args.iter().any(|arg| arg == "--partial-dir=.rsync-partial"));
    assert_eq!(
        args.last().expect("destination"),
        &format!(
            "mirror@backup.example.org:/srv/cinc-mirror/{}",
            artifact.rsync_relpath()
        )
    );
}

#[test]
fn ssh_without_identity_file_has_no_dash_i() {
    let artifact = artifact_for(b"package bytes");
    let args = ssh_target(None).rsync_args(&artifact);
    let rsh = args
        .iter()
        .position(|arg| arg == "-e")
        .map(|index| args.get(index + 1).expect("value after -e"))
        .expect("-e");
    assert!(!rsh.contains(" -i "), "unexpected identity flag in `{rsh}`");
    assert!(rsh.contains("-o BatchMode=yes"));
    assert!(rsh.contains("-o StrictHostKeyChecking=yes"));
}

#[test]
fn daemon_address_does_not_use_ssh() {
    let artifact = artifact_for(b"package bytes");
    let args = daemon_target().rsync_args(&artifact);

    assert!(
        !args.iter().any(|arg| arg == "-e"),
        "a daemon transfer must not invoke ssh: {args:?}"
    );
    assert!(
        args.iter().any(|arg| arg == "-s"),
        "the remote path must be protected from the remote shell: {args:?}"
    );
    assert!(args.iter().any(|arg| arg == "--mkpath"));
    assert!(args.iter().any(|arg| arg == "--partial-dir=.rsync-partial"));
    assert_eq!(
        args.last().expect("destination"),
        &format!(
            "rsync://backup.example.org:873/cinc/{}",
            artifact.rsync_relpath()
        )
    );
}

#[test]
fn local_address_argument_is_a_plain_path() {
    let artifact = artifact_for(b"package bytes");
    let root = Path::new("/srv/cinc");
    let args = local_target(root).rsync_args(&artifact);

    assert!(!args.iter().any(|arg| arg == "-e"));
    assert!(!args.iter().any(|arg| arg == "--mkpath"));
    assert_eq!(
        args.last().expect("destination"),
        &root.join(artifact.rsync_relpath()).to_string_lossy()
    );
}

// Local uploads with the real rsync binary ----------------------------------

#[tokio::test]
async fn fresh_upload_writes_package_metadata_and_sidecar() {
    require_rsync();

    let source = tempfile::tempdir().expect("source dir");
    let root = tempfile::tempdir().expect("target dir");
    let bytes = b"the verified package bytes";
    let artifact = artifact_for(bytes);
    let package = write_package(source.path(), bytes);

    let target = local_target(root.path());
    let outcome = target.put(&artifact, &package).await.expect("put");

    assert_eq!(outcome.remote_digest, artifact.sha256);
    assert_eq!(
        outcome.remote_ref,
        root.path().join(artifact.rsync_relpath()).to_string_lossy()
    );

    let dir = published_dir(root.path(), &artifact);
    assert_eq!(
        std::fs::read(dir.join(BASENAME)).expect("package"),
        bytes,
        "the package lands at its upstream-shaped path"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join("metadata.json")).expect("metadata"),
        artifact.metadata_json,
        "the upstream document is published byte for byte"
    );

    let sidecar = std::fs::read_to_string(sidecar_path(root.path(), &artifact)).expect("sidecar");
    assert_eq!(
        sidecar,
        format!("{}  {}\n", artifact.sha256, bytes.len()),
        "the sidecar is `<sha256>  <size>\\n`, two spaces"
    );

    assert!(
        !dir.join(".rsync-partial").exists(),
        "a complete upload leaves no partial directory"
    );
}

#[tokio::test]
async fn local_upload_handles_a_metacharacter_basename() {
    require_rsync();

    let source = tempfile::tempdir().expect("source dir");
    let root = tempfile::tempdir().expect("target dir");
    let bytes = b"the verified package bytes";
    let basename = "pkg ;$(id)'q.deb";
    let artifact = artifact_with_basename(bytes, basename);
    let package = source.path().join(basename);
    std::fs::write(&package, bytes).expect("write package");
    let target = local_target(root.path());

    let outcome = target.put(&artifact, &package).await.expect("put");

    let dir = published_dir(root.path(), &artifact);
    assert_eq!(
        std::fs::read(dir.join(basename)).expect("package"),
        bytes,
        "local paths are argv, so metacharacters stay literal"
    );
    assert_eq!(
        std::fs::read_to_string(dir.join(format!("{basename}.sha256"))).expect("sidecar"),
        format!("{}  {}\n", artifact.sha256, bytes.len())
    );
    assert_eq!(outcome.remote_digest, artifact.sha256);
    target.verify(&artifact).await.expect("verify");
}

#[tokio::test]
async fn same_bytes_are_not_rewritten() {
    require_rsync();

    let source = tempfile::tempdir().expect("source dir");
    let root = tempfile::tempdir().expect("target dir");
    let bytes = b"the verified package bytes";
    let artifact = artifact_for(bytes);
    let package = write_package(source.path(), bytes);
    let target = local_target(root.path());

    target.put(&artifact, &package).await.expect("first put");

    let dir = published_dir(root.path(), &artifact);
    let package_mtime = modified(&dir.join(BASENAME));
    let sidecar_mtime = modified(&sidecar_path(root.path(), &artifact));
    let dir_mtime = modified(&dir);

    let outcome = target.put(&artifact, &package).await.expect("second put");

    assert_eq!(outcome.remote_digest, artifact.sha256);
    assert_eq!(
        modified(&dir.join(BASENAME)),
        package_mtime,
        "an identical package must not be transferred again"
    );
    assert_eq!(
        modified(&sidecar_path(root.path(), &artifact)),
        sidecar_mtime,
        "the commit marker must be left untouched"
    );
    assert_eq!(
        modified(&dir),
        dir_mtime,
        "not even a temp file may be renamed into the directory"
    );
}

#[tokio::test]
async fn different_bytes_under_the_same_name_are_refused() {
    require_rsync();

    let source = tempfile::tempdir().expect("source dir");
    let root = tempfile::tempdir().expect("target dir");
    let original = b"the published bytes";
    let artifact = artifact_for(original);
    let package = write_package(source.path(), original);
    let target = local_target(root.path());
    target.put(&artifact, &package).await.expect("first put");

    let replacement = b"different bytes at the same coordinates";
    let conflicting = artifact_for(replacement);
    let replacement_path = write_package(source.path(), replacement);

    let error = target
        .put(&conflicting, &replacement_path)
        .await
        .expect_err("a different package under the same name must be refused");
    match error {
        TargetError::TagConflict {
            existing, incoming, ..
        } => {
            assert_eq!(existing, artifact.sha256);
            assert_eq!(incoming, conflicting.sha256);
        }
        other => panic!("expected TagConflict, got {other:?}"),
    }

    let dir = published_dir(root.path(), &artifact);
    assert_eq!(
        std::fs::read(dir.join(BASENAME)).expect("package"),
        original,
        "the original bytes stay intact"
    );
    assert_eq!(
        std::fs::read_to_string(sidecar_path(root.path(), &artifact)).expect("sidecar"),
        format!("{}  {}\n", artifact.sha256, original.len()),
        "the sidecar keeps naming the original package"
    );
}

#[tokio::test]
async fn exists_reads_the_sidecar() {
    require_rsync();

    let source = tempfile::tempdir().expect("source dir");
    let root = tempfile::tempdir().expect("target dir");
    let bytes = b"the verified package bytes";
    let artifact = artifact_for(bytes);
    let package = write_package(source.path(), bytes);
    let target = local_target(root.path());

    assert_eq!(target.exists(&artifact).await.expect("missing"), None);

    target.put(&artifact, &package).await.expect("put");
    assert_eq!(
        target.exists(&artifact).await.expect("exists"),
        Some(artifact.sha256.clone())
    );
}

#[tokio::test]
async fn verify_accepts_the_publication_that_put_wrote() {
    require_rsync();

    let source = tempfile::tempdir().expect("source dir");
    let root = tempfile::tempdir().expect("target dir");
    let bytes = b"the verified package bytes";
    let artifact = artifact_for(bytes);
    let package = write_package(source.path(), bytes);
    let target = local_target(root.path());

    target.put(&artifact, &package).await.expect("put");
    target.verify(&artifact).await.expect("verify");
}

#[tokio::test]
async fn verify_rejects_a_missing_package_behind_a_valid_sidecar() {
    require_rsync();

    let source = tempfile::tempdir().expect("source dir");
    let root = tempfile::tempdir().expect("target dir");
    let bytes = b"the verified package bytes";
    let artifact = artifact_for(bytes);
    let package = write_package(source.path(), bytes);
    let target = local_target(root.path());

    target.put(&artifact, &package).await.expect("put");
    std::fs::remove_file(published_dir(root.path(), &artifact).join(BASENAME))
        .expect("delete package");

    let error = target
        .verify(&artifact)
        .await
        .expect_err("a sidecar without a package is incomplete");
    assert!(
        matches!(error, TargetError::NotPublished { .. }),
        "expected NotPublished, got {error:?}"
    );
}

#[tokio::test]
async fn a_corrupt_sidecar_is_an_error_not_a_miss() {
    require_rsync();

    let source = tempfile::tempdir().expect("source dir");
    let root = tempfile::tempdir().expect("target dir");
    let bytes = b"the verified package bytes";
    let artifact = artifact_for(bytes);
    let package = write_package(source.path(), bytes);
    let target = local_target(root.path());

    target.put(&artifact, &package).await.expect("put");
    std::fs::write(sidecar_path(root.path(), &artifact), "not-a-digest\n")
        .expect("corrupt sidecar");

    let error = target
        .exists(&artifact)
        .await
        .expect_err("a malformed sidecar is corrupt, not absent");
    assert!(
        matches!(error, TargetError::Corrupt { .. }),
        "expected Corrupt, got {error:?}"
    );

    let error = target
        .verify(&artifact)
        .await
        .expect_err("verify must not accept a malformed sidecar");
    assert!(
        matches!(error, TargetError::Corrupt { .. }),
        "expected Corrupt, got {error:?}"
    );
}

#[tokio::test]
async fn verify_reports_a_conflict_for_a_different_package() {
    require_rsync();

    let source = tempfile::tempdir().expect("source dir");
    let root = tempfile::tempdir().expect("target dir");
    let published = b"the published bytes";
    let artifact = artifact_for(published);
    let package = write_package(source.path(), published);
    let target = local_target(root.path());
    target.put(&artifact, &package).await.expect("put");

    let different = artifact_for(b"different bytes at the same coordinates");
    let error = target
        .verify(&different)
        .await
        .expect_err("the sidecar names different bytes");
    match error {
        TargetError::TagConflict {
            existing, incoming, ..
        } if existing == artifact.sha256 && incoming == different.sha256 => {}
        other => panic!("unexpected error: {other:?}"),
    }
}

// Target set ----------------------------------------------------------------

#[tokio::test]
async fn target_set_builds_rsync_targets_in_config_order() {
    let first = tempfile::tempdir().expect("first root");
    let second = tempfile::tempdir().expect("second root");
    let target = |name: &str, root: &Path, enabled: bool| TargetConfig {
        name: name.to_string(),
        kind: TargetKind::Rsync,
        enabled,
        registry: None,
        namespace: None,
        url: Some(root.to_string_lossy().into_owned()),
        auth: TargetAuth::Anonymous,
        max_bandwidth: None,
        identity_file: None,
        password_file: None,
    };
    let config = Config {
        targets: vec![
            target("first", first.path(), true),
            target("disabled", first.path(), false),
            target("second", second.path(), true),
        ],
        ..Config::default()
    };

    let set = TargetSet::from_config(&config).expect("target set");
    let names: Vec<&str> = set.all().iter().map(|target| target.name()).collect();
    assert_eq!(names, vec!["first", "second"]);
}
