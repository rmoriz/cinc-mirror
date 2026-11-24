//! Streaming multi-hash verification tests.
//!
//! SHA-256 is the gate; SHA-512, SHA-1 and MD5 are cross-checks against the
//! upstream metadata. The known vectors pin the exact lowercase hex output so a
//! swapped digest or a buffering bug fails here rather than at a target.

use std::io::Write as _;

use cinc_mirror::hash::{hash_file, hash_reader, ExpectedHashes, VerifyOutcome};
use cinc_mirror::source::metadata::{Metadata, MetadataError};
use sha2::{Digest, Sha256};

const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const ABC_SHA512: &str = "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a\
2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f";
const ABC_SHA1: &str = "a9993e364706816aba3e25717850c26c9cd0d89d";
const ABC_MD5: &str = "900150983cd24fb0d6963f7d28e17f72";

fn metadata_json() -> serde_json::Value {
    serde_json::json!({
        "basename": "cinc_19.4.46-1_amd64.deb",
        "sha256": ABC_SHA256,
        "sha512": ABC_SHA512,
        "sha1": ABC_SHA1,
        "md5": ABC_MD5,
        "platform": "debian",
        "platform_version": "13",
        "arch": "x86_64",
        "version": "19.4.46",
        "iteration": 2,
        "license": "Apache-2.0",
        "some_future_field": { "nested": true }
    })
}

fn write_temp(contents: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().expect("temp dir");
    let path = dir.path().join("payload");
    let mut file = std::fs::File::create(&path).expect("create payload");
    file.write_all(contents).expect("write payload");
    (dir, path)
}

#[test]
fn matches_known_vector() {
    let hashes = hash_reader(&b"abc"[..]).expect("hash reader");

    assert_eq!(hashes.sha256, ABC_SHA256);
    assert_eq!(hashes.sha512.as_deref(), Some(ABC_SHA512));
    assert_eq!(hashes.sha1.as_deref(), Some(ABC_SHA1));
    assert_eq!(hashes.md5.as_deref(), Some(ABC_MD5));
    assert_eq!(hashes.size, 3);
}

#[test]
fn hash_file_matches_hash_reader() {
    let (_dir, path) = write_temp(b"abc");
    let from_file = hash_file(&path).expect("hash file");
    let from_reader = hash_reader(&b"abc"[..]).expect("hash reader");

    assert_eq!(from_file, from_reader);
}

#[test]
fn streams_files_larger_than_one_buffer() {
    let contents: Vec<u8> = (0..(1024 * 1024 + 12_345))
        .map(|index| (index % 251) as u8)
        .collect();
    let expected = format!("{:x}", Sha256::digest(&contents));

    let (_dir, path) = write_temp(&contents);
    let hashes = hash_file(&path).expect("hash file");

    assert_eq!(hashes.size, contents.len() as u64);
    assert_eq!(hashes.sha256, expected);
}

#[test]
fn size_mismatch_reported_before_hash() {
    let hashes = hash_reader(&b"abcd"[..]).expect("hash reader");
    // The digest is also wrong; the size is checked first.
    let expected = ExpectedHashes {
        sha256: "0".repeat(64),
        sha512: None,
        sha1: None,
        md5: None,
        size: Some(3),
    };

    assert_eq!(
        hashes.verify(&expected),
        VerifyOutcome::SizeMismatch {
            expected: 3,
            actual: 4
        }
    );
}

#[test]
fn hash_mismatch_reports_both() {
    let hashes = hash_reader(&b"abc"[..]).expect("hash reader");
    let expected = ExpectedHashes {
        sha256: "0".repeat(64),
        sha512: None,
        sha1: None,
        md5: None,
        size: None,
    };

    assert_eq!(
        hashes.verify(&expected),
        VerifyOutcome::HashMismatch {
            algorithm: "sha256",
            expected: "0".repeat(64),
            actual: Some(ABC_SHA256.to_string()),
        }
    );
}

#[test]
fn optional_hashes_are_cross_checked() {
    let hashes = hash_reader(&b"abc"[..]).expect("hash reader");
    let expected = ExpectedHashes {
        sha256: ABC_SHA256.to_string(),
        sha512: Some(ABC_SHA512.to_string()),
        sha1: Some(ABC_SHA1.to_string()),
        md5: Some("0".repeat(32)),
        size: Some(3),
    };

    assert_eq!(
        hashes.verify(&expected),
        VerifyOutcome::HashMismatch {
            algorithm: "md5",
            expected: "0".repeat(32),
            actual: Some(ABC_MD5.to_string()),
        }
    );
}

#[test]
fn absent_optional_digests_are_not_checked() {
    let hashes = hash_reader(&b"abc"[..]).expect("hash reader");
    let expected = ExpectedHashes {
        sha256: ABC_SHA256.to_string(),
        sha512: None,
        sha1: None,
        md5: None,
        size: Some(3),
    };

    assert_eq!(hashes.verify(&expected), VerifyOutcome::Match);
}

#[test]
fn expected_digests_compare_ignoring_case() {
    let hashes = hash_reader(&b"abc"[..]).expect("hash reader");
    let expected = ExpectedHashes {
        sha256: ABC_SHA256.to_ascii_uppercase(),
        sha512: None,
        sha1: None,
        md5: None,
        size: Some(3),
    };

    assert_eq!(hashes.verify(&expected), VerifyOutcome::Match);
}

#[test]
fn metadata_requires_sha256() {
    let mut json = metadata_json();
    json.as_object_mut().expect("object").remove("sha256");
    let error = Metadata::from_json(&json.to_string()).expect_err("missing sha256");

    assert_eq!(error, MetadataError::MissingField("sha256"));
}

#[test]
fn metadata_requires_every_documented_field() {
    for field in [
        "basename",
        "sha256",
        "platform",
        "platform_version",
        "arch",
        "version",
    ] {
        let mut json = metadata_json();
        json.as_object_mut().expect("object").remove(field);
        let error = Metadata::from_json(&json.to_string()).expect_err(field);
        assert_eq!(error, MetadataError::MissingField(field), "field {field}");
    }
}

#[test]
fn metadata_tolerates_unknown_fields_and_renders_iteration() {
    let metadata = Metadata::from_json(&metadata_json().to_string()).expect("valid metadata");

    assert_eq!(metadata.basename, "cinc_19.4.46-1_amd64.deb");
    assert_eq!(metadata.sha256, ABC_SHA256);
    assert_eq!(metadata.sha512.as_deref(), Some(ABC_SHA512));
    assert_eq!(metadata.sha1.as_deref(), Some(ABC_SHA1));
    assert_eq!(metadata.md5.as_deref(), Some(ABC_MD5));
    assert_eq!(metadata.platform, "debian");
    assert_eq!(metadata.platform_version, "13");
    assert_eq!(metadata.arch, "x86_64");
    assert_eq!(metadata.version, "19.4.46");
    assert_eq!(metadata.iteration.as_deref(), Some("2"));
}

#[test]
fn metadata_without_optional_hashes_yields_only_the_gate() {
    let json = serde_json::json!({
        "basename": "cinc-19.4.46-2-x64.msi",
        "sha256": ABC_SHA256,
        "platform": "windows",
        "platform_version": "2022",
        "arch": "x86_64",
        "version": "19.4.46"
    });
    let metadata = Metadata::from_json(&json.to_string()).expect("valid metadata");
    let expected = ExpectedHashes::from_metadata(&metadata);

    assert_eq!(expected.sha256, ABC_SHA256);
    assert_eq!(expected.sha512, None);
    assert_eq!(expected.sha1, None);
    assert_eq!(expected.md5, None);
    assert_eq!(expected.size, None);
    assert_eq!(metadata.iteration, None);
}

#[test]
fn metadata_expected_hashes_verify_a_real_file() {
    let (_dir, path) = write_temp(b"abc");
    let metadata = Metadata::from_json(&metadata_json().to_string()).expect("valid metadata");
    let mut expected = ExpectedHashes::from_metadata(&metadata);
    expected.size = Some(3);

    let hashes = hash_file(&path).expect("hash file");
    assert_eq!(hashes.verify(&expected), VerifyOutcome::Match);
}
