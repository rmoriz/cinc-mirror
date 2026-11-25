//! Content-addressed store tests.
//!
//! Every test drives a real state directory. The store's job is filesystem
//! behaviour — atomic commit, dedupe, gc, traversal refusal — so a mock would
//! only restate the implementation. Assertions look at the bytes that ended up
//! on disk and at the layout, not at internal state.

use std::fs;
use std::path::{Path, PathBuf};

use cinc_mirror::hash::{hash_file, hash_reader};
use cinc_mirror::store::{Store, StoreError};

fn bytes(seed: u8, len: usize) -> Vec<u8> {
    (0..len)
        .map(|index| seed.wrapping_add((index % 251) as u8))
        .collect()
}

fn sha256(bytes: &[u8]) -> String {
    hash_reader(bytes).expect("hash fixture").sha256
}

fn open() -> (tempfile::TempDir, Store) {
    let dir = tempfile::tempdir().expect("state dir");
    let store = Store::open(dir.path()).expect("open store");
    (dir, store)
}

fn write_partial(store: &Store, digest: &str, content: &[u8]) -> PathBuf {
    let partial = store.partial_path(digest).expect("partial path");
    fs::write(&partial, content).expect("write partial");
    partial
}

/// Every regular file below `dir`, without following symlinks.
fn files_under(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        for entry in fs::read_dir(&current).expect("read dir") {
            let entry = entry.expect("dir entry");
            if entry.file_type().expect("file type").is_dir() {
                pending.push(entry.path());
            } else {
                found.push(entry.path());
            }
        }
    }
    found
}

#[test]
fn open_creates_the_layout_and_is_idempotent() {
    let dir = tempfile::tempdir().expect("temp dir");
    let state = dir.path().join("state");

    let store = Store::open(&state).expect("first open");
    for sub in ["store", "partial", "alerts", "runs"] {
        assert!(state.join(sub).is_dir(), "`{sub}` must exist after open");
    }
    drop(store);

    Store::open(&state).expect("a second open must not fail");
}

#[test]
fn commit_is_atomic_and_deduped() {
    let (dir, store) = open();
    let content = bytes(7, 4096 + 3);
    let digest = sha256(&content);

    let first = write_partial(&store, &digest, &content);
    let committed = store.commit(&digest, &first).expect("first commit");

    assert_eq!(
        committed,
        store.path(&digest).expect("blob path"),
        "commit returns the address of the blob"
    );
    assert_eq!(
        committed.file_name().and_then(|name| name.to_str()),
        Some(digest.as_str()),
        "the file name is the proof"
    );
    assert_eq!(
        committed.parent().and_then(Path::file_name),
        Some(std::ffi::OsStr::new(&digest[..2])),
        "blobs live in a two-character shard"
    );
    assert_eq!(fs::read(&committed).expect("blob"), content);
    assert!(!first.exists(), "commit consumes the partial");
    assert!(store.has(&digest));

    let second = write_partial(&store, &digest, &content);
    let again = store.commit(&digest, &second).expect("dedupe");

    assert_eq!(again, committed);
    assert!(!second.exists(), "a deduped partial is consumed too");
    assert_eq!(
        files_under(&dir.path().join("store")),
        vec![committed.clone()],
        "a second commit of the same digest must not add a file"
    );
    assert_eq!(fs::read(&committed).expect("blob"), content);
}

#[test]
fn a_same_name_blob_with_a_different_length_is_a_digest_mismatch() {
    let (_dir, store) = open();
    let content = bytes(3, 100);
    let digest = sha256(&content);
    let committed = store.path(&digest).expect("blob path");
    fs::create_dir_all(committed.parent().expect("shard")).expect("shard dir");
    fs::write(&committed, vec![0_u8; 99]).expect("wrong-length blob");
    let partial = write_partial(&store, &digest, &content);

    let error = store
        .commit(&digest, &partial)
        .expect_err("a different length cannot be the named digest");

    assert!(
        matches!(error, StoreError::DigestMismatch { .. }),
        "unexpected error: {error:?}"
    );
    assert_eq!(
        fs::read(&committed).expect("blob"),
        vec![0_u8; 99],
        "the stored blob is left alone"
    );
    assert!(
        partial.is_file(),
        "a refused commit must not destroy the caller's partial"
    );
}

#[test]
fn gc_removes_blob_but_leaves_other() {
    let (dir, store) = open();
    let first = bytes(1, 512);
    let second = bytes(2, 640);
    let first_digest = sha256(&first);
    let second_digest = sha256(&second);

    let first_path = store
        .commit(&first_digest, &write_partial(&store, &first_digest, &first))
        .expect("first commit");
    let second_path = store
        .commit(
            &second_digest,
            &write_partial(&store, &second_digest, &second),
        )
        .expect("second commit");

    // A partial must never be the store's to remove.
    let pending = write_partial(&store, &first_digest, b"a resumable download");

    store.gc(&first_digest).expect("gc first blob");

    assert!(!store.has(&first_digest));
    assert!(!first_path.exists(), "the blob is gone");
    assert!(store.has(&second_digest));
    assert_eq!(fs::read(&second_path).expect("second blob"), second);
    assert!(
        pending.exists(),
        "gc must not touch the partial directory: {:?}",
        fs::read(&pending).expect("partial")
    );
    assert_eq!(
        fs::read(&pending).expect("partial"),
        b"a resumable download"
    );

    store.gc(&first_digest).expect("gc is idempotent");
    store
        .gc(&sha256(b"never stored"))
        .expect("gc of an absent blob is fine");

    assert_eq!(
        files_under(&dir.path().join("store")),
        vec![second_path],
        "only the other blob remains"
    );
}

#[test]
fn partial_is_separate_from_committed() {
    let (dir, store) = open();
    let content = bytes(11, 777);
    let digest = sha256(&content);

    fs::remove_dir_all(dir.path().join("partial")).expect("drop partial dir");
    let partial = store.partial_path(&digest).expect("partial path");

    assert!(
        partial.parent().expect("partial parent").is_dir(),
        "partial_path recreates its directory on demand"
    );
    assert_eq!(
        partial,
        dir.path().join("partial").join(format!("{digest}.part")),
        "partials are named after the digest they are waiting for"
    );
    assert!(!store.has(&digest));
    assert!(!store.path(&digest).expect("blob path").exists());
    assert!(!store.verify(&digest).expect("verify missing blob"));

    fs::write(&partial, &content).expect("write partial");

    assert!(!store.has(&digest), "a partial is not a committed blob");
    assert!(
        !store.verify(&digest).expect("verify with only a partial"),
        "verify reads the blob path, never the partial"
    );

    let committed = store.commit(&digest, &partial).expect("commit");

    assert!(committed.is_file());
    assert!(!partial.exists(), "the partial becomes the blob");
    assert!(store.verify(&digest).expect("verify committed blob"));
}

#[test]
fn verify_rehashes_and_detects_corruption() {
    let (_dir, store) = open();
    let content = bytes(5, 500);
    let digest = sha256(&content);
    let committed = store
        .commit(&digest, &write_partial(&store, &digest, &content))
        .expect("commit");

    assert!(
        store.verify(&digest).expect("verify intact blob"),
        "the committed bytes must hash to their name"
    );

    let corrupt = bytes(9, content.len());
    fs::write(&committed, &corrupt).expect("corrupt blob in place");
    assert!(
        !store.verify(&digest).expect("verify corrupt blob"),
        "a same-length corruption must be detected by re-hashing"
    );
    assert_eq!(
        hash_file(&committed).expect("hash corrupt blob").sha256,
        sha256(&corrupt)
    );
}

#[test]
fn refuses_path_traversal_in_sha() {
    let (dir, store) = open();
    let valid = sha256(b"valid");

    let rejected = vec![
        "../x".to_string(),
        "..".to_string(),
        "aa/bb".to_string(),
        format!("../{}", &valid[2..]),
        valid[..63].to_string(),
        format!("{valid}0"),
        valid.to_ascii_uppercase(),
        "z".repeat(64),
        String::new(),
    ];

    for digest in rejected {
        let label = format!("{digest:?}");

        let error = store.path(&digest).expect_err("path must refuse it");
        assert!(
            matches!(error, StoreError::InvalidDigest { .. }),
            "path accepted {label}: {error:?}"
        );

        let error = store
            .partial_path(&digest)
            .expect_err("partial_path must refuse it");
        assert!(
            matches!(error, StoreError::InvalidDigest { .. }),
            "partial_path accepted {label}: {error:?}"
        );

        let error = store
            .commit(&digest, Path::new("whatever.part"))
            .expect_err("commit must refuse it");
        assert!(
            matches!(error, StoreError::InvalidDigest { .. }),
            "commit accepted {label}: {error:?}"
        );

        let error = store.gc(&digest).expect_err("gc must refuse it");
        assert!(
            matches!(error, StoreError::InvalidDigest { .. }),
            "gc accepted {label}: {error:?}"
        );

        let error = store.verify(&digest).expect_err("verify must refuse it");
        assert!(
            matches!(error, StoreError::InvalidDigest { .. }),
            "verify accepted {label}: {error:?}"
        );

        assert!(!store.has(&digest), "has accepted {label}");
    }

    assert!(
        files_under(dir.path()).is_empty(),
        "a rejected digest must not create anything: {:?}",
        files_under(dir.path())
    );
}

#[cfg(unix)]
#[test]
fn free_bytes_reports_the_state_directory() {
    let (_dir, store) = open();

    let free = store
        .free_bytes()
        .expect("statvfs on a temporary directory")
        .expect("unix always answers");

    assert!(free > 0, "a writable temporary directory has free space");
}
