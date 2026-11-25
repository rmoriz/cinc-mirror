//! Content-addressed store for verified package bytes.
//!
//! A blob lives at `<state>/store/<aa>/<sha256>`, where `<aa>` is the first two
//! characters of the digest. The file name is the proof: a blob is only present
//! because a transport verified the bytes against the SHA-256 it is named by.
//! Commit therefore does not re-hash — that would read every package twice — and
//! [`Store::verify`] is the explicit re-hash used by verification runs.
//!
//! Downloads do not land in the store directly. The transport writes and resumes
//! `<state>/partial/<sha256>.part`; [`Store::commit`] fsyncs that file and
//! renames it into the shard, so a reader never observes a half-written blob.
//! A second commit of an already-present digest is deduplicated rather than
//! treated as an error, which makes interrupted runs idempotent.
//!
//! The state directory also owns `alerts/` and `runs/`; both are created here so
//! every later writer starts from the same layout.
//!
//! # Digest discipline
//!
//! Every entry point that takes a digest rejects anything that is not exactly 64
//! lowercase hexadecimal characters before it touches the filesystem. That makes
//! path traversal through a digest impossible rather than merely unlikely: `/`,
//! `\`, `.` and `..` cannot survive the alphabet check. Hashes from upstream
//! metadata are case-insensitive and must be normalised by the caller.
//!
//! # Removal
//!
//! [`Store::gc`] deletes one blob. It is the caller's confirmation that the blob
//! has been published everywhere it needs to be; the store cannot know that. It
//! never touches the partial directory, because a partial may be a resume point
//! for the next run.

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use thiserror::Error;

use crate::fsutil;
use crate::hash::hash_file;

/// A content-addressed blob store rooted at a state directory.
#[derive(Debug, Clone)]
pub struct Store {
    root: PathBuf,
}

impl Store {
    /// Open (or create) the store below `state_dir`.
    ///
    /// A leading `~` is expanded with `$HOME`, so the configuration default
    /// works without a shell. This is synchronous and performs no network I/O:
    /// it only creates `<state>/{store,partial,alerts,runs}` when they are
    /// missing.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] when one of the directories cannot be created.
    pub fn open(state_dir: &Path) -> Result<Self, StoreError> {
        let root = fsutil::expand_tilde(state_dir);
        for name in ["store", "partial", "alerts", "runs"] {
            let dir = root.join(name);
            fs::create_dir_all(&dir).map_err(|source| StoreError::io(&dir, source))?;
        }
        Ok(Self { root })
    }

    /// The blob address for `sha256`.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidDigest`] when `sha256` is not 64 lowercase
    /// hexadecimal characters.
    pub fn path(&self, sha256: &str) -> Result<PathBuf, StoreError> {
        Self::validate(sha256)?;
        Ok(self.destination(sha256))
    }

    /// The partial file a download of `sha256` resumes into, creating the
    /// partial directory on demand.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidDigest`] for an unusable digest and
    /// [`StoreError::Io`] when the partial directory cannot be created.
    pub fn partial_path(&self, sha256: &str) -> Result<PathBuf, StoreError> {
        Self::validate(sha256)?;
        let dir = self.root.join("partial");
        fs::create_dir_all(&dir).map_err(|source| StoreError::io(&dir, source))?;
        Ok(dir.join(format!("{sha256}.part")))
    }

    /// Whether a blob for `sha256` is present.
    ///
    /// This is a metadata check, not a hash: it answers "is there a file at the
    /// address" in one `stat`. Use [`Store::verify`] to prove the bytes.
    #[must_use]
    pub fn has(&self, sha256: &str) -> bool {
        Self::validate(sha256).is_ok() && self.destination(sha256).is_file()
    }

    /// Move the verified `partial` for `sha256` into the store and return its
    /// address.
    ///
    /// The partial is fsynced, then renamed into its shard, and the shard
    /// directory is fsynced so the rename survives a crash. When a blob with the
    /// same name already exists, its length is compared with the partial: equal
    /// lengths mean the earlier commit won and the partial is discarded;
    /// different lengths mean the existing file cannot be the named digest, so
    /// nothing is overwritten and [`StoreError::DigestMismatch`] is returned.
    ///
    /// The caller guarantees that the partial's bytes were verified against
    /// `sha256` by the transport. Commit does not re-hash.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidDigest`] for an unusable digest,
    /// [`StoreError::DigestMismatch`] when a same-named blob has a different
    /// length, and [`StoreError::Io`] when the partial cannot be read or fsynced,
    /// or the rename fails.
    pub fn commit(&self, sha256: &str, partial: &Path) -> Result<PathBuf, StoreError> {
        Self::validate(sha256)?;
        let destination = self.destination(sha256);
        let shard = self.root.join("store").join(&sha256[..2]);
        fs::create_dir_all(&shard).map_err(|source| StoreError::io(&shard, source))?;

        let partial_len = {
            let file = OpenOptions::new()
                .write(true)
                .open(partial)
                .map_err(|source| StoreError::io(partial, source))?;
            let len = file
                .metadata()
                .map_err(|source| StoreError::io(partial, source))?
                .len();
            file.sync_all()
                .map_err(|source| StoreError::io(partial, source))?;
            len
        };

        match fs::metadata(&destination) {
            Ok(existing) => {
                let existing_len = existing.len();
                if existing_len != partial_len {
                    return Err(StoreError::DigestMismatch {
                        sha256: sha256.to_string(),
                        existing: existing_len,
                        incoming: partial_len,
                    });
                }
                fs::remove_file(partial).map_err(|source| StoreError::io(partial, source))?;
                Ok(destination)
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                fs::rename(partial, &destination)
                    .map_err(|source| StoreError::io(partial, source))?;
                sync_directory(&shard)?;
                Ok(destination)
            }
            Err(source) => Err(StoreError::io(&destination, source)),
        }
    }

    /// Remove the blob for `sha256`.
    ///
    /// The caller confirms that the blob has been published everywhere it is
    /// needed; `gc` is never implicit. Partial files are never touched: a
    /// partial is a resume point, not a committed blob. Removing an absent blob
    /// succeeds, so a retried gc is harmless.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidDigest`] for an unusable digest and
    /// [`StoreError::Io`] when the blob exists but cannot be removed.
    pub fn gc(&self, sha256: &str) -> Result<(), StoreError> {
        Self::validate(sha256)?;
        let blob = self.destination(sha256);

        match fs::remove_file(&blob) {
            Ok(()) => {
                if let Some(shard) = blob.parent() {
                    // Fails harmlessly while another blob still lives there.
                    let _ = fs::remove_dir(shard);
                }
                Ok(())
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(StoreError::io(&blob, source)),
        }
    }

    /// Re-hash the blob for `sha256` and report whether it still matches its
    /// name.
    ///
    /// An absent blob is `Ok(false)`, not an error: verification treats a
    /// deleted local copy as missing, not as corruption.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::InvalidDigest`] for an unusable digest and
    /// [`StoreError::Io`] when an existing blob cannot be read.
    pub fn verify(&self, sha256: &str) -> Result<bool, StoreError> {
        Self::validate(sha256)?;
        let blob = self.destination(sha256);

        match hash_file(&blob) {
            Ok(hashes) => Ok(hashes.sha256 == sha256),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(source) => Err(StoreError::io(&blob, source)),
        }
    }

    /// Free bytes on the filesystem holding the state directory.
    ///
    /// `Ok(None)` means the filesystem cannot answer, which callers treat as
    /// "skip the disk check" rather than a failure.
    ///
    /// # Errors
    ///
    /// Returns [`StoreError::Io`] when `statvfs` fails for the existing state
    /// directory.
    pub fn free_bytes(&self) -> Result<Option<u64>, StoreError> {
        fsutil::free_bytes(&self.root).map_err(|source| StoreError::io(&self.root, source))
    }

    /// Reject anything that is not 64 lowercase hex characters.
    ///
    /// The alphabet check subsumes the separator check: no path separator,
    /// `.`/`..`, drive letter or absolute prefix survives it.
    fn validate(sha256: &str) -> Result<(), StoreError> {
        let valid = sha256.len() == 64
            && sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
        if valid {
            Ok(())
        } else {
            Err(StoreError::InvalidDigest {
                digest: sha256.to_string(),
            })
        }
    }

    /// The address of a validated digest.
    fn destination(&self, sha256: &str) -> PathBuf {
        self.root.join("store").join(&sha256[..2]).join(sha256)
    }
}

/// fsync a directory so a completed rename is durable.
#[cfg(unix)]
fn sync_directory(path: &Path) -> Result<(), StoreError> {
    let dir = File::open(path).map_err(|source| StoreError::io(path, source))?;
    dir.sync_all()
        .map_err(|source| StoreError::io(path, source))
}

/// Directories cannot be opened for fsync on non-Unix hosts.
#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> Result<(), StoreError> {
    Ok(())
}

/// Errors raised by the content-addressed store.
#[derive(Debug, Error)]
pub enum StoreError {
    /// The digest is not a safe 64-character lowercase hex SHA-256.
    #[error("invalid sha256 digest `{digest}`: expected 64 lowercase hex characters")]
    InvalidDigest {
        /// The rejected value.
        digest: String,
    },

    /// A blob already exists at the digest's address with another length.
    #[error(
        "stored blob for {sha256} has {existing} bytes but the incoming partial has {incoming}"
    )]
    DigestMismatch {
        /// The digest whose address is occupied.
        sha256: String,
        /// Length of the blob already in the store.
        existing: u64,
        /// Length of the partial that was to be committed.
        incoming: u64,
    },

    /// A filesystem operation failed.
    #[error("i/o failed for {path}: {source}")]
    Io {
        /// Path the operation was working on.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },
}

impl StoreError {
    fn io(path: &Path, source: io::Error) -> Self {
        Self::Io {
            path: path.to_path_buf(),
            source,
        }
    }
}
