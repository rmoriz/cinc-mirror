//! Streaming multi-hash verification.
//!
//! Payloads are hashed once, in 1 MiB reads, so a download is never buffered in
//! memory and every digest is computed over the same bytes. SHA-256 is the gate;
//! SHA-512, SHA-1 and MD5 are cross-checks against the upstream metadata.
//!
//! [`hash_file`] is the filesystem entry point; [`hash_reader`] is what the
//! transport layer uses while a payload is still a stream.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};

use crate::source::metadata::Metadata;

/// Read size used while hashing. Large enough that syscall overhead disappears,
/// small enough that hashing does not hold a meaningful amount of memory.
pub const HASH_BUFFER_SIZE: usize = 1024 * 1024;

/// Digests and byte count computed from one payload.
///
/// The optional fields are populated by [`hash_reader`]; they stay optional so a
/// caller that only knows the gate (for example a remote sidecar) can still
/// describe its expectations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hashes {
    /// Lowercase hex SHA-256.
    pub sha256: String,
    /// Lowercase hex SHA-512.
    pub sha512: Option<String>,
    /// Lowercase hex SHA-1.
    pub sha1: Option<String>,
    /// Lowercase hex MD5.
    pub md5: Option<String>,
    /// Number of bytes read.
    pub size: u64,
}

/// The digests a payload must have.
///
/// Metadata carries every digest but no size; the caller fills [`Self::size`]
/// from a directory listing or a `HEAD` request when one is available.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExpectedHashes {
    /// Required lowercase hex SHA-256.
    pub sha256: String,
    /// Optional lowercase hex SHA-512 cross-check.
    pub sha512: Option<String>,
    /// Optional lowercase hex SHA-1 cross-check.
    pub sha1: Option<String>,
    /// Optional lowercase hex MD5 cross-check.
    pub md5: Option<String>,
    /// Expected byte count, when a listing or `HEAD` supplied it.
    pub size: Option<u64>,
}

impl ExpectedHashes {
    /// Take the gate and every published cross-check from upstream metadata.
    ///
    /// Upstream metadata has no size field, so [`Self::size`] starts as `None`.
    #[must_use]
    pub fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            sha256: metadata.sha256.clone(),
            sha512: metadata.sha512.clone(),
            sha1: metadata.sha1.clone(),
            md5: metadata.md5.clone(),
            size: None,
        }
    }
}

/// Result of comparing computed hashes with expectations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerifyOutcome {
    /// Size (when expected) and every expected digest agree.
    Match,

    /// The payload is not the expected size. Reported before any digest.
    SizeMismatch {
        /// Expected byte count.
        expected: u64,
        /// Actual byte count.
        actual: u64,
    },

    /// The first digest that disagreed. `actual` is `None` when the digest was
    /// never computed; in practice [`hash_reader`] populates all four.
    HashMismatch {
        /// Digest name, e.g. `sha256` or `md5`.
        algorithm: &'static str,
        /// Value the caller expected.
        expected: String,
        /// Value computed from the payload.
        actual: Option<String>,
    },
}

impl VerifyOutcome {
    /// Whether verification succeeded.
    #[must_use]
    pub fn is_match(&self) -> bool {
        matches!(self, Self::Match)
    }
}

impl Hashes {
    /// Compare against the expected size first, then the gate, then the
    /// cross-checks in SHA-512, SHA-1, MD5 order.
    ///
    /// Only digests present in `expected` are checked. Hex comparison ignores
    /// case; the reported values keep the case the caller supplied.
    #[must_use]
    pub fn verify(&self, expected: &ExpectedHashes) -> VerifyOutcome {
        if let Some(size) = expected.size {
            if size != self.size {
                return VerifyOutcome::SizeMismatch {
                    expected: size,
                    actual: self.size,
                };
            }
        }

        let checks = [
            (
                "sha256",
                Some(expected.sha256.as_str()),
                Some(self.sha256.as_str()),
            ),
            ("sha512", expected.sha512.as_deref(), self.sha512.as_deref()),
            ("sha1", expected.sha1.as_deref(), self.sha1.as_deref()),
            ("md5", expected.md5.as_deref(), self.md5.as_deref()),
        ];

        for (algorithm, expected, actual) in checks {
            if let Some(mismatch) = check_digest(algorithm, expected, actual) {
                return mismatch;
            }
        }

        VerifyOutcome::Match
    }
}

/// Streaming digest state that can be primed from an on-disk prefix.
///
/// A resumed download must not read its partial file twice: the prefix is hashed
/// once, and the tail that the transport appends is fed into the same state. The
/// result is identical to [`hash_file`], which is exactly what the size and
/// digest gate compares against.
#[derive(Debug)]
pub struct Hasher {
    sha256: Sha256,
    sha512: Sha512,
    sha1: Sha1,
    md5: Md5,
    size: u64,
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

impl Hasher {
    /// Start from zero bytes.
    #[must_use]
    pub fn new() -> Self {
        Self {
            sha256: Sha256::new(),
            sha512: Sha512::new(),
            sha1: Sha1::new(),
            md5: Md5::new(),
            size: 0,
        }
    }

    /// Hash exactly the first `len` bytes of `path`.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] when the file cannot be opened or
    /// read, and [`io::ErrorKind::UnexpectedEof`] when the file is shorter than
    /// `len` — the caller asked for a prefix the partial no longer has.
    pub fn read_prefix(path: &Path, len: u64) -> io::Result<Self> {
        let mut hasher = Self::new();
        let mut prefix = File::open(path)?.take(len);
        let read = hasher.update_reader(&mut prefix)?;
        if read != len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{path:?} holds {read} of the expected {len} partial bytes"),
            ));
        }
        Ok(hasher)
    }

    /// Hash `path` from `offset` to its end into this state.
    ///
    /// Passing `0` as the offset hashes the whole file.
    ///
    /// # Errors
    ///
    /// Returns the underlying [`io::Error`] when the file cannot be opened,
    /// seeked or read.
    pub fn read_tail(mut self, path: &Path, offset: u64) -> io::Result<Hashes> {
        let mut file = File::open(path)?;
        file.seek(SeekFrom::Start(offset))?;
        self.update_reader(&mut file)?;
        Ok(self.finish())
    }

    /// Feed more bytes to every digest.
    pub fn update(&mut self, chunk: &[u8]) {
        self.sha256.update(chunk);
        self.sha512.update(chunk);
        self.sha1.update(chunk);
        self.md5.update(chunk);
        self.size += chunk.len() as u64;
    }

    /// Bytes hashed so far.
    #[must_use]
    pub fn size(&self) -> u64 {
        self.size
    }

    /// Close the digests and report the result.
    #[must_use]
    pub fn finish(self) -> Hashes {
        Hashes {
            sha256: to_hex(&self.sha256.finalize()),
            sha512: Some(to_hex(&self.sha512.finalize())),
            sha1: Some(to_hex(&self.sha1.finalize())),
            md5: Some(to_hex(&self.md5.finalize())),
            size: self.size,
        }
    }

    /// Read `reader` to EOF into this state, returning the bytes read.
    fn update_reader(&mut self, reader: &mut impl Read) -> io::Result<u64> {
        let mut buffer = vec![0_u8; HASH_BUFFER_SIZE];
        let mut total = 0_u64;
        loop {
            let read = reader.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            self.update(&buffer[..read]);
            total += read as u64;
        }
        Ok(total)
    }
}

/// Hash an open reader in one pass.
///
/// # Errors
///
/// Returns the underlying [`io::Error`] when reading fails.
pub fn hash_reader<R: Read>(mut reader: R) -> io::Result<Hashes> {
    let mut hasher = Hasher::new();
    hasher.update_reader(&mut reader)?;
    Ok(hasher.finish())
}

/// Hash a file in one pass using [`hash_reader`].
///
/// # Errors
///
/// Returns the underlying [`io::Error`] when the file cannot be opened or read.
pub fn hash_file(path: &Path) -> io::Result<Hashes> {
    hash_reader(File::open(path)?)
}

fn check_digest(
    algorithm: &'static str,
    expected: Option<&str>,
    actual: Option<&str>,
) -> Option<VerifyOutcome> {
    let expected = expected?;
    let agrees = actual.is_some_and(|actual| actual.eq_ignore_ascii_case(expected));
    if agrees {
        None
    } else {
        Some(VerifyOutcome::HashMismatch {
            algorithm,
            expected: expected.to_string(),
            actual: actual.map(ToString::to_string),
        })
    }
}

fn to_hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        hex.push(char::from(DIGITS[usize::from(byte >> 4)]));
        hex.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    hex
}
