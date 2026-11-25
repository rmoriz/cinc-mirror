//! Filesystem helpers shared by planning and the store.
//!
//! The only surprising operation here is free-space reporting: the plan needs it
//! before the state directory necessarily exists, and the configuration may
//! spell the state directory with a leading `~`. Both are handled without
//! requiring a shell, so a plan and the store agree on what "the state
//! directory" means.

use std::io;
use std::path::{Path, PathBuf};

/// Free bytes on the filesystem holding `path`.
///
/// A path that does not exist yet is resolved through its nearest existing
/// ancestor, which is what a first run against a fresh state directory needs.
/// `~` is expanded with `$HOME`, matching how configuration paths are written.
///
/// `Ok(None)` means the platform or the path cannot answer, for example a
/// non-Unix host or a relative path whose ancestors do not exist. Callers treat
/// that as an unknown check rather than a failed one.
///
/// # Errors
///
/// Returns the underlying I/O error when `statvfs` fails for an existing path.
pub fn free_bytes(path: &Path) -> io::Result<Option<u64>> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;

        let expanded = expand_tilde(path);
        let mut existing: &Path = &expanded;
        loop {
            if existing.exists() {
                break;
            }
            match existing.parent() {
                Some(parent) => existing = parent,
                None => return Ok(None),
            }
        }

        let Ok(c_path) = std::ffi::CString::new(existing.as_os_str().as_bytes()) else {
            return Ok(None);
        };
        let mut stats = std::mem::MaybeUninit::<libc::statvfs>::uninit();
        // SAFETY: `statvfs` writes the struct on success and `c_path` is a valid
        // NUL-terminated path.
        let result = unsafe { libc::statvfs(c_path.as_ptr(), stats.as_mut_ptr()) };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `statvfs` returned success, so the struct is initialised.
        let stats = unsafe { stats.assume_init() };

        let block_size = if stats.f_frsize == 0 {
            stats.f_bsize
        } else {
            stats.f_frsize
        };
        let available = u128::from(stats.f_bavail) * u128::from(block_size);
        Ok(u64::try_from(available).ok())
    }

    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(None)
    }
}

/// Replace a leading `~` with `$HOME`.
///
/// A path that does not start with `~` or `~/`, or a host without `$HOME`, is
/// returned unchanged; there is nothing useful to expand it to.
#[must_use]
pub fn expand_tilde(path: &Path) -> PathBuf {
    let Some(text) = path.to_str() else {
        return path.to_path_buf();
    };
    if text != "~" && !text.starts_with("~/") {
        return path.to_path_buf();
    }

    let Some(home) = std::env::var_os("HOME") else {
        return path.to_path_buf();
    };
    let rest = text.trim_start_matches('~').trim_start_matches('/');
    let mut expanded = PathBuf::from(home);
    if !rest.is_empty() {
        expanded.push(rest);
    }
    expanded
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_a_leading_tilde() {
        let home = std::env::var_os("HOME").expect("HOME");
        assert_eq!(
            expand_tilde(Path::new("~/state")),
            PathBuf::from(home).join("state")
        );
        assert_eq!(
            expand_tilde(Path::new("/tmp/state")),
            PathBuf::from("/tmp/state")
        );
    }

    #[cfg(unix)]
    #[test]
    fn reports_free_space_below_a_missing_tail() {
        let dir = tempfile::tempdir().expect("temp dir");
        let future = dir.path().join("state/store/aa");

        let free = free_bytes(&future)
            .expect("statvfs on the nearest ancestor")
            .expect("unix answers");

        assert!(free > 0);
    }
}
