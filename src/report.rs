//! Run summaries and the exit codes they imply.
//!
//! A mirror run reports counts rather than a pass/fail verdict, because a large
//! backfill is usually partial: some targets fail while the rest advance. The
//! summary therefore carries the counts, the bytes transferred and the exit code
//! the process should return. [`Summary::finish`] is the single place that maps
//! failures and incidents to a code, so the CLI cannot disagree with the report.
//!
//! Exit codes follow the specification: `0` clean, `2` partial failure, `3`
//! newly opened incidents. `64` is reserved for usage errors and is decided by
//! the command layer.

use serde::Serialize;

/// The run was clean.
pub const EXIT_OK: i32 = 0;
/// At least one target, download or store operation failed.
pub const EXIT_PARTIAL: i32 = 2;
/// The run newly opened an integrity incident.
pub const EXIT_INCIDENTS: i32 = 3;
/// The command line asked for something unusable.
pub const EXIT_USAGE: i32 = 64;

/// Counts from one run.
///
/// `published` counts successful `(artifact, target)` publications rather than
/// artifacts, because fan-out is per target. `failed` counts failed downloads
/// and publication attempts that are not incidents; a tag conflict is tracked
/// as an incident so a repeated detection does not keep failing the run.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Artifacts the crawl produced.
    pub discovered: usize,
    /// Artifacts already published on every enabled target.
    pub satisfied: usize,
    /// Artifacts whose bytes were downloaded in this run.
    pub downloaded: usize,
    /// Successful publications, one per artifact and target.
    pub published: usize,
    /// Artifacts deliberately left alone (superseded rows, dry-run changes).
    pub skipped: usize,
    /// Failed downloads and failed publication attempts.
    pub failed: usize,
    /// Incident rows this run created (deduplicated detections are not counted).
    pub incidents_opened: usize,
    /// Bytes actually transferred by the download ladder, resume offset excluded.
    pub bytes_downloaded: u64,
    /// Process exit code implied by the counts.
    pub exit_code: i32,
}

impl Summary {
    /// Set [`Summary::exit_code`] from the counts.
    ///
    /// A newly opened incident outranks a partial failure: it means the mirror
    /// saw bytes change behind a published name, which is the more urgent
    /// condition even when other targets also failed.
    #[must_use]
    pub fn finish(mut self) -> Self {
        self.exit_code = if self.incidents_opened > 0 {
            EXIT_INCIDENTS
        } else if self.failed > 0 {
            EXIT_PARTIAL
        } else {
            EXIT_OK
        };
        self
    }

    /// The summary as one line, for logs and `--json`-less output.
    ///
    /// Field order is fixed so a grep or a diff over runs stays readable.
    #[must_use]
    pub fn to_text(&self) -> String {
        format!(
            "discovered={} satisfied={} downloaded={} published={} skipped={} failed={} \
             incidents={} bytes={} exit={}",
            self.discovered,
            self.satisfied,
            self.downloaded,
            self.published,
            self.skipped,
            self.failed,
            self.incidents_opened,
            self.bytes_downloaded,
            self.exit_code,
        )
    }

    /// The summary as pretty JSON, matching the field names of [`Summary`].
    ///
    /// Serialising these plain values cannot fail; the fallback keeps the
    /// signature panic-free.
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self)
            .unwrap_or_else(|_| "{\"error\":\"summary serialisation failed\"}".to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incidents_outrank_partial_failures() {
        let summary = Summary {
            failed: 3,
            incidents_opened: 1,
            ..Summary::default()
        }
        .finish();
        assert_eq!(summary.exit_code, EXIT_INCIDENTS);
    }

    #[test]
    fn failures_exit_two_and_a_clean_run_exits_zero() {
        assert_eq!(
            Summary {
                failed: 1,
                ..Summary::default()
            }
            .finish()
            .exit_code,
            EXIT_PARTIAL
        );
        assert_eq!(Summary::default().finish().exit_code, EXIT_OK);
    }

    #[test]
    fn text_and_json_are_stable() {
        let summary = Summary {
            discovered: 3,
            satisfied: 1,
            downloaded: 2,
            published: 4,
            skipped: 0,
            failed: 0,
            incidents_opened: 0,
            bytes_downloaded: 2048,
            exit_code: 0,
        };
        assert_eq!(
            summary.to_text(),
            "discovered=3 satisfied=1 downloaded=2 published=4 skipped=0 failed=0 \
             incidents=0 bytes=2048 exit=0"
        );
        assert!(summary.to_json().contains("\"published\": 4"));
    }
}
