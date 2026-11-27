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
/// A live foreign run holds the ledger lease.
pub const EXIT_LEASE_BUSY: i32 = 4;
/// The configuration, credentials or the ledger remote are unusable.
pub const EXIT_CONFIG: i32 = 5;
/// The command line asked for something unusable.
pub const EXIT_USAGE: i32 = 64;

/// Environment variables whose values must never be printed.
const TOKEN_ENV: [&str; 3] = ["GHCR_TOKEN", "GITHUB_TOKEN", "RSYNC_PASSWORD"];

/// Hide credentials a diagnostic line may have picked up.
///
/// Errors are formatted from library types rather than raw headers, so the
/// realistic leaks are an `Authorization` header value pasted into a message
/// and a token or password that a library echoed from its environment. Both are
/// replaced with `***`; the rest of the message stays readable.
#[must_use]
pub fn redact_secrets(text: &str) -> String {
    let mut redacted = redact_header(text);

    for (name, value) in std::env::vars() {
        if !is_secret_env(&name) {
            continue;
        }
        let value = value.trim();
        // A short value is far more likely a substring of unrelated text than a
        // credential; replacing it would only corrupt the diagnostic.
        if value.len() >= 8 {
            redacted = redacted.replace(value, "***");
        }
    }

    redacted
}

/// Whether an environment variable's value is a credential.
///
/// The mirror hands `RSYNC_PASSWORD` (the rsync daemon password),
/// `CINC_MIRROR_<TARGET>_PASSWORD` (basic-auth registry credentials) and
/// `CINC_MIRROR_GHCR_API_TOKEN` (the packages delete token) to child processes
/// and libraries, so a diagnostic that quotes one must not echo it back.
fn is_secret_env(name: &str) -> bool {
    TOKEN_ENV.contains(&name)
        || (name.starts_with("CINC_MIRROR_")
            && (name.ends_with("_PASSWORD") || name.ends_with("_TOKEN")))
}

/// Replace the value of every `Authorization` header occurrence.
///
/// Only a `:` or `=` separator marks a header; the word in prose ("authorization
/// is required") is left alone.
fn redact_header(text: &str) -> String {
    let lower = text.to_ascii_lowercase();
    let mut result = String::with_capacity(text.len());
    let mut cursor = 0;
    while let Some(offset) = lower[cursor..].find("authorization") {
        let start = cursor + offset;
        let after = start + "authorization".len();
        result.push_str(&text[cursor..after]);

        // Optional whitespace, then the separator.
        let mut separator = after;
        while let Some(character) = text[separator..].chars().next() {
            if !character.is_whitespace() {
                break;
            }
            separator += character.len_utf8();
        }
        let Some(character) = text[separator..].chars().next() else {
            cursor = after;
            continue;
        };
        if character != ':' && character != '=' {
            cursor = after;
            continue;
        }
        let value_begin = separator + character.len_utf8();
        result.push_str(&text[after..value_begin]);

        // Skip the horizontal whitespace that follows the separator.
        let mut value_start = value_begin;
        while let Some(character) = text[value_start..].chars().next() {
            if !character.is_whitespace() || character == '\n' || character == '\r' {
                break;
            }
            value_start += character.len_utf8();
        }
        // Keep one space so the line stays readable.
        if value_start > value_begin {
            result.push(' ');
        }
        result.push_str("***");
        // The value runs to the end of the line.
        let value_end = text[value_start..]
            .find(['\n', '\r'])
            .map_or(text.len(), |offset| value_start + offset);
        cursor = value_end;
    }
    result.push_str(&text[cursor..]);
    result
}

/// Counts from one run.
///
/// `published` counts successful `(artifact, target)` publications rather than
/// artifacts, because fan-out is per target. `failed` counts failed downloads
/// and publication attempts that are not incidents; a tag conflict is tracked
/// as an incident so a repeated detection does not keep failing the run.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    /// Artifacts the crawl produced.
    pub discovered: usize,
    /// Artifacts already published on every enabled target.
    pub satisfied: usize,
    /// Artifacts waiting in the queue after satisfied rows were removed.
    pub queued: usize,
    /// Artifacts whose bytes were downloaded in this run.
    pub downloaded: usize,
    /// Successful publications, one per artifact and target.
    pub published: usize,
    /// Artifacts deliberately left alone (superseded rows, dry-run changes).
    pub skipped: usize,
    /// Failed downloads and failed publication attempts.
    pub failed: usize,
    /// Artifacts upstream no longer serves (`404`); one incident records each.
    ///
    /// They stay out of [`Summary::failed`] so a permanently dangling upstream
    /// reference does not fail every run, but they stay unsatisfied in the
    /// ledger, so a later run picks them up again when upstream heals.
    pub unrecoverable: usize,
    /// Incident rows this run created (deduplicated detections are not counted).
    pub incidents_opened: usize,
    /// The part of [`Summary::incidents_opened`] that is an `unrecoverable`
    /// incident.
    ///
    /// Such an incident means upstream lost a file; the mirror did everything it
    /// could, the row stays queued and an issue carries the report. It
    /// therefore does not fail the run.
    pub incidents_unrecoverable: usize,
    /// Incidents still open after the run, earlier runs' included.
    ///
    /// Reported for the operator; only newly opened incidents drive the exit
    /// code.
    pub open_incidents: usize,
    /// References the prune pass deleted.
    ///
    /// On a dry run only the probing reference of each target is deleted, so the
    /// count is what the pass really removed while
    /// [`Summary::prune_lines`] carries what it only planned.
    pub pruned: usize,
    /// References or projects the prune pass failed on.
    pub prune_failed: usize,
    /// References the prune pass left for a later run.
    pub prune_deferred: usize,
    /// Targets the prune pass skipped because their endpoint cannot delete.
    pub prune_skipped: usize,
    /// One would-be deletion per line, filled by a dry run's report-only pass.
    #[serde(skip)]
    pub prune_lines: Vec<String>,
    /// Bytes actually transferred by the download ladder, resume offset excluded.
    pub bytes_downloaded: u64,
    /// Whether a limit stopped the run with work left in the queue.
    pub capped: bool,
    /// Version of the last artifact processed, for a backfill cursor.
    pub last_version: Option<String>,
    /// Key of the last artifact processed, for a backfill cursor.
    pub last_artifact_key: Option<String>,
    /// Process exit code implied by the counts.
    pub exit_code: i32,
}

impl Summary {
    /// Set [`Summary::exit_code`] from the counts.
    ///
    /// A newly opened incident outranks a partial failure: it means the mirror
    /// saw bytes change behind a published name, which is the more urgent
    /// condition even when other targets also failed. An `unrecoverable`
    /// incident is exempt: upstream served nothing, so nothing was left undone.
    ///
    /// Prune counts never move the code: the publish job succeeded, so a prune
    /// failure or a skipped prune target leaves [`EXIT_OK`] in a publish run.
    #[must_use]
    pub fn finish(mut self) -> Self {
        self.exit_code = if self.incidents_opened > self.incidents_unrecoverable {
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
             unrecoverable={} incidents={} open_incidents={} pruned={} prune_failed={} \
             prune_deferred={} prune_skipped={} bytes={} exit={}",
            self.discovered,
            self.satisfied,
            self.downloaded,
            self.published,
            self.skipped,
            self.failed,
            self.unrecoverable,
            self.incidents_opened,
            self.open_incidents,
            self.pruned,
            self.prune_failed,
            self.prune_deferred,
            self.prune_skipped,
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
            queued: 2,
            downloaded: 2,
            published: 4,
            skipped: 0,
            failed: 0,
            incidents_opened: 0,
            open_incidents: 1,
            bytes_downloaded: 2048,
            exit_code: 0,
            ..Summary::default()
        };
        assert_eq!(
            summary.to_text(),
            "discovered=3 satisfied=1 downloaded=2 published=4 skipped=0 failed=0 \
             unrecoverable=0 incidents=0 open_incidents=1 pruned=0 prune_failed=0 \
             prune_deferred=0 prune_skipped=0 bytes=2048 exit=0"
        );
        assert!(summary.to_json().contains("\"published\": 4"));
        assert!(summary.to_json().contains("\"queued\": 2"));
        assert!(summary.to_json().contains("\"open_incidents\": 1"));
        assert!(summary.to_json().contains("\"pruned\": 0"));
        assert!(summary.to_json().contains("\"prune_failed\": 0"));
        assert!(summary.to_json().contains("\"prune_skipped\": 0"));
        assert!(!summary.to_json().contains("prune_lines"));
    }

    #[test]
    fn prune_counts_do_not_change_the_exit_code() {
        let summary = Summary {
            pruned: 2,
            prune_failed: 4,
            prune_deferred: 7,
            prune_skipped: 1,
            ..Summary::default()
        }
        .finish();
        assert_eq!(summary.exit_code, EXIT_OK);
    }

    #[test]
    fn an_unrecoverable_incident_does_not_change_the_exit_code() {
        let summary = Summary {
            incidents_opened: 2,
            incidents_unrecoverable: 2,
            ..Summary::default()
        }
        .finish();
        assert_eq!(summary.exit_code, EXIT_OK);

        let mixed = Summary {
            incidents_opened: 2,
            incidents_unrecoverable: 1,
            ..Summary::default()
        }
        .finish();
        assert_eq!(
            mixed.exit_code, EXIT_INCIDENTS,
            "a changed hash still fails"
        );
    }

    #[test]
    fn open_incidents_do_not_change_the_exit_code() {
        assert_eq!(
            Summary {
                open_incidents: 5,
                ..Summary::default()
            }
            .finish()
            .exit_code,
            EXIT_OK,
            "only newly opened incidents drive the exit code"
        );
    }

    #[test]
    fn redaction_hides_header_values_and_tokens() {
        assert_eq!(
            super::redact_header("Authorization: Bearer abc123\nnext line"),
            "Authorization: ***\nnext line"
        );
        assert_eq!(
            super::redact_header("request with authorization=Basic Zm9v failed"),
            "request with authorization=***"
        );
        assert_eq!(
            super::redact_header("authorization is required"),
            "authorization is required"
        );
    }

    #[test]
    fn credential_environment_names_are_recognised() {
        for name in [
            "GHCR_TOKEN",
            "GITHUB_TOKEN",
            "RSYNC_PASSWORD",
            "CINC_MIRROR_GHCR_PASSWORD",
            "CINC_MIRROR_GHCR_TOKEN",
            "CINC_MIRROR_GHCR_API_TOKEN",
            "CINC_MIRROR_TOKEN",
            "CINC_MIRROR_BACKUP_RSYNC_PASSWORD",
        ] {
            assert!(super::is_secret_env(name), "`{name}` must be redacted");
        }
        for name in [
            "CINC_MIRROR_GHCR_USER",
            "CINC_MIRROR_GHCR_API_BASE",
            "XRSYNC_PASSWORD",
            "HOME",
        ] {
            assert!(!super::is_secret_env(name), "`{name}` is not a credential");
        }
    }

    #[test]
    fn redaction_hides_rsync_and_mirror_password_values() {
        /// Restores `name` to its original value when the test ends.
        struct Restore(&'static str, Option<String>);
        impl Drop for Restore {
            fn drop(&mut self) {
                match self.1.take() {
                    Some(value) => std::env::set_var(self.0, value),
                    None => std::env::remove_var(self.0),
                }
            }
        }

        let _rsync = Restore("RSYNC_PASSWORD", std::env::var("RSYNC_PASSWORD").ok());
        let _mirror = Restore(
            "CINC_MIRROR_TEST_PASSWORD",
            std::env::var("CINC_MIRROR_TEST_PASSWORD").ok(),
        );
        std::env::set_var("RSYNC_PASSWORD", "daemon-password-value");
        std::env::set_var("CINC_MIRROR_TEST_PASSWORD", "registry-password-value");

        let redacted = super::redact_secrets(
            "rsync failed with RSYNC_PASSWORD=daemon-password-value and \
             CINC_MIRROR_TEST_PASSWORD=registry-password-value",
        );
        assert!(redacted.contains("***"), "{redacted}");
        assert!(!redacted.contains("daemon-password-value"), "{redacted}");
        assert!(!redacted.contains("registry-password-value"), "{redacted}");
    }
}
