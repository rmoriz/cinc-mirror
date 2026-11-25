//! Verification: compare the ledger against the store and every target.
//!
//! `verify` is read-only. It never downloads package bytes and never writes an
//! event; it reports what no longer matches what the ledger recorded, and the
//! command exits `2` when there is at least one finding.
//!
//! # Coverage
//!
//! The whole ledger is checked, including rows today's policies no longer
//! select: narrowing `mirror` to 19+ must not silently stop checking the 18.x
//! rows that were published earlier. A row whose publication to a target is
//! `superseded` is skipped for that target — the canonical reference was
//! deliberately retired by an acknowledged hash change.
//!
//! # Local blobs
//!
//! Without `--deep` only the remote publications are probed. With `--deep` the
//! mirror also re-hashes the local blob of every artifact the ledger records as
//! present (`artifacts.local = 1`): a mismatch is [`FindingKind::LocalCorrupt`],
//! an absent file is [`FindingKind::LocalMissing`]. A blob deleted by
//! `--gc-after` is recorded as `local_gc` (`local = 0`) and is skipped silently,
//! because its absence is intentional.
//!
//! # Sampling
//!
//! `--sample N` checks at most `N` artifacts and does so deterministically: the
//! list is ordered by artifact key and every `stride`-th row is taken, with
//! `stride = ceil(total / N)`. Two runs over the same ledger check the same
//! artifacts, which keeps a scheduled sample comparable over time.

use std::collections::HashSet;
use std::fmt;
use std::sync::Arc;

use thiserror::Error;

use crate::ctx::Ctx;
use crate::ledger::{ArtifactRow, LedgerError, PublicationStatus};
use crate::report::{EXIT_OK, EXIT_PARTIAL};
use crate::store::StoreError;
use crate::targets::Target;

/// What `verify` checks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyOpts {
    /// Check only these targets; `None` checks every enabled target.
    pub targets: Option<Vec<String>>,
    /// Re-hash the local store blobs as well.
    pub deep: bool,
    /// Check at most this many artifacts, deterministically sampled.
    pub sample: Option<usize>,
}

/// What a finding is about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FindingKind {
    /// The local blob is present but does not hash to its name.
    LocalCorrupt,
    /// The ledger records a local blob, but the store has none.
    LocalMissing,
    /// A target could not confirm the publication.
    Remote,
}

impl FindingKind {
    /// The stable spelling used in reports and logs.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalCorrupt => "local_corrupt",
            Self::LocalMissing => "local_missing",
            Self::Remote => "remote",
        }
    }
}

impl fmt::Display for FindingKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// One mismatch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    /// The artifact the finding concerns.
    pub artifact_key: String,
    /// The target, for a remote finding.
    pub target: Option<String>,
    /// What kind of mismatch was found.
    pub kind: FindingKind,
    /// Human-readable explanation.
    pub detail: String,
}

impl fmt::Display for Finding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} {}", self.kind, self.artifact_key)?;
        if let Some(target) = &self.target {
            write!(formatter, " target={target}")?;
        }
        write!(formatter, ": {}", self.detail)
    }
}

/// Counts and findings of one verification.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifyReport {
    /// Artifacts examined after sampling.
    pub artifacts_checked: usize,
    /// `(artifact, target)` publications probed.
    pub publications_checked: usize,
    /// Everything that did not match.
    pub findings: Vec<Finding>,
}

impl VerifyReport {
    /// Whether every examined artifact and publication matched.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }

    /// Process exit code: `2` when anything did not match, `0` when clean.
    #[must_use]
    pub fn exit_code(&self) -> i32 {
        if self.is_clean() {
            EXIT_OK
        } else {
            EXIT_PARTIAL
        }
    }
}

impl fmt::Display for VerifyReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            formatter,
            "verify: {} artifacts, {} publications, {} findings",
            self.artifacts_checked,
            self.publications_checked,
            self.findings.len()
        )?;
        for finding in &self.findings {
            writeln!(formatter, "  {finding}")?;
        }
        Ok(())
    }
}

/// Why a verification could not run.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// The options cannot describe a verification.
    #[error("usage: {reason}")]
    Usage {
        /// What is wrong with the options.
        reason: String,
    },

    /// A target filter names a target the configuration does not have.
    #[error("unknown target `{name}`")]
    UnknownTarget {
        /// The requested target name.
        name: String,
    },

    /// The ledger rejected a query.
    #[error(transparent)]
    Ledger(#[from] LedgerError),

    /// The local store could not be read.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Check the ledger against the store and the targets.
///
/// # Errors
///
/// Returns [`VerifyError::Usage`] for `--deep` combined with `--sample` or a
/// zero sample, [`VerifyError::UnknownTarget`] for a filter that names no
/// configured target, and the ledger or store error that prevented a check. A
/// target failure is a finding, never an error: verification is meant to report
/// exactly those.
pub async fn run(ctx: &Ctx, opts: VerifyOpts) -> Result<VerifyReport, VerifyError> {
    if opts.deep && opts.sample.is_some() {
        return Err(VerifyError::Usage {
            reason: "--deep and --sample are mutually exclusive".to_string(),
        });
    }
    if opts.sample == Some(0) {
        return Err(VerifyError::Usage {
            reason: "--sample must be greater than zero".to_string(),
        });
    }

    let targets = selected_targets(ctx, opts.targets.as_deref())?;
    let rows = {
        let ledger = ctx.ledger.lock().await;
        ledger.artifacts()?
    };
    let superseded = {
        let ledger = ctx.ledger.lock().await;
        let mut keys = HashSet::new();
        for target in &targets {
            for publication in ledger.publications(target.name())? {
                if publication.status == PublicationStatus::Superseded {
                    keys.insert((publication.artifact_key, publication.target));
                }
            }
        }
        keys
    };
    let rows = sample(rows, opts.sample);

    let mut report = VerifyReport {
        artifacts_checked: rows.len(),
        ..VerifyReport::default()
    };

    for row in &rows {
        let artifact = &row.artifact;
        if opts.deep {
            check_local(ctx, row, &mut report)?;
        }

        for target in &targets {
            if superseded.contains(&(artifact.key(), target.name().to_string())) {
                continue;
            }
            report.publications_checked += 1;
            if let Err(error) = target.verify(artifact).await {
                report.findings.push(Finding {
                    artifact_key: artifact.key(),
                    target: Some(target.name().to_string()),
                    kind: FindingKind::Remote,
                    detail: error.to_string(),
                });
            }
        }
    }

    Ok(report)
}

/// Re-hash the local blob the ledger records for `row`, if any.
fn check_local(ctx: &Ctx, row: &ArtifactRow, report: &mut VerifyReport) -> Result<(), VerifyError> {
    if !row.local {
        // `local = 0` is the ledger's record of a deliberate `local_gc`.
        return Ok(());
    }
    let sha256 = &row.artifact.sha256;
    if !ctx.store.has(sha256) {
        report.findings.push(Finding {
            artifact_key: row.artifact.key(),
            target: None,
            kind: FindingKind::LocalMissing,
            detail: "the ledger records a local blob but the store has none".to_string(),
        });
    } else if !ctx.store.verify(sha256)? {
        report.findings.push(Finding {
            artifact_key: row.artifact.key(),
            target: None,
            kind: FindingKind::LocalCorrupt,
            detail: "local blob does not hash to its name".to_string(),
        });
    }
    Ok(())
}

/// The targets a filter selects, in configuration order.
fn selected_targets<'a>(
    ctx: &'a Ctx,
    requested: Option<&[String]>,
) -> Result<Vec<&'a Arc<dyn Target>>, VerifyError> {
    let all = ctx.targets.all();
    let Some(names) = requested else {
        return Ok(all.iter().collect());
    };

    let mut selected: Vec<&Arc<dyn Target>> = Vec::new();
    for name in names {
        let target = all
            .iter()
            .find(|target| target.name() == name)
            .ok_or_else(|| VerifyError::UnknownTarget { name: name.clone() })?;
        if !selected.iter().any(|seen| seen.name() == name) {
            selected.push(target);
        }
    }
    Ok(selected)
}

/// Take a deterministic, bounded sample of the key-ordered rows.
///
/// `rows` is ordered by artifact key; every `stride`-th row is kept, which
/// yields at most `sample` rows because `stride = ceil(total / sample)`.
fn sample(rows: Vec<ArtifactRow>, sample: Option<usize>) -> Vec<ArtifactRow> {
    let Some(limit) = sample else {
        return rows;
    };
    if rows.is_empty() || limit == 0 {
        return Vec::new();
    }
    let stride = rows.len().div_ceil(limit).max(1);
    rows.into_iter()
        .enumerate()
        .filter(|(index, _)| index % stride == 0)
        .map(|(_, row)| row)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{Artifact, ArtifactContext, ArtifactInput};

    fn row(version: &str) -> ArtifactRow {
        let sha = "a".repeat(64);
        let artifact = Artifact::new(
            &ArtifactContext {
                channel: "stable".to_string(),
                project: "cinc".to_string(),
                version: version.to_string(),
                platform: "debian".to_string(),
                platform_version: "13".to_string(),
            },
            ArtifactInput {
                basename: format!("cinc_{version}-1_amd64.deb"),
                sha256: sha,
                metadata_json: "{}".to_string(),
                platform: "debian".to_string(),
                platform_version: "13".to_string(),
                version: version.to_string(),
                iteration: Some("1".to_string()),
                raw_arch: "x86_64".to_string(),
            },
        )
        .expect("artifact");
        ArtifactRow {
            upstream_path: artifact.rsync_relpath(),
            artifact,
            size: None,
            metadata: serde_json::Value::Null,
            first_seen: chrono::Utc::now(),
            last_seen: chrono::Utc::now(),
            superseded_by: None,
            supersedes: None,
            local: false,
        }
    }

    #[test]
    fn sampling_is_deterministic_and_bounded() {
        let rows = vec![row("18.0.1"), row("18.0.2"), row("19.0.1")];
        let first = sample(rows.clone(), Some(2));
        let second = sample(rows, Some(2));
        assert_eq!(first, second);
        assert_eq!(first.len(), 2);
    }

    #[test]
    fn a_sample_larger_than_the_ledger_keeps_everything() {
        let rows = vec![row("18.0.1"), row("18.0.2")];
        assert_eq!(sample(rows.clone(), Some(10)).len(), 2);
        assert_eq!(sample(rows.clone(), None).len(), 2);
        assert!(sample(rows, Some(0)).is_empty());
    }

    #[test]
    fn findings_are_reported_with_the_target() {
        let finding = Finding {
            artifact_key: "stable/cinc/19.4.46/debian/13/amd64/aa".to_string(),
            target: Some("oci".to_string()),
            kind: FindingKind::Remote,
            detail: "tag `x` is not published".to_string(),
        };
        assert_eq!(
            finding.to_string(),
            "remote stable/cinc/19.4.46/debian/13/amd64/aa target=oci: \
             tag `x` is not published"
        );
        assert_eq!(
            VerifyReport {
                findings: vec![finding],
                ..VerifyReport::default()
            }
            .exit_code(),
            EXIT_PARTIAL
        );
        assert_eq!(VerifyReport::default().exit_code(), EXIT_OK);
    }
}
