//! Integrity incidents: detection, alerting and the acknowledged republish.
//!
//! An incident is a ledger row plus a local JSON alert. Detection is
//! deduplicated on `(artifact_key, old_sha256, new_sha256)`: a later run that
//! sees the same triple gets the existing row back and writes no event, alert
//! or issue. Only a **newly opened** incident prints the security line, sets
//! `SECURITY_ALERT=true` in `$GITHUB_ENV` and files a GitHub issue.
//!
//! # Acknowledgement
//!
//! [`ack`] always records an `incident_acked` event. With `republish` it first
//! asks every enabled target to preserve the old bytes under the superseded
//! name, then writes the replacement artifact back under its canonical
//! reference. Every target must succeed before any old publication is marked
//! `superseded`; a partial failure restores the targets that already moved and
//! returns [`IncidentError::RepublishFailed`], leaving the ledger's publication
//! rows untouched.
//!
//! # Secrets
//!
//! Tokens are read from the environment at use time and never appear in the
//! ledger, the alerts, errors or logs.

use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chrono::{SecondsFormat, Utc};
use serde_json::{json, Value};
use thiserror::Error;

use crate::artifact::{sanitize_component, Artifact};
use crate::config::Config;
use crate::fsutil;
use crate::ledger::{
    self, Event, EventKind, IncidentFilter, Ledger, LedgerError, PublicationStatus,
};
use crate::store::{Store, StoreError};
use crate::targets::{PutOutcome, Target, TargetSet};

pub use crate::ledger::{Incident, IncidentKind, IncidentState};

/// Default GitHub API root when configuration does not override it.
const DEFAULT_API_BASE: &str = "https://api.github.com";

/// The label attached to incident issues.
const ISSUE_LABEL: &str = "security-incident";

/// Distinguishes event ids when several incidents are recorded in one process.
static EVENT_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Errors raised by the incident flow.
#[derive(Debug, Error)]
pub enum IncidentError {
    /// The ledger rejected an event or query.
    #[error(transparent)]
    Ledger(#[from] LedgerError),

    /// A local file operation failed.
    #[error("{}: {source}", path.display())]
    Io {
        /// Path the operation was working on.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: io::Error,
    },

    /// An alert could not be serialised.
    #[error("json: {0}")]
    Json(#[from] serde_json::Error),

    /// The local store could not be opened or queried.
    #[error(transparent)]
    Store(#[from] StoreError),

    /// The requested incident is not in the ledger.
    #[error("unknown incident `{id}`")]
    UnknownIncident {
        /// The requested id.
        id: String,
    },

    /// The incident cannot be republished because it names no replacement.
    #[error("incident `{id}` has no replacement to republish")]
    NotRepublishable {
        /// The incident id.
        id: String,
    },

    /// The artifact key does not have the expected `<prefix>/<sha256>` shape.
    #[error("invalid artifact key `{key}`")]
    InvalidArtifactKey {
        /// The rejected key.
        key: String,
    },

    /// An incident names an artifact the ledger has never seen.
    #[error("incident references unknown artifact `{key}`")]
    MissingArtifact {
        /// The missing artifact key.
        key: String,
    },

    /// At least one target could not publish the replacement.
    #[error("republish of incident `{id}` failed on `{target}`: {reason}")]
    RepublishFailed {
        /// The incident id.
        id: String,
        /// The target that failed, or `local-store` when the blob is missing.
        target: String,
        /// What went wrong, already stripped of credentials.
        reason: String,
    },

    /// The GitHub issue API failed. The caller logs and continues.
    #[error("github issue request failed: {message}")]
    GitHub {
        /// A redacted description of the failure.
        message: String,
    },
}

/// Detect an incident and materialise it in the ledger.
///
/// For [`IncidentKind::HashChanged`] the ledger receives a `hash_changed`
/// event, which is also what supersedes the old artifact row. Every other kind
/// receives an `incident_opened` event. Detection is deduplicated: an existing
/// incident for the same artifact key and digest pair is returned unchanged.
///
/// # Errors
///
/// Returns [`IncidentError::Ledger`] when the event cannot be appended,
/// [`IncidentError::MissingArtifact`] when the incident names an artifact the
/// ledger has not seen, and [`IncidentError::Io`] when the alert cannot be
/// written. A failed GitHub issue call is logged and never fails this function.
pub async fn open(
    ledger: &mut Ledger,
    config: &Config,
    artifact: &Artifact,
    old_sha256: &str,
    kind: IncidentKind,
) -> Result<Incident, IncidentError> {
    let new_sha256 = artifact.sha256.clone();
    let artifact_key = artifact.key();

    if let Some(existing) = find_incident(ledger, kind, &artifact_key, old_sha256, &new_sha256)? {
        return Ok(existing);
    }

    let detected_at = Utc::now();
    let id = ledger::incident_id(
        kind,
        Some(&artifact_key),
        Some(old_sha256),
        Some(&new_sha256),
    );
    let upstream_path = artifact.rsync_relpath();
    let old_key = ledger::superseded_key(&artifact_key, old_sha256).ok_or_else(|| {
        IncidentError::InvalidArtifactKey {
            key: artifact_key.clone(),
        }
    })?;

    // A hash change needs the old row; every other incident needs the artifact
    // it names. Check before creating an issue so a missing row cannot leave an
    // orphan issue behind.
    match kind {
        IncidentKind::HashChanged => {
            if ledger.artifact(&old_key)?.is_none() {
                return Err(IncidentError::MissingArtifact { key: old_key });
            }
        }
        _ => {
            if ledger.artifact(&artifact_key)?.is_none() {
                return Err(IncidentError::MissingArtifact { key: artifact_key });
            }
        }
    }

    let provisional = Incident {
        id: id.clone(),
        artifact_key: Some(artifact_key.clone()),
        kind,
        old_sha256: Some(old_sha256.to_string()),
        new_sha256: Some(new_sha256.clone()),
        detected_at,
        detail: json!({
            "upstream_path": upstream_path,
            "old_key": old_key,
        }),
        state: IncidentState::Open,
        issue_url: None,
        ack_note: None,
    };
    let issue_url = match open_github_issue(config, &provisional).await {
        Ok(url) => url,
        Err(error) => {
            tracing::warn!(%error, "github issue creation failed; the run continues");
            None
        }
    };

    let event = match kind {
        IncidentKind::HashChanged => {
            let mut detail = json!({
                "old_key": old_key,
                "old_sha256": old_sha256,
                "new_sha256": new_sha256,
                "artifact": ledger::artifact_detail(artifact),
                "upstream_path": upstream_path,
                "metadata": serde_json::from_str::<Value>(&artifact.metadata_json)
                    .unwrap_or(Value::Null),
            });
            if let Some(url) = issue_url.as_deref() {
                detail["issue_url"] = json!(url);
            }
            Event::new(
                event_run_id("incident"),
                1,
                detected_at,
                EventKind::HashChanged,
            )
            .with_artifact(artifact_key)
            .with_detail(detail)
        }
        _ => {
            let mut detail = json!({
                "id": id,
                "kind": kind.as_str(),
                "artifact_key": artifact_key,
                "old_sha256": old_sha256,
                "new_sha256": new_sha256,
                "upstream_path": upstream_path,
                "detail": {
                    "upstream_path": upstream_path,
                    "old_key": old_key,
                },
            });
            if let Some(url) = issue_url.as_deref() {
                detail["issue_url"] = json!(url);
            }
            Event::new(
                event_run_id("incident"),
                1,
                detected_at,
                EventKind::IncidentOpened,
            )
            .with_artifact(artifact_key)
            .with_detail(detail)
        }
    };

    ledger.append(&event)?;
    let incident = ledger
        .incident(&id)?
        .ok_or_else(|| IncidentError::UnknownIncident { id: id.clone() })?;

    write_alert(&config.state_dir, &incident)?;
    announce(&incident);
    record_security_alert();

    Ok(incident)
}

/// Acknowledge an incident, optionally moving the canonical reference.
///
/// `republish` publishes the replacement artifact under its canonical reference
/// on every enabled target first. Before any canonical path moves, every target
/// is asked to preserve the old bytes under the superseded name. Only when every
/// target succeeded are the old publication rows marked `superseded`, followed
/// by the `incident_acked` event. A target failure restores the targets that
/// already moved and returns [`IncidentError::RepublishFailed`] without
/// acknowledging the incident.
///
/// # Errors
///
/// Returns [`IncidentError::UnknownIncident`] for an unknown id,
/// [`IncidentError::NotRepublishable`] when the incident names no replacement,
/// [`IncidentError::RepublishFailed`] when a target or the local store fails,
/// and [`IncidentError::Ledger`] when an event cannot be appended.
pub async fn ack(
    ledger: &mut Ledger,
    targets: &TargetSet,
    config: &Config,
    id: &str,
    note: Option<&str>,
    republish: bool,
) -> Result<(), IncidentError> {
    let incident = show(ledger, id)?;

    if republish {
        let plan = republish_plan(ledger, &incident)?;
        let store = Store::open(&config.state_dir)?;
        let replacement_path = store.path(&plan.replacement.sha256)?;
        let old_path = store.path(&plan.old_artifact.sha256)?;
        if !replacement_path.is_file() {
            return Err(IncidentError::RepublishFailed {
                id: id.to_string(),
                target: "local-store".to_string(),
                reason: format!("no verified blob for {}", plan.replacement.sha256),
            });
        }

        // Keep the old bytes recoverable before any canonical path moves. This
        // is a server-side copy on targets that need one; OCI needs nothing.
        for target in targets.all() {
            if let Err(error) = target.preserve_superseded(&plan.old_artifact).await {
                return Err(IncidentError::RepublishFailed {
                    id: id.to_string(),
                    target: target.name().to_string(),
                    reason: error.to_string(),
                });
            }
        }

        let mut succeeded: Vec<(&Arc<dyn Target>, PutOutcome)> = Vec::new();
        for target in targets.all() {
            match target.republish(&plan.replacement, &replacement_path).await {
                Ok(outcome) => succeeded.push((target, outcome)),
                Err(error) => {
                    for (done, _) in &succeeded {
                        if old_path.is_file() {
                            if let Err(rollback) =
                                done.republish(&plan.old_artifact, &old_path).await
                            {
                                tracing::warn!(
                                    target = done.name(),
                                    %rollback,
                                    "could not restore the old canonical reference \
                                     after a republish failure"
                                );
                            }
                        } else {
                            tracing::warn!(
                                target = done.name(),
                                sha256 = %plan.old_artifact.sha256,
                                "the old blob is not in the local store; the canonical \
                                 reference could not be restored"
                            );
                        }
                    }
                    return Err(IncidentError::RepublishFailed {
                        id: id.to_string(),
                        target: target.name().to_string(),
                        reason: error.to_string(),
                    });
                }
            }
        }

        let run_id = event_run_id("ack");
        let mut seq = 1;

        // The replacement really is published now; record it so the next run
        // and repair do not chase it again.
        for (target, outcome) in &succeeded {
            ledger.append(
                &Event::new(run_id.clone(), seq, Utc::now(), EventKind::Published)
                    .with_artifact(plan.replacement.key())
                    .with_target(target.name())
                    .with_detail(json!({
                        "remote_ref": outcome.remote_ref,
                        "remote_digest": outcome.remote_digest,
                        "incident": id,
                    })),
            )?;
            seq += 1;
        }

        for target in targets.all() {
            if let Some(publication) = ledger.publication(&plan.old_key, target.name())? {
                if publication.status != PublicationStatus::Superseded {
                    ledger.append(
                        &Event::new(
                            run_id.clone(),
                            seq,
                            Utc::now(),
                            EventKind::PublicationSuperseded,
                        )
                        .with_artifact(plan.old_key.clone())
                        .with_target(target.name())
                        .with_detail(json!({
                            "incident": id,
                            "replacement": plan.replacement_key,
                        })),
                    )?;
                    seq += 1;
                }
            }
        }

        ledger.append(
            &Event::new(run_id, seq, Utc::now(), EventKind::IncidentAcked)
                .with_detail(json!({"id": id, "note": note})),
        )?;
    } else {
        ledger.append(
            &Event::new(event_run_id("ack"), 1, Utc::now(), EventKind::IncidentAcked)
                .with_detail(json!({"id": id, "note": note})),
        )?;
    }

    Ok(())
}

/// Every incident, open first and newest first within each state.
///
/// # Errors
///
/// Returns [`IncidentError::Ledger`] when the query fails.
pub fn list(ledger: &Ledger) -> Result<Vec<Incident>, IncidentError> {
    let mut incidents = ledger.incidents(IncidentFilter::default())?;
    incidents.sort_by(|left, right| {
        let rank = |state: IncidentState| match state {
            IncidentState::Open => 0,
            IncidentState::Acked => 1,
        };
        rank(left.state)
            .cmp(&rank(right.state))
            .then_with(|| right.detected_at.cmp(&left.detected_at))
            .then_with(|| left.id.cmp(&right.id))
    });
    Ok(incidents)
}

/// One incident from the ledger.
///
/// # Errors
///
/// Returns [`IncidentError::UnknownIncident`] when the id is not present and
/// [`IncidentError::Ledger`] when the query fails.
pub fn show(ledger: &Ledger, id: &str) -> Result<Incident, IncidentError> {
    ledger
        .incident(id)?
        .ok_or_else(|| IncidentError::UnknownIncident { id: id.to_string() })
}

/// Write `<state_dir>/alerts/<incident-id>.json` with mode `0600`.
///
/// The document is deliberately a fixed selection of fields: artifact identity,
/// both digests, the detection time and the issue URL. `detail` is never
/// serialised whole, so a token accidentally placed there cannot leak.
///
/// # Errors
///
/// Returns [`IncidentError::Io`] when the alert directory or file cannot be
/// written and [`IncidentError::Json`] when serialisation fails.
pub fn write_alert(state_dir: &Path, incident: &Incident) -> Result<PathBuf, IncidentError> {
    let state_dir = fsutil::expand_tilde(state_dir);
    let alerts = state_dir.join("alerts");
    fs::create_dir_all(&alerts).map_err(|source| io_error(&alerts, source))?;

    let name = format!("{}.json", sanitize_component(&incident.id));
    let path = alerts.join(name);
    let document = json!({
        "id": incident.id,
        "kind": incident.kind,
        "artifact_key": incident.artifact_key,
        "upstream_path": upstream_path(incident),
        "old_sha256": incident.old_sha256,
        "new_sha256": incident.new_sha256,
        "detected_at": incident.detected_at.to_rfc3339_opts(SecondsFormat::Millis, true),
        "issue_url": incident.issue_url,
    });
    let bytes = serde_json::to_vec_pretty(&document)?;

    let mut options = OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(&path)
        .map_err(|source| io_error(&path, source))?;
    file.write_all(&bytes)
        .map_err(|source| io_error(&path, source))?;
    file.sync_all().map_err(|source| io_error(&path, source))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
            .map_err(|source| io_error(&path, source))?;
    }

    Ok(path)
}

/// File an issue for `incident`, returning its `html_url` when one was made.
///
/// The repository is `GITHUB_REPOSITORY` when set, otherwise
/// [`Config::issue_repo`]. A missing token or repository is a skip with a
/// warning. Network and API failures return [`IncidentError::GitHub`]; the
/// caller logs them and continues, so issue filing can never fail a mirror run.
///
/// # Errors
///
/// Returns [`IncidentError::GitHub`] when the request or response cannot be
/// used. The message never contains the token.
pub async fn open_github_issue(
    config: &Config,
    incident: &Incident,
) -> Result<Option<String>, IncidentError> {
    let Some(token) = env_non_empty("GITHUB_TOKEN") else {
        tracing::warn!("GITHUB_TOKEN is not set; skipping the incident issue");
        return Ok(None);
    };

    let repo = env_non_empty("GITHUB_REPOSITORY").or_else(|| {
        config
            .issue_repo
            .as_deref()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(ToString::to_string)
    });
    let Some(repo) = repo else {
        tracing::warn!(
            "no GITHUB_REPOSITORY or issue_repo configured; skipping the incident issue"
        );
        return Ok(None);
    };

    let api_base = if config.incident.api_base.trim().is_empty() {
        DEFAULT_API_BASE
    } else {
        config.incident.api_base.trim_end_matches('/')
    };
    let url = format!("{api_base}/repos/{repo}/issues");
    let title = format!(
        "cinc-mirror: {} for {}",
        incident.kind,
        upstream_path(incident)
    );

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|error| IncidentError::GitHub {
            message: error.to_string(),
        })?;
    let response = client
        .post(&url)
        .header(reqwest::header::AUTHORIZATION, format!("Bearer {token}"))
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header(reqwest::header::USER_AGENT, "cinc-mirror")
        .json(&json!({
            "title": title,
            "body": issue_body(incident),
            "labels": [ISSUE_LABEL],
        }))
        .send()
        .await
        .map_err(|error| IncidentError::GitHub {
            message: error.to_string(),
        })?;

    if !response.status().is_success() {
        return Err(IncidentError::GitHub {
            message: format!("issue creation returned HTTP {}", response.status()),
        });
    }

    let value: Value = response
        .json()
        .await
        .map_err(|error| IncidentError::GitHub {
            message: format!("issue response is not JSON: {error}"),
        })?;
    Ok(value
        .get("html_url")
        .and_then(Value::as_str)
        .map(ToString::to_string))
}

/// The replacement an acknowledgement needs.
struct RepublishPlan {
    old_key: String,
    replacement_key: String,
    old_artifact: Artifact,
    replacement: Artifact,
}

fn republish_plan(ledger: &Ledger, incident: &Incident) -> Result<RepublishPlan, IncidentError> {
    if incident.kind != IncidentKind::HashChanged {
        return Err(IncidentError::NotRepublishable {
            id: incident.id.clone(),
        });
    }
    let new_key = incident
        .artifact_key
        .clone()
        .ok_or_else(|| IncidentError::NotRepublishable {
            id: incident.id.clone(),
        })?;
    let old_key = incident
        .detail
        .get("old_key")
        .and_then(Value::as_str)
        .map(ToString::to_string)
        .or_else(|| {
            incident
                .old_sha256
                .as_deref()
                .and_then(|old_sha256| ledger::superseded_key(&new_key, old_sha256))
        })
        .ok_or_else(|| IncidentError::NotRepublishable {
            id: incident.id.clone(),
        })?;

    let old_row = ledger
        .artifact(&old_key)?
        .ok_or_else(|| IncidentError::RepublishFailed {
            id: incident.id.clone(),
            target: "local-store".to_string(),
            reason: format!("old artifact `{old_key}` is not in the ledger"),
        })?;
    let replacement_key =
        old_row
            .superseded_by
            .clone()
            .ok_or_else(|| IncidentError::NotRepublishable {
                id: incident.id.clone(),
            })?;
    let replacement_row =
        ledger
            .artifact(&replacement_key)?
            .ok_or_else(|| IncidentError::RepublishFailed {
                id: incident.id.clone(),
                target: "local-store".to_string(),
                reason: format!("replacement `{replacement_key}` is not in the ledger"),
            })?;

    Ok(RepublishPlan {
        old_key,
        replacement_key,
        old_artifact: old_row.artifact,
        replacement: replacement_row.artifact,
    })
}

fn find_incident(
    ledger: &Ledger,
    kind: IncidentKind,
    artifact_key: &str,
    old_sha256: &str,
    new_sha256: &str,
) -> Result<Option<Incident>, IncidentError> {
    let incidents = ledger.incidents(IncidentFilter {
        kind: Some(kind),
        artifact_key: Some(artifact_key.to_string()),
        state: None,
    })?;
    Ok(incidents.into_iter().find(|incident| {
        incident.old_sha256.as_deref() == Some(old_sha256)
            && incident.new_sha256.as_deref() == Some(new_sha256)
    }))
}

fn upstream_path(incident: &Incident) -> String {
    incident
        .detail
        .get("upstream_path")
        .and_then(Value::as_str)
        .or_else(|| {
            incident
                .detail
                .get("detail")
                .and_then(|detail| detail.get("upstream_path"))
                .and_then(Value::as_str)
        })
        .map(ToString::to_string)
        .or_else(|| incident.artifact_key.clone())
        .unwrap_or_default()
}

fn issue_body(incident: &Incident) -> String {
    let detected_at = incident
        .detected_at
        .to_rfc3339_opts(SecondsFormat::Millis, true);
    let mut body = format!(
        "Incident `{id}` was detected at {detected_at}.\n\n\
         - kind: `{kind}`\n\
         - artifact: `{artifact}`\n\
         - upstream path: `{upstream}`\n",
        id = incident.id,
        kind = incident.kind,
        artifact = incident.artifact_key.as_deref().unwrap_or("unknown"),
        upstream = upstream_path(incident),
    );
    // An unrecoverable incident names the same digest twice on purpose: it is
    // about a file that is gone, not about bytes that changed. The other kinds
    // exist because two digests differ.
    if incident.old_sha256.is_some() && incident.old_sha256 != incident.new_sha256 {
        body.push_str(&format!(
            "- old sha256: `{}`\n- new sha256: `{}`\n",
            incident.old_sha256.as_deref().unwrap_or("unknown"),
            incident.new_sha256.as_deref().unwrap_or("unknown"),
        ));
    } else if let Some(sha256) = incident.new_sha256.as_deref() {
        body.push_str(&format!("- sha256: `{sha256}`\n"));
    }
    body.push('\n');
    body.push_str(&match incident.kind {
        IncidentKind::HashChanged => format!(
            "The mirror kept the old bytes. Review the change, then acknowledge it with \
             `cinc-mirror incidents ack {id}`; add `--republish` to move the canonical \
             reference to the new digest.",
            id = incident.id,
        ),
        IncidentKind::TagConflict => format!(
            "The reference already held different bytes, so the mirror did not overwrite it. \
             Compare the two files, then acknowledge with `cinc-mirror incidents ack {id}`; \
             add `--republish` to move the reference to the incoming digest.",
            id = incident.id,
        ),
        IncidentKind::Unrecoverable => format!(
            "Upstream no longer serves the payload, so nothing could be published and the \
             local copy (if any) is the only one left. Every run retries it, so a restored \
             file heals without help; acknowledge with `cinc-mirror incidents ack {id}` when \
             the loss is accepted.",
            id = incident.id,
        ),
        IncidentKind::ArchCollision => format!(
            "Two upstream files map to one descriptive reference. Both are published: the \
            first under the plain reference, this one under a digest-qualified one. \
            Acknowledge with `cinc-mirror incidents ack {id}` once the pair is reviewed.",
            id = incident.id,
        ),
    });
    body
}

fn announce(incident: &Incident) {
    // Two identical digests read as noise ("same -> same"); an unrecoverable
    // incident carries the digest only once.
    let digests = match (
        incident.old_sha256.as_deref(),
        incident.new_sha256.as_deref(),
    ) {
        (Some(old), Some(new)) if old != new => format!(" ({old} -> {new})"),
        (_, Some(new)) => format!(" ({new})"),
        (Some(old), None) => format!(" ({old})"),
        (None, None) => String::new(),
    };
    eprintln!(
        "SECURITY: {} incident {} for {}{digests}",
        incident.kind,
        incident.id,
        upstream_path(incident),
    );
}

fn record_security_alert() {
    let Some(path) = std::env::var_os("GITHUB_ENV") else {
        return;
    };
    let path = PathBuf::from(path);
    if !path.is_file() {
        return;
    }
    match OpenOptions::new().append(true).open(&path) {
        Ok(mut file) => {
            if let Err(error) = writeln!(file, "SECURITY_ALERT=true") {
                tracing::warn!(
                    %error,
                    path = %path.display(),
                    "could not append SECURITY_ALERT to GITHUB_ENV"
                );
            }
        }
        Err(error) => {
            tracing::warn!(
                %error,
                path = %path.display(),
                "could not open GITHUB_ENV to record SECURITY_ALERT"
            );
        }
    }
}

fn env_non_empty(name: &str) -> Option<String> {
    std::env::var(name)
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn event_run_id(prefix: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos());
    let counter = EVENT_COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{prefix}-{nanos}-{counter}")
}

fn io_error(path: impl Into<PathBuf>, source: io::Error) -> IncidentError {
    IncidentError::Io {
        path: path.into(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ledger::IncidentState;
    use chrono::TimeZone;
    use serde_json::json;

    fn incident(kind: IncidentKind) -> Incident {
        let sha256 = "a".repeat(64);
        Incident {
            id: format!("{}-0123456789abcdef", kind.as_str()),
            artifact_key: Some("stable/cinc/19.4.46/debian/13/amd64/x.deb".to_string()),
            kind,
            old_sha256: Some(sha256.clone()),
            new_sha256: Some(sha256),
            detected_at: Utc.with_ymd_and_hms(2026, 11, 26, 12, 0, 0).unwrap(),
            detail: json!({"upstream_path": "stable/cinc/19.4.46/x.deb"}),
            state: IncidentState::Open,
            issue_url: None,
            ack_note: None,
        }
    }

    #[test]
    fn an_unrecoverable_body_names_one_digest_and_explains_the_retry() {
        let body = issue_body(&incident(IncidentKind::Unrecoverable));
        assert!(body.contains("- sha256: `"), "{body}");
        assert!(!body.contains("new sha256"), "{body}");
        assert!(body.contains("Every run retries it"), "{body}");
        assert!(!body.contains("--republish"), "{body}");
    }

    #[test]
    fn a_changed_hash_body_keeps_the_pair_and_the_republish_hint() {
        let mut row = incident(IncidentKind::HashChanged);
        row.new_sha256 = Some("b".repeat(64));
        let body = issue_body(&row);
        assert!(body.contains("- old sha256: `"), "{body}");
        assert!(body.contains("- new sha256: `"), "{body}");
        assert!(body.contains("--republish"), "{body}");
    }
}
