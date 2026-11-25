//! Ledger database tests.
//!
//! Every test drives a real SQLite database in a temporary state directory.
//! The ledger's job is durability and derivation: append-only events, current
//! state materialised from them, and a rebuild that proves the events are the
//! only source of truth. A mock would only restate the reducer, so assertions
//! look at the rows a later task would read.

use std::str::FromStr;

use chrono::{DateTime, Duration, TimeZone, Utc};
use cinc_mirror::artifact::Artifact;
use cinc_mirror::ledger::{
    Event, EventKind, IncidentFilter, IncidentKind, IncidentState, Ledger, PublicationStatus,
};
use serde_json::{json, Value};

fn ts(seq: u64) -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 11, 24, 12, 0, 0)
        .single()
        .expect("valid timestamp")
        + Duration::seconds(i64::try_from(seq).expect("small seq"))
}

fn artifact(version: &str, sha_byte: char) -> Artifact {
    Artifact {
        channel: "stable".to_string(),
        project: "cinc".to_string(),
        version: version.to_string(),
        platform: "debian".to_string(),
        platform_version: "13".to_string(),
        arch: "amd64".to_string(),
        raw_arch: "x86_64".to_string(),
        basename: format!("cinc-{version}-debian-13-x86_64.pkg.tar.zst"),
        sha256: sha_byte.to_string().repeat(64),
        metadata_json: format!(
            r#"{{"basename":"cinc-{version}-debian-13-x86_64.pkg.tar.zst","sha256":"{}","iteration":1}}"#,
            sha_byte.to_string().repeat(64)
        ),
        iteration: None,
        superseded: false,
    }
}

fn detail_json(artifact: &Artifact) -> Value {
    json!({
        "channel": artifact.channel,
        "project": artifact.project,
        "version": artifact.version,
        "platform": artifact.platform,
        "platform_version": artifact.platform_version,
        "arch": artifact.arch,
        "raw_arch": artifact.raw_arch,
        "basename": artifact.basename,
        "sha256": artifact.sha256,
        "metadata_json": artifact.metadata_json,
        "iteration": artifact.iteration,
    })
}

fn seen_detail(artifact: &Artifact, size: u64) -> Value {
    json!({
        "artifact": detail_json(artifact),
        "size": size,
        "upstream_path": artifact.rsync_relpath(),
        "metadata": { "sha256": artifact.sha256 },
    })
}

fn event(
    run_id: &str,
    seq: u64,
    kind: EventKind,
    artifact_key: Option<&str>,
    target: Option<&str>,
    detail: Value,
) -> Event {
    Event {
        run_id: run_id.to_string(),
        seq,
        ts: ts(seq),
        kind,
        artifact_key: artifact_key.map(ToString::to_string),
        target: target.map(ToString::to_string),
        detail,
    }
}

fn seen(run_id: &str, seq: u64, artifact: &Artifact, size: u64) -> Event {
    let key = artifact.key();
    event(
        run_id,
        seq,
        EventKind::ArtifactSeen,
        Some(&key),
        None,
        seen_detail(artifact, size),
    )
}

fn published(run_id: &str, seq: u64, artifact: &Artifact, target: &str) -> Event {
    let key = artifact.key();
    event(
        run_id,
        seq,
        EventKind::Published,
        Some(&key),
        Some(target),
        json!({
            "remote_ref": format!("registry.example/{key}:tag"),
            "remote_digest": artifact.sha256,
        }),
    )
}

fn open() -> (tempfile::TempDir, Ledger) {
    let dir = tempfile::tempdir().expect("state dir");
    let ledger = Ledger::open(dir.path()).expect("open ledger");
    (dir, ledger)
}

fn keys(artifacts: &[Artifact]) -> Vec<String> {
    artifacts.iter().map(Artifact::key).collect()
}

#[test]
fn appends_and_materializes_artifact_and_publication() {
    let (_dir, mut ledger) = open();
    let artifact = artifact("19.4.46", 'a');
    let key = artifact.key();

    ledger
        .append(&seen("run-1", 1, &artifact, 1234))
        .expect("artifact_seen");
    ledger
        .append(&event(
            "run-1",
            2,
            EventKind::Verified,
            Some(&key),
            None,
            json!({ "sha256": artifact.sha256, "size": 1234 }),
        ))
        .expect("verified");

    assert_eq!(
        keys(&ledger.pending("ghcr").expect("pending")),
        keys(std::slice::from_ref(&artifact)),
        "a seen artifact without a publication row is pending"
    );

    ledger
        .append(&published("run-1", 3, &artifact, "ghcr"))
        .expect("published");

    assert!(
        ledger.pending("ghcr").expect("pending").is_empty(),
        "a published artifact is no longer pending"
    );

    let publication = ledger
        .publication(&key, "ghcr")
        .expect("publication query")
        .expect("publication row");
    assert_eq!(publication.status, PublicationStatus::Published);
    assert_eq!(
        publication.remote_ref.as_deref(),
        Some(format!("registry.example/{key}:tag").as_str())
    );
    assert_eq!(
        publication.remote_digest.as_deref(),
        Some(artifact.sha256.as_str())
    );
    assert_eq!(publication.attempts, 1);
    assert!(publication.next_attempt_at.is_none());
    assert!(publication.last_error.is_none());

    let row = ledger
        .artifact(&key)
        .expect("artifact query")
        .expect("artifact row");
    assert!(row.local, "verified marks the blob as present locally");
    assert_eq!(row.size, Some(1234));
    assert_eq!(row.upstream_path, artifact.rsync_relpath());
    assert_eq!(row.artifact.key(), key);
    assert_eq!(row.artifact.sha256, artifact.sha256);
    assert_eq!(row.first_seen, ts(1));
    assert_eq!(row.last_seen, ts(2));

    assert!(ledger
        .satisfied_keys("ghcr")
        .expect("satisfied keys")
        .contains(&key));
    assert_eq!(ledger.event_count().expect("event count"), 3);
}

#[test]
fn pending_excludes_satisfied_and_superseded_rows() {
    let (_dir, mut ledger) = open();

    let satisfied = artifact("9.4.0", 'a');
    let bigger = artifact("19.2.0", 'b');
    let smaller = artifact("19.1.0", 'c');
    let future = artifact("18.1.0", 'd');
    let interrupted = artifact("17.1.0", 'e');
    let superseded = artifact("16.1.0", 'f');

    let all = [
        &satisfied,
        &bigger,
        &smaller,
        &future,
        &interrupted,
        &superseded,
    ];
    for (index, artifact) in all.iter().enumerate() {
        let seq = u64::try_from(index).expect("small index") + 1;
        ledger
            .append(&seen("run-1", seq, artifact, 10))
            .expect("artifact_seen");
    }

    ledger
        .append(&published("run-1", 20, &satisfied, "ghcr"))
        .expect("published");

    let now = Utc::now();
    ledger
        .append(&event(
            "run-1",
            21,
            EventKind::PublicationFailed,
            Some(&bigger.key()),
            Some("ghcr"),
            json!({
                "error": "connection reset",
                "next_attempt_at": (now - Duration::minutes(5)).to_rfc3339(),
            }),
        ))
        .expect("failed in the past");
    ledger
        .append(&event(
            "run-1",
            22,
            EventKind::PublicationFailed,
            Some(&future.key()),
            Some("ghcr"),
            json!({
                "error": "rate limited",
                "next_attempt_at": (now + Duration::hours(1)).to_rfc3339(),
            }),
        ))
        .expect("failed in the future");
    ledger
        .append(&event(
            "run-1",
            23,
            EventKind::PublicationInterrupted,
            Some(&interrupted.key()),
            Some("ghcr"),
            json!({ "error": "process killed" }),
        ))
        .expect("interrupted");

    ledger
        .append(&published("run-1", 24, &superseded, "ghcr"))
        .expect("published before supersession");
    ledger
        .append(&event(
            "run-1",
            25,
            EventKind::PublicationSuperseded,
            Some(&superseded.key()),
            Some("ghcr"),
            json!({}),
        ))
        .expect("superseded");

    let pending = ledger.pending("ghcr").expect("pending");
    assert_eq!(
        keys(&pending),
        keys(&[bigger, smaller, interrupted]),
        "satisfied, backed-off and superseded rows are excluded; versions sort numerically"
    );

    let future_publication = ledger
        .publication(&future.key(), "ghcr")
        .expect("publication query")
        .expect("publication row");
    assert_eq!(future_publication.status, PublicationStatus::Failed);
    assert_eq!(
        future_publication.last_error.as_deref(),
        Some("rate limited")
    );
    assert!(future_publication.next_attempt_at.is_some());

    let superseded_publication = ledger
        .publication(&superseded.key(), "ghcr")
        .expect("publication query")
        .expect("publication row");
    assert_eq!(superseded_publication.status, PublicationStatus::Superseded);
    assert!(!ledger
        .satisfied_keys("ghcr")
        .expect("satisfied keys")
        .contains(&superseded.key()));

    assert_eq!(
        ledger.pending("rsync").expect("other target").len(),
        6,
        "pending state is per target"
    );
}

#[test]
fn hash_change_opens_single_incident_per_hash_pair() {
    let (_dir, mut ledger) = open();
    let old = artifact("19.4.46", 'a');
    let mut new = old.clone();
    new.sha256 = "b".repeat(64);

    ledger
        .append(&seen("run-1", 1, &old, 100))
        .expect("artifact_seen");
    ledger
        .append(&published("run-1", 2, &old, "ghcr"))
        .expect("published");

    let hash_change = event(
        "run-1",
        3,
        EventKind::HashChanged,
        Some(&new.key()),
        None,
        json!({
            "old_key": old.key(),
            "old_sha256": old.sha256,
            "new_sha256": new.sha256,
            "artifact": detail_json(&new),
            "size": 101,
            "metadata": { "sha256": new.sha256 },
        }),
    );
    ledger.append(&hash_change).expect("hash_changed");

    let old_row = ledger
        .artifact(&old.key())
        .expect("old artifact")
        .expect("old row");
    assert_eq!(old_row.superseded_by.as_deref(), Some(new.key().as_str()));

    let new_row = ledger
        .artifact(&new.key())
        .expect("new artifact")
        .expect("new row");
    assert_eq!(new_row.supersedes.as_deref(), Some(old.key().as_str()));
    assert_eq!(new_row.upstream_path, old.rsync_relpath());
    assert_eq!(new_row.size, Some(101));
    assert_eq!(new_row.artifact.key(), new.key());
    assert_eq!(new_row.artifact.sha256, new.sha256);
    assert_eq!(
        new_row.artifact.metadata_json, new.metadata_json,
        "hash_changed must keep the exact upstream metadata text"
    );
    assert_eq!(new_row.artifact.raw_arch, "x86_64");

    let open = ledger
        .incidents(IncidentFilter::open())
        .expect("open incidents");
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].kind, IncidentKind::HashChanged);
    assert_eq!(open[0].artifact_key.as_deref(), Some(new.key().as_str()));
    assert_eq!(open[0].old_sha256.as_deref(), Some(old.sha256.as_str()));
    assert_eq!(open[0].new_sha256.as_deref(), Some(new.sha256.as_str()));
    assert_eq!(open[0].state, IncidentState::Open);

    assert_eq!(
        ledger
            .publication(&old.key(), "ghcr")
            .expect("old publication")
            .expect("old row")
            .status,
        PublicationStatus::Published,
        "the old publication stays published until the incident is acked"
    );
    assert_eq!(
        ledger
            .publication(&new.key(), "ghcr")
            .expect("new publication")
            .expect("new row")
            .status,
        PublicationStatus::Pending
    );
    assert_eq!(
        keys(&ledger.pending("ghcr").expect("pending")),
        keys(std::slice::from_ref(&new)),
        "only the replacement is pending"
    );

    ledger.apply(&hash_change).expect("re-apply");
    ledger.append(&hash_change).expect("duplicate append");
    assert_eq!(
        ledger
            .incidents(IncidentFilter::open())
            .expect("open incidents")
            .len(),
        1,
        "duplicate application must not open a second incident"
    );
    assert_eq!(ledger.event_count().expect("event count"), 3);

    let open = ledger
        .incidents(IncidentFilter {
            kind: Some(IncidentKind::HashChanged),
            ..IncidentFilter::default()
        })
        .expect("filtered incidents");
    assert_eq!(open.len(), 1, "kind filter returns the incident");
}

#[test]
fn duplicate_event_is_idempotent() {
    let (_dir, mut ledger) = open();
    let artifact = artifact("19.4.46", 'a');
    let seen_event = seen("run-1", 1, &artifact, 10);
    let published_event = published("run-1", 2, &artifact, "ghcr");

    ledger.append(&seen_event).expect("first append");
    ledger.append(&seen_event).expect("second append");
    ledger.append(&published_event).expect("first publish");
    ledger.append(&published_event).expect("second publish");

    assert_eq!(ledger.event_count().expect("event count"), 2);
    assert_eq!(
        ledger.artifacts().expect("artifacts").len(),
        1,
        "one artifact row for one event"
    );

    let publication = ledger
        .publication(&artifact.key(), "ghcr")
        .expect("publication query")
        .expect("publication row");
    assert_eq!(publication.status, PublicationStatus::Published);
    assert_eq!(
        publication.attempts, 1,
        "a replayed publish is not a second attempt"
    );

    ledger.apply(&published_event).expect("reducer re-apply");
    let publication = ledger
        .publication(&artifact.key(), "ghcr")
        .expect("publication query")
        .expect("publication row");
    assert_eq!(publication.attempts, 1);
}

#[test]
fn local_gc_marks_row_and_keeps_publication_verified() {
    let (_dir, mut ledger) = open();
    let artifact = artifact("19.4.46", 'a');
    let key = artifact.key();

    ledger
        .append(&seen("run-1", 1, &artifact, 42))
        .expect("artifact_seen");
    ledger
        .append(&event(
            "run-1",
            2,
            EventKind::Verified,
            Some(&key),
            None,
            json!({ "sha256": artifact.sha256, "size": 42 }),
        ))
        .expect("verified");
    ledger
        .append(&published("run-1", 3, &artifact, "ghcr"))
        .expect("published");
    ledger
        .append(&event(
            "run-1",
            4,
            EventKind::LocalGc,
            Some(&key),
            None,
            json!({ "size": 42 }),
        ))
        .expect("local_gc");

    let row = ledger
        .artifact(&key)
        .expect("artifact query")
        .expect("artifact row");
    assert!(!row.local, "local_gc clears the local flag");
    assert_eq!(row.size, Some(42), "the size stays known");

    let publication = ledger
        .publication(&key, "ghcr")
        .expect("publication query")
        .expect("publication row");
    assert_eq!(
        publication.status,
        PublicationStatus::Published,
        "deleting the local blob never downgrades a publication"
    );
    assert!(ledger
        .satisfied_keys("ghcr")
        .expect("satisfied keys")
        .contains(&key));
}

#[test]
fn uploading_is_not_pending_until_interrupted() {
    let (_dir, mut ledger) = open();
    let artifact = artifact("19.4.46", 'a');
    let key = artifact.key();

    ledger
        .append(&seen("run-1", 1, &artifact, 10))
        .expect("artifact_seen");
    ledger
        .append(&event(
            "run-1",
            2,
            EventKind::PublicationStarted,
            Some(&key),
            Some("ghcr"),
            json!({}),
        ))
        .expect("publication_started");

    let publication = ledger
        .publication(&key, "ghcr")
        .expect("publication query")
        .expect("publication row");
    assert_eq!(publication.status, PublicationStatus::Uploading);
    assert!(
        ledger.pending("ghcr").expect("pending").is_empty(),
        "an in-flight upload is not queued again"
    );

    ledger
        .append(&event(
            "run-1",
            3,
            EventKind::PublicationInterrupted,
            Some(&key),
            Some("ghcr"),
            json!({ "error": "process killed" }),
        ))
        .expect("publication_interrupted");

    let publication = ledger
        .publication(&key, "ghcr")
        .expect("publication query")
        .expect("publication row");
    assert_eq!(publication.status, PublicationStatus::Interrupted);
    assert_eq!(publication.attempts, 1);
    assert_eq!(
        keys(&ledger.pending("ghcr").expect("pending")),
        vec![key],
        "an interrupted upload is retried on the next run"
    );
}

#[test]
fn incident_open_and_ack_update_the_row() {
    let (_dir, mut ledger) = open();
    let artifact = artifact("19.4.46", 'a');
    let key = artifact.key();

    ledger
        .append(&seen("run-1", 1, &artifact, 10))
        .expect("artifact_seen");
    ledger
        .append(&event(
            "run-1",
            2,
            EventKind::IncidentOpened,
            Some(&key),
            None,
            json!({
                "id": "tag-conflict-1",
                "kind": "tag_conflict",
                "artifact_key": key,
                "detail": { "tag": "19.4.46-debian-13-amd64" },
            }),
        ))
        .expect("incident_opened");

    let open = ledger
        .incidents(IncidentFilter::open())
        .expect("open incidents");
    assert_eq!(open.len(), 1);
    assert_eq!(open[0].id, "tag-conflict-1");
    assert_eq!(open[0].kind, IncidentKind::TagConflict);
    assert_eq!(open[0].detail["tag"], "19.4.46-debian-13-amd64");
    assert_eq!(open[0].detected_at, ts(2));
    assert!(open[0].ack_note.is_none());

    ledger
        .append(&event(
            "run-1",
            3,
            EventKind::IncidentAcked,
            Some(&key),
            None,
            json!({
                "id": "tag-conflict-1",
                "note": "expected, retagged upstream",
                "issue_url": "https://example.invalid/issues/1",
            }),
        ))
        .expect("incident_acked");

    let all = ledger
        .incidents(IncidentFilter::default())
        .expect("all incidents");
    assert_eq!(all.len(), 1);
    assert_eq!(all[0].state, IncidentState::Acked);
    assert_eq!(
        all[0].ack_note.as_deref(),
        Some("expected, retagged upstream")
    );
    assert_eq!(
        all[0].issue_url.as_deref(),
        Some("https://example.invalid/issues/1")
    );
    assert!(ledger
        .incidents(IncidentFilter::open())
        .expect("open incidents")
        .is_empty());
}

#[test]
fn imported_creates_artifact_and_published_publication() {
    let (_dir, mut ledger) = open();
    let artifact = artifact("19.4.46", 'a');
    let key = artifact.key();

    ledger
        .append(&event(
            "bootstrap-1",
            1,
            EventKind::Imported,
            Some(&key),
            Some("ghcr"),
            json!({
                "artifact": detail_json(&artifact),
                "size": 99,
                "remote_ref": "ghcr.io/rmoriz/cinc-mirror:19.4.46-debian-13-amd64",
                "remote_digest": artifact.sha256,
            }),
        ))
        .expect("imported");

    let row = ledger
        .artifact(&key)
        .expect("artifact query")
        .expect("artifact row");
    assert_eq!(row.artifact.key(), key);
    assert_eq!(row.artifact.sha256, artifact.sha256);
    assert!(!row.local, "an import does not claim local bytes");
    assert_eq!(row.size, Some(99));

    let publication = ledger
        .publication(&key, "ghcr")
        .expect("publication query")
        .expect("publication row");
    assert_eq!(publication.status, PublicationStatus::Published);
    assert_eq!(publication.attempts, 0);
    assert!(publication.remote_digest.is_some());
}

#[test]
fn run_row_stores_effective_policy_json() {
    let (_dir, mut ledger) = open();
    let artifact = artifact("19.4.46", 'a');
    let key = artifact.key();
    let policy = json!([
        {
            "id": "cinc",
            "project": "cinc",
            "channel": "stable",
            "platforms": ["debian"],
            "arches": ["amd64"],
        }
    ]);

    ledger
        .append(&event(
            "run-1",
            1,
            EventKind::RunStarted,
            None,
            None,
            json!({
                "effective_policy": policy,
                "order": "version_desc",
                "max_bytes": 4096,
                "transport_order": ["ftp", "https"],
                "host": "ci-1",
                "leased": true,
            }),
        ))
        .expect("run_started");

    assert!(ledger
        .run("run-1")
        .expect("run query")
        .expect("run row")
        .finished_at
        .is_none());

    ledger
        .append(&event(
            "run-1",
            2,
            EventKind::RunFinished,
            None,
            None,
            json!({
                "outcome": "success",
                "summary": { "published": 1, "failed": 0 },
                "cursor": {
                    "fingerprint": "policy-fingerprint-1",
                    "last_version": artifact.version,
                    "last_artifact_key": key,
                },
            }),
        ))
        .expect("run_finished");

    let run = ledger.run("run-1").expect("run query").expect("run row");
    assert_eq!(run.effective_policy, policy);
    assert_eq!(run.order.as_deref(), Some("version_desc"));
    assert_eq!(run.max_bytes, Some(4096));
    assert_eq!(run.transport_order, vec!["ftp", "https"]);
    assert_eq!(run.host, "ci-1");
    assert!(run.leased);
    assert_eq!(run.started_at, ts(1));
    assert_eq!(run.finished_at, Some(ts(2)));
    assert_eq!(run.outcome.as_deref(), Some("success"));
    assert_eq!(run.summary["published"], 1);

    let cursor = ledger
        .cursor("policy-fingerprint-1")
        .expect("cursor query")
        .expect("cursor row");
    assert_eq!(cursor.last_version.as_deref(), Some("19.4.46"));
    assert_eq!(cursor.last_artifact_key.as_deref(), Some(key.as_str()));
    assert_eq!(cursor.updated_at, ts(2));

    ledger
        .append(&event(
            "plan-1",
            1,
            EventKind::PlanRecorded,
            None,
            None,
            json!({
                "effective_policy": policy,
                "order": "version_desc",
                "summary": { "artifacts": 3, "required_bytes": 300 },
            }),
        ))
        .expect("plan_recorded");
    let plan = ledger.run("plan-1").expect("run query").expect("run row");
    assert_eq!(plan.outcome.as_deref(), Some("planned"));
    assert_eq!(plan.summary["required_bytes"], 300);
    assert!(plan.finished_at.is_some());
}

#[test]
fn schema_migrates_from_empty_and_is_rerunnable() {
    let dir = tempfile::tempdir().expect("state dir");

    {
        let ledger = Ledger::open(dir.path()).expect("first open");
        assert_eq!(ledger.schema_version().expect("schema version"), 2);
    }

    let artifact = artifact("19.4.46", 'a');
    {
        let mut ledger = Ledger::open(dir.path()).expect("second open");
        ledger
            .append(&seen("run-1", 1, &artifact, 10))
            .expect("artifact_seen");
    }

    let ledger = Ledger::open(dir.path()).expect("third open");
    assert_eq!(ledger.schema_version().expect("schema version"), 2);
    assert_eq!(ledger.event_count().expect("event count"), 1);
    assert!(ledger
        .artifact(&artifact.key())
        .expect("artifact query")
        .is_some());

    let db = dir.path().join("ledger.db");
    assert!(db.is_file(), "the ledger lives at <state>/ledger.db");
}

#[test]
fn materialize_rebuilds_derived_state() {
    let (_dir, mut ledger) = open();
    let old = artifact("19.4.46", 'a');
    let mut new = old.clone();
    new.sha256 = "b".repeat(64);

    ledger
        .append(&event(
            "run-1",
            1,
            EventKind::RunStarted,
            None,
            None,
            json!({
                "effective_policy": [{ "id": "cinc" }],
                "order": "version_desc",
                "max_bytes": 1024,
                "transport_order": ["https"],
                "host": "ci-1",
                "leased": true,
            }),
        ))
        .expect("run_started");
    ledger
        .append(&seen("run-1", 2, &old, 100))
        .expect("artifact_seen");
    ledger
        .append(&event(
            "run-1",
            3,
            EventKind::Verified,
            Some(&old.key()),
            None,
            json!({ "sha256": old.sha256, "size": 100 }),
        ))
        .expect("verified");
    ledger
        .append(&published("run-1", 4, &old, "ghcr"))
        .expect("published");
    ledger
        .append(&event(
            "run-1",
            5,
            EventKind::HashChanged,
            Some(&new.key()),
            None,
            json!({
                "old_sha256": old.sha256,
                "new_sha256": new.sha256,
                "artifact": detail_json(&new),
                "size": 101,
            }),
        ))
        .expect("hash_changed");
    ledger
        .append(&event(
            "run-1",
            6,
            EventKind::IncidentOpened,
            Some(&new.key()),
            None,
            json!({
                "id": "tag-conflict-1",
                "kind": "tag_conflict",
                "artifact_key": new.key(),
            }),
        ))
        .expect("incident_opened");
    ledger
        .append(&event(
            "run-1",
            7,
            EventKind::IncidentAcked,
            Some(&new.key()),
            None,
            json!({ "id": "tag-conflict-1", "note": "known" }),
        ))
        .expect("incident_acked");
    ledger
        .append(&event(
            "run-1",
            8,
            EventKind::LocalGc,
            Some(&new.key()),
            None,
            json!({}),
        ))
        .expect("local_gc");
    ledger
        .append(&event(
            "run-1",
            9,
            EventKind::RunFinished,
            None,
            None,
            json!({
                "outcome": "success",
                "summary": { "published": 1 },
                "cursor": {
                    "fingerprint": "fp-1",
                    "last_version": new.version,
                    "last_artifact_key": new.key(),
                },
            }),
        ))
        .expect("run_finished");

    let pending_before = ledger.pending("ghcr").expect("pending");
    let publications_before = ledger.publications("ghcr").expect("publications");
    let incidents_before = ledger
        .incidents(IncidentFilter::default())
        .expect("incidents");
    let run_before = ledger.run("run-1").expect("run query");
    let cursor_before = ledger.cursor("fp-1").expect("cursor query");
    let artifact_before = ledger.artifact(&new.key()).expect("artifact query");
    let event_count = ledger.event_count().expect("event count");

    ledger.materialize().expect("materialize");
    ledger.materialize().expect("materialize is idempotent");

    assert_eq!(ledger.event_count().expect("event count"), event_count);
    assert_eq!(ledger.pending("ghcr").expect("pending"), pending_before);
    assert_eq!(
        ledger.publications("ghcr").expect("publications"),
        publications_before
    );
    assert_eq!(
        ledger
            .incidents(IncidentFilter::default())
            .expect("incidents"),
        incidents_before
    );
    assert_eq!(ledger.run("run-1").expect("run query"), run_before);
    assert_eq!(ledger.cursor("fp-1").expect("cursor query"), cursor_before);
    assert_eq!(
        ledger.artifact(&new.key()).expect("artifact query"),
        artifact_before
    );
}

#[test]
fn materialize_replays_in_append_order_despite_clock_skew() {
    let (_dir, mut ledger) = open();
    let artifact = artifact("19.4.46", 'a');
    let key = artifact.key();

    // A host whose clock is ahead logs `artifact_seen` after `verified` was
    // already appended with an earlier timestamp. Append order is the live
    // order; a timestamp-ordered replay would apply `verified` first, match no
    // artifact row, and silently lose `local = 1`.
    let mut seen_event = seen("run-1", 1, &artifact, 100);
    seen_event.ts = ts(3_600);
    let mut verified_event = event(
        "run-1",
        2,
        EventKind::Verified,
        Some(&key),
        None,
        json!({ "sha256": artifact.sha256, "size": 100 }),
    );
    verified_event.ts = ts(1);

    ledger.append(&seen_event).expect("artifact_seen");
    ledger.append(&verified_event).expect("verified");

    assert!(
        ledger
            .artifact(&key)
            .expect("artifact query")
            .expect("artifact row")
            .local,
        "the live projection is built in append order"
    );

    ledger.materialize().expect("materialize");
    assert!(
        ledger
            .artifact(&key)
            .expect("artifact query")
            .expect("artifact row")
            .local,
        "rebuild must keep local = 1 when timestamps are skewed"
    );

    ledger.materialize().expect("materialize again");
    assert!(
        ledger
            .artifact(&key)
            .expect("artifact query")
            .expect("artifact row")
            .local,
        "materialize stays idempotent"
    );
    assert_eq!(ledger.event_count().expect("event count"), 2);
}

#[test]
fn events_round_trip_with_snake_case_kind_and_millisecond_timestamps() {
    let event = event(
        "run-1",
        7,
        EventKind::PublicationInterrupted,
        Some("stable/cinc/1/2/3/amd64/abc"),
        Some("ghcr"),
        json!({ "error": "killed" }),
    );

    let text = serde_json::to_string(&event).expect("serialise event");
    assert!(
        text.contains("\"kind\":\"publication_interrupted\""),
        "kind must serialise as a stable snake_case string: {text}"
    );
    assert!(
        text.contains("\"ts\":\"2026-11-24T12:00:07.000Z\""),
        "timestamps must be UTC RFC3339 with milliseconds: {text}"
    );

    let back: Event = serde_json::from_str(&text).expect("deserialise event");
    assert_eq!(back, event);

    for (kind, wire) in [
        (EventKind::RunStarted, "run_started"),
        (EventKind::RunFinished, "run_finished"),
        (EventKind::ArtifactSeen, "artifact_seen"),
        (EventKind::DownloadStarted, "download_started"),
        (EventKind::Verified, "verified"),
        (EventKind::PublicationStarted, "publication_started"),
        (EventKind::Published, "published"),
        (EventKind::PublicationFailed, "publication_failed"),
        (EventKind::PublicationInterrupted, "publication_interrupted"),
        (EventKind::PublicationSuperseded, "publication_superseded"),
        (EventKind::HashChanged, "hash_changed"),
        (EventKind::IncidentOpened, "incident_opened"),
        (EventKind::IncidentAcked, "incident_acked"),
        (EventKind::Imported, "imported"),
        (EventKind::LocalGc, "local_gc"),
        (EventKind::LeaseTakenOver, "lease_taken_over"),
        (EventKind::PlanRecorded, "plan_recorded"),
    ] {
        assert_eq!(kind.as_str(), wire);
        assert_eq!(
            EventKind::from_str(wire).expect("parse kind"),
            kind,
            "`{wire}` must round-trip"
        );
    }
}

#[test]
fn has_events_for_run_reports_only_recorded_run_ids() {
    let (_dir, mut ledger) = open();
    let artifact = artifact("19.4.46", 'a');

    assert!(!ledger
        .has_events_for_run("run-1")
        .expect("empty ledger query"));

    ledger
        .append(&seen("run-1", 1, &artifact, 1234))
        .expect("artifact_seen");

    assert!(ledger
        .has_events_for_run("run-1")
        .expect("recorded run query"));
    assert!(
        !ledger
            .has_events_for_run("run-2")
            .expect("unknown run query"),
        "a different run id has no events"
    );
}
