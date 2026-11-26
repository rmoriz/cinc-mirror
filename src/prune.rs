//! Prune planning: the wanted set, the protected set and what to delete.
//!
//! The wanted set is what the crawl still covers: the descriptive tag of every
//! crawled artifact, the `-superseded` archive tag when the crawl flagged the
//! artifact as superseded, and the artifact's `sha256:` digest. Every reference
//! a target lists that no wanted or protected reference claims is a delete
//! candidate.
//!
//! Two sources protect beyond the wanted set:
//!
//! - The `-superseded` tags of a replaced artifact protect it even after its
//!   incident is acknowledged. The archive outlives the incident: the local
//!   store and the rsync target keep those bytes forever.
//! - Every reference of an artifact with an open incident stays until a human
//!   decides what happens to it.
//!
//! A digest the crawl still wants also protects an untagged copy: the same
//! bytes can be listed both with and without a tag, and only the tagged copy
//! carries the identity the crawl knows.
//!
//! The module performs no I/O. Listing, deleting and reading the ledger are the
//! backends' and the caller's business.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use chrono::{DateTime, Utc};

use crate::artifact::Artifact;
use crate::ledger::{ArtifactRow, Incident, IncidentState, Publication};

/// One reference a target lists: a tag, a digest, or both.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteReference {
    /// The tag, when the reference is tagged.
    pub tag: Option<String>,
    /// The manifest digest the reference resolves to.
    pub digest: String,
    /// When the target says the reference was created, when it says so at all.
    pub created: Option<DateTime<Utc>>,
    /// Target-specific version identifier, e.g. a GitHub package version id.
    pub version_id: Option<u64>,
}

/// The tags and digests the crawl still wants.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Wanted {
    /// Descriptive and `-superseded` tags of the crawled artifacts.
    pub tags: BTreeSet<String>,
    /// `sha256:<hex>` digests of the crawled artifacts.
    pub digests: BTreeSet<String>,
}

/// The tags and digests that keep a reference alive past the wanted set.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Protection {
    /// References and tags kept for an open incident or an archived artifact.
    pub tags: BTreeSet<String>,
    /// Digests of wanted publication rows; they keep untagged copies alive.
    pub digests: BTreeSet<String>,
}

/// What [`plan`] decided.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Planned {
    /// References to delete, oldest first, at most the budget.
    pub delete: Vec<RemoteReference>,
    /// Delete candidates past the budget; they wait for the next run.
    pub deferred: usize,
    /// Untagged references that survive on their digest or their age.
    pub kept_untagged: usize,
}

/// Collect the tags and digests the crawl still wants.
///
/// A superseded artifact also wants its `-superseded` archive tag, because that
/// is the reference its bytes are published under.
#[must_use]
pub fn wanted(artifacts: &[&Artifact]) -> Wanted {
    let mut wanted = Wanted::default();
    for artifact in artifacts {
        wanted.tags.insert(artifact.tag());
        if artifact.superseded {
            wanted.tags.insert(artifact.superseded_tag());
        }
        wanted.digests.insert(format!("sha256:{}", artifact.sha256));
    }
    wanted
}

/// Reduce a stored `remote_ref` to the bare tag a listing would show.
///
/// A publication keeps the reference in the target's own form: the OCI target
/// writes `<registry>/<namespace>/<project>:<tag>`, optionally with an
/// `@<digest>` suffix, while a listing reports only the bare tag from
/// `tags/list`. The registry and the listing agree on that bare tag and nothing
/// else, so the plan can only match it. Strip the `@<digest>` suffix first, then
/// everything up to and including the last `:`.
fn bare_tag(remote_ref: &str) -> &str {
    let reference = remote_ref
        .split_once('@')
        .map_or(remote_ref, |(reference, _)| reference);
    reference.rsplit_once(':').map_or(reference, |(_, tag)| tag)
}

/// Build the protection set from the ledger.
///
/// A publication is protected when its artifact was replaced
/// (`superseded_by`) or when an open incident names its key. Both the
/// publication's reference and the artifact's two tags are kept. The reference
/// is stored in the target's own form, so it is reduced to its bare tag before
/// it is kept ([`bare_tag`]): that is all a listing shows and all the plan can
/// match. A key the ledger no longer knows still protects the reference of an
/// open incident.
///
/// The `remote_digest` of every publication whose key is wanted also protects
/// untagged copies of those bytes.
#[must_use]
pub fn protect(
    wanted_keys: &BTreeSet<String>,
    artifacts: &BTreeMap<String, &ArtifactRow>,
    incidents: &[Incident],
    publications: &[Publication],
) -> Protection {
    let mut protection = Protection::default();
    let open: BTreeSet<&str> = incidents
        .iter()
        .filter(|incident| incident.state == IncidentState::Open)
        .filter_map(|incident| incident.artifact_key.as_deref())
        .collect();

    for publication in publications {
        let artifact = artifacts.get(&publication.artifact_key).copied();
        let archived = artifact.is_some_and(|row| row.superseded_by.is_some());
        if archived || open.contains(publication.artifact_key.as_str()) {
            if let Some(remote_ref) = &publication.remote_ref {
                protection.tags.insert(bare_tag(remote_ref).to_string());
            }
            if let Some(row) = artifact {
                protection.tags.insert(row.artifact.tag());
                protection.tags.insert(row.artifact.superseded_tag());
            }
        }
        if wanted_keys.contains(&publication.artifact_key) {
            if let Some(remote_digest) = &publication.remote_digest {
                protection.digests.insert(remote_digest.clone());
            }
        }
    }
    protection
}

/// Decide which listed references to delete.
///
/// A tag survives when it is wanted or protected; the digest of the reference
/// that survives under it then protects untagged copies of the same bytes. An
/// untagged reference survives on a wanted or protected digest, or when it is
/// newer than `cutoff` (an undated one is not newer).
///
/// References are deleted oldest first, undated ones first; `budget` caps the
/// deletions and the rest is counted in [`Planned::deferred`].
#[must_use]
pub fn plan(
    wanted: &Wanted,
    protection: &Protection,
    listed: &[RemoteReference],
    cutoff: DateTime<Utc>,
    budget: usize,
) -> Planned {
    let mut planned = Planned::default();
    let mut candidates: Vec<RemoteReference> = Vec::new();
    let mut protected_digests: BTreeSet<&str> = BTreeSet::new();

    let mut by_tag: BTreeMap<&str, Vec<&RemoteReference>> = BTreeMap::new();
    for reference in listed {
        if let Some(tag) = reference.tag.as_deref() {
            by_tag.entry(tag).or_default().push(reference);
        }
    }
    // The newest reference under a tag is the one that serves it. `None` sorts
    // first, so it is the oldest, and the digest breaks ties.
    for (tag, mut references) in by_tag {
        references.sort_by(|left, right| oldest_first(left, right));
        let Some((serving, older)) = references.split_last() else {
            continue;
        };
        if wanted.tags.contains(tag) || protection.tags.contains(tag) {
            protected_digests.insert(serving.digest.as_str());
        } else {
            candidates.push((*serving).clone());
        }
        candidates.extend(older.iter().map(|reference| (*reference).clone()));
    }

    for reference in listed.iter().filter(|reference| reference.tag.is_none()) {
        let digest = reference.digest.as_str();
        let newer = reference.created.is_some_and(|created| created > cutoff);
        if wanted.digests.contains(digest)
            || protection.digests.contains(digest)
            || protected_digests.contains(digest)
            || newer
        {
            planned.kept_untagged += 1;
        } else {
            candidates.push(reference.clone());
        }
    }

    candidates.sort_by(oldest_first);
    planned.deferred = candidates.len().saturating_sub(budget);
    candidates.truncate(budget);
    planned.delete = candidates;
    planned
}

/// Order delete candidates oldest first, undated ones before everything.
///
/// The digest breaks ties so two runs over the same listing delete the same
/// references in the same order.
fn oldest_first(left: &RemoteReference, right: &RemoteReference) -> Ordering {
    left.created
        .cmp(&right.created)
        .then_with(|| left.digest.cmp(&right.digest))
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::TimeZone;
    use serde_json::Value;

    use super::*;
    use crate::artifact::{Artifact, ArtifactContext, ArtifactInput};
    use crate::ledger::{ArtifactRow, IncidentKind, IncidentState, PublicationStatus};

    fn at(day: u32) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 11, day, 0, 0, 0).unwrap()
    }

    fn sha(byte: char) -> String {
        byte.to_string().repeat(64)
    }

    fn digest(byte: char) -> String {
        format!("sha256:{}", sha(byte))
    }

    fn artifact(version: &str, sha256: &str) -> Artifact {
        Artifact::new(
            &ArtifactContext {
                channel: "stable".to_string(),
                project: "cinc".to_string(),
                version: version.to_string(),
                platform: "debian".to_string(),
                platform_version: "13".to_string(),
            },
            ArtifactInput {
                basename: format!("cinc_{version}-1_amd64.deb"),
                sha256: sha256.to_string(),
                metadata_json: "{}".to_string(),
                platform: "debian".to_string(),
                platform_version: "13".to_string(),
                version: version.to_string(),
                iteration: None,
                raw_arch: "x86_64".to_string(),
            },
        )
        .expect("artifact")
    }

    fn row(artifact: Artifact, superseded_by: Option<String>) -> ArtifactRow {
        ArtifactRow {
            upstream_path: artifact.rsync_relpath(),
            artifact,
            size: None,
            metadata: Value::Null,
            first_seen: at(1),
            last_seen: at(1),
            superseded_by,
            supersedes: None,
            local: true,
        }
    }

    fn index(rows: &[ArtifactRow]) -> BTreeMap<String, &ArtifactRow> {
        rows.iter().map(|row| (row.artifact.key(), row)).collect()
    }

    fn incident(artifact_key: Option<&str>, state: IncidentState) -> Incident {
        Incident {
            id: format!("hash_changed-{}", "0".repeat(16)),
            artifact_key: artifact_key.map(ToString::to_string),
            kind: IncidentKind::HashChanged,
            old_sha256: Some(sha('a')),
            new_sha256: Some(sha('b')),
            detected_at: at(2),
            detail: Value::Null,
            state,
            issue_url: None,
            ack_note: None,
        }
    }

    fn publication(
        artifact_key: &str,
        remote_ref: Option<&str>,
        remote_digest: Option<&str>,
    ) -> Publication {
        Publication {
            artifact_key: artifact_key.to_string(),
            target: "ghcr".to_string(),
            status: PublicationStatus::Published,
            remote_ref: remote_ref.map(ToString::to_string),
            remote_digest: remote_digest.map(ToString::to_string),
            attempts: 1,
            next_attempt_at: None,
            last_error: None,
            updated_at: at(1),
        }
    }

    fn tagged(tag: &str, digest: &str, created: Option<DateTime<Utc>>) -> RemoteReference {
        RemoteReference {
            tag: Some(tag.to_string()),
            digest: digest.to_string(),
            created,
            version_id: None,
        }
    }

    fn untagged(digest: &str, created: Option<DateTime<Utc>>) -> RemoteReference {
        RemoteReference {
            tag: None,
            digest: digest.to_string(),
            created,
            version_id: None,
        }
    }

    fn wanted_tags(tags: &[&str]) -> Wanted {
        Wanted {
            tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
            digests: BTreeSet::new(),
        }
    }

    fn wanted_digests(digests: &[&str]) -> Wanted {
        Wanted {
            tags: BTreeSet::new(),
            digests: digests.iter().map(|digest| (*digest).to_string()).collect(),
        }
    }

    fn protection_tags(tags: &[&str]) -> Protection {
        Protection {
            tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
            digests: BTreeSet::new(),
        }
    }

    #[test]
    fn wanted_collects_the_tag_the_archive_tag_and_the_digest() {
        let plain = artifact("19.4.46", &sha('a'));
        let archived = artifact("19.4.47", &sha('b')).with_superseded(true);

        let wanted = wanted(&[&plain, &archived]);

        assert!(wanted.tags.contains(&plain.tag()));
        assert!(wanted.tags.contains(&archived.tag()));
        assert!(wanted.tags.contains(&archived.superseded_tag()));
        assert_eq!(wanted.digests, BTreeSet::from([digest('a'), digest('b')]));
    }

    #[test]
    fn an_untagged_artifact_has_no_archive_tag() {
        let plain = artifact("19.4.46", &sha('a'));

        let wanted = wanted(&[&plain]);

        assert_eq!(wanted.tags, BTreeSet::from([plain.tag()]));
    }

    #[test]
    fn an_open_incident_protects_the_reference_and_both_tags() {
        let artifact = artifact("19.4.46", &sha('a'));
        let key = artifact.key();
        let reference = format!("ghcr.io/rmoriz/cinc-mirror/cinc:{}", artifact.tag());
        let rows = vec![row(artifact.clone(), None)];
        let index = index(&rows);
        let incidents = vec![incident(Some(&key), IncidentState::Open)];
        let publications = vec![
            publication(&key, Some(&reference), Some(&digest('a'))),
            publication(&key, Some(&format!("{reference}@{}", digest('a'))), None),
        ];

        let protection = protect(&BTreeSet::new(), &index, &incidents, &publications);

        assert_eq!(
            protection.tags,
            BTreeSet::from([artifact.tag(), artifact.superseded_tag()])
        );
        assert!(protection.digests.is_empty());
    }

    #[test]
    fn a_closed_incident_protects_nothing() {
        let artifact = artifact("19.4.46", &sha('a'));
        let key = artifact.key();
        let rows = vec![row(artifact.clone(), None)];
        let index = index(&rows);
        let incidents = vec![incident(Some(&key), IncidentState::Acked)];
        let publications = vec![publication(&key, Some(&artifact.tag()), Some(&digest('a')))];

        let protection = protect(&BTreeSet::new(), &index, &incidents, &publications);

        assert!(protection.tags.is_empty());
        assert!(protection.digests.is_empty());
    }

    #[test]
    fn a_superseded_row_keeps_its_archive_tag_after_the_ack() {
        let old = artifact("19.4.46", &sha('a'));
        let replacement = artifact("19.4.47", &sha('b'));
        let old_key = old.key();
        let reference = format!("ghcr.io/rmoriz/cinc-mirror/cinc:{}", old.tag());
        let rows = vec![row(old.clone(), Some(replacement.key()))];
        let index = index(&rows);
        let incidents = vec![incident(Some(&old_key), IncidentState::Acked)];
        let publications = vec![publication(&old_key, Some(&reference), Some(&digest('a')))];

        let protection = protect(&BTreeSet::new(), &index, &incidents, &publications);

        assert_eq!(
            protection.tags,
            BTreeSet::from([old.tag(), old.superseded_tag()])
        );
    }

    #[test]
    fn an_unknown_key_still_protects_its_reference() {
        let key = "stable/cinc/19.4.46/debian/13/amd64/unknown";
        let incidents = vec![incident(Some(key), IncidentState::Open)];
        let publications = vec![publication(
            key,
            Some("ghcr.io/rmoriz/cinc-mirror/cinc:19.4.46-debian-13-amd64"),
            None,
        )];

        let protection = protect(
            &BTreeSet::new(),
            &BTreeMap::new(),
            &incidents,
            &publications,
        );

        assert_eq!(
            protection.tags,
            BTreeSet::from(["19.4.46-debian-13-amd64".to_string()])
        );
    }

    #[test]
    fn an_unknown_key_with_a_digest_qualified_reference_still_protects_the_bare_tag() {
        let key = "stable/cinc/19.4.46/debian/13/amd64/unknown";
        let incidents = vec![incident(Some(key), IncidentState::Open)];
        let publications = vec![publication(
            key,
            Some(&format!(
                "ghcr.io/rmoriz/cinc-mirror/cinc:19.4.46-debian-13-amd64@{}",
                digest('a')
            )),
            None,
        )];

        let protection = protect(
            &BTreeSet::new(),
            &BTreeMap::new(),
            &incidents,
            &publications,
        );

        assert_eq!(
            protection.tags,
            BTreeSet::from(["19.4.46-debian-13-amd64".to_string()])
        );
    }

    #[test]
    fn a_reference_reduces_to_its_bare_tag() {
        assert_eq!(
            bare_tag("ghcr.io/rmoriz/cinc-mirror/cinc:19.4.46"),
            "19.4.46"
        );
        assert_eq!(bare_tag("host:5000/repo:tag"), "tag");
        assert_eq!(
            bare_tag("ghcr.io/rmoriz/cinc-mirror/cinc:19.4.46@sha256:abc"),
            "19.4.46"
        );
        assert_eq!(bare_tag("19.4.46"), "19.4.46");
    }

    #[test]
    fn a_wanted_publication_contributes_its_remote_digest() {
        let wanted_artifact = artifact("19.4.46", &sha('a'));
        let stale = artifact("19.4.45", &sha('b'));
        let wanted_key = wanted_artifact.key();
        let rows = vec![row(wanted_artifact, None), row(stale.clone(), None)];
        let index = index(&rows);
        let publications = vec![
            publication(&wanted_key, Some("keep"), Some(&digest('a'))),
            publication(&stale.key(), Some("stale"), Some(&digest('b'))),
        ];

        let protection = protect(&BTreeSet::from([wanted_key]), &index, &[], &publications);

        assert_eq!(protection.digests, BTreeSet::from([digest('a')]));
    }

    #[test]
    fn a_stale_tag_is_deleted() {
        let listed = vec![tagged("19.4.46-debian-13-amd64", &digest('a'), Some(at(1)))];

        let planned = plan(
            &Wanted::default(),
            &Protection::default(),
            &listed,
            at(10),
            10,
        );

        assert_eq!(planned.delete, listed);
        assert_eq!(planned.deferred, 0);
        assert_eq!(planned.kept_untagged, 0);
    }

    #[test]
    fn a_wanted_tag_is_kept() {
        let listed = vec![tagged("keep", &digest('a'), None)];

        let planned = plan(
            &wanted_tags(&["keep"]),
            &Protection::default(),
            &listed,
            at(10),
            10,
        );

        assert!(planned.delete.is_empty());
        assert_eq!(planned.kept_untagged, 0);
    }

    #[test]
    fn a_digest_qualified_wanted_tag_is_kept() {
        let tag = "19.4.46-debian-13-amd64-aaaaaaaaaaaa";
        let listed = vec![tagged(tag, &digest('a'), Some(at(1)))];

        let planned = plan(
            &wanted_tags(&[tag]),
            &Protection::default(),
            &listed,
            at(10),
            10,
        );

        assert!(planned.delete.is_empty());
    }

    #[test]
    fn a_protected_tag_is_kept() {
        let listed = vec![tagged(
            "19.4.46-debian-13-amd64-superseded",
            &digest('a'),
            None,
        )];

        let planned = plan(
            &Wanted::default(),
            &protection_tags(&["19.4.46-debian-13-amd64-superseded"]),
            &listed,
            at(10),
            10,
        );

        assert!(planned.delete.is_empty());
    }

    #[test]
    fn an_untagged_version_is_kept_while_its_digest_is_wanted() {
        let listed = vec![untagged(&digest('a'), Some(at(1)))];

        let planned = plan(
            &wanted_digests(&[&digest('a')]),
            &Protection::default(),
            &listed,
            at(10),
            10,
        );

        assert!(planned.delete.is_empty());
        assert_eq!(planned.kept_untagged, 1);
    }

    #[test]
    fn an_untagged_version_is_kept_while_its_digest_is_protected() {
        let listed = vec![untagged(&digest('a'), Some(at(1)))];
        let protection = Protection {
            tags: BTreeSet::new(),
            digests: BTreeSet::from([digest('a')]),
        };

        let planned = plan(&Wanted::default(), &protection, &listed, at(10), 10);

        assert!(planned.delete.is_empty());
        assert_eq!(planned.kept_untagged, 1);
    }

    #[test]
    fn a_wanted_tags_digest_protects_an_untagged_copy() {
        let listed = vec![
            tagged("keep", &digest('a'), Some(at(1))),
            untagged(&digest('a'), Some(at(1))),
        ];

        let planned = plan(
            &wanted_tags(&["keep"]),
            &Protection::default(),
            &listed,
            at(10),
            10,
        );

        assert!(planned.delete.is_empty());
        assert_eq!(planned.kept_untagged, 1);
    }

    #[test]
    fn an_untagged_version_is_kept_after_the_cutoff() {
        let listed = vec![untagged(&digest('a'), Some(at(20)))];

        let planned = plan(
            &Wanted::default(),
            &Protection::default(),
            &listed,
            at(10),
            10,
        );

        assert!(planned.delete.is_empty());
        assert_eq!(planned.kept_untagged, 1);
    }

    #[test]
    fn an_untagged_older_version_is_deleted() {
        let listed = vec![untagged(&digest('a'), Some(at(5)))];

        let planned = plan(
            &Wanted::default(),
            &Protection::default(),
            &listed,
            at(10),
            10,
        );

        assert_eq!(planned.delete, listed);
    }

    #[test]
    fn an_untagged_version_without_a_creation_time_is_deleted() {
        let listed = vec![untagged(&digest('a'), None)];

        let planned = plan(
            &Wanted::default(),
            &Protection::default(),
            &listed,
            at(10),
            10,
        );

        assert_eq!(planned.delete, listed);
    }

    #[test]
    fn the_budget_truncates_the_tail_into_deferred() {
        let oldest = tagged("oldest", &digest('a'), Some(at(1)));
        let middle = tagged("middle", &digest('b'), Some(at(2)));
        let newest = tagged("newest", &digest('c'), Some(at(3)));
        let listed = vec![newest.clone(), oldest.clone(), middle.clone()];

        let planned = plan(
            &Wanted::default(),
            &Protection::default(),
            &listed,
            at(10),
            1,
        );

        assert_eq!(planned.delete, vec![oldest]);
        assert_eq!(planned.deferred, 2);
    }

    #[test]
    fn the_newest_version_of_one_tag_wins() {
        let older = tagged("19.4.46-debian-13-amd64", &digest('a'), Some(at(1)));
        let newer = tagged("19.4.46-debian-13-amd64", &digest('b'), Some(at(3)));
        let undated = tagged("19.4.46-debian-13-amd64", &digest('c'), None);
        let listed = vec![older.clone(), newer.clone(), undated.clone()];

        let planned = plan(
            &wanted_tags(&["19.4.46-debian-13-amd64"]),
            &Protection::default(),
            &listed,
            at(10),
            10,
        );

        assert_eq!(planned.delete, vec![undated, older]);
    }

    #[test]
    fn an_older_version_sharing_a_wanted_tag_is_deleted() {
        let older = tagged("keep", &digest('a'), Some(at(1)));
        let newer = tagged("keep", &digest('b'), Some(at(2)));
        let listed = vec![older.clone(), newer.clone()];

        let planned = plan(
            &wanted_tags(&["keep"]),
            &Protection::default(),
            &listed,
            at(10),
            10,
        );

        assert_eq!(planned.delete, vec![older]);
    }

    #[test]
    fn candidates_sort_by_creation_time_with_undated_ones_first() {
        let undated = tagged("undated", &digest('a'), None);
        let later = tagged("later", &digest('b'), Some(at(9)));
        let earlier = tagged("earlier", &digest('c'), Some(at(3)));
        let listed = vec![later.clone(), undated.clone(), earlier.clone()];

        let planned = plan(
            &Wanted::default(),
            &Protection::default(),
            &listed,
            at(10),
            10,
        );

        assert_eq!(planned.delete, vec![undated, earlier, later]);
    }
}
