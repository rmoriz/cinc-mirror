//! Prune planning and execution: the wanted set, the protected set, what to
//! delete and the deletes themselves.
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
//! # Execution
//!
//! [`prune_targets`] runs the plan against every enabled target. A [`Backend`]
//! decides how a target is listed and how a reference is deleted: the
//! distribution spec for an ordinary registry, the GitHub Packages API for
//! GHCR, which answers `405` to the spec's own delete. The backend is chosen
//! once per target by [`backend_for`] from the retention mode and the registry
//! name; a target it cannot serve is skipped with a warning instead of failing
//! the pass.
//!
//! One [`Pass`] carries what the crawl and the command know: the projects still
//! in scope, the wanted set, the per-project crawl counts, the projects held
//! back, the configured projects and the deletion budget. A [`PruneReport`]
//! comes back with the counts, the skipped targets, the dry-run lines and the
//! exit code; [`PruneReport::finish`] is the only place that maps the counts to
//! that code.
//!
//! A single cutoff per target is taken just before the first listing, so a
//! reference created while the crawl ran is not old enough to be deleted. The
//! budget is spent in rounds that hand out one reference per project at a time,
//! so one large project cannot drain the target and a denial costs at most the
//! requests already in flight. Every deletion appends a `pruned` or
//! `prune_failed` event; the artifact key comes from the target's publication
//! rows and is left off when the ledger never saw the reference.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};

use chrono::{DateTime, Utc};
use futures::StreamExt as _;
use serde_json::json;
use tracing::warn;

use crate::artifact::Artifact;
use crate::config::{Config, DeleteMode, TargetConfig, TargetKind};
use crate::ctx::Ctx;
use crate::ledger::{
    ArtifactRow, Event, EventKind, Incident, IncidentFilter, IncidentState, Publication,
};
use crate::oci::{env_value, OciError, Registry, GHCR_HOST};
use crate::packages_api::{PackagesClient, PruneError, RemoteVersion};
use crate::report::{redact_secrets, EXIT_OK, EXIT_PARTIAL};
use crate::runner::Seq;

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
/// else, so the plan can only match it.
///
/// The reduction happens in three steps. A `://` scheme is dropped first
/// together with everything through it, so an `rsync://host/module:tag` reduces
/// on its own colon and not on the one separating the scheme from the host. An
/// `@<digest>` suffix is only stripped when what follows the last `@` starts
/// with `sha256:`, because the rsync target writes `<user>@<host>:<path>` and a
/// bare `@` there would otherwise leave just the SSH user. Only then is
/// everything up to and including the last `:` dropped.
///
/// A reference without any remaining `:` is returned unchanged, and one whose
/// colon belonged to a port is cut down to the part after it. Both cover shapes
/// no listing matches: a tagless `ghcr.io/<namespace>/<project>` stays whole and
/// a ported `host:5000/<repo>` becomes `5000/<repo>`. This is inert but
/// harmless, since the artifact's own tags still protect it; the reduction never
/// invents a tag that could falsely protect another one.
fn bare_tag(remote_ref: &str) -> &str {
    let reference = remote_ref
        .split_once("://")
        .map_or(remote_ref, |(_, rest)| rest);
    let reference = match reference.rsplit_once('@') {
        Some((reference, suffix)) if suffix.starts_with("sha256:") => reference,
        _ => reference,
    };
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

/// How a target deletes a reference.
///
/// The registry variant speaks the distribution spec's manifest `DELETE`; GHCR
/// answers that with `405` and only removes a version through the Packages API,
/// which the packages variant does. The packages variant is a template because
/// a [`PackagesClient`] is bound to one package: it is rebuilt per project from
/// the fields kept here.
#[derive(Debug)]
pub enum Backend {
    /// Distribution-spec deletes against a registry.
    Registry(std::sync::Arc<Registry>),
    /// GitHub Packages version deletes.
    Packages {
        /// API root the versions are listed and deleted under.
        api_base: String,
        /// Owner the packages belong to.
        owner: String,
        /// Package path prefix below the owner, without the owner itself.
        repository: String,
        /// Token the API authenticates with.
        token: String,
    },
}

/// The inputs of one prune pass.
#[derive(Debug)]
pub struct Pass<'a> {
    /// Projects still in scope; each is listed and reconciled.
    pub projects: &'a [&'a str],
    /// What the crawl still wants.
    pub wanted: &'a Wanted,
    /// Per-project count of crawled artifacts; `0` and an absent entry both
    /// empty the package.
    pub crawled: &'a BTreeMap<String, usize>,
    /// Projects whose crawl lost a document; they stay untouched.
    pub hold_back: &'a HashSet<String>,
    /// Every project the configuration names, enabled or not.
    pub configured: &'a HashSet<String>,
    /// Also delete packages of projects no policy names any more.
    pub sweep_orphans: bool,
    /// Report the deletions instead of performing them, apart from the one
    /// probing deletion per target (see [`prune_targets`]).
    pub dry_run: bool,
    /// Deletion attempts allowed per target; `0` deletes nothing and leaves the
    /// whole plan deferred. A refused or already gone reference refunds its
    /// attempt, a failed one spends it.
    pub budget: usize,
    /// Event sequence of the run; `None` appends nothing.
    pub seq: Option<&'a Seq>,
}

/// What one prune pass did.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct PruneReport {
    /// References deleted. A dry run lists and counts these alike, so on a dry
    /// run this is [`PruneReport::lines`]`.len()`; a real pass deletes them and
    /// leaves `lines` empty.
    pub pruned: usize,
    /// References or projects that failed; an unsupported target never bumps
    /// it and only lands in [`PruneReport::targets_skipped`].
    pub failed: usize,
    /// References left for a later run: the budget, a failed listing, a denied
    /// delete and the tail of an abandoned project.
    pub deferred: usize,
    /// Targets whose backend cannot delete; they are left alone.
    pub targets_skipped: Vec<String>,
    /// One `registry/repo:tag` (or `@digest`) line per planned deletion; filled
    /// on a dry run only. The probing deletion of a target is listed and
    /// [counted](Self::pruned) like the rest of its plan, so the two agree.
    pub lines: Vec<String>,
    /// Process exit code implied by the counts.
    pub exit_code: i32,
}

impl PruneReport {
    /// Set [`PruneReport::exit_code`] from the counts.
    ///
    /// A partial failure and a skipped target both mean the target set was not
    /// fully reconciled; deferred references do not, because the budget is
    /// meant to leave them for the next run.
    #[must_use]
    pub fn finish(mut self) -> Self {
        self.exit_code = if self.failed > 0 || !self.targets_skipped.is_empty() {
            EXIT_PARTIAL
        } else {
            EXIT_OK
        };
        self
    }
}

/// The target names a prune run should touch, in configuration order.
///
/// An empty `requested` selects every enabled OCI target. Otherwise every name
/// must be an enabled OCI target: a name the configuration does not know, a
/// name of another kind and a disabled target are usage errors, so a typo cannot
/// silently reconcile nothing. The result is deduplicated and follows the
/// configuration order, not the argument order.
///
/// # Errors
///
/// Returns [`PruneError::Usage`] for a name that is not an enabled OCI target.
pub fn selected_targets<'a>(
    config: &'a Config,
    requested: &[String],
) -> Result<Vec<&'a str>, PruneError> {
    if requested.is_empty() {
        return Ok(config
            .targets
            .iter()
            .filter(|target| target.enabled && target.kind == TargetKind::Oci)
            .map(|target| target.name.as_str())
            .collect());
    }

    for name in requested {
        let target = config
            .targets
            .iter()
            .find(|target| &target.name == name)
            .ok_or_else(|| PruneError::Usage {
                reason: format!("target `{name}` is not an enabled oci target"),
            })?;
        if target.kind != TargetKind::Oci {
            return Err(PruneError::Usage {
                reason: format!("target `{name}` is not an oci target"),
            });
        }
        if !target.enabled {
            return Err(PruneError::Usage {
                reason: format!("target `{name}` is not enabled"),
            });
        }
    }

    Ok(config
        .targets
        .iter()
        .filter(|target| requested.contains(&target.name))
        .map(|target| target.name.as_str())
        .collect())
}

/// Pick the delete backend for `target`.
///
/// [`DeleteMode::Auto`] uses the packages API exactly on [`GHCR_HOST`] and the
/// registry everywhere else. A target this build cannot delete for — not OCI,
/// no token, a namespace without an owner — is `None` after a warning, so the
/// pass skips it instead of failing.
#[must_use]
pub fn backend_for(config: &Config, target: &TargetConfig) -> Option<Backend> {
    if target.kind != TargetKind::Oci {
        warn!(
            target = target.name.as_str(),
            kind = %target.kind,
            "prune only knows oci targets; skipping"
        );
        return None;
    }
    if !target.enabled {
        return None;
    }
    let registry = target
        .registry
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    if registry.is_empty() {
        warn!(
            target = target.name.as_str(),
            "target has no registry; skipping"
        );
        return None;
    }

    let packages = match config.retention.delete {
        DeleteMode::PackagesApi => true,
        DeleteMode::Registry => false,
        DeleteMode::Auto => registry.eq_ignore_ascii_case(GHCR_HOST),
    };
    if !packages {
        return match Registry::from_target(target, config) {
            Ok(registry) => Some(Backend::Registry(std::sync::Arc::new(registry))),
            Err(error) => {
                warn!(
                    target = target.name.as_str(),
                    error = %redact_secrets(&error.to_string()),
                    "cannot build the registry client; skipping the target"
                );
                None
            }
        };
    }

    let namespace = target
        .namespace
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    let Some((owner, repository)) = namespace.split_once('/') else {
        warn!(
            target = target.name.as_str(),
            namespace, "packages need an `<owner>/<repository>` namespace; skipping the target"
        );
        return None;
    };
    if repository.is_empty() {
        warn!(
            target = target.name.as_str(),
            namespace, "the namespace has no repository below the owner; skipping the target"
        );
        return None;
    }
    let token = env_value("GHCR_TOKEN").or_else(|| env_value("GITHUB_TOKEN"));
    let Some(token) = token else {
        warn!(
            target = target.name.as_str(),
            "packages deletes need GHCR_TOKEN or GITHUB_TOKEN; skipping the target"
        );
        return None;
    };

    Some(Backend::Packages {
        api_base: config.retention.api_base.clone(),
        owner: owner.to_string(),
        repository: repository.to_string(),
        token,
    })
}

/// Prune every enabled target against `pass`.
///
/// Each target is independent: a listing failure, a denied token or a
/// `405`-only registry stays inside the report, and the remaining targets still
/// run.
///
/// A dry run performs exactly one deletion per target: the first reference it
/// would delete is deleted for real and doubles as the capability probe, and it
/// is listed and counted like the rest of the plan. Without that probe an
/// endpoint that answers `405` to `DELETE` would be planned in full — a dry run
/// against GHCR with `delete = "registry"` would promise deletions that the real
/// run then skips. The alternative, a separate `HEAD`-then-`DELETE` probe, costs
/// an extra request and has to duplicate the budget and error handling; reusing
/// the first candidate keeps both and reports what actually happens. An
/// unsupported endpoint therefore lands in [`PruneReport::targets_skipped`] with
/// nothing planned, and the rest of its references count as deferred.
pub async fn prune_targets(ctx: &Ctx, pass: &Pass<'_>) -> PruneReport {
    let mut report = PruneReport::default();
    let concurrency = usize::try_from(ctx.config.upload_concurrency)
        .unwrap_or(1)
        .clamp(1, 4);

    for target in ctx.config.targets.iter().filter(|target| target.enabled) {
        let Some(backend) = backend_for(&ctx.config, target) else {
            continue;
        };
        prune_target(ctx, pass, target, &backend, concurrency, &mut report).await;
    }

    report.finish()
}

/// A listed reference together with the project it belongs to.
struct Candidate {
    project: String,
    reference: RemoteReference,
}

/// One project's listing, its emptiness and, on the packages backend, the
/// client that is bound to its package.
struct ListedProject {
    project: String,
    references: Vec<RemoteReference>,
    empty: bool,
    client: Option<PackagesClient>,
}

/// Why a project could not be listed.
enum ListFailure {
    /// The endpoint does not offer the delete path.
    Unsupported,
    /// The credential was refused.
    Denied(String),
    /// Anything else.
    Failed(String),
}

/// What happened to one reference.
enum Deleted {
    /// The manifest or version was gone before the probe; no event, no count.
    Missing,
    /// The reference was deleted.
    Pruned(String),
    /// The endpoint does not support deletes.
    Unsupported,
    /// The credential was refused.
    Denied(String),
    /// The delete failed.
    Failed(String),
}

/// Run one target and fold its outcome into `report`.
async fn prune_target(
    ctx: &Ctx,
    pass: &Pass<'_>,
    target: &TargetConfig,
    backend: &Backend,
    concurrency: usize,
    report: &mut PruneReport,
) {
    let namespace = target
        .namespace
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    let registry = match backend {
        Backend::Registry(registry) => registry.registry().to_string(),
        Backend::Packages { .. } => target.registry.as_deref().unwrap_or_default().to_string(),
    };

    let (index, protection) = protection_and_index(ctx, target, pass.wanted).await;
    let empty_wanted = Wanted::default();
    let empty_protection = Protection::default();

    // The cutoff sits immediately before the first listing of this target, so
    // a reference created while the crawl ran is not old enough to delete.
    let cutoff = Utc::now();

    // Orphans first: a package no policy names is emptied completely.
    let mut listed: Vec<ListedProject> = Vec::new();
    if let Backend::Packages {
        api_base,
        owner,
        repository,
        token,
    } = backend
    {
        if pass.sweep_orphans {
            match PackagesClient::new(api_base, owner, repository, token.clone()) {
                Ok(client) => match client.packages().await {
                    Ok(packages) => {
                        let prefix = format!("{repository}/");
                        for package in packages {
                            let Some(project) = package.strip_prefix(&prefix) else {
                                continue;
                            };
                            if pass.configured.contains(project) {
                                continue;
                            }
                            warn!(
                                target = target.name.as_str(),
                                project, "package belongs to no configured project; emptying it"
                            );
                            match list_references(backend, target, project).await {
                                Ok((references, client)) => listed.push(ListedProject {
                                    project: project.to_string(),
                                    references,
                                    empty: true,
                                    client,
                                }),
                                Err(failure) => {
                                    if note_list_failure(target, failure, project, report) {
                                        return;
                                    }
                                }
                            }
                        }
                    }
                    Err(failure) => {
                        let failure = list_failure(failure);
                        if note_list_failure(target, failure, target.name.as_str(), report) {
                            return;
                        }
                    }
                },
                Err(error) => {
                    warn!(
                        target = target.name.as_str(),
                        error = %redact_secrets(&error.to_string()),
                        "cannot build the packages client; skipping the target"
                    );
                    note_skip(target, report);
                    return;
                }
            }
        }
    }

    let mut seen_projects: BTreeSet<&str> = BTreeSet::new();
    for project in pass.projects.iter().copied() {
        if pass.hold_back.contains(project) || !seen_projects.insert(project) {
            continue;
        }
        let empty = pass.crawled.get(project).is_none_or(|count| *count == 0);
        if empty {
            warn!(
                target = target.name.as_str(),
                project, "project has no crawled artifacts; emptying its package"
            );
        }
        match list_references(backend, target, project).await {
            Ok((references, client)) => listed.push(ListedProject {
                project: project.to_string(),
                references,
                empty,
                client,
            }),
            Err(failure) => {
                if note_list_failure(target, failure, project, report) {
                    return;
                }
            }
        }
    }

    // Plan every project with the whole budget; the rounds below hand it out
    // one reference per project at a time, so no project can drain the target
    // and a denial costs at most the requests already in flight.
    struct Slot {
        project: String,
        references: VecDeque<RemoteReference>,
        dead: bool,
    }
    let mut slots: Vec<Slot> = Vec::new();
    for project in &listed {
        let (wanted, protection) = if project.empty {
            (&empty_wanted, &empty_protection)
        } else {
            (pass.wanted, &protection)
        };
        let planned = plan(wanted, protection, &project.references, cutoff, usize::MAX);
        report.deferred += planned.deferred;
        slots.push(Slot {
            project: project.project.clone(),
            dead: planned.delete.is_empty(),
            references: planned.delete.into(),
        });
    }
    if let Backend::Packages { .. } = backend {
        let mut seen: BTreeSet<u64> = BTreeSet::new();
        for slot in &mut slots {
            slot.references
                .retain(|reference| match reference.version_id {
                    Some(id) => seen.insert(id),
                    None => true,
                });
            slot.dead = slot.references.is_empty();
        }
    }
    let clients: BTreeMap<&str, &PackagesClient> = listed
        .iter()
        .filter_map(|project| {
            project
                .client
                .as_ref()
                .map(|client| (project.project.as_str(), client))
        })
        .collect();

    let mut budget = pass.budget;
    let mut abandoned = false;
    let mut probed = false;
    while budget > 0 && !abandoned {
        // One round: at most one reference per live project, and never more
        // than the budget. A project that fails to list or delete therefore
        // wastes at most one slot.
        let mut window: Vec<(usize, Candidate)> = Vec::new();
        for (index, slot) in slots.iter_mut().enumerate() {
            if budget == 0 {
                break;
            }
            if slot.dead {
                continue;
            }
            let Some(reference) = slot.references.pop_front() else {
                continue;
            };
            budget -= 1;
            window.push((
                index,
                Candidate {
                    project: slot.project.clone(),
                    reference,
                },
            ));
        }
        if window.is_empty() {
            break;
        }

        if pass.dry_run {
            // The first reference of the target is deleted for real: it probes
            // whether the endpoint deletes at all, so a `405` reaches the
            // report instead of turning into plans. A probe that really went is
            // counted and listed like any other deletion; everything after it
            // is planned only (`prune_targets` explains why).
            if !probed {
                probed = true;
                let mut window = window.into_iter();
                let Some((index, candidate)) = window.next() else {
                    break;
                };
                let repo = format!("{namespace}/{}", candidate.project);
                let client = clients.get(candidate.project.as_str()).copied();
                let outcome = delete_one(backend, client, &repo, &candidate).await;
                if matches!(outcome, Deleted::Unsupported) {
                    warn!(
                        target = target.name.as_str(),
                        "endpoint does not support deletes; skipping the target"
                    );
                    note_skip(target, report);
                    abandoned = true;
                    // The probed reference was only refused, so it waits like
                    // the rest; that one was already taken off its slot.
                    report.deferred += 1;
                    for (index, candidate) in window {
                        slots[index].references.push_front(candidate.reference);
                    }
                    continue;
                }
                match outcome {
                    Deleted::Missing => budget += 1,
                    Deleted::Pruned(_) => {
                        // The probe really went; it counts and is listed like
                        // any other planned deletion, so count and lines agree.
                        report.pruned += 1;
                        report.lines.push(display_reference(
                            &registry,
                            &format!("{namespace}/{}", candidate.project),
                            &candidate.reference,
                        ));
                    }
                    Deleted::Denied(reason) => {
                        report.failed += 1;
                        budget += 1;
                        warn!(
                            target = target.name.as_str(),
                            project = slots[index].project.as_str(),
                            reason,
                            "delete denied; abandoning the project"
                        );
                        slots[index].dead = true;
                    }
                    Deleted::Failed(_) => report.failed += 1,
                    Deleted::Unsupported => {}
                }
                for (_, candidate) in window {
                    report.pruned += 1;
                    report.lines.push(display_reference(
                        &registry,
                        &format!("{namespace}/{}", candidate.project),
                        &candidate.reference,
                    ));
                }
            } else {
                // Planned only, but each one counts like a deletion: the lines
                // and the count describe the same plan.
                for (_, candidate) in &window {
                    report.pruned += 1;
                    report.lines.push(display_reference(
                        &registry,
                        &format!("{namespace}/{}", candidate.project),
                        &candidate.reference,
                    ));
                }
            }
            continue;
        }

        let outcomes: Vec<(usize, Deleted)> =
            futures::stream::iter(window.iter().map(|(slot, candidate)| async {
                let repo = format!("{namespace}/{}", candidate.project);
                let remote_ref = display_reference(&registry, &repo, &candidate.reference);
                let client = clients.get(candidate.project.as_str()).copied();
                let outcome = delete_one(backend, client, &repo, candidate).await;
                record(ctx, pass, target, &repo, &remote_ref, &outcome, &index).await;
                (*slot, outcome)
            }))
            .buffer_unordered(concurrency)
            .collect()
            .await;

        for (index, outcome) in outcomes {
            match outcome {
                Deleted::Missing => budget += 1,
                Deleted::Pruned(_) => report.pruned += 1,
                Deleted::Unsupported => {
                    note_skip(target, report);
                    abandoned = true;
                    budget += 1;
                }
                Deleted::Denied(reason) => {
                    report.failed += 1;
                    budget += 1;
                    warn!(
                        target = target.name.as_str(),
                        project = slots[index].project.as_str(),
                        reason,
                        "delete denied; abandoning the project"
                    );
                    slots[index].dead = true;
                }
                Deleted::Failed(_) => {
                    report.failed += 1;
                }
            }
        }
    }
    // Everything still queued was either stopped by the budget or belongs to
    // a dead project; both wait for the next run.
    report.deferred += slots
        .iter()
        .map(|slot| slot.references.len())
        .sum::<usize>();

    if !pass.dry_run && report.targets_skipped.contains(&target.name) {
        warn!(
            target = target.name.as_str(),
            "endpoint does not support deletes; skipping the target"
        );
    }
}

/// Build the publication index and the protection set for `target`.
///
/// The index maps a stored `remote_ref`, and its form before any `@<digest>`,
/// to the artifact key, so a deleted reference can still be attributed. The
/// protection set protects open incidents, archived artifacts and the digests
/// of wanted publications, exactly like the plan documents.
async fn protection_and_index(
    ctx: &Ctx,
    target: &TargetConfig,
    wanted: &Wanted,
) -> (BTreeMap<String, String>, Protection) {
    let ledger = ctx.ledger.lock().await;
    let rows = match ledger.artifacts() {
        Ok(rows) => rows,
        Err(error) => {
            warn!(
                target = target.name.as_str(),
                error = %redact_secrets(&error.to_string()),
                "cannot read the ledger; planning without artifact rows"
            );
            Vec::new()
        }
    };
    let publications = ledger.publications(&target.name).unwrap_or_else(|error| {
        warn!(
            target = target.name.as_str(),
            error = %redact_secrets(&error.to_string()),
            "cannot read the publications; the target may be over-pruned"
        );
        Vec::new()
    });
    let incidents = ledger
        .incidents(IncidentFilter::default())
        .unwrap_or_else(|error| {
            warn!(
                target = target.name.as_str(),
                error = %redact_secrets(&error.to_string()),
                "cannot read the incidents; the target may be over-pruned"
            );
            Vec::new()
        });
    drop(ledger);

    let mut index = BTreeMap::new();
    for publication in &publications {
        let Some(remote_ref) = &publication.remote_ref else {
            continue;
        };
        index.insert(remote_ref.clone(), publication.artifact_key.clone());
        // The bare key is last-write-wins when two untagged publications share
        // a package: an event can then only attach one of their keys, but the
        // rows live under different artifacts anyway.
        if let Some((bare, _)) = remote_ref.rsplit_once('@') {
            index.insert(bare.to_string(), publication.artifact_key.clone());
        }
    }

    let wanted_keys: BTreeSet<String> = rows
        .iter()
        .filter(|row| {
            wanted
                .digests
                .contains(&format!("sha256:{}", row.artifact.sha256))
        })
        .map(|row| row.artifact.key())
        .collect();
    let by_key: BTreeMap<String, &ArtifactRow> =
        rows.iter().map(|row| (row.artifact.key(), row)).collect();
    let protection = protect(&wanted_keys, &by_key, &incidents, &publications);
    (index, protection)
}

/// List the references of `project` through `backend`.
///
/// The packages variant also hands back the client bound to the project, so
/// the deletes go to the same package the listing came from.
async fn list_references(
    backend: &Backend,
    target: &TargetConfig,
    project: &str,
) -> Result<(Vec<RemoteReference>, Option<PackagesClient>), ListFailure> {
    let namespace = target
        .namespace
        .as_deref()
        .map(str::trim)
        .unwrap_or_default();
    match backend {
        Backend::Registry(registry) => {
            let repo = format!("{namespace}/{project}");
            registry.list_tags(&repo).await.map_or_else(
                |error| Err(oci_failure(&error)),
                |tags| {
                    let references = tags
                        .into_iter()
                        .map(|tag| RemoteReference {
                            tag: Some(tag),
                            digest: String::new(),
                            created: None,
                            version_id: None,
                        })
                        .collect();
                    Ok((references, None))
                },
            )
        }
        Backend::Packages {
            api_base,
            owner,
            repository,
            token,
        } => {
            let package = format!("{repository}/{project}");
            let client = PackagesClient::new(api_base, owner, &package, token.clone())
                .map_err(|error| ListFailure::Failed(redact_secrets(&error.to_string())))?;
            let versions = client.versions().await.map_err(list_failure)?;
            let references = versions.into_iter().map(reference_from_version).collect();
            Ok((references, Some(client)))
        }
    }
}

/// Turn one listed package version into a reference.
fn reference_from_version(version: RemoteVersion) -> RemoteReference {
    RemoteReference {
        tag: version.tags.into_iter().next(),
        digest: version.digest,
        created: Some(version.created_at),
        version_id: Some(version.id),
    }
}

/// Delete one candidate.
async fn delete_one(
    backend: &Backend,
    client: Option<&PackagesClient>,
    repo: &str,
    candidate: &Candidate,
) -> Deleted {
    match backend {
        Backend::Registry(registry) => {
            let reference = candidate
                .reference
                .tag
                .as_deref()
                .unwrap_or(&candidate.reference.digest);
            match registry.head_manifest(repo, reference).await {
                Ok(None) => Deleted::Missing,
                Ok(Some(digest)) => match registry.delete_manifest(repo, &digest).await {
                    Ok(()) => Deleted::Pruned(digest),
                    Err(error) => oci_delete_failure(&error),
                },
                Err(error) => oci_delete_failure(&error),
            }
        }
        Backend::Packages { .. } => {
            let Some(client) = client else {
                return Deleted::Failed("the package has no client".to_string());
            };
            let Some(version_id) = candidate.reference.version_id else {
                return Deleted::Failed("the version has no id".to_string());
            };
            match client.delete(version_id).await {
                Ok(()) => Deleted::Pruned(candidate.reference.digest.clone()),
                Err(error) => match error {
                    PruneError::Unsupported { .. } => Deleted::Unsupported,
                    PruneError::Denied { .. } => {
                        Deleted::Denied(redact_secrets(&error.to_string()))
                    }
                    other => Deleted::Failed(redact_secrets(&other.to_string())),
                },
            }
        }
    }
}

/// Append the event of one outcome.
async fn record(
    ctx: &Ctx,
    pass: &Pass<'_>,
    target: &TargetConfig,
    repo: &str,
    remote_ref: &str,
    outcome: &Deleted,
    index: &BTreeMap<String, String>,
) {
    let Some(seq) = pass.seq else {
        return;
    };
    let (kind, detail) = match outcome {
        Deleted::Pruned(digest) => (
            EventKind::Pruned,
            json!({
                "remote_ref": remote_ref,
                "remote_digest": digest,
                "package": format!("{}/{repo}", target.registry.as_deref().unwrap_or_default()),
            }),
        ),
        Deleted::Failed(error) => (
            EventKind::PruneFailed,
            json!({"remote_ref": remote_ref, "error": redact_secrets(error)}),
        ),
        Deleted::Missing | Deleted::Unsupported | Deleted::Denied(_) => return,
    };

    let mut event = Event::new(ctx.run_id.as_str(), seq.next(), Utc::now(), kind)
        .with_target(target.name.as_str())
        .with_detail(detail);
    if let Some(key) = index.get(remote_ref) {
        event = event.with_artifact(key.clone());
    }

    if let Err(error) = ctx.ledger.lock().await.append(&event) {
        warn!(
            target = target.name.as_str(),
            error = %redact_secrets(&error.to_string()),
            "cannot append the prune event"
        );
    }
}

/// Format a reference the way a human retries it and a dry run prints it.
fn display_reference(registry: &str, repo: &str, reference: &RemoteReference) -> String {
    match &reference.tag {
        Some(tag) => format!("{registry}/{repo}:{tag}"),
        None => format!("{registry}/{repo}@{}", reference.digest),
    }
}

/// Classify a registry error.
fn oci_failure(error: &OciError) -> ListFailure {
    match error {
        OciError::Status { status: 405, .. } => ListFailure::Unsupported,
        OciError::Status { status: 403, .. } => {
            ListFailure::Denied(redact_secrets(&error.to_string()))
        }
        other => ListFailure::Failed(redact_secrets(&other.to_string())),
    }
}

/// Classify a registry error of one delete attempt.
fn oci_delete_failure(error: &OciError) -> Deleted {
    match oci_failure(error) {
        ListFailure::Unsupported => Deleted::Unsupported,
        ListFailure::Denied(reason) => Deleted::Denied(reason),
        ListFailure::Failed(reason) => Deleted::Failed(reason),
    }
}

/// Classify a packages error.
fn list_failure(error: PruneError) -> ListFailure {
    match error {
        PruneError::Unsupported { .. } => ListFailure::Unsupported,
        PruneError::Denied { .. } => ListFailure::Denied(redact_secrets(&error.to_string())),
        other => ListFailure::Failed(redact_secrets(&other.to_string())),
    }
}

/// Record a listing failure; returns whether the target is abandoned.
fn note_list_failure(
    target: &TargetConfig,
    failure: ListFailure,
    project: &str,
    report: &mut PruneReport,
) -> bool {
    match failure {
        ListFailure::Unsupported => {
            warn!(
                target = target.name.as_str(),
                project, "endpoint does not support deletes; skipping the target"
            );
            note_skip(target, report);
            true
        }
        ListFailure::Denied(reason) => {
            warn!(
                target = target.name.as_str(),
                project, reason, "list denied; abandoning the project"
            );
            report.failed += 1;
            false
        }
        ListFailure::Failed(reason) => {
            warn!(
                target = target.name.as_str(),
                project, reason, "cannot list the project"
            );
            report.failed += 1;
            false
        }
    }
}

/// Record that `target` is skipped, once.
fn note_skip(target: &TargetConfig, report: &mut PruneReport) {
    if !report.targets_skipped.contains(&target.name) {
        report.targets_skipped.push(target.name.clone());
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::TimeZone;
    use serde_json::Value;

    use super::*;
    use crate::artifact::{Artifact, ArtifactContext, ArtifactInput};
    use crate::config::TargetAuth;
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

    fn target(name: &str, kind: TargetKind, enabled: bool) -> TargetConfig {
        TargetConfig {
            name: name.to_string(),
            kind,
            enabled,
            registry: Some("registry.example".to_string()),
            namespace: Some("owner/repository".to_string()),
            url: None,
            auth: TargetAuth::Anonymous,
            max_bandwidth: None,
            identity_file: None,
            password_file: None,
        }
    }

    fn config_of(targets: Vec<TargetConfig>) -> Config {
        Config {
            targets,
            ..Config::default()
        }
    }

    #[test]
    fn selected_targets_defaults_to_every_enabled_oci_target() {
        let config = config_of(vec![
            target("oci", TargetKind::Oci, true),
            target("rsync", TargetKind::Rsync, true),
            target("off", TargetKind::Oci, false),
        ]);

        assert_eq!(
            selected_targets(&config, &[]).expect("the default selection"),
            vec!["oci"]
        );
    }

    #[test]
    fn selected_targets_dedups_and_follows_the_configuration_order() {
        let config = config_of(vec![
            target("a", TargetKind::Oci, true),
            target("b", TargetKind::Oci, true),
        ]);
        let requested = vec!["b".to_string(), "a".to_string(), "b".to_string()];

        assert_eq!(
            selected_targets(&config, &requested).expect("the selection"),
            vec!["a", "b"]
        );
    }

    #[test]
    fn selected_targets_rejects_a_name_that_is_not_an_enabled_oci_target() {
        let config = config_of(vec![
            target("oci", TargetKind::Oci, true),
            target("rsync", TargetKind::Rsync, true),
            target("off", TargetKind::Oci, false),
        ]);

        for (name, reason) in [
            ("rsync", "not an oci target"),
            ("off", "not enabled"),
            ("ghost", "not an enabled oci target"),
        ] {
            let error = selected_targets(&config, &[name.to_string()]).expect_err("a usage error");
            let message = error.to_string();
            assert!(
                message.starts_with("usage: ")
                    && message.contains(name)
                    && message.contains(reason),
                "{message}"
            );
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
        assert_eq!(
            bare_tag("deploy@mirror.example:/srv/cinc/stable/cinc/19.4.46/x.tar.gz"),
            "/srv/cinc/stable/cinc/19.4.46/x.tar.gz"
        );
        assert_eq!(bare_tag("rsync://host/module/path:19.4.46"), "19.4.46");
        assert_eq!(
            bare_tag("ghcr.io/rmoriz/cinc-mirror/cinc@sha256:abc"),
            "ghcr.io/rmoriz/cinc-mirror/cinc"
        );
        assert_eq!(
            bare_tag("ghcr.io/rmoriz/cinc-mirror/cinc"),
            "ghcr.io/rmoriz/cinc-mirror/cinc"
        );
        assert_eq!(bare_tag("host:5000/repo"), "5000/repo");
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
