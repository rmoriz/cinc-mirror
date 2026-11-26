# Prune OCI publications the policy no longer wants

Status: draft for approval · 2026-11-26

## Intent

Every policy in `mirror.ci.toml` pins the current major of a product
(`versions = ["19.*"]`). When upstream starts a new major the glob is bumped,
and from that moment the whole previous major is still in GHCR and nothing
removes it. The registry only ever grows; the mirror serves fewer and fewer of
the bytes it holds.

The mirror should reconcile the registry against the policy instead: after a
run — and on demand — every OCI reference the current crawl does not want is
deleted. The policy is the definition of what is mirrored, so anything outside
it is garbage, no matter how recently it was published. There is no retention
window and no keep-N rule.

Deletion needs two backends. GHCR's registry API answers `405 UNSUPPORTED` to
`DELETE /v2/<repo>/manifests/<digest>` and `/blobs/<digest>` (verified against
`ghcr.io` on 2026-11-26), so GHCR can only be pruned through the GitHub Packages
API. An ordinary registry (Harbor, distribution, zot, GitLab, a local mock)
supports the distribution spec `DELETE`. Both paths are first-class: the mirror's
own test and operator story may not depend on GitHub.

## Goals

1. After a `mirror` or `backfill` run, delete every reference in each crawled
   project's repository that the crawl did not produce.
2. A standalone `prune` command with the same scope filters as `mirror`, for
   finishing a bounded or failed prune, and usable without publishing.
3. Two deletion backends behind one interface: distribution spec `DELETE`
   (blobs and manifests by digest) for ordinary registries, GitHub Packages API
   (package versions by id) for GHCR, selected automatically by registry host
   or forced by configuration.
4. Prune is off in a plain `mirror.toml`, on in `mirror.ci.toml`. A local run
   against the untracked config stays conservative; CI cannot forget the switch.
5. `--dry-run` lists what would be deleted and deletes nothing.
6. Every deletion and every failure is a ledger event; the run summary counts
   both and `--json` carries them.
7. A pruned publication is a first-class state: `verify` stops checking it, and
   a later policy change that wants the artifact again republishes it instead of
   being blocked by the row.

## Non-goals

- Pruning an rsync target. `rsync` has no equivalent of the version API and a
  wrong `--delete` destroys files; it is a separate change.
- Local store GC. It exists (`--gc-after`) and is unrelated.
- Liberation of blob storage on ordinary registries. The spec path deletes
  manifests and leaves unreferenced blobs to the registry's own GC — deleting a
  blob that surviving manifests still reference (the shared empty config, shared
  metadata layers) breaks pulls.
- Verification that a deletion actually freed space. GHCR reclaims on its own
  schedule and never reports it.

## Anti-goals

- Deleting a version whose package bytes the crawl still wants.
- Emptying a project's repository after a failed crawl.
- Making a prune problem fail a publish run that otherwise succeeded.
- Deleting the bytes an open incident is holding.

## Constraints

- Deletion on GHCR is `DELETE /users|orgs/{owner}/packages/container/{pkg}/versions/{id}`
  (and `/orgs/` for an organisation owner, which has to be probed). It needs
  `delete:packages` for a PAT; in the workflow `secrets.GITHUB_TOKEN` with
  `packages: write` on a repository-linked package is enough. A package that is
  not linked to this repository rejects the workflow token.
- Listing on GHCR is `GET …/versions?per_page=100&page=N`. A version carries
  `id`, `name` (the manifest digest), `created_at` and
  `metadata.container.tags`.
- Listing on an ordinary registry is `GET /v2/<repo>/tags/list?n=…&last=…`,
  paged by the `Link` header, and returns tag names only — no digests, no
  creation times. A digest is resolved with a manifest `HEAD` when needed.
- `--limit` bounds processing, not the crawl: the run already holds the complete
  wanted set for its scope. But `--project` / `--versions` narrow the crawl, so
  a prune must stay inside the projects the crawl covered — except for the
  orphan sweep, which is the one pass that ranges over the namespace (see the
  open decisions).
- An encoded GHCR package path is `<repo>/<project>`; the namespace's first
  segment is the owner, its second is the repository. A namespace with fewer
  than two segments is packages-API-ineligible (warn, skip). The path travels
  percent-encoded (`<repo>%2F<project>`) as a single URL path segment, so the
  packages client builds URLs from `Url::path_segments_mut` and never through
  `Registry::url_for`, which splits on `/`. The existing
  `.github/workflows/delete-packages.yml` encodes it the same way.
- The ledger keys publications on `(artifact_key, target)` and stores
  `remote_ref` and `remote_digest`, but only tag names are reliable on both
  backends, and a package digest and a manifest digest are different values —
  reconcile on **tag names**. A GHCR version `name` is a *manifest* digest, so
  digests protect untagged versions only through a map built from the listing
  plus the ledger's `remote_digest`.
- `TargetSet` hands out `Arc<dyn Target>` with no registry or namespace
  accessor, so pruners are built from `ctx.config.targets` (`kind == Oci &&
  enabled`), not from the target set. `--target` naming an rsync target is a
  usage error, as `repair::selected_targets` already does.
- `Config` derives `Serialize + PartialEq` and denies unknown fields, so
  `RetentionConfig` needs `Default + Debug + Clone + PartialEq + Serialize +
  Deserialize`, a `print_config` line, and validation of `delete`.

## Approaches

**1. Ledger-driven.** Delete the `remote_ref` of every publication row that is
`published` but whose artifact is not in the wanted set. No listing code.
Rejected because it cannot see a tag created by `bootstrap` or by hand, cannot
see a version that lost its tag, and leaves whatever a failed run left behind.

**2. Reconcile the target against the crawl.** List what the target holds,
subtract the wanted tags and the protected references, delete the rest.
Self-healing and independent of ledger completeness; it costs listing plumbing
on both backends. **Chosen.**

**3. Delegate to `ghcr-cleanup-action` in CI.** Its rules are `keep-n`,
`older-than` and `exclude-tags` — the retention model the owner ruled out — and
it covers GHCR only. Rejected.

## The design

### Configuration

A new top-level table, defaulted so an existing `mirror.toml` keeps working:

```toml
[retention]
prune = false                      # CI sets true
delete = "auto"                    # auto | registry | packages-api
api_base = "https://api.github.com" # packages path only
max_deletions = 2000               # per target and run; the rest waits
```

`auto` resolves to `packages-api` when the registry host is `ghcr.io` and to
`registry` otherwise. `delete = "registry"` against GHCR is allowed and reports
the `405` as a per-reference failure once, then skips that target with a warning
rather than deleting nothing silently. `prune = true` with no OCI target is a
`config check` warning, not an error.

`mirror.ci.toml` gains `prune = true`. No other line changes.

### What is wanted

For each project the crawl covered, for each enabled OCI target:

- wanted tags: `artifact.tag()` for every crawled artifact of that project, and
  `artifact.superseded_tag()` when the artifact is flagged superseded. A tag the
  ledger qualified with a digest (`tag_override`) is wanted under that qualified
  name, because the crawl reuses the stored reference.

A project is "covered" when the crawl returned for a policy naming it. A crawl
error already fails the run before pruning. A project whose crawl returns zero
artifacts is still pruned — an empty wanted set means the whole package goes,
which is what a major bump looks like for the superseded line — and the run
warns with the project name so a wrong glob is visible. For the same reason a
policy whose crawl reported skipped metadata documents is held back for the run:
those documents dropped their tags from the wanted set, so pruning them would
delete bytes the policy still asks for.

### What is protected besides the wanted set

- Every reference a publication row holds whose artifact has an open incident
  (canonical tag and `-superseded` tag).
- Every `-superseded` tag of a row with `superseded_by` set, open incident or
  not. The immutability archive outlives the incident: the local GC also keeps
  those blobs forever, and the rsync target keeps
  `<basename>.superseded-<sha12>` forever.
- On the packages path, an untagged version whose manifest digest is either a
  wanted tag's digest in the listing, or the `remote_digest` of a wanted
  publication row; and any untagged version created after the cutoff.
- On the spec path, nothing is deleted that arrived after the cutoff: resolve
  `HEAD` before `DELETE`, and a missing manifest is a no-op success.

### Both backends

`src/prune.rs` owns the wanted set, the protection rules, ordering, the limit,
the events and the summary. The backends only list and delete:

```rust
pub struct RemoteReference {
    pub tag: Option<String>,
    pub digest: String,
    pub created: Option<DateTime<Utc>>,
    pub version_id: Option<u64>,
}

#[async_trait]
trait Pruner: Send + Sync {
    fn name(&self) -> &str;
    async fn list(&self, project: &str) -> Result<Vec<RemoteReference>, PruneError>;
    async fn delete(&self, project: &str, reference: &RemoteReference) -> Result<(), PruneError>;
    /// Packages path only: projects that have a package but no policy.
    async fn orphans(&self) -> Result<Vec<String>, PruneError> {
        Ok(Vec::new())
    }
}
```

`PruneError` distinguishes `Unsupported` (the `405`), `Denied`, `List` and
`Transport`, each carrying the registry, repository and reference; errors are
formatted through `redact_secrets`.

- `src/oci.rs` gains `list_tags` (Link-paged, bounded page count),
  `head_manifest` (the cutoff probe) and `delete_manifest`; all reuse the
  existing token cache, scope and retry machinery, and `NotFound` on `DELETE`
  from either backend counts as success.
- `src/packages_api.rs` is a small client built like the issue filer in
  `src/report.rs` (`reqwest`, `Bearer`, `Accept: application/vnd.github+json`,
  `User-Agent: cinc-mirror`): `list_versions`, `delete_version`,
  `list_packages`, and the `/users/` → `/orgs/` probe — a `404` on the owner
  means the other form, cached per run. It has its own `[retention] api_base`.
- Deletion runs under a semaphore of `min(config.upload_concurrency, 4)`. The
  packages path orders oldest first and then by digest, newest-last; the spec
  path has no creation times and orders by digest alone.
- The budget is per target and run, but the queue round-robins the projects the
  way `interleave_projects` already does for publishes, so no project starves
  while another drains its whole history.
- A `Denied` answer aborts that package with one warning instead of burning the
  remaining budget on references that will fail the same way; the spec path's
  `Unsupported` does the same for the target.
- The cutoff instant is taken immediately before the list phase, not at
  `run_started`, so a push that lands during a long crawl is still protected.

### Scope of the orphan sweep

The spec has no package catalogue, so only the packages path can see a package
that no policy names any more. `orphans()` lists `GET /users|orgs/{owner}/packages?package_type=container`,
keeps the names below `<repo>/` (the namespace's repository segment), and
returns those whose trailing segment no policy names — an *enabled or disabled*
policy both count as configured, so a project that is only switched off keeps
its package. Every version of a true orphan is deleted; the package itself
stays, so a reappearing policy finds an empty repository instead of a fresh one,
which the mirror handles either way.

The sweep never reaches past the run's scope. With `--project` or `--versions`
only the named projects are reconciled and the sweep is skipped with an info
line; a run without those filters has the whole configuration as its scope and
sweeps.

### The ledger

- `EventKind::Pruned` (`pruned`, detail `{remote_ref, remote_digest, package}`)
  and `EventKind::PruneFailed` (`prune_failed`, detail `{remote_ref, error}`)
  get `as_str`/`FromStr` arms and a line in the module doc's event list.
- `publications.artifact_key` is a foreign key to `artifacts(key)` and foreign
  keys are on, so an event cannot carry a key that has no row. The pruner builds
  a `remote_ref → artifact_key` index from `publications(target)` first and
  attaches the key with `.with_artifact()` only when a row exists; the `pruned`
  reducer then only updates an existing row (a deleted tag with no ledger row
  produces no key and no update). `prune_failed` never touches the row.
- `PublicationStatus::Pruned` is a new variant with `as_str`/`FromStr` arms; the
  column is plain `TEXT`, so no migration is needed. `verify` skips it the way
  it skips `Superseded`, and its module doc says so.
- `repair` skips `Pruned` rows unless `--include-pruned` is given. Otherwise one
  `repair` would re-download the whole pruned history and undo the retention;
  with the flag it is the deliberate way to restore a major.
- `classify` needs no change: it only accepts `Published` as satisfied, so a
  `Pruned` row is a `Retry` and the artifact is published again when a later
  policy wants it. A policy flip back to a pruned major re-downloads it —
  accepted; the bytes are gone on purpose.
- `run_finished` gains `pruned`, `prune_failed` and `prune_deferred` in its
  summary JSON.
- Rollback to the previous binary needs both reverted: an unknown `pruned`
  event makes the older replay fail, and `[retention]` alone breaks it because
  `Config` denies unknown fields.

### Running it

- `RunOpts` gains `prune: bool`, filled from `[retention] prune` (CI) or
  `run --prune`; `backfill` inherits it the same way. `--set retention.*` is not
  wired into `apply_overrides` (neither is `[incident]`); `prune` says as much
  in its docs.
- The cut off: `run()` returns early for `dry_run` before any prune placement
  below `collect_garbage` is reached. The dry-run prune pass therefore runs
  *before* that return and fills the summary with what it would delete; the real
  pass runs after `collect_garbage`, before `run_finished`.
- The prune pass skips a target when: the run is a dry run without `--json` and
  the caller asked for no list, the packages credential is missing, the
  namespace is ineligible, or the target answered `Unsupported`. All but the
  first are warnings.
- `--dry-run` streams the would-be deletions to stdout as
  `<registry>/<repo>:<tag>` (or `<registry>/<repo>@<digest>` for an untagged
  version), one per line, and writes no events.
- `repair` gains `--include-pruned`, and its module doc says prune is not a
  repair target by default.
- `prune` is a new subcommand: `ScopeFilterArgs`, `--dry-run`, `--json`,
  `--target` (repeatable, default every enabled OCI target), `--limit`
  (overrides `max_deletions`; `ScopeFilterArgs` has no limit field, so the
  argument struct defines its own), and the standard lease. It crawls but
  neither downloads nor publishes, so it works while only metadata is
  reachable, and it still prunes nothing when the crawl fails.

### Reporting and exit codes

`Summary` gains `pruned`, `prune_failed`, `prune_deferred`. `Summary::finish`
stays the only exit-code authority and its doc comment gains a line: prune
counts do not move the code of a publish run, because the publish job succeeded
and a prune problem must not fail it. `run_finished.outcome` therefore stays
`"success"` when only prunes failed. The standalone `prune` command owns a
`PruneReport` with its own `exit_code`: `EXIT_OK`, or `EXIT_PARTIAL` when a
deletion failed or a target was skipped for a credential/capability reason.

### Credentials

`CINC_MIRROR_<TARGET>_API_TOKEN`, else `GHCR_TOKEN`, else `GITHUB_TOKEN`. Absent
on a `packages-api` target: warn, skip the target. `is_secret_env` gains a
`CINC_MIRROR_*_TOKEN` rule (which flips the existing assertion that
`CINC_MIRROR_GHCR_TOKEN` is not a credential), so an error quoting the token is
redacted.

## Testing

- `tests/common/registry.rs` needs a digest index (it currently keys manifests by
  PUT reference only, so `HEAD`/`DELETE` by digest 404), `GET /tags/list` with
  `Link` paging, a deletion counter, and a switch to answer `405` for a
  GHCR-like registry.
- A new `tests/common/packages.rs` mock serves the packages API: versions with
  ids, tags, `created_at`; `DELETE …/versions/{id}`; the `/users/` → `/orgs/`
  probe; the package catalogue; and a denial switch.
- `tests/prune.rs` covers: wanted tag kept; a digest-qualified tag kept; stale
  tag deleted; open incident's canonical and superseded tags kept; closed
  incident's superseded tag kept; untagged version wanted-by-digest kept;
  untagged version newer than the cutoff kept; older untagged version deleted;
  the `max_deletions` tail deferred and reported; `--dry-run` deletes nothing
  and surfaces a listing failure as a warning; a failed deletion does not change
  a publish run's exit code; `prune` alone exits `2`; a project outside
  `--project` is untouched; `404` on `DELETE` is success; a denial aborts the
  package with one warning; orphan package pruned; non-`<repo>/` package
  untouched; two targets share the budget correctly.
- `tests/ledger_db.rs` and `tests/ledger_files.rs`: replaying `pruned` sets the
  status on an existing row and is a no-op without one; `verify` skips it.
- `tests/cli.rs`: flag surface, `[retention]` defaults and an invalid `delete`
  value.
- `tests/e2e.rs`: a run with `prune = true` publishes a wanted artifact and
  removes a seeded stale one.

## Rollout

1. Land behind `prune = false`; `mirror.ci.toml` turns it on in the same change.
2. First scheduled run deletes the pre-policy history: `cinc` and friends hold
   thousands of `18.*` and older versions. `max_deletions` spreads that over
   several six-hourly runs; the summary reports the deferral.
3. `README.md` gains a "Retention" section stating that the policy is the
   keep-set, that the first real prune removes whole old majors, and that the
   installer falls back to upstream for them. The fallback wording may need
   matching text in `cinc-mirror.github.io` (`install.sh`/`install.ps1`), which
   is a separate repository.

## Left to the builder

- Whether `Pruner` lives in `targets::oci_target::OciTarget` or beside it in
  `prune.rs`; the target trait is publish-shaped and the pruner needs no
  artifact.
- Exact page sizes, retry counts and whether a `405` is remembered for the whole
  target or per reference.
- Whether the orphan sweep runs in the same pass as the project reconcile or in
  its own bounded pass with its own budget.
