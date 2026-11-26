# Cinc Mirror — Rust rewrite

Status: design for review
Branch: `rust`
Date: 2026-11-24
Plan: [2026-11-24-rust-mirror-implementation.md](../plans/2026-11-24-rust-mirror-implementation.md)

## Intent

Replace the shell + `oras` + `curl` mirror with one Rust binary that crawls the
Cinc download tree, verifies every artifact against its published hash, stores
it, and publishes it to one or more targets. The mirror must be able to do a
complete first pass, recover from interruption, and backfill newly published
packages incrementally, while treating "same path, different hash" as a
security incident.

Why now: the previous implementation is a single shell script with no resume,
no retry, no state and no integrity history. The workflow that drove it still
references two scripts that were deleted, so the automated path is dead. The
old shell version did keep a checksum ledger and a `REMOTE_CHANGE` alert; that
intent is kept here and made durable.

## Goals

- Full mirror of ALL configured projects in one run, with per-project scope
  policies (version bounds/globs, platforms, arches) and ad-hoc narrowing.
- An estimate mode that traverses the source and reports transfer volume
  without downloading package bodies.
- HTTPS-only for listings and metadata; payload may come over FTP because the
  hash is what proves the bytes.
- Verify SHA-256 (plus SHA-512/SHA-1/MD5 cross-checks when present) and size
  before anything is published.
- Publish to N targets in one pass: OCI registries (GHCR today, any compliant
  registry via config) and rsync (second target). Fan-out is unconditional:
  every artifact goes to every enabled target.
- Durable, append-only ledger of every observation, publication and incident,
  committed to this repository.
- Resume after crash, repair gaps, and backfill new packages without redoing
  work.
- Immutable artifacts: an existing publication is never silently replaced. A
  changed upstream hash opens an incident and keeps the old bytes.
- One-shot CLI suitable for a laptop, a systemd timer and GitHub Actions;
  triggers stay out of the binary.

## Non-goals (v1)

- Serving files to installers (existing `install.sh` keeps doing that).
- Windows, Solaris and AIX **installers**; `.msi` artifacts are mirrored like
  any other package, only the consumer-side support stays unchanged. A Windows
  client would be a PowerShell counterpart to `install.sh` in the
  `cinc-mirror.github.io` repo, not part of this binary.
- Implementing the rsync wire protocol from scratch (the binary shells out to
  `rsync`; everything else is native Rust).
- Signing (minisign/sigstore) and SBOM generation — later.
- Deleting or garbage-collecting upstream versions automatically.

## Anti-goals

- Overwriting a tag or file when the upstream hash changes.
- Trusting a directory listing or filename for anything authoritative.
- Uploading before the full hash is known and matched.
- Per-target re-download: one fetch, many writers.
- Hiding state outside the ledger (no "it's in the registry, just HEAD it").

## Constraints

- Upstream: `downloads.cinc.sh` and `ftp.osuosl.org` (`pub/cinc/files/...`).
  Autoindex and `metadata.json` over HTTPS; `ftp`, `ftps` and `https` all
  serve payloads. Metadata is authoritative and carries `basename`, `platform`,
  `platform_version`, `arch`, `version`, `sha256`, `sha512`, `sha1`, `md5`.
- Registry: GHCR accepts anonymous pulls and token-authenticated pushes. Bulk
  storage quotas and 429s are expected; runs must be resumable, not
  restart-from-zero.
- Backfill may run on ephemeral, limited runners (Actions 6 h cap, small disk),
  so the binary needs `--limit`, a cursor and cheap startup.
- `rsync` binary must be present only when an rsync target is configured.

## Approaches considered

### Overall shape

1. **Single Rust binary with subcommands (chosen).** Library plus CLI, no
   daemon, no shell dependency. Runs locally and in CI unchanged.
2. Rust daemon with a thin control CLI. Better for continuous scheduling,
   but status, leases and systemd become prerequisites before the first byte
   is mirrored.
3. Keep the shell and add a Rust helper. Splits auth, verification and retry
   across two runtimes again.

### OCI client

1. **`oci-client` for auth and manifests, our own streaming blob upload (chosen).**
   Token scopes, challenge parsing and manifest JSON come from a maintained
   crate; layer uploads stream from disk over `reqwest` because packages reach
   hundreds of megabytes and must not be buffered whole.
2. Hand-rolled client for everything. Full control, but re-implements token
   scopes, challenges and manifest handling.
3. Shell out to `oras`. Rejected: the point of the rewrite is removing it.

### Ledger storage

1. **Committed to this repository (chosen).** Each run appends one immutable
   NDJSON file; local SQLite is a cache rebuilt from those files. The hash
   history is reviewable in git, survives the laptop and needs no second
   credential store. Concurrent writers are separated by one file per run, so
   there are no line-level conflicts.
2. Registry as system of record. Audit trail next to the data, but a second
   set of packages and clunky review.
3. R2/S3 bucket. Concurrency-safe, but one more credential and service.

### Where bytes live

The repository holds ledger/incident records only — never packages. Blobs live
in the local state dir (`store/`) and in the targets. `store gc` is explicit;
runs may pass `--gc-after` to delete each store file once every enabled target
reports success, which keeps CI runners inside disk limits. `repair` prefers the
store copy, re-fetches from upstream when it is gone, and marks the artifact
`unrecoverable` plus opens an incident when upstream no longer has those bytes
either. A fresh clone plus `ledger pull` can rebuild all state except the local
blob cache.

### Payload transport

Ordered ladder, per artifact: `ftp` → `ftps` → `https`, configurable and
overridable. FTP is first because it is measurably faster from the mirroring
host; the hash, not the transport, carries integrity.

### Fan-out

1. **One download, one verification, N independent target writers (chosen).**
   Failure of one target does not force a re-fetch for the others.
2. Per-target full pipeline. Simpler failure model, N times the bandwidth.

## Design

### Crate layout

```text
src/main.rs            CLI dispatch, exit codes
src/config.rs          mirror.toml + env, validation, redaction
src/source/mod.rs      index + metadata client (HTTPS only)
src/source/transport.rs ftp/ftps/https ladder, resume offsets, retries
src/crawl.rs           tree walk, filters, dedupe, queue rows
src/store.rs           content-addressed store, partials, hashing
src/ledger/mod.rs      events, current-state materialisation, lease
src/ledger/registry.rs ledger segments as OCI artifacts
src/oci.rs             registry client wrapper, tag/ref mapping, auth
src/targets/mod.rs     Target trait, fan-out, per-target journals
src/targets/oci_target.rs
src/targets/rsync_target.rs
src/verify.rs          deep/sampled verification, repair queue
src/incident.rs        incident records, local alerts, GitHub issues
src/runner.rs          worker pool, backpressure, rate limits
src/report.rs          run summary, exit codes, structured output
```

### Projects and scope policy

Every mirrored project is a policy entry in config, not a CLI convention. A
policy has a unique `id`, the upstream `project` and `channel`, version bounds
or globs, allowed platforms with optional platform versions, and allowed
arches; a project absent from config is never mirrored. Two policies may share
a `project` on different channels because `id` is what disambiguates.

```toml
[[projects]]
id = "cinc-stable"
project = "cinc"
channel = "stable"
min_version = "19.0.0"
platforms = ["debian", "ubuntu", "el"]
arches = ["amd64", "arm64"]

[[projects]]
id = "cinc-auditor"
project = "cinc-auditor"
channel = "stable"
min_version = "7.0.0"
platforms = ["debian", "ubuntu", "el", "windows"]
arches = ["amd64", "arm64"]

[[projects]]
id = "omnibus-toolchain"
project = "omnibus-toolchain"
channel = "stable"
all_versions = true
platforms = "*"
arches = "*"
```

Version selection: `min_version`, `max_version`, `versions = ["18.8.*"]` and
`all_versions = true`, intersected. `all_versions = true` removes the global
`min_version` floor for that policy. Versions compare numerically segment by
segment, so `19.10.0` > `19.4.46`. Globs are `*`/`?` only and match whole
segments. `platforms`/`arches` take exact values or `*`; `platform_versions` is
an optional map limiting specific platforms and must key a platform listed in
`platforms` unless `platforms = "*"`.

`--project` accepts policy ids, or a bare project name to select every policy
for it. `--everything` selects all enabled policies; combining it with
`--project` is a usage error.

### Filter composition

Resolution is always: config → `--set` → CLI filters → policy intersection.
`--set <id>.<field>=<value>` (or a bare global key) replaces that field before
intersection, and may introduce a policy that is not in the file. Arrays are
comma-separated and replace wholesale; booleans parse as `true`/`false`; unknown
keys are errors. `plan` and `mirror` share this resolver, and the resolved
policy is embedded in plan output and in the `runs` row, so an estimate can
never describe a different set from the run.

CLI filters normally narrow. The single widening exception is
`--all-versions`, which clears the version bounds of the selected policies;
`--min-version` narrows only when it is higher than the policy's own floor.
`--versions`, `--platform`, `--platform-version` and `--arch` always intersect.


### Plan (estimate)

`cinc-mirror plan` runs the same crawl and diff as `mirror` but never downloads
a package body and never takes the lease: it only reads the ledger and the
source. It resolves sizes with a single `MLSD` per directory over FTP, falling
back to `SIZE` per file and then `HEAD Content-Length` — metadata itself has no
size field. Output: artifact count and total bytes, split by project, platform,
arch and target; how much is already satisfied versus new; largest single
artifacts; whether the state dir has room; and the projected duration at the
configured bandwidth. `--limit-bytes` caps **download** bytes and uploads are never cut: the artifact
that crosses the cap is finished, so overshoot is at most one artifact. The
queue is ordered deterministically (`version` descending, then project, platform,
arch) and satisfied/terminal rows are dropped before ordering, so a capped run
always makes progress and the next run's prefix shrinks. `--order
smallest-first|largest-first` changes this for size-driven passes. The chosen
order and the cap are recorded in the run row.

Plan always writes `plan-<run_id>.json` to the state dir (or `--out`), and
`--record` also appends a plan event; the file embeds the resolved policy, so a
later comparison is possible.

### Flows

**mirror / backfill**

1. Acquire the ledger lease (see Ledger). Refresh every 60 s; refuse to start
   if a live foreign lease is held, steal after 10 min expiry and log a
   takeover event. With `--allow-unleased` (CI default) an unreachable ledger
   remote only warns.
2. Update the ledger branch: `git fetch`, then fast-forward or rebase. Load all
   ledger files newer than the local high-water mark into SQLite, idempotently
   by `(run_id, seq)`.
3. Crawl: fetch index over HTTPS, filter, fetch each `metadata.json`, validate
   it, derive the artifact key, upsert `artifacts`.
4. Diff against `publications`. Classify each artifact as `new`, `satisfied`,
   `retry`, `hash_changed` or `failed_permanently`. `hash_changed` opens an
   incident, publishes the new bytes under the superseded key and leaves the
   descriptive tag on the old artifact until it is acked.
5. For `new`/`retry`: download to `partial/<sha256>.part` via the transport
   ladder with resume, compute all hashes while streaming, compare size and
   hashes, then move to `store/<aa>/<sha256>`.
6. Fan out to every enabled target, unconditionally, tracking one
   `publications` row per `(artifact, target)` with its own attempts and
   backoff.
7. Write the run's event file, remove the lease, `git push` to the ledger
   branch (pull-rebase and retry if rejected), print the summary, exit non-zero
   on partial failure or open incidents.

**verify** — re-hash store files, HEAD published blobs/manifests, compare to
ledger, and for rsync fetch the remote `sha256` sidecar. `--sample N` for quick
checks. Never downloads from upstream. Policy narrowing does not orphan
history: `verify` and `repair` cover every ledger row regardless of current
policies, and additionally accept `--project`/`--channel` as filters.

**repair** — for `failed`, `missing_local` and `missing_remote` rows: re-push
from the store, or re-fetch when the store copy is gone, then re-verify.
Artifacts dropped by an earlier `--gc-after` are marked `local_gc` so `verify
--deep` skips their absent local copy instead of reporting corruption.

**incidents list|show|ack** — open incidents come from the ledger. `ack`
records a note, and with `--republish` moves the descriptive tag to the new
digest (old manifest stays addressable by digest) or renames the old rsync file
to `<basename>.superseded-<shortsha>`.

### Identity, tags and arch

The canonical artifact key is
`<channel>/<project>/<version>/<platform>/<platform_version>/<mapped_arch>/<sha256>`.
`upstream_path` is indexed but not unique, so a superseded artifact can coexist
with its replacement.

Tag: `<version>-<platform>-<platform_version>-<mapped_arch>`, plus
`-r<iteration>` when `iteration` is not `1` (upstream publishes e.g.
`cinc-19.4.46-2-x64.msi` beside `-1` for the same version). Lowercased,
`+`/`:` → `_`, capped at 128 characters. A superseded artifact is published as
`<tag>-superseded` and, for rsync, `<basename>.superseded-<shortsha>`. Existing
iteration-1 tags keep their current names, so bootstrap matches them.

Arch mapping keeps the existing public namespace: `x86_64`→`amd64`,
`aarch64`→`arm64`, `armv7l`/`armv7hl`→`armv7`, `ppc64le`→`ppc64le`,
`s390x`→`s390x`, `i386`/`i686`→`386`; anything else is sanitised and passed
through. If two raw values would map to the same tag with different digests,
the first file keeps the tag, the latecomer is published under
`<tag>-<shortsha>`, and the pair is reported as an incident.

### Bootstrap

Existing GHCR artifacts predate the ledger. `cinc-mirror ledger bootstrap`
HEADs every candidate tag, fetches its manifest, reads the package layer
digest, requires it to equal the upstream `sha256`, and records a satisfied
publication plus an `imported` event. Rows already imported are skipped. It is
explicit, never implicit, and safe to re-run. On a registry without the
artifact, nothing is recorded and `mirror` simply creates it.

### Superseded artifacts

A `hash_changed` artifact becomes a new `artifacts` row keyed by the same
`upstream_path` and the new `sha256`, with `supersedes` on the new row and
`superseded_by` on the old one. Both rows remain, so the old publication stays
verifiable and repairable. New bytes are still fanned out immediately, but only
under the superseded name; the descriptive tag/name keeps serving the old bytes
until a human decides.

`incidents ack <id>` records the note and marks the incident acked.
`--republish` then moves the descriptive ref/name to the new digest and marks
the old publication `superseded`, so `repair` and `verify` stop chasing it. The
old blob and manifest stay addressable by digest. Without `--republish`, ack
only closes the incident and the canonical name keeps the old bytes.

### Invariants

- `store` files are addressed by verified SHA-256; the name is the proof.
- Immutability is about **package bytes**, not manifest bytes. Two manifests for
  a tag are compatible when their package layer digest is equal; annotation or
  media-type differences are not incidents. A tag or remote path is only
  created if absent, or if it already resolves to the same package digest.
- Metadata is fetched over HTTPS with certificate verification; a run aborts
  rather than fetch metadata over cleartext.
- Publishing is last: verify → store → fan out.
- Every state change is an event; current-state tables are derived.
- Artifact keys and tags are sanitised (`/`, `+`, `:`, uppercase) with length
  caps; metadata `basename` cannot escape the store path.

### Ledger

SQLite (WAL) with append-only `events` and derived `artifacts`,
`publications`, `incidents`, `runs`, `cursors`. A `runs` row carries the
resolved policy JSON, order, limits, transport order, host and outcome, so the
ledger explains itself without the original shell history.

```sql
events(id INTEGER PRIMARY KEY, run_id TEXT, seq INTEGER, ts TEXT, kind TEXT,
       artifact_key TEXT, target TEXT, detail_json TEXT)
artifacts(key TEXT PRIMARY KEY, upstream_path TEXT, sha256 TEXT,
          size INTEGER, basename TEXT, project TEXT, channel TEXT,
          version TEXT, iteration TEXT, platform TEXT, platform_version TEXT,
          arch TEXT, metadata_json TEXT, first_seen TEXT, last_seen TEXT,
          superseded_by TEXT, supersedes TEXT)
publications(artifact_key TEXT, target TEXT, status TEXT, remote_ref TEXT,
             remote_digest TEXT, attempts INTEGER, next_attempt_at TEXT,
             last_error TEXT, updated_at TEXT, PRIMARY KEY(artifact_key, target))
incidents(id TEXT PRIMARY KEY, artifact_key TEXT, kind TEXT, old_sha256 TEXT,
          new_sha256 TEXT, detected_at TEXT, detail_json TEXT, state TEXT,
          issue_url TEXT, ack_note TEXT)
```

Segments are NDJSON event batches committed to the orphan branch `ledger` at
`runs/<run_id>.ndjson`, with the lease in `lease.json`, incidents in
`incidents/<id>.json` and a compacted `snapshot-<n>.ndjson` every 500 runs.
`ledger compact` writes a snapshot and `ledger gc` deletes run files it covers.
The local `ledger.db` is disposable; deleting it and re-reading the branch is
always safe. Because one file belongs to exactly one run, parallel writers
never touch the same lines; the branch update is guarded by `git push`
fast-forward, so a rejected push re-reads and rebases. A laptop run's events are
also mirrored to `./alerts/` for review without the branch.

Incidents: file on the ledger branch, local JSON alert, stderr line,
`SECURITY_ALERT=true` step output when `GITHUB_ACTIONS` is set, and an issue in
the mirror repo labelled `security-incident` when a token with `issues: write`
is available. Detection is deduplicated: one open incident per
`(artifact_key, old_sha256, new_sha256)`, later runs only bump its `last_seen`
and comment once. Only **newly opened** incidents drive exit code `3`; open
incidents from earlier runs are summarized in the report.

The ledger is a clone of this repository; the workflow therefore needs
`contents: write` in addition to `packages: write` and `issues: write`. The
lease is a cheap dedicated ref (`refs/heads/ledger-lease`, a one-line JSON
blob) so heartbeats never touch the event files. Lease acquisition and
heartbeat are best-effort: a transient push failure logs a warning and the run
continues; only a *rejected* push with a live foreign lease stops startup.
With the remote unreachable entirely, `--allow-unleased` (default in CI) lets
the run proceed, and the run marks itself unleased in its report.

### Targets

```rust
trait Target {
    fn name(&self) -> &str;
    fn probe(&self) -> Result<()>;
    fn exists(&self, a: &Artifact) -> Result<Option<Digest>>;
    fn put(&self, a: &Artifact, blob: &Path) -> Result<Digest>;
    fn verify(&self, a: &Artifact) -> Result<()>;
}
```

`oci_target`: `HEAD` blob → `POST` upload → `PATCH` chunks → `PUT` digest,
then manifest with `artifactType application/vnd.cinc.package.v1+json`, layers
for package and `metadata.json`, and the existing annotations
(`org.opencontainers.artifact.title`, `.description.platform`,
`.description.platform-version`, `.description.machine`,
`.description.version`). Ref: `<registry>/<namespace>/<repo>/<project>:<version>-<platform>-<platform-version>-<arch>`.

`rsync_target`: accepts **both** address forms — `ssh://[user@]host[:port]/path` (SSH transport, `auth = "ssh-key"`, host key checked, `-e "ssh -o BatchMode=yes -o StrictHostKeyChecking=yes"`) and `rsync://host[:port]/module/path` (rsync daemon, `auth = "daemon"` with optional password file, no host key). Layout mirrors upstream (`<channel>/<project>/<version>/<platform>/<platform-version>/<basename>` plus `metadata.json` and a `<basename>.sha256` sidecar), upload to `.tmp/` then `mv`, `--partial-dir`, `--checksum`.

Target credentials, per `auth` mode:

- `docker` — read `$DOCKER_CONFIG/config.json` (default `~/.docker/config.json`), including `credHelpers`/`credsStore`; in CI `GHCR_TOKEN` or `GITHUB_TOKEN` overrides with basic `x-access-token`/`<actor>`.
- `basic` — `user` and `password` from env or file reference.
- `bearer` — pre-issued token from env.
- `anonymous` — no auth, pull-only probes.
- rsync `ssh-key` — the agent or `identity_file`; `daemon` — `password_file`.

Tokens are read from the environment at use time, never written to logs or
the ledger.

### Config

`mirror.toml` (0600, git-ignored) plus env overrides:

```toml
state_dir = "~/.local/state/cinc-mirror"
concurrency = 4            # parallel downloads
upload_concurrency = 2     # parallel uploads per target
max_bandwidth = "0"        # global download cap, e.g. "40MiB/s"; 0 = unlimited
transport = ["ftp", "ftps", "https"]
metadata_transport = "https"
min_version = "18"         # default floor for policies without one

[[projects]]
id = "cinc-stable"
project = "cinc"
channel = "stable"
min_version = "19.0.0"
platforms = ["debian", "ubuntu"]
arches = ["amd64", "arm64"]

[[projects]]
id = "omnibus-toolchain"
project = "omnibus-toolchain"
channel = "stable"
all_versions = true
platforms = "*"
arches = "*"

[ledger]
branch = "ledger"
remote = "origin"

[[targets]]
name = "ghcr"
kind = "oci"
registry = "ghcr.io"
namespace = "rmoriz/cinc-mirror"
auth = "docker"          # docker | basic | bearer | anonymous

[[targets]]
name = "rsync"
kind = "rsync"
url = "ssh://mirror@backup.example.org/srv/cinc-mirror"
auth = "ssh-key"
enabled = false
```

Targets are named in config and **all enabled targets always receive every
artifact** — there is no per-run target selection and no target is special.
Each keeps its own backoff; `--target` exists only on `verify` and `repair` to
scope a check.

`cinc-mirror config check` validates, probes each target (auth, `GET /v2/`,
write/delete of a probe blob, rsync host key, free space) and redacts secrets.
It rejects duplicate policy ids, `platform_versions` keys absent from a
non-wildcard `platforms`, unknown `--set` keys, and a `min_version` above a
`max_version`. Durations and sizes (`--max-bandwidth`, `--limit-bytes`) take
human units such as `40MiB/s` or `2GiB` as well as raw numbers.

### Rate limiting, retries

Three independent knobs, all configurable and overridable per run:

- `concurrency` — parallel downloads, default 4.
- `upload_concurrency` — parallel uploads **per target**, default 2.
- `max_bandwidth` — global download cap (`"40MiB/s"`, `0` = unlimited), applied
  by a shared token bucket around the copy loop so sockets are paced, not just
  the scheduler. A target may set its own `max_bandwidth` for its uploads.

Per-host cap is additionally 3. 429/503 halves effective concurrency (floor 1)
and restores it on a success streak. A bandwidth cap slows transfer but never
aborts. Download: 3 tries per transport with jittered backoff, then next
transport. Upload: 4 tries, then `retry` with `next_attempt_at`. 404/403/451
fail the artifact permanently with the response body. Tag pointing at a
different digest is an incident, not a retry.

### Resume and recovery

Partials keep their byte offset; FTP `REST`/`APPE`, HTTP `Range`. A run start
marks rows stuck since the previous lease as `interrupted` and requeues them.
Blob uploads are idempotent by digest; manifest PUTs are idempotent by digest.
`verify --deep` plus `repair` are the supported path after an unclean stop.

## CLI

```
cinc-mirror mirror   [--project P]… [--versions SPEC] [--all-versions]
                     [--everything] [--platform P]… [--platform-version V]…
                     [--arch A]… [--min-version V] [--transport T]…
                     [--concurrency N] [--upload-concurrency N]
                     [--max-bandwidth RATE] [--limit N] [--limit-bytes SIZE]
                     [--order version-desc|smallest-first|largest-first]
                     [--gc-after] [--allow-unleased] [--set K=V]… [--dry-run]
cinc-mirror plan     [same filters] [--json] [--by project|platform|arch|target|version]
                     [--out FILE] [--record]
cinc-mirror backfill [same filters] [--since RFC3339] [--limit N]
cinc-mirror verify   [--target N]… [--deep | --sample N]
cinc-mirror repair   [--target N]… [--limit N]
cinc-mirror incidents list | show <id> | ack <id> [--republish] [-m NOTE]
cinc-mirror ledger   bootstrap | pull | push | compact | gc | export
cinc-mirror targets  list | check
cinc-mirror config   check
```

Exit codes: `0` all good, `2` partial failure, `3` open/new incidents, `4`
lease busy, `5` config/auth, `64` usage.

## Testing

- Unit: tag/key/path sanitisation (including iteration suffixes and `.msi`
  names), version comparison and glob semantics,
  per-project policy intersection and `--set` precedence, `--limit-bytes`
  counting and deterministic ordering, `local_gc` handling, metadata parsing
  (including hostile `basename`), hash-ladder comparison, arch mapping,
  bootstrap manifest equivalence, backoff.
- Integration with local fixtures: `wiremock` for HTTPS index/metadata,
  `libunftp` for FTP/FTPS, a minimal in-process registry mock, `file://` rsync
  via a local dir. Cover resume after truncation, hash mismatch, incident on
  hash change, superseded publication, ack/republish, partial target failure,
  repair of both a corrupt store copy and a missing remote, `plan` totals
  against known fixture sizes, and `--limit-bytes` terminating mid-run.
- One opt-in live test against `downloads.cinc.sh` and a scratch GHCR package.
- CI: `fmt`, `clippy -D warnings`, `cargo audit`, tests, musl/arm64 release
  builds with checksums, container image.

## Rollout

1. Land the binary and tests behind the `rust` branch.
2. Create the orphan `ledger` branch and `ledger-lease` ref.
3. `plan` all projects (see Plan) and record the expected volume in the run
   report.
4. `ledger bootstrap` against the existing GHCR packages; expect `imported`
   rows and no incidents. Manifest compatibility is judged on the package
   layer digest, so existing annotation differences do not fire.
5. Local dry run on a single platform, then a real single-project run.
6. Full local run with the rsync target pointed at a scratch host.
7. Replace `mirror-cinc.yml` with a `backfill.yml` (schedule plus
   `repository_dispatch`, `concurrency: cinc-mirror`, `contents: write`,
   `packages: write`, `issues: write`) using `--limit`, `--limit-bytes`,
   `--gc-after` and a self-redispatch cursor.
8. Optional Cloudflare Worker: cron that fires the same `repository_dispatch`;
   no mirroring logic in JS.
9. Delete the shell scripts and `oras` setup once the new path has run clean
   for two weeks.

## Left to the builder

Module internals, exact `oci-client` version and its gaps, token cache, DDL
details and migrations, upload chunk size, rsync batching, test fixture
inventory, CI runner choice, Worker code, packaging and binary distribution.

## Decisions made in conversation

- Immutability is mandatory; hash changes are incidents with a kept history.
- Metadata/hash path must be TLS; payload over FTP is acceptable.
- Fan-out to N targets after one download and one verification.
- Fan-out is unconditional: every artifact goes to every enabled target.
- rsync is the second target, not a backup target.
- No package bytes in the repository; hash records and incidents are committed
  to it once the tool runs.
- Download/upload parallelism and a bandwidth ceiling are configurable.
- Every mirrored project is a config policy (id, project, channel, version
  bounds/globs, platforms, arches); `--everything` runs all enabled policies.
- CLI filters intersect policies; only `--all-versions` widens. `--set` applies
  before intersection and may add a policy.
- Policies govern `mirror`/`backfill`/`plan` only; `verify`/`repair` cover all
  ledger rows.
- `--limit-bytes` counts downloads, finishes the crossing artifact, and runs in
  deterministic order so capped runs always progress.
- An estimate mode traverses sizes over FTP without downloading bodies.
- The ledger lives on an orphan `ledger` branch of this repo; the CI job gets
  `contents: write`.
- Initial run local; backfill on Actions or a serverless trigger.
