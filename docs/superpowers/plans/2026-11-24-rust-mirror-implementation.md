# CINC Mirror Rust Rewrite — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a single Rust binary that crawls the CINC download tree, verifies every artifact, keeps an append-only hash ledger in git, and fans the bytes out to OCI and rsync targets with resume, repair, backfill and an estimate mode.

**Architecture:** One `cinc-mirror` crate with a thin CLI and a library of focused modules. The source layer reads index and metadata over HTTPS and payloads over an FTP/FTPS/HTTPS ladder. A content-addressed store verifies SHA-256 before a `Target` trait fan-out writes to every enabled target. All state is append-only events materialised into SQLite; events are committed as NDJSON on an orphan `ledger` branch.

**Tech Stack:** Rust 2021 (MSRV 1.85), tokio, reqwest (rustls), suppaftp, `oci-client` for auth/manifests with streaming blob uploads, rusqlite, clap, serde, tracing.

**Spec:** `docs/superpowers/specs/2026-11-24-rust-mirror-design.md`

## Global Constraints

- Metadata and directory listings are fetched over HTTPS only; a cleartext metadata fallback is forbidden.
- Payload transports are tried in configured order, default `["ftp", "ftps", "https"]`.
- SHA-256 is the gate; SHA-512/SHA-1/MD5 are cross-checks when present. Nothing is published before the full hash matches.
- Immutability compares **package bytes**: a tag may only be created if absent or already resolving to the same package digest.
- Existing ref/tag for iteration 1 stays `<version>-<platform>-<platform_version>-<arch>`; iteration ≠ 1 appends `-r<iteration>`; superseded artifacts append `-<sha12>`.
- Arch map: `x86_64→amd64`, `aarch64→arm64`, `armv7l→armv7`, `armv7hl→armv7`, `i386→386`, `i686→386`; others pass through sanitised.
- Every enabled target receives every artifact; no per-run target selection on `mirror`/`backfill`/`plan`.
- No package bytes are ever committed; blobs live in `state_dir` and targets.
- Ledger writes are append-only; SQLite is derived state and must be rebuildable from NDJSON.
- Exit codes: `0` ok, `2` partial failure, `3` newly opened incidents, `4` lease busy, `5` config/auth, `64` usage.
- Credentials are read from environment or files at use time and never logged or written to the ledger.
- Sizes and durations accept human units (`2GiB`, `40MiB/s`).
- Deterministic queue order: version descending, then project id, platform, platform_version, arch; satisfied/terminal rows removed before ordering.
- `--limit-bytes` counts download bytes, finishes the crossing artifact, never truncates an upload.
- Only `rsync` may be executed as a subprocess; everything else is native.

## Review Focus

- A partial file resumed against a source whose file changed (shorter remote, different bytes): must restart from zero, not splice two versions together.
- Metadata that is valid JSON but hostile or degenerate (`basename` with `/` or `..`, missing `sha256`, `platform` disagreeing with the path): must fail that artifact without escaping the store or poisoning the ledger.
- Registry with an existing tag whose package layer digest differs (old artifact or attacker): must open an incident and leave the tag untouched, not overwrite.
- Interruption mid fan-out (one target published, another not): the next run must not re-download and must retry only the missing target.
- `--limit-bytes` at or below a single artifact, and a cap that is smaller than the first artifact: must still make progress or fail cleanly without an infinite loop.

---
### Task 1: Crate scaffold, config model, `config check`

**Files:**
- Create: `Cargo.toml`, `src/main.rs`, `src/lib.rs`, `src/cli.rs`, `src/config.rs`, `tests/config.rs`
- Create: `mirror.toml.example`, `.gitignore` additions (`/target`, `mirror.toml`, `state/`)

**Interfaces:**
- Consumes: nothing.
- Produces: `Config`, `ProjectPolicy`, `TargetConfig`, `LedgerConfig`, `TransportKind`, `Config::load(Option<&Path>) -> Result<Config, ConfigError>`, `Config::validate(&self) -> Result<(), ConfigError>`, `Config::apply_overrides(&mut self, &[String]) -> Result<(), ConfigError>`, CLI enum `Command`.

- [ ] **Step 1: Write failing config tests**

```rust
#[test]
fn rejects_duplicate_policy_ids() { /* two [[projects]] with id "cinc" -> Err(DuplicatePolicyId) */ }

#[test]
fn rejects_platform_version_for_unlisted_platform() {
    // platforms = ["ubuntu"], platform_versions.debian = ["13"] -> Err
}

#[test]
fn wildcard_platforms_accept_platform_versions() {
    // platforms = "*", platform_versions.debian = ["13"] -> Ok
}

#[test]
fn rejects_min_above_max() { /* min_version = "20", max_version = "19" -> Err */ }

#[test]
fn apply_overrides_replaces_field_and_adds_policy() {
    // --set cinc-stable.min_version=19.2.0 ; --set extra.project=foo
}

#[test]
fn unknown_toml_key_is_an_error() { /* #[serde(deny_unknown_fields)] */ }
```

- [ ] **Step 2: Run `cargo test --test config` and confirm it fails to compile**

Run: `cargo test --test config`
Expected: error `no crate cinc_mirror` / missing types.

- [ ] **Step 3: Create `Cargo.toml` and the module skeleton**

Use these dependencies (pin majors; adjust only if a newer major is required to build):

```toml
[package]
name = "cinc-mirror"
version = "0.1.0"
edition = "2021"
rust-version = "1.80"

[dependencies]
anyhow = "1"
async-trait = "0.1"
chrono = { version = "0.4", features = ["serde"] }
clap = { version = "4", features = ["derive", "env"] }
futures = "0.3"
humantime = "2"
indicatif = "0.17"
oci-client = "0.14"
percent-encoding = "2"
rand = "0.8"
reqwest = { version = "0.12", default-features = false, features = ["rustls-tls", "stream", "json"] }
rusqlite = { version = "0.32", features = ["bundled"] }
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha1 = "0.10"
sha2 = "0.10"
md-5 = "0.10"
suppaftp = { version = "6", features = ["async", "async-rustls"] }
thiserror = "1"
tokio = { version = "1", features = ["rt-multi-thread", "macros", "fs", "io-util", "sync", "time", "process"] }
toml = "0.8"
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["json", "env-filter"] }
url = "2"

[dev-dependencies]
assert_cmd = "2"
axum = "0.7"
libunftp = "0.20"
predicates = "3"
tempfile = "3"
wiremock = "0.6"
```

Define `Config` with `#[serde(deny_unknown_fields)]` on every struct and
`#[serde(default)]` where the spec gives defaults. Implement `cli.rs` with
`#[derive(Parser)] pub struct Cli { #[command(subcommand)] pub cmd: Command, #[arg(long, global = true)] pub config: Option<PathBuf> }`
and stub commands that return `bail!("not implemented")`. `main.rs` prints errors and maps them to exit code `5` for config/auth, `64` for clap usage.

- [ ] **Step 4: Run the config tests and `cargo run -- config check`**

Run: `cargo test --test config && cargo run -- config check --config mirror.toml.example`
Expected: all tests pass; command reports the parsed policies and targets with no secrets.

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock src tests mirror.toml.example .gitignore
git commit -m "feat: scaffold crate with config model and validation"
```

---
### Task 2: Version semantics and policy resolution

**Files:**
- Create: `src/version.rs`, `src/scope.rs`, `tests/scope.rs`
- Modify: `src/lib.rs`, `src/config.rs` (types reference `Version`, `VersionGlob`)

**Interfaces:**
- Consumes: `Config`, `ProjectPolicy`.
- Produces: `Version` (`Ord`, `FromStr`, `Display`), `VersionGlob::matches(&Version)`, `ScopeArgs`, `ResolvedPolicy`, `ResolvedScope`, `Config::resolve(&ScopeArgs) -> Result<ResolvedScope, ScopeError>`.

- [ ] **Step 1: Write failing tests for version semantics**

```rust
#[test] fn numeric_segments_not_lexicographic() { assert!(v("19.10.0") > v("19.4.46")); }

#[test] fn globs_match_whole_segments() {
    assert!(g("18.8.*").matches(&v("18.8.11")));
    assert!(!g("18.8.*").matches(&v("18.9.1")));
}

#[test] fn all_versions_clears_global_floor() {
    // policy all_versions=true, global min_version=18, version 17.1.0 -> included
}

#[test] fn cli_narrows_but_all_versions_widens() {
    // policy min_version=19; --min-version 19.2 -> 19.2 floor
    // --all-versions -> no floor
}

#[test] fn everything_plus_project_is_usage_error() { /* Err(EverythingWithProject) */ }

#[test] fn project_name_selects_all_its_policies() {
    // ids cinc-stable + cinc-unstable, --project cinc -> both
}

#[test] fn set_applies_before_cli_intersection() { /* --set policy.min_version=19.5 + --min-version 19.2 -> 19.5 */ }
```

- [ ] **Step 2: Run `cargo test --test scope` to confirm failure**

Expected: missing `Version`/`resolve` symbols.

- [ ] **Step 3: Implement version comparison, globs, and resolver**

`Version` parses dot-separated `u64` segments, rejects empty/non-numeric.
`VersionGlob` stores `Vec<Segment>` where `Segment::Wildcard` matches any single
segment. `resolve` walks `Config.projects`, applies `--set` mutations already
stored on `Config`, intersects with `ScopeArgs`, and returns policies in config
order with the effective floor. Widening is limited to `all_versions`.

- [ ] **Step 4: Run tests**

Run: `cargo test --test scope`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/version.rs src/scope.rs src/lib.rs src/config.rs tests/scope.rs
git commit -m "feat: version comparison and policy resolution"
```

---
### Task 3: Artifact identity, tags, rsync paths

**Files:**
- Create: `src/artifact.rs`, `tests/artifact.rs`

**Interfaces:**
- Consumes: nothing (upstream metadata is not a dependency yet).
- Produces: `Artifact`, `ArtifactInput { basename, sha256, platform, platform_version, version, iteration, raw_arch }`, `Artifact::new(&ArtifactContext, ArtifactInput) -> Result<Artifact, ArtifactError>`, `Artifact::tag(&self) -> String`, `Artifact::superseded_tag(&self) -> String`, `Artifact::rsync_relpath(&self) -> String`, `mapped_arch(&str) -> String`, `sanitize_component(&str) -> String`, `ARTIFACT_TYPE`.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn maps_raw_arches() { assert_eq!(mapped_arch("x86_64"), "amd64"); assert_eq!(mapped_arch("aarch64"), "arm64"); }

#[test] fn iteration_one_keeps_legacy_tag() {
    // version 19.4.46, debian/13, amd64, iteration Some("1")
    assert_eq!(tag, "19.4.46-debian-13-amd64");
}

#[test] fn iteration_two_gets_suffix() {
    // windows/2022, x86_64, iteration Some("2") -> "19.4.46-windows-2022-amd64-r2"
}

#[test] fn superseded_tag_appends_sha12() { /* ...-<12 hex> */ }

#[test] fn rejects_hostile_basename() {
    // "../../etc/passwd" and "a/b.deb" -> Err(InvalidBasename)
}

#[test] fn sanitizes_and_caps_tag_length() { /* <=128, only [a-z0-9._-] */ }

#[test] fn rsync_relpath_is_upstream_shaped() { /* "stable/cinc/19.4.46/debian/13/cinc_...deb" */ }

#[test] fn detects_tag_collision_between_two_artifacts() { /* same tag, different sha -> Err */ }
```

- [ ] **Step 2: Run `cargo test --test artifact` and confirm failure**

- [ ] **Step 3: Implement `src/artifact.rs`**

Key: `<channel>/<project>/<version>/<platform>/<platform_version>/<mapped_arch>/<sha256>`.
Tag: lowercased, `+`/`:`→`_`, reject `/`, append `-r<iteration>` when iteration
parses and is not `1`, cap at 128 by truncating and appending `-<sha12>`.
`ArtifactContext`
holds the crawl values (`channel`, `project`, `version`, `platform`,
`platform_version`); `ArtifactInput` holds the metadata values. `new` validates
`basename` is a single safe component, requires a 64-hex `sha256`, and takes
platform/platform_version/version from the input only when they match the
context (mismatch is `ArtifactError::ContextMismatch`). Task 5 adds
`Metadata::to_input()` so the source layer can feed this.

- [ ] **Step 4: Run tests**

Run: `cargo test --test artifact`
Expected: all pass.

- [ ] **Step 5: Commit**

```bash
git add src/artifact.rs src/lib.rs tests/artifact.rs
git commit -m "feat: artifact identity, tag and path mapping"
```

---
### Task 4: Streaming multi-hash verification

**Files:**
- Create: `src/hash.rs`, `tests/hash.rs`
- Create: `src/source/metadata.rs` (the deserialised upstream metadata used by hash verification)

**Interfaces:**
- Consumes: nothing.
- Produces: `Hashes { sha256, sha512, sha1, md5, size }`, `ExpectedHashes`, `hash_file(&Path) -> io::Result<Hashes>`, `Hashes::verify(&self, &ExpectedHashes) -> VerifyOutcome`, `ExpectedHashes::from_metadata(&Metadata)`.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn matches_known_vector() { /* sha256 of "abc" = ba7816bf... */ }

#[test] fn size_mismatch_reported_before_hash() { /* expected 3, actual 4 -> SizeMismatch */ }

#[test] fn hash_mismatch_reports_both() { /* expected all zeros -> HashMismatch { expected, actual } */ }

#[test] fn optional_hashes_are_cross_checked() { /* wrong md5 with right sha256 -> Mismatch("md5") */ }

#[test] fn metadata_requires_sha256() { /* missing -> Err */ }
```

- [ ] **Step 2: Run `cargo test --test hash` to confirm failure**

- [ ] **Step 3: Implement streaming hashing**

`hash_file` opens the file once, updates sha2/sha1/md-5 digests over 1 MiB
buffers, returns lowercase hex and byte count. `verify` checks size first, then
sha256, then any optional digest present in `ExpectedHashes`.

- [ ] **Step 4: Run tests, then commit**

```bash
cargo test --test hash
git add src/hash.rs src/source/metadata.rs src/lib.rs tests/hash.rs
git commit -m "feat: streaming sha256 verification with cross-checks"
```

---
### Task 5: HTTPS index and metadata client

**Files:**
- Create: `src/source/mod.rs`, `src/source/index.rs`, `tests/source_index.rs`, `tests/source_metadata.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `Metadata`, `ArtifactContext`, `Config`.
- Produces: `Source::new(&SourceConfig) -> Result<Source>`, `Source::list(&self, dir: &str) -> Result<Vec<IndexEntry>>`, `Source::metadata(&self, path: &str) -> Result<Metadata>`, `IndexEntry { name: String, is_dir: bool }`, `SourceConfig { https_base: Url, ftp_host: String, ftp_base_path: String, transports: Vec<TransportKind> }`.

- [ ] **Step 1: Write failing index tests**

```rust
#[test] fn parses_apache_autoindex() { /* fixture HTML -> ["19.4.46/","19.3.14/"] as dirs, files flagged */ }

#[test] fn ignores_sort_links_parent_and_absolute_hrefs() { /* ?C=N, ../, https://osuosl.org */ }

#[test] fn rejects_untrusted_metadata_host() { /* config https_base https://evil -> ok by config; redirect to http -> Err */ }

#[test] fn metadata_parses_required_fields() { /* fixture with basename/sha256/arch/... */ }

#[test] fn metadata_missing_sha256_is_an_error() { /* Err(MetadataError::MissingField("sha256")) */ }
```

- [ ] **Step 2: Run `cargo test --test source_index --test source_metadata` and confirm failure**

- [ ] **Step 3: Implement with reqwest + wiremock tests**

`list` builds `<https_base>/<dir>/`, requires the response URL and final URL to
be `https`, parses `<a href="...">` entries with a small regex-free HTML scan,
decodes percent-encoding, strips trailing `/` for dirs, and drops query links,
absolute URLs, `../` and the Apache header/sort links. `metadata` fetches the
`*.metadata.json` path, enforces `https` after redirects, and deserialises into
`Metadata` (unknown fields tolerated, required fields validated).

- [ ] **Step 4: Run tests, then commit**

```bash
cargo test --test source_index --test source_metadata
git add src/source src/lib.rs tests/source_index.rs tests/source_metadata.rs
git commit -m "feat: https index and metadata client"
```

---
### Task 6: Size resolution and `plan`

**Files:**
- Create: `src/source/size.rs`, `src/plan.rs`, `tests/plan.rs`
- Modify: `src/source/mod.rs`, `src/cli.rs`

**Interfaces:**
- Consumes: `Source`, `ResolvedScope`, `Config`; a caller-provided set of already-satisfied artifact keys (the ledger arrives in Task 9, so plan must not depend on it yet).
- Produces: `Source::sizes(&self, dir: &str) -> Result<HashMap<String, u64>>`, `Plan { artifacts: usize, total_bytes: u64, satisfied_bytes: u64, by_project: BTreeMap<String, GroupTotals>, by_platform: …, by_arch: …, largest: Vec<(String, u64)>, effective_policy: serde_json::Value, projected_seconds: Option<u64> }`, `plan::build(&Source, &ResolvedScope, &HashSet<String>, Option<u64>) -> Result<Plan>`, `Plan::to_json(&self) -> String`.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn parses_mlsd_lines() { /* "type=file;size=51993096; x.deb" -> 51993096 */ }

#[test] fn size_falls_back_to_head_when_mlsd_missing() { /* wiremock HEAD */ }

#[test] fn totals_group_by_project_platform_arch() { /* two fixtures -> exact bytes */ }

#[test] fn satisfied_artifacts_count_separately() { /* ledger says published -> satisfied_bytes, not total */ }

#[test] fn json_embeds_effective_policy_and_is_stable() { /* field order/serde struct */ }

#[test] fn projected_duration_uses_max_bandwidth() { /* 100 MiB at 10 MiB/s -> 10s */ }
```

- [ ] **Step 2: Run `cargo test --test plan` to confirm failure**

- [ ] **Step 3: Implement MLSD/SIZE/HEAD resolution and plan aggregation**

`Source::sizes` opens one FTP control connection per directory, issues `MLSD`,
parses `type=file;size=N;name` records; if MLSD is unsupported, issues `SIZE`
per `*.metadata.json` sibling basename; if FTP is unreachable, HEADs each
`https` package URL and reads `Content-Length`. `plan::build` crawls metadata,
takes the satisfied-key set as an argument, aggregates, and writes
`plan-<run_id>.json` when `--out` is given. Task 18 passes
`ledger.satisfied_keys()`, so plan gains ledger awareness only at wiring time.

- [ ] **Step 4: Run tests, then commit**

```bash
cargo test --test plan
git add src/source/size.rs src/plan.rs src/source/mod.rs src/cli.rs tests/plan.rs
git commit -m "feat: size resolution and plan estimate"
```

---
### Task 7: Payload transport ladder with resume

**Files:**
- Create: `src/source/transport.rs`, `tests/transport.rs`
- Modify: `src/source/mod.rs`, `src/hash.rs` (resumable hash state)

**Interfaces:**
- Consumes: `Hashes`, `ExpectedHashes`, `SourceConfig`.
- Produces: `TransportKind { Ftp, Ftps, Https }`, `TransportError { NotFound, Auth, Retryable, Protocol }`, `Source::download(&self, remote_path: &str, dest: &Path, expected: &ExpectedHashes, resume_from: u64) -> Result<Hashes, DownloadError>`, `Source::download_with_ladder(...) -> Result<(Hashes, TransportKind), DownloadError>`.

- [ ] **Step 1: Write failing tests**

```rust
#[tokio::test]
async fn resumes_http_download_from_partial_size() { /* Range: bytes=5- -> body tail, final hash matches */ }

#[tokio::test]
async fn restarts_when_remote_is_shorter_than_partial() { /* server says 3 bytes, partial 10 -> truncate, full GET */ }

#[tokio::test]
async fn restart_when_partial_hash_differs_after_completion() { /* corrupted part -> Err(Corrupt) not silent */ }

#[tokio::test]
async fn falls_back_to_next_transport_on_5xx() { /* first transport 503 twice -> second succeeds */ }

#[tokio::test]
async fn auth_and_404_do_not_advance_transport() { /* 404 -> Err immediately */ }

#[tokio::test]
async fn exhausted_ladder_reports_last_error_and_observed_hash() { /* Err includes observed sha256 */ }
```

- [ ] **Step 2: Run `cargo test --test transport` and confirm failure**

- [ ] **Step 3: Implement the ladder**

`download` opens `.part` with append, resumes at `resume_from` only when the
remote size is larger, updates a resumed hasher. FTP/FTPS via `suppaftp`
`retr_as_stream` with `restart_from`; HTTPS via `Range` + `206` check. On
completion: truncate leftovers, hash the file, compare with `expected`; a
mismatch deletes the partial and returns `DownloadError::Corrupt { expected, observed }`.
3 attempts per transport with jittered 1/2/4 s backoff; 404/403/451 are fatal.

- [ ] **Step 4: Run tests, then commit**

```bash
cargo test --test transport
git add src/source/transport.rs src/source/mod.rs src/hash.rs tests/transport.rs
git commit -m "feat: resumable ftp/ftps/https download ladder"
```

---
### Task 8: Content-addressed store and FTP integration

**Files:**
- Create: `src/store.rs`, `tests/store.rs`, `tests/ftp_integration.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `Artifact`, `Hashes`.
- Produces: `Store::open(&Path) -> Result<Store>`, `Store::partial_path(&self, &str) -> PathBuf`, `Store::path(&self, &str) -> PathBuf`, `Store::commit(&self, &str, &Path) -> Result<PathBuf>`, `Store::has(&self, &str) -> bool`, `Store::gc(&self, &str) -> Result<()>`, `Store::free_bytes(&self) -> Result<u64>`.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn commit_is_atomic_and_deduped() { /* two commits same sha -> one file, no error */ }

#[test] fn gc_removes_blob_but_leaves_other() { /* ... */ }

#[test] fn refuses_path_traversal_in_sha() { /* "../x" -> Err(InvalidDigest) */ }

#[test] fn partial_is_separate_from_committed() { /* ... */ }

#[tokio::test]
async fn ftp_roundtrip_matches_hash() { /* libunftp with fixture bytes -> download -> verify */ }
```

- [ ] **Step 2: Run tests and confirm failure**

- [ ] **Step 3: Implement the store**

Layout: `<state>/store/<aa>/<sha256>`, `<state>/partial/<sha256>.part`,
`<state>/alerts/`, `<state>/runs/`. `commit` fsyncs the partial, renames into
place (skip if present), and returns the path. `gc` removes the blob only.
`free_bytes` uses `libc::statvfs` via a small `nix`-free FFI block or
`fs2`-equivalent; if unavailable return `None` and skip the disk check.

- [ ] **Step 4: Run tests, then commit**

```bash
cargo test --test store --test ftp_integration
git add src/store.rs src/lib.rs tests/store.rs tests/ftp_integration.rs
git commit -m "feat: content-addressed store and ftp integration"
```

---
### Task 9: Ledger schema, events, materialisation

**Files:**
- Create: `src/ledger/mod.rs`, `src/ledger/schema.sql`, `tests/ledger_db.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `Artifact`, `Hashes`.
- Produces: `Ledger::open(&Path) -> Result<Ledger>`, `Ledger::append(&mut self, &Event) -> Result<()>`, `Ledger::apply(&mut self, &Event) -> Result<()>`, `Ledger::materialize(&mut self) -> Result<()>`, `Ledger::pending(&self, &str) -> Result<Vec<Artifact>>`, `Ledger::incidents(&self, IncidentFilter) -> Result<Vec<Incident>>`, `Event { run_id, seq, ts, kind, artifact_key, target, detail }`, `EventKind`.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn appends_and_materializes_artifact_and_publication() { /* ... */ }

#[test] fn pending_excludes_satisfied_and_superseded_rows() { /* ... */ }

#[test] fn hash_change_opens_single_incident_per_hash_pair() { /* apply twice -> one open incident */ }

#[test] fn duplicate_event_is_idempotent() { /* same run_id+seq twice -> one row */ }

#[test] fn local_gc_marks_row_and_keeps_publication_verified() { /* ... */ }

#[test] fn run_row_stores_effective_policy_json() { /* ... */ }

#[test] fn schema_migrates_from_empty_and_is_rerunnable() { /* open twice */ }
```

- [ ] **Step 2: Run `cargo test --test ledger_db` and confirm failure**

- [ ] **Step 3: Implement schema and reducer**

Tables exactly as the spec (plus `schema_version`). `apply` is a match on
`EventKind` that upserts derived rows; incidents dedupe on
`(artifact_key, old_sha256, new_sha256)` with `state='open'`. `materialize`
rebuilds artifacts/publications from events when the DB is deleted.

- [ ] **Step 4: Run tests, then commit**

```bash
cargo test --test ledger_db
git add src/ledger/mod.rs src/ledger/schema.sql src/lib.rs tests/ledger_db.rs
git commit -m "feat: append-only ledger with materialized state"
```

---
### Task 10: Ledger files, git branch, lease

**Files:**
- Create: `src/ledger/files.rs`, `src/ledger/git.rs`, `tests/ledger_files.rs`, `tests/ledger_git.rs`
- Modify: `src/ledger/mod.rs`, `src/cli.rs`

**Interfaces:**
- Consumes: `Ledger`, `Event`.
- Produces: `LedgerStore { workdir: PathBuf, branch: String, remote: String }` with `sync(&self) -> Result<()>`, `write_run(&self, &[Event]) -> Result<PathBuf>`, `commit_and_push(&self, &Path, &str) -> Result<()>`, `load_all(&mut Ledger) -> Result<u64>`; `Lease::acquire(&LedgerStore, &str, Duration) -> Result<Option<Lease>>`, `Lease::refresh(&mut self)`, `Lease::release(self)`.

- [ ] **Step 1: Write failing tests against a local bare repo**

```rust
#[test] fn write_run_produces_sorted_ndjson() { /* events sorted by seq, one per line */ }

#[test] fn load_all_is_idempotent() { /* apply same files twice -> same row counts */ }

#[test] fn sync_rebases_when_remote_advanced() { /* second clone pushes first */ }

#[test] fn lease_blocks_second_live_holder() { /* ttl 10m -> None + Busy */ }

#[test] fn expired_lease_is_stolen_and_logged() { /* ttl 1ms -> acquired, takeover event */ }

#[test] fn push_rejection_pulls_and_retries() { /* bare repo hook moves ref */ }

#[test] fn snapshot_compaction_keeps_history() { /* compact -> snapshot file, run files still loadable */ }
```

- [ ] **Step 2: Run tests and confirm failure**

- [ ] **Step 3: Implement files and git**

`LedgerStore` clones/fetches `refs/heads/ledger` into `<state>/ledger-repo` with
`git` CLI (`Command::new("git")`), writes `runs/<run_id>.ndjson`, commits with a
message carrying the summary, and pushes with up to 3 pull-rebase retries. The
lease is a JSON blob at `lease.json` committed to `refs/heads/ledger-lease`;
acquire reads the ref, compares `expires_at`, writes and pushes with
`--force-with-lease`; a rejected push with a live foreign lease is
`LeaseError::Busy`. Heartbeat failures are warnings, never fatal.

- [ ] **Step 4: Run tests, then commit**

```bash
cargo test --test ledger_files --test ledger_git
git add src/ledger src/cli.rs tests/ledger_files.rs tests/ledger_git.rs
git commit -m "feat: git-backed ledger segments and lease"
```

---
### Task 11: OCI registry client

**Files:**
- Create: `src/oci.rs`, `tests/oci.rs`, `tests/common/registry.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `Config` target config.
- Produces: `Registry::new(OciConfig) -> Result<Registry>`, `Registry::probe(&self) -> Result<()>`, `Registry::head_blob(&self, digest: &str) -> Result<bool>`, `Registry::upload_blob(&self, path: &Path, digest: &str) -> Result<()>`, `Registry::put_manifest(&self, repo: &str, reference: &str, manifest: &serde_json::Value) -> Result<String>`, `Registry::get_manifest(&self, repo: &str, reference: &str) -> Result<serde_json::Value>`, `Registry::package_digest_for_tag(&self, repo: &str, tag: &str) -> Result<Option<String>>`, `OciAuth` (Docker/Basic/Bearer/Anonymous).

- [ ] **Step 1: Write failing tests against the axum mock registry**

```rust
#[tokio::test] async fn anonymous_pull_uses_token_endpoint() { /* 401 challenge -> GET /token -> retry with Bearer */ }

#[tokio::test] async fn docker_config_credentials_are_used() { /* temp DOCKER_CONFIG with auth base64 */ }

#[tokio::test] async fn env_token_overrides_docker_config() { /* GHCR_TOKEN -> x-access-token basic */ }

#[tokio::test] async fn upload_streams_without_buffering_whole_file() { /* assert body arrives in >1 chunk (mock counts reads) */ }

#[tokio::test] async fn existing_blob_skips_upload() { /* HEAD 200 -> no POST */ }

#[tokio::test] async fn manifest_put_returns_digest_and_is_retried_on_5xx() { /* 500,500,201 */ }

#[tokio::test] async fn token_cache_reuses_unexpired_token() { /* /token called once */ }
```

- [ ] **Step 2: Run `cargo test --test oci` and confirm failure**

- [ ] **Step 3: Implement auth, upload, manifest**

Use `oci-client` for `RegistryAuth` resolution and manifest serialisation;
implement `upload_blob` with `reqwest`: `POST /v2/<repo>/blobs/uploads/`, then
one `PUT <location>?digest=<digest>` streaming the file with a known
`Content-Length`, 4 attempts with backoff. `put_manifest` uses
`PUT /v2/<repo>/manifests/<ref>` with `application/vnd.oci.image.manifest.v1+json`.
`probe` does `GET /v2/` then a non-destructive token fetch for `push,pull`.
The mock registry in `tests/common/registry.rs` implements the v2 routes with
in-memory blobs and manifests.

- [ ] **Step 4: Run tests, then commit**

```bash
cargo test --test oci
git add src/oci.rs src/lib.rs tests/oci.rs tests/common/registry.rs
git commit -m "feat: streaming oci registry client"
```

---
### Task 12: OCI target

**Files:**
- Create: `src/targets/mod.rs`, `src/targets/oci_target.rs`, `tests/oci_target.rs`
- Modify: `src/lib.rs`

**Interfaces:**
- Consumes: `Registry`, `Artifact`, `Hashes`.
- Produces: `PutOutcome { remote_ref: String, remote_digest: String }`, `#[async_trait] trait Target { fn name(&self) -> &str; async fn probe(&self) -> Result<()>; async fn exists(&self, &Artifact) -> Result<Option<String>>; async fn put(&self, &Artifact, &Path) -> Result<PutOutcome>; async fn verify(&self, &Artifact) -> Result<()>; }`, `TargetSet::from_config(&Config) -> Result<TargetSet>`, `TargetSet::all(&self) -> &[Arc<dyn Target>]`. OCI's digest is the manifest digest; rsync's is the package sha256.

- [ ] **Step 1: Write failing tests**

```rust
#[tokio::test] async fn put_writes_expected_manifest_and_annotations() { /* artifactType, title, platform, platform-version, machine, version; metadata layer */ }

#[tokio::test] async fn exists_returns_none_when_tag_missing() { /* ... */ }

#[tokio::test] async fn exists_returns_digest_when_same_package() { /* ... */ }

#[tokio::test] async fn put_refuses_to_overwrite_different_package() { /* Err(TagConflict) */ }

#[tokio::test] async fn verify_detects_missing_metadata_layer() { /* ... */ }

#[tokio::test] async fn superseded_artifact_uses_suffixed_tag() { /* ... */ }
```

- [ ] **Step 2: Run tests and confirm failure**

- [ ] **Step 3: Implement the OCI target**

Repo path is `<namespace>/<project>`; reference is `Artifact::tag()` or the
superseded tag. Manifest: config blob `{}` with `application/vnd.oci.empty.v1+json`,
layer 0 = package (`application/octet-stream`) with `org.opencontainers.image.title`,
layer 1 = `metadata.json` (`application/json`), and the four
`org.opencontainers.artifact.*` annotations. `put` uploads layers, checks the
existing tag first, and returns the manifest digest.

- [ ] **Step 4: Run tests, then commit**

```bash
cargo test --test oci_target
git add src/targets src/lib.rs tests/oci_target.rs
git commit -m "feat: oci target with immutable tag semantics"
```

---
### Task 13: rsync target

**Files:**
- Create: `src/targets/rsync_target.rs`, `tests/rsync_target.rs`
- Modify: `src/targets/mod.rs`, `src/config.rs`

**Interfaces:**
- Consumes: `Target`, `Artifact`.
- Produces: `RsyncTarget::new(RsyncConfig) -> Result<Self>`, `RsyncAddress` parser for `ssh://` and `rsync://`, argv construction `rsync_args(&self, &Artifact) -> Vec<String>`, sidecar writer.

- [ ] **Step 1: Write failing tests**

```rust
#[test] fn parses_ssh_and_daemon_addresses() { /* ssh://u@h:22/p ; rsync://h/mod */ }

#[test] fn ssh_address_uses_strict_host_key_and_batch_mode() { /* argv contains -e ssh -o BatchMode=yes -o StrictHostKeyChecking=yes */ }

#[test] fn daemon_address_does_not_use_ssh() { /* no -e */ }

#[test] fn upload_goes_to_tmp_then_renames() { /* local dir target: final exists, .tmp gone */ }

#[test] fn sidecar_written_with_sha_and_size() { /* "<sha>  <size>\n" */ }

#[test] fn existing_same_bytes_is_not_rewritten() { /* mtime unchanged */ }

#[test] fn existing_different_bytes_is_an_incident() { /* Err(TargetConflict) */ }
```

- [ ] **Step 2: Run tests and confirm failure**

- [ ] **Step 3: Implement the target**

Build the remote path from `Artifact::rsync_relpath()`, upload to
`<path>.tmp-<run_id>`, then `mv` on the remote (`rsync --remove-source-files` is
not used; a second `rsync` of an empty marker is overkill — use
`rsync -e ssh a b && ssh mv` only for ssh form, and `rsync --temp-dir` +
`--partial-dir` for daemon form). Verify by reading `<basename>.sha256`
sidecar. Skip the whole test group at runtime with a printed notice when the
`rsync` binary is absent.

- [ ] **Step 4: Run tests, then commit**

```bash
cargo test --test rsync_target
git add src/targets/rsync_target.rs src/targets/mod.rs src/config.rs tests/rsync_target.rs
git commit -m "feat: rsync target with atomic upload"
```

---
### Task 14: Incidents, superseded flow, ack/republish

**Files:**
- Create: `src/incident.rs`, `tests/incidents.rs`
- Modify: `src/ledger/mod.rs`, `src/targets/mod.rs`, `src/cli.rs`

**Interfaces:**
- Consumes: `Ledger`, `TargetSet`.
- Produces: `Incident { id, artifact_key, kind, old_sha256, new_sha256, detected_at, state, issue_url }`, `IncidentKind { HashChanged, TagConflict, Unrecoverable, ArchCollision }`, `incident::open(&mut Ledger, …) -> Result<Incident>`, `incident::ack(&mut Ledger, &TargetSet, &str, Option<&str>, bool) -> Result<()>`, `incident::write_alert(&Path, &Incident)`, `incident::open_github_issue(&Incident) -> Result<Option<String>>`.

- [ ] **Step 1: Write failing tests**

```rust
#[tokio::test] async fn hash_change_opens_incident_and_keeps_old_tag() { /* ... */ }

#[tokio::test] async fn new_bytes_published_only_under_superseded_name() { /* ... */ }

#[tokio::test] async fn ack_without_republish_leaves_canonical_tag() { /* ... */ }

#[tokio::test] async fn ack_republish_moves_tag_and_stops_repair() { /* publication.status == superseded */ }

#[tokio::test] async fn duplicate_detection_is_suppressed() { /* second run -> no new incident, issue comment once */ }

#[tokio::test] async fn github_issue_failure_does_not_fail_the_run() { /* Err swallowed, warning event */ }

#[test] fn alert_file_is_json_and_redacted() { /* no token-like strings */ }
```

- [ ] **Step 2: Run tests and confirm failure**

- [ ] **Step 3: Implement incidents**

`open` writes the incident row/event, the alert file, a stderr line, the
`SECURITY_ALERT` GitHub Actions env output, and optionally a GitHub issue via
`POST /repos/{owner}/{repo}/issues` using `GITHUB_TOKEN`. `ack` with
`republish=true` calls `Target::put` for the replacement under the canonical
ref and marks old publications `superseded` only after every target succeeds.

- [ ] **Step 4: Run tests, then commit**

```bash
cargo test --test incidents
git add src/incident.rs src/ledger src/targets src/cli.rs tests/incidents.rs
git commit -m "feat: incident flow with explicit ack and republish"
```

---
### Task 15: Runner — queue, concurrency, limits, fan-out

**Files:**
- Create: `src/runner.rs`, `src/net/ratelimit.rs`, `src/report.rs`, `tests/runner.rs`
- Modify: `src/lib.rs`, `src/cli.rs`

**Interfaces:**
- Consumes: `Source`, `Store`, `Ledger`, `TargetSet`, `Incident`, `ResolvedScope`.
- Produces: `Ctx { config: Config, scope: ResolvedScope, source: Source, store: Store, ledger: tokio::sync::Mutex<Ledger>, targets: TargetSet, rate: Arc<RateLimiter>, run_id: String }`, `RunOpts { max_artifacts: Option<usize>, max_bytes: Option<u64>, order: Order, gc_after: bool, dry_run: bool }`, `Order { VersionDesc, SmallestFirst, LargestFirst }`, `runner::run(&Ctx, RunOpts) -> Result<Summary>`, `Summary` with counts and exit code, `RateLimiter::new(Option<u64>) -> Arc<RateLimiter>`, `RateLimiter::consume(&self, u64).await`. `Ctx` is shared by `verify`, `repair` and `bootstrap`; ledger access is serialised through the mutex.

- [ ] **Step 1: Write failing tests**

```rust
#[tokio::test] async fn queue_order_is_deterministic_and_skips_satisfied() { /* ... */ }

#[tokio::test] async fn limit_bytes_finishes_crossing_artifact_and_stops() { /* cap 1 byte -> exactly 1 artifact, bytes >= cap */ }

#[tokio::test] async fn limit_bytes_zero_fails_with_usage_error() { /* Err, exit 64 */ }

#[tokio::test] async fn partial_target_failure_is_retried_only_for_missing_target() { /* fetch count == 1 across runs */ }

#[tokio::test] async fn interrupted_upload_is_requeued_on_next_run() { /* status uploading -> interrupted -> retried */ }

#[tokio::test] async fn concurrency_never_exceeds_configured_max() { /* instrumented source counts in-flight */ }

#[tokio::test] async fn rate_limiter_stretches_transfer_time() { /* 1 MiB at 1 MiB/s ~ 1s */ }

#[tokio::test] async fn dry_run_publishes_nothing_and_writes_no_events() { /* ... */ }
```

- [ ] **Step 2: Run `cargo test --test runner` and confirm failure**

- [ ] **Step 3: Implement the runner**

Pipeline per artifact: ledger lookup → skip if satisfied → download (store
partial) → verify (already done in download) → commit to store → for each
target: `exists` then `put`, recording a publication per target → `incident` on
tag conflict → optional `gc`. Bounded `Semaphore` for downloads and a second
per target for uploads. The byte budget is checked before starting an artifact
and re-checked after each. `run` writes `runs/<run_id>.ndjson`, updates the
`runs` row with the resolved policy and summary, releases the lease, returns
`Summary`.

- [ ] **Step 4: Run tests, then commit**

```bash
cargo test --test runner
git add src/runner.rs src/net/ratelimit.rs src/report.rs src/lib.rs src/cli.rs tests/runner.rs
git commit -m "feat: resumable runner with limits and fan-out"
```

---
### Task 16: Verify and repair

**Files:**
- Create: `src/verify.rs`, `src/repair.rs`, `tests/verify.rs`, `tests/repair.rs`
- Modify: `src/cli.rs`

**Interfaces:**
- Consumes: `Ledger`, `Store`, `TargetSet`, `Source`.
- Produces: `verify::run(&Ctx, VerifyOpts) -> Result<VerifyReport>`, `repair::run(&Ctx, RepairOpts) -> Result<RepairReport>`, `VerifyOpts { targets: Option<Vec<String>>, deep: bool, sample: Option<usize> }`.

- [ ] **Step 1: Write failing tests**

```rust
#[tokio::test] async fn deep_verify_hashes_local_blobs() { /* corrupt one -> report lists it */ }

#[tokio::test] async fn deep_verify_skips_local_gc_rows() { /* no false corruption */ }

#[tokio::test] async fn verify_checks_every_target_by_default() { /* one missing -> report */ }

#[tokio::test] async fn repair_repushes_from_store_without_download() { /* fetch count 0 */ }

#[tokio::test] async fn repair_refetches_when_store_missing() { /* fetch count 1 */ }

#[tokio::test] async fn repair_marks_unrecoverable_and_incident_when_upstream_gone() { /* ... */ }

#[tokio::test] async fn verify_ignores_current_policy_narrowing() { /* 18.x rows still checked after policy says 19+ */ }
```

- [ ] **Step 2: Run tests and confirm failure**

- [ ] **Step 3: Implement verify and repair**

Verify iterates ledger rows (`--sample` picks deterministic every-nth by key
hash), hashes local blobs when present and not `local_gc`, calls
`Target::verify`. Repair classifies each failure: local corrupt → re-download;
missing remote + local present → re-put; both missing → fetch, else
`Unrecoverable` + incident. Reports are printed and returned with the exit
code.

- [ ] **Step 4: Run tests, then commit**

```bash
cargo test --test verify --test repair
git add src/verify.rs src/repair.rs src/cli.rs tests/verify.rs tests/repair.rs
git commit -m "feat: deep verification and repair"
```

---
### Task 17: Bootstrap import of existing GHCR artifacts

**Files:**
- Create: `src/bootstrap.rs`, `tests/bootstrap.rs`
- Modify: `src/cli.rs`

**Interfaces:**
- Consumes: `Source`, `Ledger`, `TargetSet`, `Artifact`.
- Produces: `bootstrap::run(&Ctx) -> Result<BootstrapReport { imported, skipped, conflicts }>`.

- [ ] **Step 1: Write failing tests**

```rust
#[tokio::test] async fn imports_tag_when_layer_digest_matches_upstream_sha() { /* publication satisfied + imported event */ }

#[tokio::test] async fn skips_already_imported_rows() { /* second run imported == 0 */ }

#[tokio::test] async fn reports_conflict_when_layer_differs() { /* incident, nothing overwritten */ }

#[tokio::test] async fn missing_tag_is_not_an_error() { /* skipped */ }

#[tokio::test] async fn legacy_manifest_with_other_annotations_is_compatible() { /* same layer digest -> imported */ }
```

- [ ] **Step 2: Run tests and confirm failure**

- [ ] **Step 3: Implement bootstrap**

Crawl metadata, build artifacts, and for each enabled OCI target resolve the
tag. If absent, skip. If present, compare the package-layer digest to
`sha256`: equal → record `imported` + satisfied publication; different →
`TagConflict` incident. Never push during bootstrap.

- [ ] **Step 4: Run tests, then commit**

```bash
cargo test --test bootstrap
git add src/bootstrap.rs src/cli.rs tests/bootstrap.rs
git commit -m "feat: bootstrap existing registry artifacts into the ledger"
```

---
### Task 18: CLI wiring, reports, end-to-end test

**Files:**
- Create: `tests/e2e.rs`, `tests/cli.rs`
- Modify: `src/main.rs`, `src/cli.rs`, `src/report.rs`

**Interfaces:**
- Consumes: everything above.
- Produces: working `mirror`, `plan`, `backfill`, `verify`, `repair`, `incidents`, `ledger`, `targets`, `config` commands with spec exit codes; `--json` reports.

- [ ] **Step 1: Write failing CLI tests**

```rust
#[test] fn config_check_prints_redacted_summary() { /* GHCR_TOKEN set -> not present in output */ }

#[test] fn usage_errors_exit_64() { /* --everything --project cinc */ }

#[test] fn lease_busy_exits_4() { /* pre-created live lease */ }

#[test] fn incidents_open_exit_3_only_when_new() { /* second run exits 0 with summary */ }

#[test] fn partial_target_failure_exits_2() { /* ... */ }

#[tokio::test] async fn e2e_mirror_then_noop_then_repair() {
    /* wiremock https index+metadata, libunftp payload, axum registry, local rsync dir:
       run 1 publishes both targets; run 2 downloads 0; break one target; run 3 repairs only it */
}
```

- [ ] **Step 2: Run `cargo test --test cli --test e2e` and confirm failure**

- [ ] **Step 3: Wire commands and reports**

Map errors to exit codes; add `--json` to reports; ensure every command logs
through `tracing` with a JSON option and redacts `Authorization` values.
`backfill` = `mirror` with `--since` cursor from `cursors` table; a completed
capped run writes the next cursor (`last_artifact_key`, `last_version`) so a
redispatch continues instead of restarting.

- [ ] **Step 4: Run the full suite**

Run: `cargo test`
Expected: all tests pass, e2e included.

- [ ] **Step 5: Commit**

```bash
git add src tests
git commit -m "feat: complete cli, reports and end-to-end coverage"
```

---
### Task 19: CI, backfill workflow, documentation

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/workflows/backfill.yml`
- Modify: `README.md`, `.gitignore`, `docs/superpowers/specs/2026-11-24-rust-mirror-design.md` (link the plan)
- Deferred: deleting `cinc-mirror-single.sh` and `fetch-blob.sh` is a follow-up after two clean weeks; this task only marks them deprecated in the README.

**Interfaces:**
- Consumes: the binary.
- Produces: green CI, a scheduled backfill job, operator docs.

- [ ] **Step 1: Add CI**

`ci.yml`: `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`,
`cargo test`, `cargo audit`, release builds for `x86_64-unknown-linux-musl`,
`aarch64-unknown-linux-musl`, `aarch64-apple-darwin` with SHA-256 checksums.

- [ ] **Step 2: Add the backfill workflow**

`on: schedule (every 6 h), repository_dispatch, workflow_dispatch`; permissions
`contents: write`, `packages: write`, `issues: write`; `concurrency: group:
cinc-mirror, cancel-in-progress: false`; steps: checkout, install `rsync`,
`cargo run --release -- mirror --everything --limit 40 --limit-bytes 8GiB
--gc-after --allow-unleased`, then upload `plan-*.json` and `runs/*.ndjson` as
artifacts, then `repository_dispatch` again when the run was capped.

- [ ] **Step 3: Update docs**

README: scripts still present but marked deprecated, config example, `plan`/`verify`/`repair`/`incidents`
usage, ledger branch, privacy note (no package bytes in repo), and the Windows
statement (`.msi` mirrored, installer not provided).

- [ ] **Step 4: Verify YAML and the command surface**

Run: `python3 -c "import yaml,sys; [yaml.safe_load(open(f)) for f in ['.github/workflows/ci.yml','.github/workflows/backfill.yml']]" && cargo run -- --help`
Expected: no YAML errors, all subcommands listed.

- [ ] **Step 5: Commit**

```bash
git add .github README.md .gitignore docs
git commit -m "ci: test, release and scheduled backfill workflows"
```

---

## Self-Review Notes

- Spec coverage: every spec section maps to a task — config/policies (1–2), identity (3), verification (4, 7), source and plan (5–6), store (8), ledger and git (9–10), OCI (11–12), rsync (13), incidents (14), runner (15), verify/repair (16), bootstrap (17), CLI (18), CI/rollout (19).
- The spec's `--set` grammar, iteration suffix, arch map and window scope land in Tasks 1–3 and 18, with tests.
- Deliberate omission: no task implements `ledger gc`/`compact` beyond what Task 10's snapshot test covers; the command surface in Task 18 includes them and they reuse `LedgerStore`.
