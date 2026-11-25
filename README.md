# CINC Mirror

![CINC Mirror Logo](cinc-mirror.jpeg)

This repository mirrors CINC packages. Metadata is read from downloads.cinc.sh /
ftp.osuosl.org; every package is verified against its published hash and then
published to GHCR as OCI artifacts, and optionally to an rsync target — roughly
what Homebrew does for bottles.

The mirror is a single Rust binary, built from this repository. It replaces the
former shell + ORAS + curl scripts: the crawl, download, verification,
publication and repair paths are one program, and every observation is recorded
in a durable ledger committed back to this repository.

## Trademark / Remarks

This project is neither affiliated nor approved by Progress Chef and/or the Cinc community project. Use at your own risk. Feel free to open issues but don't expect a SLA. Service may stop/break at any time. Solaris? AIX? 10 year old OS versions? Sorry, won't work.

## Usage/Installation

To install the mirrored CINC packages, run the following command:

```bash
curl -sSL https://cinc-mirror.github.io/install.sh | bash
```

The actual script is at https://github.com/cinc-mirror/cinc-mirror.github.io and should replace https://omnitruck.cinc.sh/install.sh - metadata is still retreived from cinc.sh, only packages are retrieved from ghcr.

**Requirements:**
- curl must be installed
- Only supports CINC 18+
- The installer is POSIX-only; Windows has no installer here. The mirrored
  `.msi` packages can be downloaded and installed directly (see
  [Windows](#windows)).

## Build from source

Requirements: Rust 1.89 or newer. `rsync` is needed only when an rsync target is
configured; OCI-only operation does not use it.

```bash
cargo build --release
./target/release/cinc-mirror --help
```

The test suite runs without network access:

```bash
cargo test
```

## Configuration

The mirror reads `mirror.toml` from the working directory, or the file given
with `--config`. The file is git-ignored and should be mode `0600`. It never
contains credentials: a target names an auth mode and the secret is read from
the environment, Docker config or a key file at use time.

A commented, ready-to-edit example that publishes to GHCR is in
`mirror.toml.example`; copy it to `mirror.toml`.

Every project is an explicit policy. Version bounds, globs, platforms, platform
versions and architectures narrow what is crawled; `all_versions` and `"*"`
widen it.

```toml
state_dir = "~/.local/state/cinc-mirror"
concurrency = 4
upload_concurrency = 2
max_bandwidth = "0"                 # e.g. "40MiB/s"; 0 = unlimited
transport = ["ftp", "ftps", "https"] # payload ladder, in order
metadata_transport = "https"
min_version = "18"

[[projects]]
id = "cinc-stable"
project = "cinc"
channel = "stable"
min_version = "19.0.0"
platforms = ["debian", "ubuntu", "el"]
arches = ["amd64", "arm64"]

[projects.platform_versions]
debian = ["12", "13"]

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
namespace = "<owner>/cinc-mirror"
auth = "docker"

[[targets]]
name = "rsync"
kind = "rsync"
url = "ssh://mirror@backup.example.org/srv/cinc-mirror"
auth = "ssh-key"
identity_file = "~/.ssh/id_ed25519"
```

`mirror.ci.toml` is the committed configuration the scheduled workflow uses; it
mirrors all six upstream projects at every version.

When adding a new project, the GHCR package is private by default. Make it
public once under **Package settings → Change package visibility**, e.g.
https://github.com/users/rmoriz/packages/container/package/cinc-mirror%2Fcinc-workstation

## Commands

Run `cinc-mirror <command> --help` for the full flag set. Global options are
`--config <FILE>`, `--allow-unleased` and `--log-format text|json`.

- `plan` — estimate a run without downloading package bytes:
  `cinc-mirror plan --everything --json`
- `mirror` — crawl upstream and publish every new artifact:
  `cinc-mirror mirror --everything --limit 50 --gc-after`
- `backfill` — fill historical versions that are not mirrored yet:
  `cinc-mirror backfill --everything --limit 50`
- `verify` — re-hash and compare known publications (a deterministic sample or
  the local store): `cinc-mirror verify --sample 200` or
  `cinc-mirror verify --deep`
- `repair` — re-publish or re-fetch artifacts that need repair:
  `cinc-mirror repair --target rsync`
- `incidents` — inspect and acknowledge integrity incidents:
  `cinc-mirror incidents list`, `cinc-mirror incidents show <id>`,
  `cinc-mirror incidents ack <id> [--republish]`
- `ledger bootstrap` — rebuild ledger rows from an existing mirror:
  `cinc-mirror ledger bootstrap`
- `ledger pull` — fetch the ledger branch: `cinc-mirror ledger pull`
- `ledger push` — push the ledger branch: `cinc-mirror ledger push`
- `ledger compact` — fold event segments into a snapshot:
  `cinc-mirror ledger compact`
- `ledger gc` — garbage-collect superseded ledger data:
  `cinc-mirror ledger gc`
- `ledger export` — export ledger rows: `cinc-mirror ledger export`
- `targets` — inspect configured targets: `cinc-mirror targets list`,
  `cinc-mirror targets check`
- `config check` — validate the configuration without network access:
  `cinc-mirror config check` (add `--probe` to test auth and connectivity)

## The ledger branch

The ledger lives on the `ledger` branch of this repository and is cloned into
`<state_dir>/ledger-repo`. It records what was observed, published, verified,
repaired and reported — hashes, sizes, references, events and incidents. It
never contains package bytes. Do not hand-edit it; the binary commits and pushes
each run.

Because the ledger also persists the backfill cursor, an interrupted or bounded
`backfill` run continues where it stopped on the next invocation; a plain
`mirror` needs no cursor, because its rows already tell it what is satisfied.

## Immutability policy

A publication is immutable. If the same upstream path later presents a different
SHA-256, the mirror does not overwrite it: it records an incident (and files a
GitHub issue when a token and repository are configured) and keeps the old
bytes. Nothing is replaced until an operator
acknowledges the incident with `cinc-mirror incidents ack <id>`. Adding
`--republish` moves the old publication aside — on rsync it is kept as
`<basename>.superseded-<sha12>`, in the registry under a superseded tag — and
then publishes the replacement under the canonical name.

## CI and scheduled backfill

`.github/workflows/ci.yml` runs formatting, clippy, tests on Linux and macOS, the
MSRV build, `cargo audit`, rustdoc and an offline test run. It never touches the
live upstream, a registry or GHCR. After the test matrix passes it builds
release binaries for Linux amd64/arm64 and macOS arm64. On pushes to `main` it
publishes them, plus `SHA256SUMS`, on the rolling `latest` GitHub Release,
replacing the previous build so only the current commit's binaries remain.

`.github/workflows/backfill.yml` is the only workflow that talks to the live
CINC upstream and GHCR. It runs every six hours, and can also be started with
`workflow_dispatch` or a `backfill` `repository_dispatch`. Each run is bounded
(`--limit 50 --limit-bytes 8GiB`); `mirror` resumes through the ledger — the
next run classifies already-published artifacts as satisfied and continues
with what is left, so the workflow does not redispatch itself. (The resume
cursor applies to `backfill` mode, which this workflow does not use.) The
concurrency group `cinc-mirror` serialises runs instead of cancelling one
mid-publication.

## Windows

Windows packages (`.msi`) are mirrored like every other platform. This
repository does not provide a Windows installer; the POSIX installer remains
POSIX-only. Use the mirrored `.msi` directly.

## Why?

Proof of concept. OSUOSL is doing an awesome job, just their connection with Cogent is terrible slow. In Germany you get speeds below 1Mbit/s which sucks on CI/CD or mass rollouts. Why not offload such traffic to Microsoft GitHub(TM) ;)

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
