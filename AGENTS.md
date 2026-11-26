# AGENTS.md

## Where the pieces live

This repository mirrors artifacts and owns the ledger. The public website and
the download installers are a separate repository:

- **website repository**: `cinc-mirror.github.io`
  (https://github.com/cinc-mirror/cinc-mirror.github.io)

`install.sh` and `install.ps1`, their output text, and the install instructions
on the site are edited **there**, not here. A local clone usually sits next to
this checkout (`../cinc-mirror.github.io`).

The GHCR package path the installers use is `ghcr.io/rmoriz/cinc-mirror/<project>`;
this repository defines it in `mirror.ci.toml` (`namespace`).
