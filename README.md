# CINC Mirror

![CINC Mirror Logo](cinc-mirror.jpeg)

This repository provides a mirror for CINC packages.
Metadata and packages will be retrieved from downloads.cinc.sh / ftp.osuosl.org and stored on GHCR as OCI blobs. Kind of the same homebrew does.


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
- Windows is not supported

## Scripts

- `install.sh` - Main installation script, hosted at https://cinc-mirror.github.io/install.sh
- `install-debian13-arm.sh` - Debian 13 ARM-specific installer (just for testing)
- `cinc-mirror-single.sh` - Single package mirror script
- `fetch-blob.sh` - Blob fetching example using curl (example how to download a blob by sha256 hash). If you are serious, just get [ORAS](https://oras.land/)

## Mirroring

```bash
# mirror
PROJECT="cinc-workstation" PLATFORM_FILTER="ubuntu" VERSIONS="25.*" ./cinc-mirror-single.sh

# test
docker run --rm -it ubuntu bash -c "apt-get update && apt-get install -y curl && curl -L https://cinc-mirror.github.io/install.sh | bash -s -- -P cinc-workstation" 

```

## GitHub Actions (not yet)

## Why?

Proof of concept. OSUOSL is doing an awesome job, just their connection with Cogent is terrible slow. In Germany you get speeds below 1Mbit/s which sucks on CI/CD or mass rollouts. Why not offload such traffic to Microsoft GitHub(TM) ;)

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.
