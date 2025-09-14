# CINC Mirror

![CINC Mirror Logo](cinc-mirror.jpeg)

This repository provides a mirror for CINC packages and installation scripts.

## Installation

To install CINC, run the following command:

```bash
curl -sSL https://cinc-mirror.github.io/install.sh | bash
```

**Requirements:**
- curl must be installed
- Only supports CINC 18+
- Windows is not supported

## Scripts

- `install.sh` - Main installation script, hosted at https://cinc-mirror.github.io/install.sh
- `install-debian13-arm.sh` - Debian 13 ARM-specific installer (just for testing)
- `cinc-mirror-single.sh` - Single package mirror script
- `fetch-blob.sh` - Blob fetching example using curl (example how to download a blob by sha256 hash). If you are serious, just get [ORAS](https://oras.land/)

## GitHub Actions (not yet)

## License

This project is licensed under the Apache License 2.0 - see the [LICENSE](LICENSE) file for details.