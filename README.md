# Cinc Mirror

A secure, immutable mirror of Cinc packages from the official FTP site to GitHub Container Registry (GHCR).

## Overview

This repository contains scripts to automatically mirror Cinc (Chef Infra) packages from the official FTP distribution site to GHCR. The mirror implements strict immutability policies to ensure package integrity and detect potential security incidents.

## Features

- 🔒 **Immutable Mirroring**: Once mirrored, files are never updated
- 🚨 **Security Monitoring**: SHA256 checksum verification and change detection
- 🤖 **Automated**: GitHub Actions for daily mirroring
- 📦 **OCI Artifacts**: Packages stored as OCI artifacts in GHCR
- 🛡️ **Incident Response**: Tools for investigating security alerts

## Quick Start

1. **Setup the repository:**
   ```bash
   ./setup-github-actions.sh
   ```

2. **Configure your settings:**
   Edit `config.env` with your GitHub username/organization

3. **Push to GitHub:**
   ```bash
   git add .
   git commit -m "Initial commit"
   git push origin main
   ```

4. **The mirror will run automatically** every day at 2 AM UTC

## Files

- `mirror-cinc.sh` - Main mirroring script
- `security-incident-response.sh` - Security incident investigation tools
- `setup-github-actions.sh` - Setup script for GitHub Actions
- `config.env` - Configuration template
- `.github/workflows/mirror-cinc.yml` - GitHub Actions workflow

## Security

This mirror implements a **strict immutability policy**:

- Files are never overwritten once mirrored
- SHA256 checksums ensure file integrity
- Changes to source files trigger security alerts
- Manual review required for any source changes

## Documentation

For detailed documentation, see:
- [FTP to GHCR Mirroring Guide](FTP_TO_GHCR_README.md)

## License

This mirror setup is provided as-is for educational and backup purposes.