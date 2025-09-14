# Cinc FTP Mirror to GHCR

This script mirrors Cinc packages from the official FTP site to GitHub Container Registry (GHCR), similar to how Homebrew hosts binaries.

## Features

- **Immutable Mirroring**: Once mirrored, files are never updated - changes trigger security alerts
- Mirrors Cinc packages from `ftps://downloads.cinc.sh/pub/cinc/files/stable/cinc/`
- Filters versions 18 and above (configurable)
- Only processes Debian and Ubuntu distributions
- Downloads all package files and metadata
- Uploads files to GHCR as OCI artifacts
- **Security Monitoring**: SHA256 checksum verification and integrity monitoring
- **Incident Response**: Automated alerts for source file changes or local corruption

## Security & Immutability Policy

This mirror implements a **strict immutability policy** for security:

### Core Principles
- **Immutable Files**: Once a file is mirrored to GHCR, it is never updated or overwritten
- **Checksum Verification**: All files are verified using SHA256 checksums
- **Change Detection**: Any changes to source files trigger security alerts
- **Integrity Monitoring**: Local file corruption is detected and reported

### Security Events
- **Remote Changes**: If FTP source files change, security alerts are triggered
- **Local Corruption**: If local files are corrupted, integrity violations are logged
- **Manual Review**: All security events require manual investigation before any action

### Why Immutability Matters
- **Supply Chain Security**: Prevents malicious package updates
- **Reproducible Builds**: Ensures consistent artifacts over time
- **Audit Trail**: Complete history of all file states
- **Incident Response**: Clear detection of unauthorized changes

## Prerequisites

1. **GitHub CLI (`gh`)**: Install from https://cli.github.com/
2. **ORAS**: Install from https://oras.land/
3. **curl**: Usually pre-installed on most systems
4. **Docker or Podman**: For registry authentication
5. **SHA256 tools**: `sha256sum` or `shasum` for checksum verification

## Setup

1. **Authenticate with GitHub**:
   ```bash
   gh auth login
   ```

2. **Set environment variables**:
   ```bash
   export GHCR_ORG="your-github-username-or-org"
    export GHCR_REPO="cinc-mirror"  # Optional, defaults to "cinc-mirror"
   export GITHUB_TOKEN="your-github-personal-access-token"
   export MIRROR_DIR="./cinc-mirror"  # Optional, defaults to "./cinc-mirror"
   ```

3. **Make the script executable**:
   ```bash
   chmod +x mirror-cinc.sh
   ```

## Usage

### Local Usage

#### Full Mirror
```bash
./mirror-cinc.sh
```

#### Mirror Specific Version
```bash
# Edit the script to modify the version filtering logic
MIN_VERSION="18.8.0" ./mirror-cinc.sh
```

#### Dry Run (Download Only)
```bash
# Comment out the upload_to_ghcr calls in the script for testing
./mirror-cinc.sh
```

### GitHub Actions Setup

For automated periodic mirroring, use GitHub Actions:

1. **Setup the repository:**
   ```bash
   ./setup-github-actions.sh
   ```

2. **Configure your settings:**
   Edit `config.env` with your GitHub username/organization

3. **Push to GitHub:**
   ```bash
   git add .
   git commit -m "Add Cinc mirror with GitHub Actions"
   git push origin main
   ```

4. **The workflow will:**
   - Run automatically every day at 2 AM UTC
   - Only sync changed/new files (incremental updates)
   - Upload logs and reports as artifacts
   - Create releases with mirror statistics

#### Manual Trigger
You can also trigger the workflow manually:
- Go to the Actions tab in your GitHub repository
- Select "Mirror Cinc Packages to GHCR"
- Click "Run workflow"
- Optionally specify minimum version or force full sync

## Configuration

The script can be configured via environment variables:

- `GHCR_ORG`: Your GitHub organization or username (required)
- `GHCR_REPO`: Repository name for packages (default: "cinc-mirror")
- `MIRROR_DIR`: Local directory for downloaded files (default: "./cinc-mirror")
- `MIN_VERSION`: Minimum version to mirror (default: "18")

## FTPS Structure

The script processes this structure:
```
ftps://downloads.cinc.sh/pub/cinc/files/stable/cinc/
├── 18.0.169/
│   ├── debian/
│   │   ├── 11/
│   │   │   ├── cinc_18.0.169-1_amd64.deb
│   │   │   ├── cinc_18.0.169-1_amd64.deb.metadata.json
│   │   │   ├── cinc_18.0.169-1_arm64.deb
│   │   │   └── cinc_18.0.169-1_arm64.deb.metadata.json
│   │   └── 12/
│   └── ubuntu/
│       ├── 18.04/
│       └── 20.04/
└── 18.8.11/
    └── ...
```

## GHCR Structure

Files are uploaded to GHCR with this structure:
```
ghcr.io/{org}/{repo}:{version}/{distro}/{distro_version}/{filename}
```

Example:
```
ghcr.io/myorg/cinc-mirror:18.8.11/debian/12/cinc_18.8.11-1_amd64.deb
```

## Security Incident Response

When security alerts are triggered, use the incident response script:

```bash
# Show all security information
./security-incident-response.sh full

# Verify specific file integrity
./security-incident-response.sh verify 18.8.11/debian/12/cinc_18.8.11-1_amd64.deb

# Compare file with remote source
./security-incident-response.sh compare 18.8.11/debian/12/cinc_18.8.11-1_amd64.deb

# Create incident report
./security-incident-response.sh report
```

### Response Workflow
1. **Alert Triggered**: GitHub Actions workflow fails with security alert
2. **Investigation**: Use the response script to gather information
3. **Verification**: Manually verify source legitimacy
4. **Decision**: Accept changes, reject changes, or investigate further
5. **Documentation**: Create incident report for audit trail

### Manual Override
If legitimate changes need to be accepted:
```bash
FORCE_FULL_SYNC=true ./mirror-cinc.sh
```

## Troubleshooting

### Authentication Issues
- Ensure `GITHUB_TOKEN` has `write:packages` permission
- Verify `gh auth status` shows authenticated state
- Check that Docker/Podman can authenticate with GHCR

### FTP Connection Issues
- The FTP site may have rate limiting
- Some versions may be temporarily unavailable
- Network connectivity issues

### ORAS Upload Issues
- Ensure ORAS is properly installed
- Check GHCR repository permissions
- Verify artifact size limits (GHCR has limits on individual artifact sizes)

### Security & Integrity Issues
- **Checksum mismatches**: Verify SHA256 tools are installed
- **Permission errors**: Ensure write access to mirror directory
- **False positives**: Check network connectivity during integrity checks

## License

This script is provided as-is for mirroring Cinc packages. Please respect the terms of service of both the FTP site and GitHub.