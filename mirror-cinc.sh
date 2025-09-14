#!/bin/bash

# Cinc FTP Mirror to GHCR Script
# Mirrors Cinc packages from FTP to GitHub Container Registry

set -e

# Load configuration from config.env if it exists
if [ -f "config.env" ]; then
    source config.env
fi

# Configuration (with defaults)
FTP_BASE="${FTP_BASE:-ftp://downloads.cinc.sh/pub/cinc/files/stable/cinc}"
GHCR_ORG="${GHCR_ORG:-your-github-org}"  # Set your GitHub org/username
GHCR_REPO="${GHCR_REPO:-cinc-packages}"  # Repository name for packages
MIRROR_DIR="${MIRROR_DIR:-./cinc-mirror}"
MIN_VERSION="${MIN_VERSION:-18}"  # Minimum version to mirror

# Parse TARGET_DISTROS if it's a string, otherwise use array
if [ -n "$TARGET_DISTROS" ] && [ "${TARGET_DISTROS:0:1}" != "(" ]; then
    # TARGET_DISTROS is a string, convert to array
    IFS=' ' read -r -a TARGET_DISTROS_ARRAY <<< "$TARGET_DISTROS"
else
    # Use default array
    TARGET_DISTROS_ARRAY=("debian" "ubuntu")
fi

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Get list of versions from FTP (logs -> stderr, data -> stdout)
get_versions() {
    log_info "Fetching available versions from FTP..." >&2
    local raw
    raw=$(curl -s -l "$FTP_BASE/" | sort -V) || return 1
    local filtered=()

    # Only include specific versions for stability
    local allowed_versions=("18.8.9" "18.8.11")

    for v in $raw; do
        if [[ " ${allowed_versions[@]} " =~ " $v " ]]; then
            filtered+=("$v")
        fi
    done
    echo "${filtered[@]}"
}

# Get distros for a version
get_distros() {
    local version="$1"
    local pattern
    pattern="$(IFS=\|; echo "${TARGET_DISTROS_ARRAY[*]}")"
    curl -s -l "$FTP_BASE/$version/" | grep -E "^(${pattern})$" || true
}

# Get distro versions for a distro
get_distro_versions() {
    local version="$1"
    local distro="$2"
    curl -s -l "$FTP_BASE/$version/$distro/"
}

# Check dependencies
check_dependencies() {
    local missing_deps=()

    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    fi

    if ! command -v gh &> /dev/null; then
        missing_deps+=("gh (GitHub CLI)")
    fi

    if ! command -v oras &> /dev/null; then
        missing_deps+=("oras (OCI Registry as Storage)")
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Please install missing dependencies and try again."
        exit 1
    fi
}

# Authenticate with GHCR
authenticate_ghcr() {
    log_info "Authenticating with GitHub Container Registry..."

    if ! gh auth status &> /dev/null; then
        log_error "Not authenticated with GitHub CLI. Please run 'gh auth login' first."
        exit 1
    fi

    # Login to GHCR
    echo $GITHUB_TOKEN | docker login ghcr.io -u $GHCR_ORG --password-stdin 2>/dev/null || {
        log_warn "Docker login failed, trying podman..."
        echo $GITHUB_TOKEN | podman login ghcr.io -u $GHCR_ORG --password-stdin 2>/dev/null || {
            log_error "Failed to authenticate with container registry. Please ensure GITHUB_TOKEN is set."
            exit 1
        }
    }
}

# Download file from FTP
download_file() {
    local ftp_path="$1"
    local local_path="$2"

    mkdir -p "$(dirname "$local_path")"

    if curl -s "$ftp_path" -o "$local_path"; then
        log_info "Downloaded: $ftp_path -> $local_path"
        return 0
    else
        log_error "Failed to download: $ftp_path"
        return 1
    fi
}

# Upload file to GHCR using ORAS
upload_to_ghcr() {
    local local_path="$1"
    local remote_path="$2"

    local filename=$(basename "$local_path")
    # Sanitize the remote path for use as a tag (replace slashes with hyphens)
    local sanitized_path=$(echo "$remote_path" | tr '/' '-')
    local oci_ref="ghcr.io/$GHCR_ORG/$GHCR_REPO:$sanitized_path"

    log_info "Uploading $filename to $oci_ref"

    # Create a temporary directory for ORAS
    local temp_dir=$(mktemp -d)
    cp "$local_path" "$temp_dir/$filename"

    # Create a simple artifact manifest
    cat > "$temp_dir/artifact.yaml" << EOF
{
  "mediaType": "application/vnd.oci.artifact.manifest.v1+json",
  "artifactType": "application/octet-stream",
  "blobs": [],
  "annotations": {
    "org.opencontainers.artifact.title": "$filename",
    "org.opencontainers.artifact.description": "Cinc package $filename"
  }
}
EOF

    if oras push "$oci_ref" \
        --artifact-type "application/octet-stream" \
        --annotation "org.opencontainers.artifact.title=$filename" \
        --disable-path-validation \
        "$temp_dir/$filename"; then
        log_info "Successfully uploaded $filename to GHCR"
        rm -rf "$temp_dir"
        return 0
    else
        log_error "Failed to upload $filename to GHCR - aborting workflow"
        rm -rf "$temp_dir"
        exit 1  # Fail fast on upload errors
    fi
}

# Mirror a specific version
mirror_version() {
    local version="$1"
    log_info "Mirroring version: $version"

    local distros
    distros=$(get_distros "$version")

    for distro in $distros; do
        log_info "Processing distro: $distro"

        local distro_versions
        distro_versions=$(get_distro_versions "$version" "$distro")

        for distro_version in $distro_versions; do
            log_info "Processing $distro $distro_version"

            local ftp_dir="$FTP_BASE/$version/$distro/$distro_version"
            local files
            files=$(curl -s -l "$ftp_dir/")

            for file in $files; do
                local ftp_path="$ftp_dir/$file"
                local local_path="$MIRROR_DIR/$version/$distro/$distro_version/$file"
                local remote_path="$version/$distro/$distro_version/$file"

                # Download file
                if download_file "$ftp_path" "$local_path"; then
                    # Upload to GHCR
                    upload_to_ghcr "$local_path" "$remote_path"
                fi
            done
        done
    done
}

# Checksum storage and verification
CHECKSUM_FILE="$MIRROR_DIR/.checksums.sha256"
INTEGRITY_LOG="$MIRROR_DIR/.integrity.log"

# Initialize checksum storage
init_checksum_storage() {
    touch "$CHECKSUM_FILE"
    touch "$INTEGRITY_LOG"
}

# Calculate SHA256 checksum of file
calculate_checksum() {
    local file_path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "$file_path" | awk '{print $1}'
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "$file_path" | awk '{print $1}'
    else
        log_error "No SHA256 tool available"
        return 1
    fi
}

# Store checksum for a file
store_checksum() {
    local file_path="$1"
    local remote_path="$2"
    local checksum

    checksum=$(calculate_checksum "$file_path")
    if [ $? -eq 0 ] && [ -n "$checksum" ]; then
        # Store in format: checksum filepath remote_path timestamp
        echo "$checksum $file_path $remote_path $(date -u +%Y-%m-%dT%H:%M:%SZ)" >> "$CHECKSUM_FILE"
        log_info "Stored checksum for: $remote_path"
        return 0
    else
        log_error "Failed to calculate checksum for: $file_path"
        return 1
    fi
}

# Verify file integrity and check for changes
verify_file_integrity() {
    local local_path="$1"
    local remote_path="$2"

    # Check if file exists locally
    if [ ! -f "$local_path" ]; then
        return 0  # File doesn't exist, can be downloaded
    fi

    # Get stored checksum
    local stored_checksum
    stored_checksum=$(grep "$remote_path" "$CHECKSUM_FILE" | tail -1 | awk '{print $1}')

    if [ -z "$stored_checksum" ]; then
        log_warn "No stored checksum found for: $remote_path"
        return 0  # No checksum stored, allow download
    fi

    # Calculate current checksum
    local current_checksum
    current_checksum=$(calculate_checksum "$local_path")

    if [ "$stored_checksum" != "$current_checksum" ]; then
        log_error "LOCAL FILE INTEGRITY VIOLATION: $remote_path"
        log_error "Stored checksum: $stored_checksum"
        log_error "Current checksum: $current_checksum"
        echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) INTEGRITY_VIOLATION $remote_path $stored_checksum $current_checksum" >> "$INTEGRITY_LOG"
        return 2  # Integrity violation
    fi

    # Check if remote file has changed
    local remote_checksum
    remote_checksum=$(curl -s -I "$FTP_BASE/$remote_path" | grep -i "content-length" | awk '{print $2}' | tr -d '\r')

    if [ -n "$remote_checksum" ]; then
        local local_size
        local_size=$(stat -f%z "$local_path" 2>/dev/null || stat -c%s "$local_path" 2>/dev/null)

        if [ "$remote_checksum" != "$local_size" ]; then
            log_error "REMOTE FILE CHANGE DETECTED: $remote_path"
            log_error "Local size: $local_size"
            log_error "Remote size: $remote_checksum"
            echo "$(date -u +%Y-%m-%dT%H:%M:%SZ) REMOTE_CHANGE $remote_path $local_size $remote_checksum" >> "$INTEGRITY_LOG"

            # Trigger security alert
            trigger_security_alert "$remote_path" "remote_change" "$local_size" "$remote_checksum"
            return 3  # Remote change detected
        fi
    fi

    log_info "File integrity verified: $remote_path"
    return 1  # File exists and is unchanged
}

# Trigger security alert
trigger_security_alert() {
    local file_path="$1"
    local alert_type="$2"
    local local_value="$3"
    local remote_value="$4"

    log_error "🚨 SECURITY ALERT: $alert_type detected for $file_path"

    # Create alert file for GitHub Actions
    local alert_file="$MIRROR_DIR/.security-alert"
    {
        echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
        echo "type: $alert_type"
        echo "file: $file_path"
        echo "local_value: $local_value"
        echo "remote_value: $remote_value"
        echo "action_required: IMMEDIATE_SECURITY_REVIEW"
    } > "$alert_file"

    # Set GitHub Actions output
    echo "SECURITY_ALERT=true" >> $GITHUB_ENV
    echo "ALERT_TYPE=$alert_type" >> $GITHUB_ENV
    echo "ALERT_FILE=$file_path" >> $GITHUB_ENV
}

# Check if file should be processed (immutable policy)
should_process_file() {
    local local_path="$1"
    local remote_path="$2"

    # Always verify integrity first
    verify_file_integrity "$local_path" "$remote_path"
    local integrity_result=$?

    case $integrity_result in
        0)
            # File doesn't exist locally, can be downloaded
            return 0
            ;;
        1)
            # File exists and is verified, skip processing
            return 1
            ;;
        2)
            # Local integrity violation - this is critical
            log_error "CRITICAL: Local file corruption detected: $remote_path"
            return 2
            ;;
        3)
            # Remote change detected - security incident
            log_error "CRITICAL: Remote file change detected: $remote_path"
            return 3
            ;;
        *)
            log_error "Unknown integrity check result: $integrity_result"
            return 1
            ;;
    esac
}

# Main function
main() {
    log_info "Starting Cinc FTP to GHCR mirror process"

    # Create logs directory
    mkdir -p logs
    exec > >(tee -a "logs/mirror-$(date +%Y%m%d-%H%M%S).log") 2>&1

    # Check dependencies
    check_dependencies

    # Authenticate with GHCR
    authenticate_ghcr

    # Create mirror directory
    mkdir -p "$MIRROR_DIR"

    # Initialize checksum storage
    init_checksum_storage

    # Get versions to mirror
    local versions
    versions=$(get_versions)

    if [ -z "$versions" ]; then
        log_error "No versions found to mirror"
        exit 1
    fi

    log_info "Found versions to mirror: $versions"

    # Track statistics
    total_files=0
    new_files=0
    skipped_files=0
    integrity_violations=0
    security_alerts=0

    # Mirror each version
    for version in $versions; do
        log_info "Processing version: $version"

        local distros
        distros=$(get_distros "$version")

        for distro in $distros; do
            log_info "Processing distro: $distro"

            local distro_versions
            distro_versions=$(get_distro_versions "$version" "$distro")

            for distro_version in $distro_versions; do
                log_info "Processing $distro $distro_version"

                local ftp_dir="$FTP_BASE/$version/$distro/$distro_version"
                local files
                files=$(curl -s -l "$ftp_dir/")

                if [ -z "$files" ]; then
                    log_warn "No files found in: $ftp_dir"
                    continue
                fi

                for file in $files; do
                    # Skip if file is empty
                    [ -z "$file" ] && continue

                    # Skip symlinks (files containing ->)
                    if [[ "$file" == *' -> '* ]]; then
                        continue
                    fi

                    # Skip metadata files for now (we'll handle them separately)
                    if [[ "$file" == *.metadata.json ]]; then
                        continue
                    fi

                    total_files=$((total_files + 1))
                    local ftp_path="$ftp_dir/$file"
                    local local_path="$MIRROR_DIR/$version/$distro/$distro_version/$file"
                    local remote_path="$version/$distro/$distro_version/$file"

                    # Check file integrity and determine action
                    should_process_file "$local_path" "$remote_path"
                    local process_result=$?

                    case $process_result in
                        0)
                            # File doesn't exist, download and store
                            log_info "Downloading new file: $remote_path"
                            if download_file "$ftp_path" "$local_path"; then
                                # Store checksum before uploading
                                if store_checksum "$local_path" "$remote_path"; then
                    # Upload to GHCR
                    log_info "About to call upload_to_ghcr for: $remote_path"
                    if upload_to_ghcr "$local_path" "$remote_path"; then
                        log_info "Upload function returned successfully"
                        ((new_files++))
                        log_info "Successfully mirrored: $remote_path"
                    else
                        log_error "Failed to upload to GHCR: $remote_path"
                    fi
                    log_info "Finished processing file: $file"
                                else
                                    log_error "Failed to store checksum for: $remote_path"
                                fi
                            else
                                log_error "Failed to download: $ftp_path"
                            fi
                            ;;
                        1)
                            # File exists and verified, skip
                            ((skipped_files++))
                            ;;
                        2)
                            # Local integrity violation
                            ((integrity_violations++))
                            log_error "SKIPPING FILE DUE TO LOCAL INTEGRITY VIOLATION: $remote_path"
                            ;;
                        3)
                            # Remote change detected - security incident
                            ((security_alerts++))
                            log_error "SECURITY INCIDENT: Remote change detected for immutable file: $remote_path"
                            ;;
                        *)
                            log_error "Unknown processing result ($process_result) for: $remote_path"
                            ;;
                    esac
                done
            done
        done
    done

    # Log final statistics
    log_info "Mirror process completed"
    log_info "Statistics:"
    log_info "  - Total files processed: $total_files"
    log_info "  - New files mirrored: $new_files"
    log_info "  - Files skipped (already exist): $skipped_files"
    log_info "  - Integrity violations detected: $integrity_violations"
    log_info "  - Security alerts triggered: $security_alerts"

    # Security summary
    if [ $security_alerts -gt 0 ]; then
        log_error "🚨 SECURITY INCIDENTS DETECTED: $security_alerts files have changed on the source!"
        log_error "These files have been left unchanged in the mirror for security review."
    fi

    if [ $integrity_violations -gt 0 ]; then
        log_error "⚠️  INTEGRITY VIOLATIONS DETECTED: $integrity_violations local files are corrupted!"
        log_error "These files should be investigated and potentially re-downloaded."
    fi

    # Save statistics for GitHub Actions
    echo "MIRROR_STATS_TOTAL=$total_files" >> $GITHUB_ENV
    echo "MIRROR_STATS_NEW=$new_files" >> $GITHUB_ENV
    echo "MIRROR_STATS_SKIPPED=$skipped_files" >> $GITHUB_ENV
    echo "MIRROR_STATS_INTEGRITY_VIOLATIONS=$integrity_violations" >> $GITHUB_ENV
    echo "MIRROR_STATS_SECURITY_ALERTS=$security_alerts" >> $GITHUB_ENV
}

# Run main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi