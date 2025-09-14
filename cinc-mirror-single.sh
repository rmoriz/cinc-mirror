#!/bin/bash

# Single Script Cinc Mirror Solution
# Mirrors Cinc packages from FTP to GitHub Container Registry using metadata.json files

set -e

# Configuration with defaults
CHANNEL="${CHANNEL:-stable}"
PROJECT="${PROJECT:-cinc}"
VERSIONS="${VERSIONS:-18.8.11}"
FTP_BASE="ftp.osuosl.org"
TARGET_REGISTRY="ghcr.io"
TARGET_ORG="${TARGET_ORG:-rmoriz}"
TARGET_REPO="${TARGET_REPO:-cinc-mirror}"

# For prototyping - limit to debian/13
PLATFORM_FILTER="${PLATFORM_FILTER:-debian}"
PLATFORM_VERSION_FILTER="${PLATFORM_VERSION_FILTER:-13}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1" >&2
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Check dependencies
check_dependencies() {
    local missing_deps=()

    if ! command -v curl &> /dev/null; then
        missing_deps+=("curl")
    fi

    if ! command -v oras &> /dev/null; then
        missing_deps+=("oras")
    fi

    if [ ${#missing_deps[@]} -ne 0 ]; then
        log_error "Missing dependencies: ${missing_deps[*]}"
        log_info "Please install missing dependencies and try again."
        exit 1
    fi
}

# Extract basename and sha256 from metadata.json using shell methods
parse_metadata() {
    local metadata_file="$1"
    local basename_line sha256_line
    
    # Extract basename (look for "basename": "filename")
    basename_line=$(grep '"basename"' "$metadata_file" | head -1)
    if [[ $basename_line =~ \"basename\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]]; then
        echo "basename=${BASH_REMATCH[1]}"
    fi
    
    # Extract sha256 (look for "sha256": "hash")
    sha256_line=$(grep '"sha256"' "$metadata_file" | head -1)
    if [[ $sha256_line =~ \"sha256\"[[:space:]]*:[[:space:]]*\"([^\"]+)\" ]]; then
        echo "sha256=${BASH_REMATCH[1]}"
    fi
}

# Download file from FTP (plain FTP; server does not support FTPS/AUTH TLS)
download_file() {
    local ftp_path="$1"
    local local_path="$2"
    
    mkdir -p "$(dirname "$local_path")"
    
    log_info "Downloading (plain FTP): $ftp_path"
    local url="ftp://$FTP_BASE/$ftp_path"
    local cmd="curl -s $url -o $local_path"
    log_info "Executing: $cmd"
    if curl -s "$url" -o "$local_path"; then
        log_info "Downloaded: $ftp_path -> $local_path"
        return 0
    else
        log_error "Failed to download: $ftp_path"
        return 1
    fi
}

# Upload file to GHCR using ORAS with metadata
upload_to_ghcr() {
    local local_file="$1"
    local version="$2"
    local platform="$3"
    local platform_version="$4"
    local machine="$5"
    local metadata_file="$6"
    
    local original_filename=$(basename "$local_file")
    # Remove temp_ prefix if present
    local clean_filename="${original_filename#temp_}"
    local tag="$version-$platform-$platform_version-$machine"
    local oci_ref="$TARGET_REGISTRY/$TARGET_ORG/$TARGET_REPO/$PROJECT:$tag"
    
    log_info "Uploading $clean_filename to $oci_ref"
    
    # Create temporary directory for ORAS
    local temp_dir=$(mktemp -d)
    log_info "Created temp dir: $temp_dir"
    
    # Copy file with clean filename
    cp "$local_file" "$temp_dir/$clean_filename"
    
    # Copy metadata.json if provided
    if [ -f "$metadata_file" ]; then
        cp "$metadata_file" "$temp_dir/metadata.json"
        log_info "Copied metadata.json to temp dir"
    fi
    
    # Change to temp dir
    pushd "$temp_dir" > /dev/null
    
    # Build ORAS push command
    local push_cmd=(oras push "$oci_ref"
        --artifact-type "application/vnd.cinc.package.v1+json"
        --annotation "org.opencontainers.artifact.title=$clean_filename"
        --annotation "org.opencontainers.artifact.description.platform=$platform"
        --annotation "org.opencontainers.artifact.description.platform-version=$platform_version"
        --annotation "org.opencontainers.artifact.description.machine=$machine"
        --annotation "org.opencontainers.artifact.description.version=$version"
        --disable-path-validation)
    
    # Add files to upload
    push_cmd+=("$clean_filename")
    if [ -f "metadata.json" ]; then
        push_cmd+=("metadata.json")
    fi
    
    log_info "Executing ORAS command: ${push_cmd[*]}"
    local push_output
    if push_output=$("${push_cmd[@]}" 2>&1); then
        log_info "Successfully uploaded $clean_filename to GHCR"
        log_info "Push output: $push_output"
        popd > /dev/null
        rm -rf "$temp_dir"
        return 0
    else
        log_error "Failed to upload $clean_filename to GHCR"
        log_error "ORAS output: $push_output"
        popd > /dev/null
        rm -rf "$temp_dir"
        return 1
    fi
}

# Get directory listing from FTP (plain FTP)
get_ftp_listing() {
    local ftp_path="$1"
    local cmd="curl -s -l ftp://$FTP_BASE/$ftp_path/"
    log_info "Executing: $cmd"
    curl -s -l "ftp://$FTP_BASE/$ftp_path/" 2>/dev/null || true
}

# Process a single version
process_version() {
    local version="$1"
    log_info "Processing version: $version"
    
    local ftp_base_path="pub/cinc/files/$CHANNEL/$PROJECT/$version"
    
    # Get platform directories
    local platforms
    platforms=$(get_ftp_listing "$ftp_base_path")
    
    for platform in $platforms; do
        # Skip if not matching platform filter
        if [ "$PLATFORM_FILTER" != "*" ] && [ "$platform" != "$PLATFORM_FILTER" ]; then
            log_info "Skipping platform $platform (filter: $PLATFORM_FILTER)"
            continue
        fi
        
        log_info "Processing platform: $platform"
        
        # Get platform version directories
        local platform_versions
        platform_versions=$(get_ftp_listing "$ftp_base_path/$platform")
        
        for platform_version in $platform_versions; do
            # Skip if not matching platform version filter
            if [ "$PLATFORM_VERSION_FILTER" != "*" ] && [ "$platform_version" != "$PLATFORM_VERSION_FILTER" ]; then
                log_info "Skipping platform version $platform_version (filter: $PLATFORM_VERSION_FILTER)"
                continue
            fi
            
            log_info "Processing platform version: $platform_version"
            
            # Get files directly in platform/version directory
            local files
            files=$(get_ftp_listing "$ftp_base_path/$platform/$platform_version")
            
            # Process metadata.json files
            for file in $files; do
                if [[ "$file" == *.metadata.json ]]; then
                    log_info "Found metadata file: $file"
                    
                    # Extract machine architecture from filename
                    # e.g., cinc_18.8.11-1_arm64.deb.metadata.json -> arm64
                    local machine=""
                    if [[ "$file" =~ _([^_]+)\.deb\.metadata\.json$ ]]; then
                        machine="${BASH_REMATCH[1]}"
                    elif [[ "$file" =~ _([^_]+)\.rpm\.metadata\.json$ ]]; then
                        machine="${BASH_REMATCH[1]}"
                    else
                        # Try to extract from other patterns
                        machine="unknown"
                    fi
                    
                    log_info "Extracted machine architecture: $machine"
                    
                    local metadata_path="$ftp_base_path/$platform/$platform_version/$file"
                    local local_metadata_file="./temp_metadata.json"
                    
                    # Download metadata.json
                    if download_file "$metadata_path" "$local_metadata_file"; then
                        # Parse metadata to get basename and sha256
                        local metadata_info
                        metadata_info=$(parse_metadata "$local_metadata_file")
                        
                        local basename sha256
                        eval "$metadata_info"
                        
                        if [ -n "$basename" ] && [ -n "$sha256" ]; then
                            log_info "Metadata parsed - basename: $basename, sha256: $sha256"
                            
                            # Download the actual file
                            local file_path="$ftp_base_path/$platform/$platform_version/$basename"
                            local local_file="./temp_$basename"
                            
                            if download_file "$file_path" "$local_file"; then
                                # Verify SHA256 if possible
                                local calculated_sha256
                                if command -v sha256sum >/dev/null 2>&1; then
                                    log_info "Calculating SHA256 with sha256sum"
                                    calculated_sha256=$(sha256sum "$local_file" | awk '{print $1}')
                                elif command -v shasum >/dev/null 2>&1; then
                                    log_info "Calculating SHA256 with shasum"
                                    calculated_sha256=$(shasum -a 256 "$local_file" | awk '{print $1}')
                                fi
                                
                                if [ -n "$calculated_sha256" ] && [ "$calculated_sha256" != "$sha256" ]; then
                                    log_error "SHA256 mismatch for $basename"
                                    log_error "Expected: $sha256"
                                    log_error "Calculated: $calculated_sha256"
                                    continue
                                fi
                                
                                # Upload to GHCR
                                if upload_to_ghcr "$local_file" "$version" "$platform" "$platform_version" "$machine" "$local_metadata_file"; then
                                    log_info "Successfully processed $basename"
                                else
                                    log_error "Failed to upload $basename"
                                fi
                                
                                # Clean up local file
                                rm -f "$local_file"
                            else
                                log_error "Failed to download $basename"
                            fi
                        else
                            log_error "Failed to parse metadata from $file"
                        fi
                        
                        # Clean up metadata file
                        rm -f "$local_metadata_file"
                    else
                        log_error "Failed to download metadata file $file"
                    fi
                fi
            done
        done
    done
}

# Main function
main() {
    log_info "Starting Cinc single script mirror process"
    log_info "Channel: $CHANNEL, Project: $PROJECT, Versions: $VERSIONS"
    log_info "Target: $TARGET_REGISTRY/$TARGET_ORG/$TARGET_REPO"
    log_info "Platform filter: $PLATFORM_FILTER/$PLATFORM_VERSION_FILTER"
    
    # Check dependencies
    check_dependencies
    
    # Process versions
    if [ "$VERSIONS" = "*" ]; then
        # Get all available versions
        log_info "Getting all available versions..."
        local all_versions
        all_versions=$(get_ftp_listing "pub/cinc/files/$CHANNEL/$PROJECT")
        
        for version in $all_versions; do
            process_version "$version"
        done
    else
        # Process specified versions (comma-separated)
        IFS=',' read -ra VERSION_ARRAY <<< "$VERSIONS"
        for version in "${VERSION_ARRAY[@]}"; do
            # Trim whitespace
            version=$(echo "$version" | xargs)
            process_version "$version"
        done
    fi
    
    log_info "Mirror process completed"
}

# Show usage
usage() {
    echo "Usage: $0 [options]"
    echo ""
    echo "Options:"
    echo "  CHANNEL=<channel>              Set channel (default: stable)"
    echo "  PROJECT=<project>              Set project (default: cinc)"
    echo "  VERSIONS=<versions>            Set versions (default: 18.8.11, use '*' for all)"
    echo "  TARGET_ORG=<org>               Set target GitHub org (default: rmoriz)"
    echo "  TARGET_REPO=<repo>             Set target repository (default: cinc-mirror)"
    echo "  PLATFORM_FILTER=<platform>    Set platform filter (default: debian)"
    echo "  PLATFORM_VERSION_FILTER=<ver> Set platform version filter (default: 13)"
    echo ""
    echo "Examples:"
    echo "  $0"
    echo "  VERSIONS='18.8.11,18.8.9' $0"
    echo "  VERSIONS='*' PLATFORM_FILTER='*' PLATFORM_VERSION_FILTER='*' $0"
}

# Parse command line arguments
if [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    usage
    exit 0
fi

# Run main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi