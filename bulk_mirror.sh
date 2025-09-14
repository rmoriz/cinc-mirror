#!/bin/bash

# Bulk mirror script for CINC omnitruck metadata
# Mirrors multiple versions and platforms

set -e

CHANNEL=${1:-stable}
PROJECT=${2:-cinc}

# Common platforms to mirror
PLATFORMS=(
    "ubuntu:20.04:x86_64"
    "ubuntu:18.04:x86_64"
    "centos:7:x86_64"
    "centos:8:x86_64"
    "debian:10:x86_64"
    "debian:11:x86_64"
    "mac_os_x:11:x86_64"
    "mac_os_x:12:x86_64"
)

# Versions to mirror (you can customize this)
VERSIONS=(17 18)

echo "Starting bulk mirror for $CHANNEL/$PROJECT"
echo "Platforms: ${#PLATFORMS[@]} combinations"
echo "Versions: ${VERSIONS[*]}"
echo

for version in "${VERSIONS[@]}"; do
    for platform_info in "${PLATFORMS[@]}"; do
        IFS=':' read -r platform platform_version machine <<< "$platform_info"

        echo "Mirroring: $platform $platform_version $machine v$version"
        ./mirror_metadata.sh "$CHANNEL" "$PROJECT" "$version" "$platform" "$platform_version" "$machine"
        echo
    done
done

echo "Bulk mirror complete!"
echo "Files created in: $CHANNEL/$PROJECT/"
echo
echo "Next steps:"
echo "1. Review the generated metadata files"
echo "2. Commit and push to GitHub"
echo "3. Enable GitHub Pages in repository settings"