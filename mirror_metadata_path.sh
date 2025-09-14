#!/bin/bash

# Script to mirror CINC omnitruck metadata to static files using path-based URLs
# Creates files at: channel/project/platform/platform_version/machine/version
# Instead of: channel/project/platform-platform_version-machine/version

set -e

CHANNEL=${1:-stable}
PROJECT=${2:-cinc}
VERSION=${3:-18}
PLATFORM=${4:-ubuntu}
PLATFORM_VERSION=${5:-20.04}
MACHINE=${6:-x86_64}

echo "Fetching metadata for: $CHANNEL/$PROJECT v$VERSION on $PLATFORM $PLATFORM_VERSION $MACHINE"

# Create directory structure for path-based URLs
DIR_PATH="$CHANNEL/$PROJECT/$PLATFORM/$PLATFORM_VERSION/$MACHINE"
mkdir -p "$DIR_PATH"

# Fetch metadata from omnitruck
METADATA_URL="https://omnitruck.cinc.sh/$CHANNEL/$PROJECT/metadata?v=$VERSION&p=$PLATFORM&pv=$PLATFORM_VERSION&m=$MACHINE"
METADATA_FILE="$DIR_PATH/$VERSION"

echo "Fetching from: $METADATA_URL"
curl -s "$METADATA_URL" > "$METADATA_FILE"

if [ ! -s "$METADATA_FILE" ]; then
    echo "Error: Failed to fetch metadata"
    rm -f "$METADATA_FILE"
    exit 1
fi

echo "Saved metadata to: $METADATA_FILE"
cat "$METADATA_FILE"

echo "Mirror URL will be: https://username.github.io/repo/$DIR_PATH/$VERSION"