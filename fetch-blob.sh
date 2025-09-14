#!/bin/bash

set -euo pipefail

usage() {
    echo "Usage: $0 <registry>/<namespace>/<repository>@<digest> -o <output_file>"
    echo "Example: $0 ghcr.io/rmoriz/cinc-packages/cinc@sha256:81a46c0ae31de496d73bc9f02f8245fcd4e6a3c54f9e4490aabbc6195612951a -o file.deb"
    exit 1
}

if [ $# -lt 3 ]; then
    usage
fi

BLOB_REF="$1"
shift

OUTPUT_FILE=""
while [[ $# -gt 0 ]]; do
    case $1 in
        -o)
            OUTPUT_FILE="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

if [ -z "$OUTPUT_FILE" ]; then
    echo "Error: Output file (-o) is required"
    usage
fi

# Parse the blob reference
if [[ ! "$BLOB_REF" =~ ^([^/]+)/(.+)@(sha256:[a-f0-9]{64})$ ]]; then
    echo "Error: Invalid blob reference format"
    echo "Expected format: registry/namespace/repository@sha256:digest"
    exit 1
fi

REGISTRY="${BASH_REMATCH[1]}"
REPO_PATH="${BASH_REMATCH[2]}"
DIGEST="${BASH_REMATCH[3]}"

echo "Fetching blob from $REGISTRY/$REPO_PATH with digest $DIGEST"

# Get authentication token if needed
TOKEN=""
if command -v docker >/dev/null 2>&1; then
    # Try to get token from docker credentials
    AUTH_URL="https://$REGISTRY/token?service=$REGISTRY&scope=repository:$REPO_PATH:pull"
    TOKEN_RESPONSE=$(curl -s "$AUTH_URL" || echo "")
    if [ -n "$TOKEN_RESPONSE" ]; then
        TOKEN=$(echo "$TOKEN_RESPONSE" | grep -o '"token":"[^"]*"' | cut -d'"' -f4 || echo "")
    fi
fi

# Construct the blob URL
BLOB_URL="https://$REGISTRY/v2/$REPO_PATH/blobs/$DIGEST"

# Fetch the blob
echo "Downloading to $OUTPUT_FILE..."
if [ -n "$TOKEN" ]; then
    curl -L -H "Authorization: Bearer $TOKEN" -o "$OUTPUT_FILE" "$BLOB_URL"
else
    curl -L -o "$OUTPUT_FILE" "$BLOB_URL"
fi

if [ $? -eq 0 ]; then
    echo "Successfully downloaded blob to $OUTPUT_FILE"
else
    echo "Error: Failed to download blob"
    exit 1
fi