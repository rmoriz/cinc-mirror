#!/bin/bash

# Delete all packages from GHCR
# Usage: ./delete-ghcr-packages.sh

set -euo pipefail

# Configuration
USER="rmoriz"
PACKAGE_NAME="cinc-mirror/cinc"
PACKAGE_TYPE="container"
REPO_OWNER="rmoriz"
REPO_NAME="cinc-mirror"

echo "Deleting all versions of package: $PACKAGE_NAME for user: $USER"

# Function to delete versions using user API
delete_via_user_api() {
    echo "Attempting to delete via user packages API..."

    # URL encode the package name
    ENCODED_PACKAGE_NAME=$(echo "$PACKAGE_NAME" | sed 's|/|%2F|g')
    echo "Encoded package name: $ENCODED_PACKAGE_NAME"

    # List versions
    if ! gh api "/users/$USER/packages/$PACKAGE_TYPE/$ENCODED_PACKAGE_NAME/versions" --jq '.[].id' > /tmp/versions 2>/dev/null; then
        echo "Could not access package versions via user API"
        return 1
    fi

    if [ ! -s /tmp/versions ]; then
        echo "No versions found to delete"
        return 0
    fi

    echo "Found package versions:"
    cat /tmp/versions

    VERSION_COUNT=$(wc -l < /tmp/versions)
    echo "Found $VERSION_COUNT versions to delete"

    # Delete each version
    while read -r VERSION_ID; do
        if [ -n "$VERSION_ID" ] && [[ "$VERSION_ID" =~ ^[0-9]+$ ]]; then
            echo "Deleting version ID: $VERSION_ID"
            if gh api -X DELETE "/users/$USER/packages/$PACKAGE_TYPE/$ENCODED_PACKAGE_NAME/versions/$VERSION_ID" 2>/dev/null; then
                echo "Successfully deleted version ID: $VERSION_ID"
            else
                echo "Failed to delete version ID: $VERSION_ID (may already be deleted)"
            fi
        else
            echo "Skipping invalid version ID: $VERSION_ID"
        fi
    done < /tmp/versions

    return 0
}

# Function to delete versions using repository API
delete_via_repo_api() {
    echo "Attempting to delete via repository packages API..."

    # Find package ID
    if ! gh api "/repos/$REPO_OWNER/$REPO_NAME/packages?package_type=$PACKAGE_TYPE" --jq ".[] | select(.name == \"$PACKAGE_NAME\") | .id" > /tmp/package_id 2>/dev/null; then
        echo "Could not find package in repository"
        return 1
    fi

    if [ ! -s /tmp/package_id ]; then
        echo "Package not found in repository"
        return 1
    fi

    PACKAGE_ID=$(cat /tmp/package_id)
    echo "Found package ID: $PACKAGE_ID"

    # List versions
    if ! gh api "/repos/$REPO_OWNER/$REPO_NAME/packages/$PACKAGE_TYPE/$PACKAGE_ID/versions" --jq '.[].id' > /tmp/versions 2>/dev/null; then
        echo "Could not access package versions via repository API"
        return 1
    fi

    if [ ! -s /tmp/versions ]; then
        echo "No versions found to delete"
        return 0
    fi

    echo "Found package versions:"
    cat /tmp/versions

    VERSION_COUNT=$(wc -l < /tmp/versions)
    echo "Found $VERSION_COUNT versions to delete"

    # Delete each version
    while read -r VERSION_ID; do
        if [ -n "$VERSION_ID" ] && [[ "$VERSION_ID" =~ ^[0-9]+$ ]]; then
            echo "Deleting version ID: $VERSION_ID"
            if gh api -X DELETE "/repos/$REPO_OWNER/$REPO_NAME/packages/$PACKAGE_TYPE/$PACKAGE_ID/versions/$VERSION_ID" 2>/dev/null; then
                echo "Successfully deleted version ID: $VERSION_ID"
            else
                echo "Failed to delete version ID: $VERSION_ID (may already be deleted)"
            fi
        else
            echo "Skipping invalid version ID: $VERSION_ID"
        fi
    done < /tmp/versions

    return 0
}

# Main execution
if delete_via_user_api; then
    echo "Successfully deleted packages via user API"
elif delete_via_repo_api; then
    echo "Successfully deleted packages via repository API"
else
    echo "Failed to delete packages using both APIs"
    exit 1
fi

# Clean up temp files
rm -f /tmp/versions /tmp/package_id

echo "Package deletion process completed for $PACKAGE_NAME"