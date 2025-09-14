#!/bin/bash

# Simple wrapper script to run the Cinc mirror process

set -e

echo "=== Cinc FTP to GHCR Mirror ==="
echo

# Check if config.env exists
if [ ! -f "config.env" ]; then
    echo "Configuration file not found. Creating from template..."
    cp config.env config.env.backup 2>/dev/null || true
    echo "Please edit config.env with your settings before running this script."
    echo "Required settings:"
    echo "  - GHCR_ORG: Your GitHub username or organization"
    echo "  - GITHUB_TOKEN: Your GitHub personal access token (with write:packages permission)"
    echo
    exit 1
fi

# Run setup test
echo "Running setup verification..."
if ! ./test-setup.sh; then
    echo
    echo "Setup test failed. Please fix the issues above and try again."
    exit 1
fi

echo
echo "Starting mirror process..."
echo "This may take a while depending on the number of versions and files."
echo "You can monitor progress in the terminal output."
echo

# Run the mirror script
./mirror-cinc.sh

echo
echo "Mirror process completed successfully!"
echo "Check your GHCR repository at: https://github.com/$GHCR_ORG/$GHCR_REPO/pkgs/container/$GHCR_REPO"