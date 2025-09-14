#!/bin/bash

# Setup script for GitHub Actions Cinc mirror

set -e

echo "=== Setting up GitHub Actions for Cinc Mirror ==="
echo

# Check if we're in a git repository
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo "Error: Not in a git repository. Please run 'git init' first."
    exit 1
fi

# Check if GitHub CLI is available
if ! command -v gh > /dev/null 2>&1; then
    echo "Error: GitHub CLI (gh) is not installed."
    echo "Please install it from: https://cli.github.com/"
    exit 1
fi

# Check if user is authenticated with GitHub
if ! gh auth status > /dev/null 2>&1; then
    echo "Error: Not authenticated with GitHub CLI."
    echo "Please run 'gh auth login' first."
    exit 1
fi

echo "✓ GitHub CLI is authenticated"

# Create .github/workflows directory if it doesn't exist
mkdir -p .github/workflows

# Check if workflow file exists
if [ -f ".github/workflows/mirror-cinc.yml" ]; then
    echo "✓ GitHub Actions workflow file already exists"
else
    echo "✗ GitHub Actions workflow file not found"
    echo "Please ensure mirror-cinc.yml is in .github/workflows/"
    exit 1
fi

# Create config.env if it doesn't exist
if [ -f "config.env" ]; then
    echo "✓ Configuration file exists"
else
    echo "Creating default configuration file..."
    cat > config.env << 'EOF'
# Configuration file for Cinc FTP to GHCR mirror script
# Copy this file to config.env and modify the values as needed

# GitHub Container Registry settings (will be set automatically in GitHub Actions)
GHCR_ORG="your-github-username-or-org"
GHCR_REPO="cinc-packages"

# GitHub Personal Access Token (will use GITHUB_TOKEN in Actions)
GITHUB_TOKEN="your-github-personal-access-token"

# Local mirror directory
MIRROR_DIR="./cinc-mirror"

# Minimum version to mirror (default: 18)
MIN_VERSION="18"

# Target distributions to mirror (space-separated)
TARGET_DISTROS="debian ubuntu"

# FTPS base URL
FTP_BASE="ftps://downloads.cinc.sh/pub/cinc/files/stable/cinc"
EOF
    echo "✓ Created config.env template"
    echo "  Please edit config.env with your GitHub username/organization"
fi

# Make scripts executable
chmod +x mirror-cinc.sh test-setup.sh run-mirror.sh setup-github-actions.sh

echo "✓ Made scripts executable"

# Create .gitignore if it doesn't exist
if [ ! -f ".gitignore" ]; then
    cat > .gitignore << 'EOF'
# Mirror files
cinc-mirror/
logs/

# Configuration with secrets
config.env

# OS files
.DS_Store
Thumbs.db

# Temporary files
*.tmp
*.log
EOF
    echo "✓ Created .gitignore"
fi

# Check repository settings
REPO_INFO=$(gh repo view --json name,owner,isPrivate,hasIssues,hasWiki,hasProjects)

if echo "$REPO_INFO" | grep -q '"isPrivate": true'; then
    echo "⚠️  Repository is private. Make sure your GitHub token has 'write:packages' permission."
else
    echo "✓ Repository is public"
fi

echo
echo "=== Setup Complete ==="
echo
echo "Next steps:"
echo "1. Edit config.env with your GitHub username/organization"
echo "2. Commit and push these files to GitHub:"
echo "   git add ."
echo "   git commit -m 'Add Cinc mirror with GitHub Actions'"
echo "   git push origin main"
echo
echo "3. The workflow will run automatically every day at 2 AM UTC"
echo "   You can also trigger it manually from the Actions tab"
echo
echo "4. Monitor the workflow runs in the GitHub Actions tab"
echo "   Check the 'mirror-logs-*' artifacts for detailed logs"