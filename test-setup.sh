#!/bin/bash

# Test script to verify setup before running the full mirror

set -e

# Load configuration
if [ -f "config.env" ]; then
    source config.env
fi

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

echo "=== Cinc FTP to GHCR Mirror - Setup Test ==="
echo

# Test 1: Check dependencies
echo "1. Checking dependencies..."
deps=("curl" "gh" "oras")
missing_deps=()

for dep in "${deps[@]}"; do
    if command -v "$dep" &> /dev/null; then
        log_success "$dep is installed"
    else
        log_error "$dep is missing"
        missing_deps+=("$dep")
    fi
done

if [ ${#missing_deps[@]} -ne 0 ]; then
    echo
    log_error "Missing dependencies: ${missing_deps[*]}"
    echo "Please install them and run this test again."
    exit 1
fi

echo

# Test 2: Check GitHub authentication
echo "2. Checking GitHub authentication..."
if gh auth status &> /dev/null; then
    log_success "GitHub CLI is authenticated"
else
    log_error "GitHub CLI is not authenticated"
    echo "Run: gh auth login"
    exit 1
fi

echo

# Test 3: Check configuration
echo "3. Checking configuration..."
if [ -f "config.env" ]; then
    log_success "Configuration file found"
else
    log_warn "Configuration file not found (config.env)"
    echo "Copy config.env.example to config.env and fill in your values"
fi

# Check required variables
required_vars=("GHCR_ORG" "GITHUB_TOKEN")
missing_vars=()

for var in "${required_vars[@]}"; do
    if [ -n "${!var}" ] && [ "${!var}" != "your-github-username-or-org" ] && [ "${!var}" != "your-github-personal-access-token" ]; then
        log_success "$var is set"
    else
        log_error "$var is not set or has default value"
        missing_vars+=("$var")
    fi
done

if [ ${#missing_vars[@]} -ne 0 ]; then
    echo
    log_error "Missing or invalid configuration: ${missing_vars[*]}"
    echo "Please set these in config.env or environment variables"
    exit 1
fi

echo

# Test 4: Check FTP connectivity
echo "4. Checking FTP connectivity..."
FTP_BASE="${FTP_BASE:-ftp://downloads.cinc.sh/pub/cinc/files/stable/cinc}"

if curl -s --connect-timeout 10 "$FTP_BASE/" &> /dev/null; then
    log_success "FTP site is accessible"
else
    log_error "Cannot connect to FTP site"
    echo "Check your internet connection and firewall settings"
    exit 1
fi

echo

# Test 5: Check available versions
echo "5. Checking available versions..."
versions=$(curl -s -l "$FTP_BASE/" 2>/dev/null | sort -V)
if [ -n "$versions" ]; then
    log_success "Found versions on FTP site"
    echo "Sample versions: $(echo "$versions" | tail -5 | tr '\n' ' ')"
else
    log_error "Could not retrieve version list from FTP"
    exit 1
fi

echo

# Test 6: Test GHCR authentication
echo "6. Testing GHCR authentication..."
registry_test=$(echo "$GITHUB_TOKEN" | docker login ghcr.io -u "$GHCR_ORG" --password-stdin 2>&1)
if [ $? -eq 0 ]; then
    log_success "GHCR authentication successful"
else
    log_warn "Docker authentication failed, trying podman..."
    podman_test=$(echo "$GITHUB_TOKEN" | podman login ghcr.io -u "$GHCR_ORG" --password-stdin 2>&1)
    if [ $? -eq 0 ]; then
        log_success "GHCR authentication successful (podman)"
    else
        log_error "GHCR authentication failed"
        echo "Check your GITHUB_TOKEN and GHCR_ORG settings"
        exit 1
    fi
fi

echo
log_success "All tests passed! You can now run ./mirror-cinc.sh"
echo
echo "Next steps:"
echo "1. Review and update config.env if needed"
echo "2. Run: ./mirror-cinc.sh"