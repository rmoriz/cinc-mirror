#!/bin/bash

# Security Incident Response Script for Cinc Mirror
# This script helps investigate and respond to security alerts

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
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

# Configuration
MIRROR_DIR="${MIRROR_DIR:-./cinc-mirror}"
ALERT_FILE="$MIRROR_DIR/.security-alert"
INTEGRITY_LOG="$MIRROR_DIR/.integrity.log"
CHECKSUM_FILE="$MIRROR_DIR/.checksums.sha256"

# Function to display security alert details
show_alert_details() {
    if [ ! -f "$ALERT_FILE" ]; then
        log_error "No security alert file found at: $ALERT_FILE"
        return 1
    fi

    echo "=== SECURITY ALERT DETAILS ==="
    cat "$ALERT_FILE"
    echo
}

# Function to show integrity violations
show_integrity_violations() {
    if [ ! -f "$INTEGRITY_LOG" ]; then
        log_warn "No integrity log found at: $INTEGRITY_LOG"
        return 0
    fi

    echo "=== INTEGRITY VIOLATIONS ==="
    echo "Recent violations:"
    tail -10 "$INTEGRITY_LOG"
    echo

    echo "Summary of violations:"
    echo "Total violations: $(wc -l < "$INTEGRITY_LOG")"
    echo "Remote changes: $(grep "REMOTE_CHANGE" "$INTEGRITY_LOG" | wc -l)"
    echo "Integrity violations: $(grep "INTEGRITY_VIOLATION" "$INTEGRITY_LOG" | wc -l)"
    echo
}

# Function to verify specific file
verify_file() {
    local remote_path="$1"
    local local_path="$MIRROR_DIR/$remote_path"

    echo "=== VERIFYING FILE: $remote_path ==="

    if [ ! -f "$local_path" ]; then
        log_error "Local file not found: $local_path"
        return 1
    fi

    # Get stored checksum
    local stored_checksum
    stored_checksum=$(grep "$remote_path" "$CHECKSUM_FILE" | tail -1 | awk '{print $1}')

    if [ -z "$stored_checksum" ]; then
        log_error "No stored checksum found for: $remote_path"
        return 1
    fi

    # Calculate current checksum
    local current_checksum
    if command -v sha256sum >/dev/null 2>&1; then
        current_checksum=$(sha256sum "$local_path" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        current_checksum=$(shasum -a 256 "$local_path" | awk '{print $1}')
    else
        log_error "No SHA256 tool available"
        return 1
    fi

    echo "Stored checksum: $stored_checksum"
    echo "Current checksum: $current_checksum"

    if [ "$stored_checksum" = "$current_checksum" ]; then
        log_success "File integrity verified ✓"
        return 0
    else
        log_error "File integrity violation detected ✗"
        return 1
    fi
}

# Function to compare with remote source
compare_with_remote() {
    local remote_path="$1"
    local ftp_base="${FTP_BASE:-ftps://downloads.cinc.sh/pub/cinc/files/stable/cinc}"
    local ftp_url="$ftp_base/$remote_path"
    local local_path="$MIRROR_DIR/$remote_path"

    echo "=== COMPARING WITH REMOTE: $remote_path ==="

    # Get remote file info
    local remote_info
    remote_info=$(curl -s --ftp-ssl -I "$ftp_url")

    if [ $? -ne 0 ]; then
        log_error "Failed to connect to remote: $ftp_url"
        return 1
    fi

    local remote_size
    remote_size=$(echo "$remote_info" | grep -i "content-length" | awk '{print $2}' | tr -d '\r')

    local local_size
    local_size=$(stat -f%z "$local_path" 2>/dev/null || stat -c%s "$local_path" 2>/dev/null)

    echo "Local file size: $local_size bytes"
    echo "Remote file size: $remote_size bytes"

    if [ "$local_size" = "$remote_size" ]; then
        log_success "File sizes match"
    else
        log_error "File sizes differ - potential security incident!"
        echo "Size difference: $((remote_size - local_size)) bytes"
    fi
}

# Function to show remediation options
show_remediation_options() {
    echo "=== REMEDIATION OPTIONS ==="
    echo
    echo "1. INVESTIGATE FURTHER:"
    echo "   - Check the source FTP site manually"
    echo "   - Verify the legitimacy of changes"
    echo "   - Contact the upstream maintainers"
    echo
    echo "2. ACCEPT CHANGES (if legitimate):"
    echo "   - Run: ./mirror-cinc.sh with FORCE_FULL_SYNC=true"
    echo "   - This will update the files and new checksums"
    echo
    echo "3. REJECT CHANGES (security incident):"
    echo "   - Keep the current immutable files"
    echo "   - Document the incident"
    echo "   - Consider removing the mirror temporarily"
    echo
    echo "4. RESTORE FROM BACKUP:"
    echo "   - If you have backups, restore the original files"
    echo "   - Update checksums accordingly"
    echo
}

# Function to create incident report
create_incident_report() {
    local report_file="security-incident-report-$(date +%Y%m%d-%H%M%S).md"

    echo "=== CREATING INCIDENT REPORT ==="
    {
        echo "# Security Incident Report"
        echo ""
        echo "**Date:** $(date)"
        echo "**Investigator:** $(whoami)"
        echo ""
        echo "## Alert Details"
        if [ -f "$ALERT_FILE" ]; then
            cat "$ALERT_FILE"
        fi
        echo ""
        echo "## Integrity Violations"
        if [ -f "$INTEGRITY_LOG" ]; then
            tail -20 "$INTEGRITY_LOG"
        fi
        echo ""
        echo "## Investigation Notes"
        echo "- [ ] Verified source legitimacy"
        echo "- [ ] Contacted upstream maintainers"
        echo "- [ ] Performed manual file comparison"
        echo "- [ ] Decision: [ACCEPT/REJECT/INVESTIGATE]"
        echo ""
        echo "## Remediation Actions"
        echo "1. "
        echo "2. "
        echo "3. "
        echo ""
    } > "$report_file"

    log_success "Incident report created: $report_file"
}

# Main function
main() {
    echo "=== Cinc Mirror Security Incident Response Tool ==="
    echo

    case "${1:-help}" in
        "alerts")
            show_alert_details
            ;;
        "violations")
            show_integrity_violations
            ;;
        "verify")
            if [ -z "$2" ]; then
                log_error "Usage: $0 verify <remote-path>"
                exit 1
            fi
            verify_file "$2"
            ;;
        "compare")
            if [ -z "$2" ]; then
                log_error "Usage: $0 compare <remote-path>"
                exit 1
            fi
            compare_with_remote "$2"
            ;;
        "report")
            create_incident_report
            ;;
        "remediation")
            show_remediation_options
            ;;
        "full")
            show_alert_details
            echo
            show_integrity_violations
            echo
            show_remediation_options
            ;;
        "help"|*)
            echo "Usage: $0 <command> [options]"
            echo
            echo "Commands:"
            echo "  alerts          Show security alert details"
            echo "  violations      Show integrity violations"
            echo "  verify <path>   Verify specific file integrity"
            echo "  compare <path>  Compare file with remote source"
            echo "  report          Create incident report"
            echo "  remediation     Show remediation options"
            echo "  full            Show all information"
            echo "  help            Show this help"
            echo
            echo "Examples:"
            echo "  $0 alerts"
            echo "  $0 verify 18.8.11/debian/12/cinc_18.8.11-1_amd64.deb"
            echo "  $0 compare 18.8.11/debian/12/cinc_18.8.11-1_amd64.deb"
            ;;
    esac
}

# Run main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi