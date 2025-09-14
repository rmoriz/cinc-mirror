#!/bin/bash

# Script to get file sizes recursively from FTP
# Usage: ./get-ftp-sizes.sh [ftp-url] [max-depth]

FTP_URL="${1:-ftp://downloads.cinc.sh/pub/cinc/files/stable/cinc}"
MAX_DEPTH="${2:-3}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to get file size using curl
get_file_size() {
    local file_url="$1"
    local size

    # Try to get content-length header
    size=$(curl -s -I "$file_url" | grep -i "content-length" | awk '{print $2}' | tr -d '\r' | xargs)

    if [ -n "$size" ] && [ "$size" -gt 0 ] 2>/dev/null; then
        echo "$size"
    else
        echo "0"
    fi
}

# Function to format size in human readable format
format_size() {
    local size="$1"
    if [ "$size" -eq 0 ]; then
        echo "unknown"
        return
    fi

    if [ "$size" -gt 1073741824 ]; then
        echo "$(( size / 1073741824 ))GB"
    elif [ "$size" -gt 1048576 ]; then
        echo "$(( size / 1048576 ))MB"
    elif [ "$size" -gt 1024 ]; then
        echo "$(( size / 1024 ))KB"
    else
        echo "${size}B"
    fi
}

# Function to recursively list directory with sizes
list_directory() {
    local url="$1"
    local current_depth="$2"
    local indent="$3"

    if [ "$current_depth" -gt "$MAX_DEPTH" ]; then
        return
    fi

    log_info "${indent}Scanning: $url"

    # Get directory listing
    local listing
    listing=$(curl -s -l "$url/")

    if [ $? -ne 0 ]; then
        log_error "${indent}Failed to list: $url"
        return
    fi

    local total_size=0
    local file_count=0
    local dir_count=0

    for item in $listing; do
        local item_url="$url/$item"

        # Check if it's a directory (simple heuristic: no file extension or specific patterns)
        if [[ "$item" != *"."* ]] || [[ "$item" =~ ^[0-9]+(\.[0-9]+)*$ ]]; then
            # Likely a directory
            ((dir_count++))
            if [ "$current_depth" -lt "$MAX_DEPTH" ]; then
                local sub_size
                sub_size=$(list_directory "$item_url" $((current_depth + 1)) "$indent  ")
                if [ "$sub_size" -gt 0 ]; then
                    total_size=$((total_size + sub_size))
                fi
            fi
        else
            # Likely a file
            ((file_count++))
            local file_size
            file_size=$(get_file_size "$item_url")
            if [ "$file_size" -gt 0 ]; then
                total_size=$((total_size + file_size))
                echo "${indent}  $(format_size $file_size) - $item"
            else
                echo "${indent}  unknown - $item"
            fi
        fi
    done

    if [ "$total_size" -gt 0 ]; then
        echo "${indent}Total: $(format_size $total_size) ($file_count files, $dir_count dirs)"
    else
        echo "${indent}Total: unknown size ($file_count files, $dir_count dirs)"
    fi

    echo "$total_size"
}

# Main function
main() {
    echo "=== FTP Directory Size Scanner ==="
    echo "URL: $FTP_URL"
    echo "Max depth: $MAX_DEPTH"
    echo

    if ! curl -s --connect-timeout 5 "$FTP_URL/" > /dev/null; then
        log_error "Cannot connect to FTP server: $FTP_URL"
        exit 1
    fi

    log_info "Connected to FTP server successfully"
    echo

    local total_size
    total_size=$(list_directory "$FTP_URL" 1 "")

    echo
    echo "=== Summary ==="
    echo "Total size scanned: $(format_size $total_size)"
    echo "Note: Sizes are approximate and may not include all files if depth limit is reached"
}

# Run main function
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi