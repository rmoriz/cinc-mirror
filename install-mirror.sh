#!/bin/sh
# CINC installer modified for GitHub mirror with path-based URLs
# Original omnitruck URL: https://omnitruck.cinc.sh/$channel/$project/metadata?v=$version&p=$platform&pv=$platform_version&m=$machine
# Mirror URL: https://username.github.io/repo/$channel/$project/$platform/$platform_version/$machine/$version

# This is a modified version of the official CINC install.sh that uses path-based parameters
# instead of query parameters to work with static GitHub Pages hosting.

# Default values
channel="stable"
project="cinc"

while getopts pnv:c:f:P:d:s:l:a opt
do
  case "$opt" in
    v)  version="$OPTARG";;
    c)  channel="$OPTARG";;
    p)  channel="current";; # compat for prerelease option
    n)  channel="current";; # compat for nightlies option
    f)  cmdline_filename="$OPTARG";;
    P)  project="$OPTARG";;
    d)  cmdline_dl_dir="$OPTARG";;
    s)  install_strategy="$OPTARG";;
    l)  download_url_override="$OPTARG";;
    a)  checksum="$OPTARG";;
    \?) echo >&2 \
      "usage: $0 [-P project] [-c release_channel] [-v version] [-f filename | -d download_dir] [-s install_strategy] [-l download_url_override] [-a checksum]"
      exit 1;;
  esac
done

shift `expr $OPTIND - 1`

# Platform detection (simplified - copy from original install.sh)
machine=`uname -m`
os=`uname -s`

# Basic platform detection
if [ -f "/etc/os-release" ]; then
  . /etc/os-release
  platform=$ID
  platform_version=$VERSION_ID
else
  platform="unknown"
  platform_version="unknown"
fi

# Normalize architecture
case $machine in
  "x86_64"|"amd64") machine="x86_64";;
  "aarch64") machine="aarch64";;
  *) machine="x86_64";; # fallback
esac

echo "Platform: $platform $platform_version $machine"

# Construct mirror URL using path-based parameters
MIRROR_BASE="https://YOUR_USERNAME.github.io/YOUR_REPO"
metadata_url="$MIRROR_BASE/$channel/$project/$platform/$platform_version/$machine/$version"

echo "Fetching metadata from mirror: $metadata_url"

# Download metadata
tmp_dir="/tmp/install.$$"
mkdir -p "$tmp_dir"
metadata_file="$tmp_dir/metadata.txt"

if command -v curl >/dev/null 2>&1; then
  curl -s "$metadata_url" > "$metadata_file"
elif command -v wget >/dev/null 2>&1; then
  wget -q -O "$metadata_file" "$metadata_url"
else
  echo "Error: neither curl nor wget found"
  exit 1
fi

if [ ! -s "$metadata_file" ]; then
  echo "Error: Failed to download metadata from mirror"
  echo "URL: $metadata_url"
  rm -rf "$tmp_dir"
  exit 1
fi

echo "Metadata downloaded successfully"
cat "$metadata_file"

# Parse metadata (same format as original)
download_url=$(awk '$1 == "url" { print $2 }' "$metadata_file")
sha256=$(awk '$1 == "sha256" { print $2 }' "$metadata_file")

if [ -z "$download_url" ] || [ -z "$sha256" ]; then
  echo "Error: Invalid metadata format"
  rm -rf "$tmp_dir"
  exit 1
fi

echo "Download URL: $download_url"
echo "SHA256: $sha256"

# Download and install package (simplified - would need full implementation)
echo "Would download and install: $download_url"

# Cleanup
rm -rf "$tmp_dir"

echo "Installation complete (simplified example)"