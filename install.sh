#!/bin/sh
# Modified to use path-based parameters instead of query parameters
# Original: metadata_url="https://omnitruck.cinc.sh/$channel/$project/metadata?v=$version&p=$platform&pv=$platform_version&m=$machine"
# Modified: metadata_url="https://YOUR_USERNAME.github.io/YOUR_REPO/$channel/$project/$platform/$platform_version/$machine/$version"

# ... existing code ...

metadata_url="https://YOUR_USERNAME.github.io/YOUR_REPO/$channel/$project/$platform/$platform_version/$machine/$version"

# ... rest of existing code ...