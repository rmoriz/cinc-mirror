# Abstract
Create a new single script mirroring solution for cinc, a opensource fork of chef



# Technical details
- defaults:
  channel="stable"
  project="cinc"
  versions="18.8.11"
- use curl with ftps

# Workflow

- connect via curl/ftps, go to the channel/project folder
- process all $version folders when "*" is specified, if not, comma separated list of versions to process (e.g. 18.8.11)
- recurse the structure to get the "*.metadata.json" files
- for each each json file:
    - download json file
    - extract basename, sha256
    - download file (basename):
        - source: ftp.osuosl.org/pub/cinc/files/$channel/$project/$version/$platform/$platform_version/$basename
    - use oras to upload the file to target: ghcr.io/rmoriz/cinc-mirror/$project:$version-$platform-$platform_version-$machine 
    -  add metadata.json to the metadata of target
