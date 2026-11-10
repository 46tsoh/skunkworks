#!/usr/bin/env bash
# Pull the tool images Aegis uses, LOCALLY. Each adapter runs its image with
# `--network none` (no egress) at scan time; this script only fetches them.
# Adapters whose image is absent degrade to their offline fixture, so pulling
# is optional and incremental — pull only the tools you want to run live.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
while IFS=$'\t' read -r name kind image; do
  case "$image" in
    HOST*|"") echo "skip $name ($kind): host-local, no image";;
    *) echo "==> docker pull $image  ($name, $kind)"; docker pull "$image" || echo "   (failed; $name will use its fixture)";;
  esac
done < "$here/images.txt"

# nuclei ships no templates in its image; provision them once into a named
# volume that the web adapter mounts read-only at scan time. Only needed for
# live `web` scans (aegis scan --tool web); safe to skip otherwise.
if docker image inspect projectdiscovery/nuclei:v3.3.5 >/dev/null 2>&1; then
  echo "==> provisioning nuclei templates into volume aegis-nuclei-templates"
  docker run --rm -v aegis-nuclei-templates:/root/nuclei-templates \
    projectdiscovery/nuclei:v3.3.5 -ut >/dev/null 2>&1 \
    && echo "   templates ready" || echo "   (template provisioning failed)"
fi

echo "Done. Check availability with:  aegis tools"
