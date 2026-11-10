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

# Trivy ships no vulnerability DB in its image and cannot download it under
# --network none. Provision it once (this needs network) into a named volume
# that the `sca` adapter mounts read-write at scan time; the scan itself then
# runs offline. Only needed for live `sca` scans; safe to skip otherwise.
if docker image inspect aquasec/trivy:0.58.1 >/dev/null 2>&1; then
  echo "==> provisioning Trivy vuln DB into volume aegis-trivy-cache"
  docker run --rm -v aegis-trivy-cache:/root/.cache/trivy \
    aquasec/trivy:0.58.1 fs --download-db-only --cache-dir /root/.cache/trivy \
    >/dev/null 2>&1 \
    && echo "   vuln DB ready" || echo "   (Trivy DB provisioning failed)"
fi

echo "Done. Check availability with:  aegis tools"
