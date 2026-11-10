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

# Semgrep's --config auto fetches rules from semgrep.dev, unreachable under
# --network none. Provision the OSS semgrep-rules ruleset once (this needs
# network) into a named volume the `semgrep` adapter mounts read-only; the scan
# then runs offline. Only needed for live `semgrep` scans; safe to skip.
if docker image inspect semgrep/semgrep:1.95.0 >/dev/null 2>&1; then
  echo "==> provisioning semgrep-rules into volume aegis-semgrep-rules"
  docker run --rm -v aegis-semgrep-rules:/rules --entrypoint sh \
    semgrep/semgrep:1.95.0 -c \
    'rm -rf /rules/* /rules/.git 2>/dev/null; \
     git clone --depth 1 https://github.com/semgrep/semgrep-rules /rules' \
    >/dev/null 2>&1 \
    && echo "   rules ready" || echo "   (semgrep-rules provisioning failed)"
fi

# The proxy (mitmproxy) and browser (headless-Chromium) adapters need no
# provisioned data volume: proxy replays a recorded flow file the operator
# captures out-of-band, and browser mounts its driver (docker/drivers/
# browser_navlog.js) and the saved/served target read-only at scan time. The
# only requirement is their pinned images, pulled by the loop above. Both run
# fully offline (--network none) at scan time.
if docker image inspect mitmproxy/mitmproxy:11.1.3 >/dev/null 2>&1; then
  echo "proxy: image ready — capture flows once with 'mitmdump -w flows' against"
  echo "       an authorized target, then: aegis scan --tool proxy /path/to/flows"
fi
if docker image inspect zenika/alpine-chrome:124-with-puppeteer >/dev/null 2>&1; then
  echo "browser: image ready — point it at a locally saved/served site:"
  echo "         aegis scan --tool browser /path/to/saved-site"
fi

echo "Done. Check availability with:  aegis tools"
