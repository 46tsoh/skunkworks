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
echo "Done. Check availability with:  aegis tools"
