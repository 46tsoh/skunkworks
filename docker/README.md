# Local tool images

Aegis's binary-backed tool adapters run their tools inside **local Docker
containers** — nothing is installed on the host and nothing is hosted remotely.
Every container is launched with `--network none` (no egress), read-only target
mounts, and CPU/memory/time caps (see `aegis/tools/runtime.py`).

## Fixture-first, image-optional

Each capability ships an **offline fixture adapter** that parses a recorded
native output with the *same parser* the live adapter uses. So the whole
pipeline runs — and the full test suite passes — with **no images pulled and no
network**. An image is needed only to run that tool *live*; when the image is
absent the adapter degrades to its fixture (and `aegis tools` shows it).

## Pulling images

```bash
./docker/pull-images.sh      # pull all (incremental; failures fall back to fixtures)
docker pull semgrep/semgrep:1.95.0   # or pull just the ones you want
aegis tools                  # show which tools are live vs fixture
aegis run --use-tools        # run both engines, sourcing candidates from tools
```

`images.txt` is the manifest (`name  kind  image`). Some images are large
(CodeQL, AFL++, frida, ZAP); pull only what you need. `forensics` and `poc` run
on the host (git / python) and need no image.

## Notes on image choices

A few images are best-effort public references (noted in the adapter source):
CodeQL has no single canonical public image; `crash` reuses the AFL++ image for
its triage tooling. Swap the `IMAGE` constant in the adapter module if you
prefer a different local image — the parser (the tested contract) is unchanged.
