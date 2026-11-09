"""Command-line entry point for the triage POC.

Examples
--------
    python -m poc.cli                              # sample data, static backend
    python -m poc.cli --input data/sample_findings.json --out /tmp/out
    python -m poc.cli --backend basal              # basal-omni primary (local)
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .backends import build_router
from .models import Candidate
from .pipeline import run

_DEFAULT_INPUT = Path(__file__).resolve().parent.parent / "data" / "sample_findings.json"


def load_candidates(path: Path) -> list[Candidate]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Candidate(**item) for item in data]


def _print_report(result, backend: str) -> None:
    m = result.metrics
    print(f"\n=== Triage report (backend: {backend}) ===")
    print(
        f"candidates={m['candidates']}  accepted={m['accepted']}  "
        f"rejected={m['rejected']}  decisions={m['decisions']} "
        f"(cache hits {m['decision_cache_hits']})"
    )
    print(f"decisions_by_backend={m['decisions_by_backend']}")
    print(f"stage_counts={m['stage_counts']}")

    print("\n-- Accepted (ranked) --")
    if not result.accepted:
        print("  (none)")
    for f in result.accepted:
        flag = "EXPLOITABLE" if f.exploitable else f"info (stopped@{f.stages_passed})"
        print(
            f"  [{f.severity:8} {f.cvss_score:4}] {f.candidate.id} "
            f"{f.candidate.title}  post={f.posterior:.2f}  {flag}"
        )

    print("\n-- Rejected --")
    if not result.rejected:
        print("  (none)")
    for r in result.rejected:
        print(f"  {r.candidate.id} {r.candidate.title}  <{r.stage}: {r.reason}>")
    print()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Strix+RAPTOR+decision-model triage POC")
    parser.add_argument("--input", type=Path, default=_DEFAULT_INPUT,
                        help="JSON array of candidate findings")
    parser.add_argument("--backend", choices=["static", "basal", "jev"],
                        default="static", help="decision backend (default: static)")
    parser.add_argument("--out", type=Path, default=None,
                        help="directory to write report.json and decisions.jsonl")
    args = parser.parse_args(argv)

    candidates = load_candidates(args.input)
    log_path = (args.out / "decisions.jsonl") if args.out else None
    router = build_router(candidates, backend=args.backend, log_path=log_path)
    result = run(router, candidates)

    _print_report(result, args.backend)

    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "report.json").write_text(
            json.dumps(result.as_dict(), indent=2), encoding="utf-8"
        )
        print(f"Wrote {args.out / 'report.json'} and {args.out / 'decisions.jsonl'}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
