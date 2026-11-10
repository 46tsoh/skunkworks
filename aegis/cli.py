"""Command-line entry point for Aegis.

Examples
--------
    aegis analyze                                   # sample data, offline
    aegis analyze --input data/sample_findings.json --out /tmp/out
    aegis analyze --backend basal                   # localhost model server
    python -m aegis analyze --out ./run             # module form

All backends are offline (``static``) or localhost (``basal``) by default;
``jev`` (remote) requires ``--allow-egress``.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aegis import __version__
from aegis.analysis.backends import build_router
from aegis.analysis.pipeline import run
from aegis.config import AegisConfig
from aegis.knowledge.models import Candidate

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_INPUT = _REPO_ROOT / "data" / "sample_findings.json"

_CANDIDATE_FIELDS = {
    "id", "title", "cwe", "component", "cvss_vector",
    "description", "evidence", "hints", "source_engine", "metadata",
}


def load_candidates(path: Path) -> list:
    """Load candidate findings from a JSON array file."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for item in data:
        known = {k: v for k, v in item.items() if k in _CANDIDATE_FIELDS}
        extra = {k: v for k, v in item.items() if k not in _CANDIDATE_FIELDS}
        if extra:
            known.setdefault("metadata", {}).update(extra)
        out.append(Candidate(**known))
    return out


def _print_report(kb, backend: str) -> None:
    m = kb.metrics
    print(f"\n=== Aegis analysis report (backend: {backend}) ===")
    print(
        f"candidates={m['candidates']}  accepted={m['accepted']}  "
        f"rejected={m['rejected']}  decisions={m['decisions']} "
        f"(cache hits {m['decision_cache_hits']})"
    )
    print(f"decisions_by_backend={m['decisions_by_backend']}")
    print(f"stage_counts={m['stage_counts']}")
    print(f"severity={kb.severity_counts()}  engines={kb.engine_counts()}")

    print("\n-- Accepted (ranked) --")
    if not kb.accepted:
        print("  (none)")
    for f in kb.accepted:
        flag = "EXPLOITABLE" if f.exploitable else f"info (stopped@{f.stages_passed})"
        owasp = f.owasp or "-"
        print(
            f"  [{f.severity:8} {f.cvss_score:4}] {f.id} {f.title}  "
            f"post={f.posterior:.2f}  {owasp}  {flag}"
        )

    print("\n-- Rejected --")
    if not kb.rejected:
        print("  (none)")
    for r in kb.rejected:
        print(f"  {r.candidate.id} {r.candidate.title}  <{r.stage}: {r.reason}>")
    print()


def _cmd_analyze(args: argparse.Namespace) -> int:
    candidates = load_candidates(args.input)
    log_path = (args.out / "decisions.jsonl") if args.out else None
    config = AegisConfig.from_env(
        backend=args.backend,
        local_only=not args.allow_egress,
        log_path=log_path,
    )
    if args.posterior_min is not None:
        config.posterior_min = args.posterior_min
    router = build_router(candidates, config=config)
    kb = run(router, candidates, posterior_min=config.posterior_min)

    _print_report(kb, config.backend)

    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "report.json").write_text(
            json.dumps(kb.as_dict(), indent=2), encoding="utf-8"
        )
        print(f"Wrote {args.out / 'report.json'} and {args.out / 'decisions.jsonl'}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Aegis — unified local-only security-analysis framework",
    )
    parser.add_argument("--version", action="version", version=f"aegis {__version__}")
    sub = parser.add_subparsers(dest="command")

    analyze = sub.add_parser("analyze", help="run the combined analysis pipeline")
    analyze.add_argument("--input", type=Path, default=_DEFAULT_INPUT,
                         help="JSON array of candidate findings")
    analyze.add_argument("--backend", choices=["static", "basal", "jev"],
                         default="static", help="decision backend (default: static)")
    analyze.add_argument("--posterior-min", type=float, default=None,
                         help="hypothesis posterior floor (default from config)")
    analyze.add_argument("--allow-egress", action="store_true",
                         help="permit the remote 'jev' backend (off by default)")
    analyze.add_argument("--out", type=Path, default=None,
                         help="directory for report.json and decisions.jsonl")
    analyze.set_defaults(func=_cmd_analyze)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        # Default to analyze for a bare invocation.
        args = parser.parse_args(["analyze", *(argv or [])])
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
