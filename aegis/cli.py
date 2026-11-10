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
from aegis.knowledge.loader import load_candidates  # noqa: F401  (re-exported)

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_INPUT = _REPO_ROOT / "data" / "sample_findings.json"
_DEFAULT_TARGET = _REPO_ROOT / "data" / "sample_target"


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


def _print_run(result) -> None:
    kb = result.kb
    print(f"\n=== Aegis unified run ({result.run_id}, backend: {result.backend}) ===")
    print(f"target={result.target}")
    for r in result.engine_reports:
        if r.ran:
            print(f"  engine {r.name:8} [{r.kind:7}] candidates={r.candidates} "
                  f"accepted={r.accepted} rejected={r.rejected}")
        else:
            print(f"  engine {r.name:8} [{r.kind:7}] SKIPPED ({r.skipped_reason or r.error})")
    m = kb.metrics
    print(f"cross-engine dedup collapsed {m['cross_engine_dedup']} finding(s)")
    print(f"unified: accepted={m['accepted']} rejected={m['rejected']}  "
          f"severity={kb.severity_counts()}  engines={kb.engine_counts()}")
    print("\n-- Unified findings (ranked) --")
    for f in kb.accepted:
        flag = "EXPLOITABLE" if f.exploitable else f"info (stopped@{f.stages_passed})"
        print(f"  [{f.severity:8} {f.cvss_score:4}] {f.id} ({f.source_engine}) "
              f"{f.title}  {f.owasp or '-'}  {flag}")
    print()


def _cmd_run(args: argparse.Namespace) -> int:
    from aegis.engines import default_orchestrator
    from aegis.engines.base import RunConfig

    log_path = (args.out / "decisions.jsonl") if args.out else None
    aegis_cfg = AegisConfig.from_env(
        backend=args.backend, local_only=not args.allow_egress, log_path=log_path,
    )
    config = RunConfig(
        target=str(args.target), aegis=aegis_cfg,
        parallel=not args.serial, out_dir=args.out, run_id=args.run_id,
    )
    result = default_orchestrator().run(config)
    _print_run(result)
    if args.out:
        print(f"Wrote {result.report_path} and {log_path}")
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

    run_p = sub.add_parser(
        "run", help="run BOTH engines over the sample target (unified report)")
    run_p.add_argument("--target", type=Path, default=_DEFAULT_TARGET,
                       help="local sample-target directory")
    run_p.add_argument("--backend", choices=["static", "basal", "jev", "llm"],
                       default="static", help="decision backend (default: static)")
    run_p.add_argument("--allow-egress", action="store_true",
                       help="permit remote backends (off by default)")
    run_p.add_argument("--serial", action="store_true",
                       help="run engines serially instead of in parallel")
    run_p.add_argument("--run-id", default=None,
                       help="fixed run id (deterministic output)")
    run_p.add_argument("--out", type=Path, default=None,
                       help="directory for report.json and decisions.jsonl")
    run_p.set_defaults(func=_cmd_run)
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
