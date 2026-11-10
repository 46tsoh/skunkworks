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
    if m.get("degraded"):
        fails = m.get("tool_failures", [])
        detail = ", ".join("{}:{}={}".format(f["engine"], f["name"], f["status"])
                           for f in fails) or "engine error"
        print(f"  ! run DEGRADED: {len(fails)} tool(s) did not complete ({detail})")
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
    cfg_kwargs = dict(
        backend=args.backend,
        decision_model=getattr(args, "decision_model", "jev"),
        local_only=not args.allow_egress, log_path=log_path,
    )
    if args.mode is not None:  # don't clobber AEGIS_MODE env with the None default
        cfg_kwargs["mode"] = args.mode
    aegis_cfg = AegisConfig.from_env(**cfg_kwargs)
    config = RunConfig(
        target=str(args.target), aegis=aegis_cfg,
        parallel=not args.serial, out_dir=args.out, run_id=args.run_id,
    )
    registry = None
    if args.use_tools:
        from aegis.tools import default_registry
        registry = default_registry()
    result = default_orchestrator(registry=registry).run(config)
    _print_run(result)
    if args.out:
        print(f"Wrote {result.report_path} and {log_path}")
    return 0


def _cmd_tools(args: argparse.Namespace) -> int:
    from aegis.tools import default_registry, docker_available
    reg = default_registry(prefer_docker=not args.fixtures_only)
    print(f"=== Aegis tools (docker daemon: "
          f"{'up' if docker_available() else 'absent'}) ===")
    report = reg.status_report()
    for name in reg.names():
        row = report[name]
        live = "live" if row["available"] and not args.fixtures_only else "fixture"
        print(f"  {name:10} [{row['kind']:7}] "
              f"binary={row['requires_binary'] or '-':8} available={row['available']}")
    return 0


def _cmd_calibrate(args: argparse.Namespace) -> int:
    from aegis.calibration import calibrate, recommended_thresholds
    report = calibrate(args.corpus, backend=args.backend,
                       target_recall=args.target_recall)
    print(f"\n=== Aegis calibration (backend: {report.backend}, "
          f"corpus: {report.corpus_size}) ===")
    for kind, kc in report.kinds.items():
        b = kc.best_f1()
        rf = kc.at(kc.recommended_recall_first)
        print(f"\n{kind}")
        print(f"  max-F1       thr={b.threshold:.2f}  P={b.precision:.2f} "
              f"R={b.recall:.2f} F1={b.f1:.2f}")
        print(f"  recall-first thr={kc.recommended_recall_first:.2f}  "
              f"P={rf.precision:.2f} R={rf.recall:.2f} "
              f"(target recall {kc.target_recall})")
    rec = recommended_thresholds(report, recall_first=True)
    print(f"\nRecommended thresholds (recall-first): {rec}")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(report.as_dict(), indent=2),
                            encoding="utf-8")
        print(f"Wrote {args.out}")
    return 0


def _cmd_dashboard(args: argparse.Namespace) -> int:
    """One command: run both engines over the sample target, then open the UI."""
    import shutil
    import subprocess

    from aegis.engines import default_orchestrator
    from aegis.engines.base import RunConfig

    ui_dir = _REPO_ROOT / "ui"
    data_dir = ui_dir / "public" / "data"
    registry = None
    if args.use_tools:
        from aegis.tools import default_registry
        registry = default_registry()
    dash_kwargs = dict(
        backend=args.backend,
        decision_model=getattr(args, "decision_model", "jev"),
        local_only=not args.allow_egress,
        log_path=data_dir / "decisions.jsonl")
    if getattr(args, "mode", None) is not None:
        dash_kwargs["mode"] = args.mode
    aegis_cfg = AegisConfig.from_env(**dash_kwargs)
    config = RunConfig(target=str(args.target), aegis=aegis_cfg,
                       parallel=not args.serial, out_dir=data_dir,
                       run_id=args.run_id)
    result = default_orchestrator(registry=registry).run(config)
    _print_run(result)
    print(f"\nWrote unified run to {data_dir}")

    if args.no_serve:
        print("Start the dashboard with:  cd ui && npm run dev")
        return 0
    if shutil.which("npm") is None:
        print("npm not found — install Node, then: cd ui && npm run dev")
        return 0
    if not (ui_dir / "node_modules").exists():
        print("Installing dashboard dependencies (first run)…")
        if subprocess.run(["npm", "install"], cwd=ui_dir).returncode != 0:
            print("npm install failed — run it manually in ui/.")
            return 1
    print("\nStarting the dashboard (http://localhost:5173) — Ctrl-C to stop.")
    try:
        subprocess.run(["npm", "run", "dev"], cwd=ui_dir)
    except KeyboardInterrupt:
        pass
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
    run_p.add_argument("--mode",
                       choices=["full-llm", "llm+decision", "static"],
                       default=None,
                       help="operating mode: full-llm (one LLM plans+decides) | "
                            "llm+decision (LLM plans, decision model decides) | "
                            "static (offline). Overrides --backend when set.")
    run_p.add_argument("--backend", choices=["static", "basal", "jev", "llm"],
                       default="static",
                       help="low-level decider (default: static; --mode is "
                            "preferred for real runs)")
    run_p.add_argument("--decision-model", choices=["jev", "basal"],
                       default="jev",
                       help="decision model for llm+decision mode (default: jev)")
    run_p.add_argument("--allow-egress", action="store_true",
                       help="permit remote backends (off by default)")
    run_p.add_argument("--serial", action="store_true",
                       help="run engines serially instead of in parallel")
    run_p.add_argument("--run-id", default=None,
                       help="fixed run id (deterministic output)")
    run_p.add_argument("--use-tools", action="store_true",
                       help="source candidates from the tool registry (fixtures "
                            "offline; live Docker tools when images are present)")
    run_p.add_argument("--out", type=Path, default=None,
                       help="directory for report.json and decisions.jsonl")
    run_p.set_defaults(func=_cmd_run)

    tools_p = sub.add_parser("tools", help="list tool adapters and availability")
    tools_p.add_argument("--fixtures-only", action="store_true",
                         help="report the offline fixture adapters only")
    tools_p.set_defaults(func=_cmd_tools)

    cal = sub.add_parser("calibrate",
                         help="calibrate decision thresholds on a labeled corpus")
    cal.add_argument("--corpus", type=Path,
                     default=_REPO_ROOT / "data" / "corpus" / "labeled.json")
    cal.add_argument("--backend", choices=["static"], default="static")
    cal.add_argument("--target-recall", type=float, default=1.0)
    cal.add_argument("--out", type=Path, default=None,
                     help="write the full calibration report JSON here")
    cal.set_defaults(func=_cmd_calibrate)

    dash = sub.add_parser(
        "dashboard",
        help="run both engines over the sample target and open the dashboard")
    dash.add_argument("--target", type=Path, default=_DEFAULT_TARGET)
    dash.add_argument("--mode",
                      choices=["full-llm", "llm+decision", "static"],
                      default=None, help="operating mode (overrides --backend)")
    dash.add_argument("--decision-model", choices=["jev", "basal"],
                      default="jev")
    dash.add_argument("--backend", choices=["static", "basal", "jev", "llm"],
                      default="static")
    dash.add_argument("--use-tools", action="store_true",
                      help="source candidates from the tool registry")
    dash.add_argument("--allow-egress", action="store_true")
    dash.add_argument("--serial", action="store_true")
    dash.add_argument("--run-id", default=None)
    dash.add_argument("--no-serve", action="store_true",
                      help="write the run data but do not start the dev server")
    dash.set_defaults(func=_cmd_dashboard)
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
