"""``aegis agent`` — the autonomous, headless, Strix-style driver.

Give it a goal and a target; it drives the whole engagement itself: it chains
the live network scanners (recon → web → dast), triages every finding through
the dynamic agent loop into one knowledge base, and then **stops at the
confirm-to-exploit gate**. Only with explicit go-ahead (``--exploit`` headless,
or a typed ``go`` in the shell) does it send stage-1 exploit-confirmation probes
at the leads it can auto-target.

Two invariants carry over from the shell and are never relaxed:

* **Every live action is gated.** Each scanner phase and each exploit attempt
  passes :func:`aegis.shell.authorize` (``--authorized`` + in-scope,
  default-deny) on the exact target bytes the tool will use, before any traffic.
* **The agent loop never receives authorization state.** The planner/decider
  see only the candidate pool and the goal; scope and the ``authorized`` flag
  live in this driver, so a planned step can never widen its own authority.

See ``docs/specs/autonomous-agent.md``. Clean-room, local-only.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional
from urllib.parse import parse_qs, urlparse

from aegis.config import AegisConfig
from aegis.knowledge.base import KnowledgeBase
from aegis.redteam import EngagementScope
from aegis.redteam.http import sanitize_text
from aegis.redteam.techniques import technique_for
from aegis.shell import (
    _finding_key, _load_sample_pool, authorize, fold_findings, run_narration,
)

#: The scanner phases the agent chains, in order. Each is an explicit, gated
#: Docker scanner run — never the ungated in-loop registry path.
DEFAULT_PHASES = ("recon", "web", "dast")


# --------------------------------------------------------------------------- #
# Per-phase target forms. nmap wants a bare host; nuclei/ZAP want a URL.
# --------------------------------------------------------------------------- #
def _host_of(target: str) -> str:
    if "://" in target:
        return urlparse(target).hostname or target
    return target.split("/", 1)[0]


def _url_of(target: str) -> str:
    return target if "://" in target else f"http://{target}"


def phase_target(phase: str, target: str) -> str:
    return _host_of(target) if phase == "recon" else _url_of(target)


# --------------------------------------------------------------------------- #
# Auto-target a stage-1 exploit from a confirmed finding.
# --------------------------------------------------------------------------- #
def attemptable(finding) -> Optional["tuple[str, str, str]"]:
    """Derive ``(type, target, param)`` for a stage-1 ``attempt`` from a finding,
    or ``None`` if it cannot be auto-targeted.

    - ``type``: the technique name for the finding's CWE, else its title's
      keyword (via ``technique_for``). No technique → not attemptable.
    - ``target``: the candidate ``component`` — must be an http(s) URL.
    - ``param``: structured ``metadata['param']`` (persisted by the dast adapter),
      else the first query-string parameter of the URL. None → not attemptable.
    """
    cand = finding.candidate
    tech = technique_for(cand.cwe) or technique_for(finding.title)
    if tech is None:
        return None
    target = cand.component
    if not isinstance(target, str) or not target.startswith(("http://", "https://")):
        return None
    param = cand.metadata.get("param")
    if not param:
        qs = parse_qs(urlparse(target).query)
        param = next(iter(qs), None)
    if not param:
        return None
    return (tech.name, target, str(param))


# --------------------------------------------------------------------------- #
# Outcome
# --------------------------------------------------------------------------- #
@dataclass
class AgentOutcome:
    live: bool
    phases: List[dict] = field(default_factory=list)      # {phase,target,status,candidates}
    findings: int = 0
    exploitable_leads: List[dict] = field(default_factory=list)  # {type,target,param,id}
    skipped_leads: List[dict] = field(default_factory=list)      # {id,reason}
    attempted: List[dict] = field(default_factory=list)   # {type,target,param,verified,cwe,proof}
    exploit_ran: bool = False
    degraded: bool = False
    n_candidates: int = 0

    def as_dict(self) -> dict:
        return {
            "live": self.live, "phases": self.phases, "findings": self.findings,
            "exploitable_leads": self.exploitable_leads,
            "skipped_leads": self.skipped_leads, "attempted": self.attempted,
            "exploit_ran": self.exploit_ran,
            "verified": sum(1 for a in self.attempted if a.get("verified")),
            "degraded": self.degraded,
        }


# --------------------------------------------------------------------------- #
# The driver
# --------------------------------------------------------------------------- #
def drive_agent(
    *,
    target: str,
    goal: str,
    scope: EngagementScope,
    authorized: bool,
    exploit: bool,
    config: AegisConfig,
    sink,
    kb: KnowledgeBase,
    write: Callable[[str], None],
    registry=None,
    transport=None,
    phases=DEFAULT_PHASES,
    confirm: Optional[Callable[[], str]] = None,
) -> AgentOutcome:
    """Run the autonomous engagement to completion (minus the gated exploit).

    ``confirm`` (interactive only) is called at the confirm-to-exploit gate; it
    returns the operator's typed line (``go`` proceeds). Headless callers pass
    ``exploit=True`` to skip the prompt, or leave it ``False`` to stop at the gate.
    """
    seen_keys: set = set()
    outcome = AgentOutcome(live=authorized)

    # 1. SCAN — chain the live scanners, each gated, each triaged into the KB.
    if authorized:
        for phase in phases:
            ptarget = phase_target(phase, target)
            ok, reason = authorize(scope, authorized, ptarget)
            if not ok:
                sink.emit("a0001", "scope_refused",
                          target=sanitize_text(ptarget, 160), reason=reason)
                write(f"  [{phase}] REFUSED — {reason}")
                outcome.phases.append({"phase": phase, "target": ptarget,
                                       "status": "refused", "candidates": 0})
                continue
            if Path(ptarget).exists():  # same local-path refusal as `scan`
                write(f"  [{phase}] refusing: {ptarget!r} is a local path")
                outcome.phases.append({"phase": phase, "target": ptarget,
                                       "status": "refused_local", "candidates": 0})
                continue
            cands = _run_scanner(phase, ptarget, registry, write)
            if cands is None:
                outcome.degraded = True
                outcome.phases.append({"phase": phase, "target": ptarget,
                                       "status": "error", "candidates": 0})
                continue
            outcome.n_candidates += len(cands)
            write(f"  [{phase}] {ptarget} → {len(cands)} candidate(s); triaging…")
            if cands:
                cmd_kb, _ = run_narration(cands, config, sink, goal)
                fold_findings(kb, cmd_kb, seen_keys)
            outcome.phases.append({"phase": phase, "target": ptarget,
                                   "status": "ok", "candidates": len(cands)})
    else:
        # Not authorized: no live traffic. Narrate offline over the sample pool
        # so the agent still reasons and demonstrates the flow — clearly labelled.
        write("  not authorized — offline narration only (no live scan).")
        pool = _load_sample_pool()
        outcome.n_candidates = len(pool)
        if pool:
            cmd_kb, _ = run_narration(pool, config, sink, goal)
            fold_findings(kb, cmd_kb, seen_keys)

    kb.rank()
    outcome.findings = len(kb.accepted)

    # 2. TRIAGE — which confirmed findings can be auto-targeted for stage-1?
    for f in kb.accepted:
        if not f.exploitable:
            continue
        m = attemptable(f)
        if m is None:
            outcome.skipped_leads.append(
                {"id": f.id, "reason": "no technique / not a URL / no param"})
            continue
        outcome.exploitable_leads.append(
            {"type": m[0], "target": m[1], "param": m[2], "id": f.id})

    write(f"  {outcome.findings} finding(s); "
          f"{len(outcome.exploitable_leads)} auto-attemptable, "
          f"{len(outcome.skipped_leads)} not auto-targetable.")

    # 3. CONFIRM-TO-EXPLOIT GATE — stop here unless explicitly told to proceed.
    if not outcome.exploitable_leads:
        return outcome
    proceed = exploit
    if not proceed and confirm is not None:
        write(f"  {len(outcome.exploitable_leads)} exploitable lead(s). "
              f"Type `go` to send stage-1 confirm probes (anything else skips):")
        proceed = (confirm() or "").strip().lower() in ("go", "yes", "y")
    if not proceed:
        write("  stopped before exploit — re-run with --exploit "
              "(or type `go`) to send stage-1 confirm probes.")
        return outcome

    # 4. EXPLOIT — stage-1 confirm, every attempt gated + scope re-checked.
    from aegis.redteam import RedTeamEngine
    outcome.exploit_ran = True
    engine = RedTeamEngine(scope, transport=transport,
                           on_event=lambda e: sink.emit(
                               "a0003", e.get("event", "event"),
                               **{k: v for k, v in e.items() if k != "event"}))
    for lead in outcome.exploitable_leads:
        ok, reason = authorize(scope, authorized, lead["target"])
        if not ok:
            write(f"  [exploit] REFUSED {lead['target']} — {reason}")
            outcome.attempted.append({**lead, "verified": False,
                                      "note": "refused"})
            continue
        res = engine.attempt(lead["type"], lead["target"], lead["param"])
        mark = "CONFIRMED" if res.verified else "not confirmed"
        write(f"  [exploit] {mark} [{res.cwe}] {sanitize_text(lead['target'], 120)}"
              f" ({lead['param']})")
        outcome.attempted.append({**lead, "verified": bool(res.verified),
                                  "cwe": res.cwe,
                                  "proof": sanitize_text(res.proof or "", 300)})
    return outcome


def _run_scanner(phase: str, target: str, registry, write):
    """Run one live Docker scanner; return its candidates, or None on failure."""
    try:
        from aegis.tools import default_registry
        from aegis.tools.base import DockerBackedTool
    except Exception as exc:  # noqa: BLE001
        write(f"  [{phase}] scan unavailable: {sanitize_text(str(exc), 160)}")
        return None
    reg = registry or default_registry()
    try:
        tool = reg.get(phase)
    except KeyError:
        write(f"  [{phase}] no such tool")
        return None
    if not isinstance(tool, DockerBackedTool) or not getattr(
            tool, "allows_network", False):
        write(f"  [{phase}] not a live network scanner (image not pulled?)")
        return None
    result = tool.run(target, network="bridge", host=target, url=target)
    if not result.ok:
        for e in result.errors:
            write(f"  [{phase}] ! {sanitize_text(str(e), 160)}")
        return None
    cands = list(result.candidates)
    for c in cands:
        c.source_engine = "dynamic"
    return cands


# --------------------------------------------------------------------------- #
# report.json — the same shape the dashboard and `aegis run` use.
# --------------------------------------------------------------------------- #
def write_report(out_dir: Path, kb: KnowledgeBase, sink, router, *, run_id: str,
                 target: str, config: AegisConfig, started: float,
                 outcome: AgentOutcome) -> Path:
    import json

    from aegis.engines.base import EngineReport

    kb.rank()
    kb.metrics = {
        "candidates": outcome.n_candidates,
        "accepted": len(kb.accepted),
        "rejected": len(kb.rejected),
        "cross_engine_dedup": 0,
        "decisions": getattr(getattr(router, "metrics", None), "calls", 0),
        "decision_cache_hits": getattr(getattr(router, "metrics", None),
                                       "cache_hits", 0),
        "degraded": outcome.degraded,
        "tool_failures": [],
        "agent": outcome.as_dict(),
    }
    payload = kb.as_dict()
    payload["transcript"] = sink.events
    payload["run"] = {
        "run_id": run_id, "target": target, "backend": config.backend,
        "engines": [EngineReport(
            name="agent", kind="dynamic", available=True, ran=True,
            candidates=outcome.n_candidates, accepted=len(kb.accepted),
            rejected=len(kb.rejected)).as_dict()],
        "cross_engine_dedup": 0, "started_at": started,
        "finished_at": _now(), "duration_ms": (_now() - started) * 1000.0,
        "decision_log_path": str(out_dir / "decisions.jsonl"),
    }
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / "report.json"
    path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return path


def _now() -> float:
    return time.time()


__all__ = ["drive_agent", "AgentOutcome", "attemptable", "phase_target",
           "write_report", "DEFAULT_PHASES"]
