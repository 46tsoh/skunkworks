"""``aegis shell`` — an interactive, Strix-style REPL over the dynamic loop.

The operator types one command per line; the agent streams its transcript live
to the terminal; and **every live action funnels through a single scope +
authorization gate** before any network traffic. Session state (the frozen
engagement scope, the one-time ``--authorized`` assertion, config, the shared
knowledge base) is held for the life of the process, but the agent loop is
*never* handed a reference to it — so a typed goal can never widen its own
authority.

Clean-room: this reproduces the *shape* of Strix's interactive terminal
(``strix/interface/tui/``), in original code, local-only. See
``docs/specs/interactive-shell.md``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Sequence, TextIO

from aegis.config import AegisConfig
from aegis.engines.dynamic import DynamicEngine
from aegis.engines.events import EventSink
from aegis.knowledge.base import KnowledgeBase
from aegis.knowledge.loader import load_candidates
from aegis.knowledge.models import Candidate
from aegis.redteam import EngagementScope
from aegis.redteam.http import sanitize_text

_REPO_ROOT = Path(__file__).resolve().parent.parent
_DEFAULT_TARGET = _REPO_ROOT / "data" / "sample_target"

#: The only weakness kinds a typed ``attempt`` may request. Free text is clamped
#: to this set before it reaches the red-team engine; anything else is refused.
ATTEMPT_TYPES = ("xss", "sqli", "redirect", "cmdi", "traversal", "ssti")


# --------------------------------------------------------------------------- #
# Session state — held across commands; NEVER passed into the agent loop.
# --------------------------------------------------------------------------- #
@dataclass
class SessionState:
    scope: EngagementScope
    authorized: bool
    config: AegisConfig
    sink: EventSink
    out_dir: Optional[Path] = None
    kb: KnowledgeBase = field(default_factory=KnowledgeBase)
    pool: List[Candidate] = field(default_factory=list)
    # ``registry`` is used ONLY by the live ``scan`` verb (Docker scanners); it
    # is never handed to the offline narration engine.
    registry: object = None
    # Test-only transport injected into the red-team engine for ``attempt``;
    # ``None`` in production (the engine builds its own scope-gated transport).
    transport: object = None
    steps: int = 0
    _seen_spawns: set = field(default_factory=set)


# --------------------------------------------------------------------------- #
# THE gate — every live verb funnels through this, before any network action.
# --------------------------------------------------------------------------- #
def gate(session: SessionState, target: str) -> "tuple[bool, str]":
    """Authorize one live action against ``target``. Fail-closed.

    Order: the operator's one-time ``--authorized`` assertion, then the frozen
    engagement scope (default-deny). ``check()`` returns a decision and never
    raises, so we branch on ``in_scope`` — we do not ``try/except``.
    """
    if not session.authorized:
        return (False, "not authorized — start the shell with --authorized to "
                "act against live targets you are permitted to test")
    decision = session.scope.check(target)
    if not decision.in_scope:
        return (False, f"out of scope: {decision.reason}")
    return (True, "")


# --------------------------------------------------------------------------- #
# The engine subclass — drives the loop over the current command's pool, with
# an optional operator instruction folded into the prompt STATE (not task).
# --------------------------------------------------------------------------- #
class ShellSession(DynamicEngine):
    """A :class:`DynamicEngine` driven once per operator command.

    It never wires a registry and never sets ``self._probe``, so
    :meth:`DynamicEngine.run` builds a ``SampleProbe`` over the in-hand pool —
    structurally offline (no ``RegistryProbe``, no ``tool.run``, no socket).
    """

    def __init__(self, pool: Sequence[Candidate], instruction: str = "",
                 event_sink=None) -> None:
        super().__init__(event_sink=event_sink)
        self._pool = list(pool)
        self._instruction = instruction

    def enumerate_candidates(self, target, config):  # noqa: D401
        return self._pool

    def _context(self, kb, unprobed, pending) -> str:
        base = DynamicEngine._context(kb, unprobed, pending)
        if self._instruction:
            # Fold into STATE: the router sees only state and keys its cache on
            # it, so an instruction in `task` alone would be an inert no-op.
            return f"{base} Operator instruction: {self._instruction}"
        return base


# --------------------------------------------------------------------------- #
# Terminal renderer — format/print only; never calls emit (no re-entrancy).
# --------------------------------------------------------------------------- #
def _render_event(event: dict, write: Callable[[str], None],
                  seen_spawns: set) -> None:
    """Render one event to the terminal. All target-derived text is sanitized."""
    et = event.get("type")
    aid = event.get("agent_id", "?")

    def s(key: str, limit: int = 160) -> str:
        return sanitize_text(str(event.get(key, "")), limit)

    if et == "spawn":
        if aid in seen_spawns:
            return  # muted: re-spawned each command; the JSONL keeps every line
        seen_spawns.add(aid)
        write(f"  + spawn {aid} [{s('role')}] {s('task')}")
    elif et == "assistant":
        write(f"  {aid}: {s('text')}")
    elif et == "think":
        write(f"    · think: {s('text')}")
    elif et == "tool_call":
        write(f"    → tool {s('tool')} {s('args')}")
    elif et == "tool_output":
        write(f"    ← {s('tool')}: {s('status')} ({event.get('count', 0)} cand)")
    elif et == "decision":
        write(f"    ⟐ decide {s('kind')} → {s('outcome')} "
              f"p={event.get('probability', 0)} [{s('backend')}]")
    elif et == "message":
        tgt = s("to") or s("from")
        write(f"    ✉ {aid}→{tgt}: {s('text')}")
    elif et == "finding":
        flag = " EXPLOITABLE" if event.get("exploitable") else ""
        write(f"  ! finding [{s('severity')}] {s('title')}{flag}")
    elif et == "finish":
        write(f"  = finish {aid}: {s('summary')}")
    elif et == "scope_refused" or et == "scope_check":
        write(f"    ⊘ {et}: {s('target')} in_scope={event.get('in_scope')}")
    else:  # unknown/custom types still surface, sanitized
        write(f"    · {et} {aid}")


def _make_renderer(session: SessionState, write: Callable[[str], None]):
    def on_emit(event: dict) -> None:
        _render_event(event, write, session._seen_spawns)
    return on_emit


# --------------------------------------------------------------------------- #
# Offline narration — drives the dynamic loop over a pool, no network.
# --------------------------------------------------------------------------- #
def _narrate(session: SessionState, pool: Sequence[Candidate],
             instruction: str, write: Callable[[str], None]) -> int:
    """Run the dynamic loop over ``pool`` (offline), merge findings into the
    session KB, and return the count of new accepted findings this command."""
    from aegis.analysis.backends import build_router
    from aegis.engines.base import EngineReport  # noqa: F401 (type clarity)

    session._seen_spawns = set()  # per-command spawn de-dup
    engine = ShellSession(pool, instruction=instruction, event_sink=session.sink)
    if session.config.uses_planner:
        from aegis.llm import build_llm
        engine.set_planner(build_llm(local_only=session.config.local_only))
    router = build_router(list(pool), config=session.config)
    cmd_kb = KnowledgeBase()
    engine.run("", cmd_kb, router, session.config)
    before = len(session.kb.accepted)
    session.kb.merge(cmd_kb)
    session.steps += 1
    new = len(session.kb.accepted) - before
    write(f"  ({len(cmd_kb.accepted)} finding(s) this command; "
          f"{len(session.kb.accepted)} in session)")
    return new


def _load_sample_pool() -> List[Candidate]:
    path = _DEFAULT_TARGET / "candidates_dynamic.json"
    if path.exists():
        return load_candidates(path, source_engine="dynamic")
    return []


# --------------------------------------------------------------------------- #
# Command handlers
# --------------------------------------------------------------------------- #
_HELP = """\
commands:
  help                         show this help
  scope                        print the engagement scope
  status                       session counters
  findings                     list accepted findings (session)
  transcript                   replay the event stream
  goal <text>                  narrate the loop over the in-hand pool (offline)
  focus <surface>              probe <surface> first on the next goal
  run [local-path]             offline analysis over a local path
  scan <target> [tool]         LIVE scanner (gated: --authorized + in-scope)
  attempt <type> <target> <param>   stage-1 red-team confirm (gated)
                               type ∈ xss|sqli|redirect|cmdi|traversal|ssti
  exit | quit                  leave"""


def _cmd_scope(session: SessionState, write) -> None:
    sc = session.scope
    write(f"engagement: {sc.engagement or '(unnamed)'}  "
          f"authorized_by: {sc.authorized_by or '(none)'}")
    write(f"  hosts: {sc.hosts or '[]'}")
    write(f"  urls:  {sc.urls or '[]'}")
    write(f"  deny:  {sc.deny_hosts or '[]'}")
    write(f"  max_hosts={sc.max_hosts} post_exploit={sc.allow_post_exploit} "
          f"lateral={sc.allow_lateral}")
    write(f"  authorized(session)={session.authorized}")


def _cmd_status(session: SessionState, write) -> None:
    write(f"steps={session.steps}  pool={len(session.pool)}  "
          f"accepted={len(session.kb.accepted)}  "
          f"authorized={session.authorized}  "
          f"engagement={session.scope.engagement or '(unnamed)'}  "
          f"mode={session.config.mode}")


def _cmd_findings(session: SessionState, write) -> None:
    acc = session.kb.rank() if hasattr(session.kb, "rank") else session.kb.accepted
    if not acc:
        write("  (no findings)")
        return
    for f in acc:
        flag = " EXPLOITABLE" if getattr(f, "exploitable", False) else ""
        write(f"  [{f.severity:8} {f.cvss_score:4.1f}] "
              f"{sanitize_text(f.title, 120)}{flag}")


def _cmd_transcript(session: SessionState, write) -> None:
    events = session.sink.events
    if not events:
        write("  (empty)")
        return
    for e in events:
        _render_event(e, write, set())  # replay shows every spawn


def _cmd_focus(session: SessionState, arg: str, write) -> None:
    if not arg:
        write("usage: focus <surface>")
        return
    matched = [c for c in session.pool if c.component == arg]
    if not matched:
        write(f"  no pooled surface named {arg!r} "
              f"(surfaces: {sorted({c.component for c in session.pool})})")
        return
    rest = [c for c in session.pool if c.component != arg]
    session.pool = matched + rest
    write(f"  focused {arg!r} first ({len(matched)} candidate(s))")


def _cmd_goal(session: SessionState, arg: str, write) -> None:
    pool = session.pool or _load_sample_pool()
    if not session.pool:
        session.pool = pool
    if not pool:
        write("  (no leads in pool — run a scan or `run <path>` first)")
        return
    _narrate(session, pool, arg, write)


def _cmd_run(session: SessionState, arg: str, write) -> None:
    if arg:
        p = Path(arg)
        if not p.exists():
            write(f"  refusing: {arg!r} is not an existing local path; `run` is "
                  f"offline analysis of local code/artifacts only")
            return
        src = p / "candidates_dynamic.json" if p.is_dir() else p
        pool = load_candidates(src, source_engine="dynamic") if src.exists() else []
    else:
        pool = _load_sample_pool()
    if not pool:
        write("  (no candidates found at that path)")
        return
    session.pool = pool
    _narrate(session, pool, "", write)


def _cmd_scan(session: SessionState, parts: Sequence[str], write) -> None:
    if len(parts) < 1:
        write("usage: scan <target> [tool]")
        return
    target, tool_name = parts[0], (parts[1] if len(parts) > 1 else "recon")
    ok, reason = gate(session, target)
    if not ok:
        session.sink.emit("a0001", "scope_refused", target=target,
                          in_scope=False, reason=reason)
        write(f"  REFUSED — {reason}")
        return
    try:
        from aegis.tools import default_registry
        from aegis.tools.base import DockerBackedTool
    except Exception as exc:  # noqa: BLE001
        write(f"  scan unavailable: {exc}")
        return
    reg = session.registry or default_registry()
    try:
        tool = reg.get(tool_name)
    except KeyError:
        write(f"  unknown tool {tool_name!r}; see `aegis tools`")
        return
    if not isinstance(tool, DockerBackedTool) or not getattr(
            tool, "allows_network", False):
        write(f"  tool {tool_name!r} is not a live network scanner "
              f"(image not pulled, or not a recon/web/dast tool)")
        return
    write(f"  [authorized+in-scope] {tool_name} → {target}")
    session._seen_spawns = set()
    result = tool.run(target, network="bridge", host=target, url=target)
    write(f"  status={result.status.value} candidates={len(result.candidates)}")
    if not result.ok:
        for e in result.errors:
            write(f"  ! {sanitize_text(str(e))}")
        return
    cands = list(result.candidates)
    for c in cands:
        c.source_engine = "dynamic"
    session.pool = cands
    _narrate(session, cands, "", write)


def _cmd_attempt(session: SessionState, parts: Sequence[str], write) -> None:
    if len(parts) < 3:
        write("usage: attempt <type> <target> <param>")
        return
    kind, target, param = parts[0], parts[1], parts[2]
    if kind not in ATTEMPT_TYPES:
        write(f"  refusing: unknown weakness type {kind!r}; "
              f"choose one of {'|'.join(ATTEMPT_TYPES)}")
        return
    ok, reason = gate(session, target)  # authorized + scope, before any probe
    if not ok:
        session.sink.emit("a0003", "scope_refused", target=target,
                          in_scope=False, reason=reason)
        write(f"  REFUSED — {reason}")
        return
    from aegis.redteam import RedTeamEngine

    def _bridge(e: dict) -> None:
        # Dispatcher-thread emit (outside any on_emit) → one level deep, safe.
        etype = e.get("event", "event")
        session.sink.emit("a0003", etype,
                          **{k: v for k, v in e.items() if k != "event"})

    engine = RedTeamEngine(session.scope, transport=session.transport,
                           on_event=_bridge)
    result = engine.attempt(kind, target, param)
    if not result.in_scope:
        write(f"  REFUSED — {sanitize_text(result.note)}")
        return
    if not result.attempted:
        write(f"  {sanitize_text(result.note)}")
        return
    status = "CONFIRMED" if result.verified else "not confirmed"
    write(f"  {status}  [{result.cwe}]  {result.requests} request(s)")
    if result.proof:
        write(f"  proof: {sanitize_text(result.proof)}")
    for e in result.evidence:
        write(f"    - {sanitize_text(e)}")


# --------------------------------------------------------------------------- #
# The REPL
# --------------------------------------------------------------------------- #
def run_shell(session: SessionState, stdin: TextIO, stdout: TextIO) -> int:
    """Read commands until exit/EOF. Always returns 0 (clean exit)."""
    def write(line: str = "") -> None:
        print(line, file=stdout)

    write("aegis shell — interactive agent REPL (type `help`, `exit` to leave)")
    _cmd_scope(session, write)
    write("")

    for raw in stdin:
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        verb, rest = parts[0].lower(), parts[1:]
        arg = line[len(parts[0]):].strip()

        if verb in ("exit", "quit"):
            break
        elif verb == "help":
            write(_HELP)
        elif verb == "scope":
            _cmd_scope(session, write)
        elif verb == "status":
            _cmd_status(session, write)
        elif verb == "findings":
            _cmd_findings(session, write)
        elif verb == "transcript":
            _cmd_transcript(session, write)
        elif verb == "goal":
            _cmd_goal(session, arg, write)
        elif verb == "focus":
            _cmd_focus(session, arg, write)
        elif verb == "run":
            _cmd_run(session, arg, write)
        elif verb == "scan":
            _cmd_scan(session, rest, write)
        elif verb == "attempt":
            _cmd_attempt(session, rest, write)
        else:
            write(f"  unknown command {verb!r}; type `help`")

    write("bye")
    return 0


__all__ = ["SessionState", "ShellSession", "gate", "run_shell", "ATTEMPT_TYPES"]
