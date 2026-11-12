"""``aegis shell`` — an interactive, Strix-style REPL over the dynamic loop.

The operator types one command per line; the agent streams its transcript live
to the terminal; and **every live action funnels through one scope +
authorization gate, enforced structurally at the dispatcher** (a verb table
marks each live verb, so a future verb cannot forget the gate). Session state
(the frozen engagement scope, the one-time ``--authorized`` assertion, config,
the shared knowledge base) is held for the life of the process, but the agent
loop is handed only ``(target, kb, router, config, sink)`` — never the scope or
the authorization flag — so a typed goal cannot widen its own authority.

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
# Session state — held across commands; only `config` and `sink` are ever
# handed to the agent loop (never `scope` or `authorized`).
# --------------------------------------------------------------------------- #
@dataclass
class SessionState:
    scope: EngagementScope
    authorized: bool
    config: AegisConfig
    sink: EventSink
    out_dir: Optional[Path] = None
    kb: KnowledgeBase = field(default_factory=KnowledgeBase)
    #: ``None`` means "no target ever loaded this session" (fall back to the
    #: bundled sample for offline narration). An empty list means "a real run
    #: set the pool and it found nothing" — the sample is NOT substituted then,
    #: so a scan that finds nothing can never be back-filled with demo data.
    pool: Optional[List[Candidate]] = None
    # Used ONLY by the live ``scan`` verb (Docker scanners); never handed to the
    # offline narration engine.
    registry: object = None
    # Test-only transport injected into the red-team engine for ``attempt``.
    transport: object = None
    steps: int = 0
    _seen_keys: set = field(default_factory=set)


# --------------------------------------------------------------------------- #
# THE gate — the dispatcher calls this before any live verb's handler runs.
# --------------------------------------------------------------------------- #
def authorize(scope: EngagementScope, authorized: bool,
              target: str) -> "tuple[bool, str]":
    """The single authorization decision for one live action. Fail-closed.

    Order: the operator's one-time ``--authorized`` assertion, then the frozen
    engagement scope (default-deny). ``check()`` returns a decision and never
    raises, so we branch on ``in_scope`` — we do not ``try/except``. Shared by
    the shell dispatcher and the autonomous agent so there is one gate.
    """
    if not authorized:
        return (False, "not authorized — pass --authorized to act against live "
                "targets you are permitted to test")
    decision = scope.check(target)
    if not decision.in_scope:
        return (False, f"out of scope: {decision.reason}")
    return (True, "")


def gate(session: SessionState, target: str) -> "tuple[bool, str]":
    """Authorize one live action for a shell session (see :func:`authorize`)."""
    return authorize(session.scope, session.authorized, target)


# --------------------------------------------------------------------------- #
# The engine subclass — drives the loop over the current command's pool, with
# an optional operator instruction folded into the prompt STATE (not task).
# --------------------------------------------------------------------------- #
class ShellSession(DynamicEngine):
    """A :class:`DynamicEngine` driven once per operator command.

    It never wires a registry and never sets ``self._probe``, so
    :meth:`DynamicEngine.run` builds a ``SampleProbe`` over the in-hand pool —
    no ``RegistryProbe`` and no ``tool.run``, i.e. no traffic to the *target*.
    (Under ``--mode full-llm|llm+decision`` the loop still contacts the
    configured planner endpoint — loopback under ``local_only``.)
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
# Terminal renderer — format/print only; closes over `write` alone (never the
# session), and never calls emit (no re-entrancy under the sink lock).
# --------------------------------------------------------------------------- #
def _render_event(event: dict, write: Callable[[str], None]) -> None:
    """Render one event to the terminal. All target-derived text is sanitized."""
    et = event.get("type")
    aid = event.get("agent_id", "?")

    def s(key: str, limit: int = 160) -> str:
        return sanitize_text(str(event.get(key, "")), limit)

    if et == "spawn":
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
    elif et in ("scope_refused", "auth_refused", "scope_check"):
        write(f"    ⊘ {et}: {s('target')} ({s('reason')})")
    else:  # unknown/custom types still surface, sanitized
        write(f"    · {et} {aid}")


def _make_renderer(write: Callable[[str], None]):
    def on_emit(event: dict) -> None:
        _render_event(event, write)
    return on_emit


# --------------------------------------------------------------------------- #
# Offline narration — drives the dynamic loop over a pool (no target traffic).
# --------------------------------------------------------------------------- #
def _finding_key(f) -> tuple:
    comp = getattr(getattr(f, "candidate", None), "component", "")
    return (getattr(f, "title", ""), comp)


def run_narration(pool: Sequence[Candidate], config: AegisConfig, sink,
                  instruction: str = ""):
    """Drive the dynamic loop once over ``pool`` into a fresh KnowledgeBase.

    Reused by the shell's ``goal`` verb and by the autonomous agent for its
    per-phase triage. Returns ``(cmd_kb, router)``. Offline (static mode) this
    is deterministic and generates no target traffic.
    """
    from aegis.analysis.backends import build_router

    engine = ShellSession(pool, instruction=instruction, event_sink=sink)
    if config.uses_planner:
        from aegis.llm import build_llm
        engine.set_planner(build_llm(local_only=config.local_only))
    router = build_router(list(pool), config=config)
    cmd_kb = KnowledgeBase()
    engine.run("", cmd_kb, router, config)
    return cmd_kb, router


def fold_findings(session_kb: KnowledgeBase, cmd_kb: KnowledgeBase,
                  seen_keys: set) -> int:
    """Fold a command's accepted findings into a session KB, deduped by
    (title, component). Returns the count of genuinely new findings."""
    new = 0
    for f in cmd_kb.accepted:
        key = _finding_key(f)
        if key in seen_keys:
            continue
        seen_keys.add(key)
        session_kb.add_finding(f)
        new += 1
    return new


def _narrate(session: SessionState, pool: Sequence[Candidate],
             instruction: str, write: Callable[[str], None]) -> int:
    """Run the dynamic loop over ``pool``, then fold *new* accepted findings
    into the session KB (deduped so a repeated goal does not double-count)."""
    cmd_kb, _ = run_narration(pool, session.config, session.sink, instruction)
    new = fold_findings(session.kb, cmd_kb, session._seen_keys)
    session.steps += 1
    write(f"  ({len(cmd_kb.accepted)} finding(s) this command; {new} new; "
          f"{len(session.kb.accepted)} in session)")
    return new


def _load_sample_pool() -> List[Candidate]:
    path = _DEFAULT_TARGET / "candidates_dynamic.json"
    if path.exists():
        return load_candidates(path, source_engine="dynamic")
    return []


# --------------------------------------------------------------------------- #
# Command handlers — uniform signature (session, parts, arg, write).
# --------------------------------------------------------------------------- #
def _h_help(session, parts, arg, write) -> None:
    write(_HELP)


def _h_scope(session, parts, arg, write) -> None:
    sc = session.scope
    write(f"engagement: {sc.engagement or '(unnamed)'}  "
          f"authorized_by: {sc.authorized_by or '(none)'}")
    write(f"  hosts: {sc.hosts or '[]'}")
    write(f"  urls:  {sc.urls or '[]'}")
    write(f"  deny:  {sc.deny_hosts or '[]'}")
    write(f"  max_hosts={sc.max_hosts} post_exploit={sc.allow_post_exploit} "
          f"lateral={sc.allow_lateral}")
    write(f"  authorized(session)={session.authorized}")


def _h_status(session, parts, arg, write) -> None:
    write(f"steps={session.steps}  pool={len(session.pool or [])}  "
          f"accepted={len(session.kb.accepted)}  "
          f"authorized={session.authorized}  "
          f"engagement={session.scope.engagement or '(unnamed)'}  "
          f"mode={session.config.mode}")


def _h_findings(session, parts, arg, write) -> None:
    acc = session.kb.rank() if hasattr(session.kb, "rank") else session.kb.accepted
    if not acc:
        write("  (no findings)")
        return
    for f in acc:
        flag = " EXPLOITABLE" if getattr(f, "exploitable", False) else ""
        write(f"  [{f.severity:8} {f.cvss_score:4.1f}] "
              f"{sanitize_text(f.title, 120)}{flag}")


def _h_transcript(session, parts, arg, write) -> None:
    events = session.sink.events
    if not events:
        write("  (empty)")
        return
    for e in events:
        _render_event(e, write)


def _h_focus(session, parts, arg, write) -> None:
    if not arg:
        write("usage: focus <surface>")
        return
    pool = session.pool or []
    matched = [c for c in pool if c.component == arg]
    if not matched:
        write(f"  no pooled surface named {arg!r} "
              f"(surfaces: {sorted({c.component for c in pool})})")
        return
    session.pool = matched + [c for c in pool if c.component != arg]
    write(f"  focused {arg!r} first ({len(matched)} candidate(s))")


def _h_goal(session, parts, arg, write) -> None:
    if session.pool is None:
        session.pool = _load_sample_pool()
    pool = session.pool
    if not pool:
        write("  (no leads in pool — run a scan or `run <path>` first)")
        return
    _narrate(session, pool, arg, write)


def _h_run(session, parts, arg, write) -> None:
    if arg:
        p = Path(arg)
        if not p.exists():
            write(f"  refusing: {arg!r} is not an existing local path; `run` is "
                  f"offline analysis of local code/artifacts only")
            return
        src = p / "candidates_dynamic.json" if p.is_dir() else p
        try:
            pool = load_candidates(src, source_engine="dynamic") if src.exists() \
                else []
        except (ValueError, OSError) as exc:
            write(f"  could not load candidates from {arg!r}: "
                  f"{sanitize_text(str(exc), 160)}")
            return
    else:
        pool = _load_sample_pool()
    if not pool:
        write("  (no candidates found at that path)")
        return
    session.pool = pool
    _narrate(session, pool, "", write)


def _h_scan(session, parts, arg, write) -> None:
    # The dispatcher has already gated parts[0]; this handler assumes authorized
    # + in-scope. It only runs network scanners through a Docker adapter.
    target, tool_name = parts[0], (parts[1] if len(parts) > 1 else "recon")
    try:
        from aegis.tools import default_registry
        from aegis.tools.base import DockerBackedTool
    except Exception as exc:  # noqa: BLE001
        write(f"  scan unavailable: {sanitize_text(str(exc), 160)}")
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
    write(f"  [authorized+in-scope] {tool_name} → {sanitize_text(target, 160)}")
    result = tool.run(target, network="bridge", host=target, url=target)
    write(f"  status={result.status.value} candidates={len(result.candidates)}")
    if not result.ok:
        for e in result.errors:
            write(f"  ! {sanitize_text(str(e))}")
        return
    cands = list(result.candidates)
    for c in cands:
        c.source_engine = "dynamic"
    session.pool = cands  # may be [] — a real empty result, never back-filled
    _narrate(session, cands, "", write)


def _h_agent(session, parts, arg, write) -> None:
    # The dispatcher has already gated parts[0] (authorized + in-scope). Runs
    # the autonomous driver, streaming; at the confirm-to-exploit gate it reads
    # the NEXT line from the REPL's stdin as the go/no-go answer.
    from aegis.agent import drive_agent

    target = parts[0]
    goal = " ".join(parts[1:]) if len(parts) > 1 else ""
    confirm = getattr(session, "_read_line", None)
    outcome = drive_agent(
        target=target, goal=goal, scope=session.scope,
        authorized=session.authorized, exploit=False, config=session.config,
        sink=session.sink, kb=session.kb, write=write,
        registry=session.registry, transport=session.transport, confirm=confirm)
    session.steps += 1
    fold = len(session.kb.accepted)
    write(f"  agent done: {outcome.findings} finding(s) this run; "
          f"{len(outcome.attempted)} attempt(s); {fold} in session.")


def _h_attempt(session, parts, arg, write) -> None:
    # The dispatcher has already gated parts[1] (authorized + in-scope). The
    # type is clamped here; the red-team engine re-checks scope (defense in
    # depth) and routes every request through its scope-gated transport.
    kind, target, param = parts[0], parts[1], parts[2]
    if kind not in ATTEMPT_TYPES:
        write(f"  refusing: unknown weakness type {kind!r}; "
              f"choose one of {'|'.join(ATTEMPT_TYPES)}")
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
    # attempt honours the engagement scope's post-exploit / lateral switches
    # (default off); surface their results rather than hiding that they ran.
    pe = result.post_exploit
    if pe and pe.get("ran"):
        write("  -- post-exploit (read-only proof) --")
        if pe.get("flag"):
            write(f"  FLAG [{sanitize_text(pe.get('flag_path', ''))}]: "
                  f"{sanitize_text(pe.get('flag', ''))}")
    lat = result.lateral
    if lat and lat.get("ran"):
        write("  -- lateral movement (in-scope only, read-only) --")
        for h in lat.get("refused_out_of_scope", []):
            write(f"    refused (out of scope, not touched): {sanitize_text(h)}")
        for pv in lat.get("pivots", []):
            reach = "reachable" if pv.get("reachable") else "no response"
            line = f"    pivot {sanitize_text(pv.get('url', ''))} → {reach}"
            if pv.get("flag"):
                line += f"  FLAG: {sanitize_text(pv.get('flag', ''))}"
            write(line)


# --------------------------------------------------------------------------- #
# The verb table — the single source of truth for dispatch. ``live`` marks a
# verb that reaches the network; the dispatcher gates it (and only it) before
# the handler runs. ``target`` extracts the gated target from the parts list.
# --------------------------------------------------------------------------- #
@dataclass
class _Verb:
    handler: Callable
    live: bool = False
    target: Optional[Callable[[Sequence[str]], Optional[str]]] = None
    usage: str = ""


_VERBS = {
    "help": _Verb(_h_help),
    "scope": _Verb(_h_scope),
    "status": _Verb(_h_status),
    "findings": _Verb(_h_findings),
    "transcript": _Verb(_h_transcript),
    "focus": _Verb(_h_focus),
    "goal": _Verb(_h_goal),
    "run": _Verb(_h_run),
    "scan": _Verb(
        _h_scan, live=True, usage="usage: scan <target> [tool]",
        target=lambda parts: parts[0] if len(parts) >= 1 else None),
    "attempt": _Verb(
        _h_attempt, live=True, usage="usage: attempt <type> <target> <param>",
        target=lambda parts: parts[1] if len(parts) >= 3 else None),
    "agent": _Verb(
        _h_agent, live=True, usage="usage: agent <target> [goal...]",
        target=lambda parts: parts[0] if len(parts) >= 1 else None),
}


_HELP = """\
commands:
  help                         show this help
  scope                        print the engagement scope
  status                       session counters
  findings                     list accepted findings (session)
  transcript                   replay the event stream
  goal <text>                  narrate the loop over the pool (no target
                               traffic; uses the local model under LLM modes)
  focus <surface>              probe <surface> first on the next goal
  run [local-path]             offline analysis over a local path
  scan <target> [tool]         LIVE scanner (gated: --authorized + in-scope)
  attempt <type> <target> <param>   stage-1 red-team confirm (gated)
                               type ∈ xss|sqli|redirect|cmdi|traversal|ssti
  agent <target> [goal...]     autonomous: chain scanners, triage, then pause
                               for `go` before sending stage-1 exploit probes
  exit | quit                  leave"""


# --------------------------------------------------------------------------- #
# The REPL — one structural gate for live verbs, and every command guarded so
# a single bad command (or a hostile live response) can never kill the session.
# --------------------------------------------------------------------------- #
def run_shell(session: SessionState, stdin: TextIO, stdout: TextIO) -> int:
    """Read commands until exit/EOF. Always returns 0 (clean exit)."""
    def write(line: str = "") -> None:
        print(line, file=stdout)

    write("aegis shell — interactive agent REPL (type `help`, `exit` to leave)")
    _h_scope(session, [], "", write)
    write("")

    # The autonomous `agent` verb reads its go/no-go confirmation from the next
    # REPL line; expose a reader over the same stdin iterator.
    session._read_line = lambda: next(stdin, "")

    for raw in stdin:
        line = raw.strip()
        if not line:
            continue
        parts = line.split()
        verb = parts[0].lower()
        rest = parts[1:]
        arg = line[len(parts[0]):].strip()

        if verb in ("exit", "quit"):
            break
        spec = _VERBS.get(verb)
        if spec is None:
            write(f"  unknown command {verb!r}; type `help`")
            continue
        try:
            if spec.live:
                target = spec.target(rest)
                if target is None:
                    write(spec.usage)
                    continue
                ok, reason = gate(session, target)
                if not ok:
                    etype = "scope_refused" if session.authorized \
                        else "auth_refused"
                    session.sink.emit("a0001", etype,
                                      target=sanitize_text(target, 160),
                                      reason=reason)
                    write(f"  REFUSED — {reason}")
                    continue
            spec.handler(session, rest, arg, write)
        except Exception as exc:  # a bad command never kills the session
            write(f"  error: {sanitize_text(str(exc), 200)}")

    write("bye")
    return 0


__all__ = ["SessionState", "ShellSession", "gate", "run_shell", "ATTEMPT_TYPES"]
