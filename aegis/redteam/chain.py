"""Autonomous attack chaining — a bounded, scope-safe attack tree (milestone 26).

This module composes the existing read-only stage-1/2/3 primitives into a
*dependency graph* in which one confirmed step's typed, untrusted artifacts
become the preconditions of the next. It adds **orchestration and typed
artifact-passing, not new offensive reach**: every live action still goes
through the exact same triple gate (``authorize`` + ``scope.check`` +
``ScopeGatedTransport``) on the exact per-step target bytes, at every depth.

See ``docs/specs/attack-chaining.md`` (the authoritative design). The one
load-bearing new control is the **derivation clamp** (:func:`clamp_op` /
:func:`derive_targets` / :func:`match_trusted`): the planner — or an
attacker-influenced artifact — may *propose*, but a pure clamp over a trusted
finite set the caller owns *disposes*, fail-closed. An extracted value can seed
a hypothesis; it can never by itself authorize an action, become a
target/command/arg, or enter the scope.

Safety invariants realized here (proved in the spec, enforced by code + tests):

* **Scope never auto-expands.** There is no scope mutator anywhere; ``trusted``
  is computed once from the frozen operator scope and never grows. A discovered
  out-of-scope host is logged (``discovered_refused``) and never contacted.
* **Every artifact is untrusted.** Its ``role`` fixes the one position it may
  ever flow into. ``file``/``flag`` values are terminal data — they are NEVER
  turned into a target/command/arg. Only scanner-structured ``surface`` values
  and in-scope-proven ``host_reach`` values ever seed a new *action*, and only
  after a fresh ``scope.is_in_scope`` re-check on the operator's own bytes.
* **The planner never receives ``scope``/``authorized``.** Its whole vocabulary
  is pick-an-op (a ``CHAIN_OPS`` key gated by stage opt-in) and order-the-
  frontier (an index into the code-built frontier). Offline it is absent.
* **Bounded + terminating.** ``max_depth``/``max_breadth``/``max_steps``/
  ``max_requests``/``deadline`` are code/operator-owned; the monotone ``seen``
  set over a finite dedup-key space makes the frontier terminate.

Clean-room, local-only. New module; reuses ``engine``/``postexploit``/
``lateral``/``techniques``/``scope`` verbatim.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import parse_qs, urlparse

from aegis.redteam.http import sanitize_text
from aegis.redteam.scope import EngagementScope, _canon_host
from aegis.redteam.techniques import technique_for

# --------------------------------------------------------------------------- #
# §3 — the chain data model. All vocabularies are closed/enumerated.
# --------------------------------------------------------------------------- #
#: The typed roles an :class:`Artifact` may carry. ``credential`` is DEFERRED to
#: M27 (see spec §8): it is defined here so the vocabulary is complete and the
#: deferral is explicit, but it is never minted or consumed in M26.
ARTIFACT_ROLES = frozenset({
    "foothold",    # a confirmed sequence-capable cmdi (drives extract/pivot)
    "surface",     # an in-scope URL minted ONLY from a scanner-structured candidate
    "host_reach",  # an in-scope host proven reachable by move_laterally
    "file",        # a file body read by stage-2 (attacker-controlled DATA)
    "flag",        # a captured flag (terminal evidence)
    "credential",  # DEFERRED to M27 — not minted or consumed in M26
})

#: Roles that in M26 only ever carry terminal DATA — never a seed for an action.
_TERMINAL_ROLES = frozenset({"file", "flag", "credential"})

# A length cap on every artifact value (defense against log/transcript bloat and
# injection; values are also sanitize_text'd at mint).
_VALUE_CAP = 512


@dataclass(frozen=True)
class Artifact:
    """The typed, **untrusted/attacker-influenced** output of a step.

    ``role`` fixes which position the value may ever flow into (§5). ``meta`` is
    ENGINE-INTERNAL (e.g. the cmdi template, the cached ExploitResult, the
    scanner-structured kind/param used to route a confirm) and is **never**
    serialized to the planner, transcript, or report.
    """

    role: str
    value: str
    origin_step: str
    meta: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        # meta is deliberately excluded — it may hold the foothold template /
        # cached result and must never reach the planner/transcript/report.
        return {"role": self.role, "value": self.value,
                "origin_step": self.origin_step}


def make_artifact(role: str, value: str, origin_step: str,
                  meta: Optional[dict] = None) -> Artifact:
    """Mint an artifact, ``sanitize_text``'ing and length-bounding the value."""
    if role not in ARTIFACT_ROLES:
        raise ValueError(f"unknown artifact role {role!r}")
    return Artifact(role=role, value=sanitize_text(str(value), _VALUE_CAP),
                    origin_step=origin_step, meta=dict(meta or {}))


@dataclass
class ChainStep:
    """One node in the attack tree. ``target`` is ALWAYS operator-derived (§5)."""

    id: str
    op: str
    target: str
    param: str = ""
    inputs: Tuple[Artifact, ...] = ()
    depth: int = 0
    parent_id: Optional[str] = None
    status: str = "pending"   # pending|refused_scope|refused_derivation|
    #                           attempted|confirmed|unconfirmed|capped|skipped_dup
    requests: int = 0
    produced: List[Artifact] = field(default_factory=list)
    result: Optional[dict] = None
    note: str = ""
    # engine-internal routing (kind for a confirm); never serialized.
    kind: str = ""

    def as_dict(self) -> dict:
        return {
            "id": self.id, "op": self.op,
            "target": sanitize_text(self.target, 256), "param": self.param,
            "inputs": [a.as_dict() for a in self.inputs],
            "depth": self.depth, "parent_id": self.parent_id,
            "status": self.status, "requests": self.requests,
            "produced": [a.as_dict() for a in self.produced],
            "result": self.result, "note": sanitize_text(self.note, 400),
        }


@dataclass
class ChainBudget:
    """All code/operator-owned bounds. Never planner-influenced."""

    max_depth: int = 0        # DEFAULT 0 ⇒ degenerate to today's flat loop
    max_breadth: int = 4      # children promoted per node (also ≤ scope.max_hosts)
    max_steps: int = 16       # total nodes; excess logged "capped", never dropped
    max_requests: int = 512   # summed across steps — hard anti-DoS wall
    deadline: Optional[float] = None  # monotonic-clock cap (see run_chain)

    def as_dict(self) -> dict:
        return {"max_depth": self.max_depth, "max_breadth": self.max_breadth,
                "max_steps": self.max_steps, "max_requests": self.max_requests,
                "deadline": self.deadline}


# --------------------------------------------------------------------------- #
# §5 — CHAIN_OPS registry. A closed set with NO destructive/write member.
# Each op declares which artifact roles it NEEDS, which it PRODUCES, and a GATE
# that reads the frozen scope's per-stage opt-in (checked FIRST, like
# clamp_depth's active_allowed). ``confirm``/``retriage`` are always available
# (gated only by authorize + scope at dispatch); ``extract``/``pivot`` require
# the operator's per-stage switch.
# --------------------------------------------------------------------------- #
@dataclass(frozen=True)
class _Op:
    name: str
    needs: Tuple[str, ...]
    produces: Tuple[str, ...]
    gate: Callable[[EngagementScope], bool]


CHAIN_OPS: Dict[str, _Op] = {
    "confirm": _Op("confirm", needs=(), produces=("foothold",),
                   gate=lambda s: True),
    "extract": _Op("extract", needs=("foothold",), produces=("file", "flag"),
                   gate=lambda s: bool(s.allow_post_exploit)),
    "pivot": _Op("pivot", needs=("foothold",), produces=("host_reach",),
                 gate=lambda s: bool(s.allow_lateral)),
    "retriage": _Op("retriage", needs=("host_reach",), produces=("surface",),
                    gate=lambda s: True),
}


# --------------------------------------------------------------------------- #
# §5 — the derivation clamp. Three pure, no-I/O functions: the planner (or an
# artifact) PROPOSES; a clamp over a trusted finite set the caller owns
# DISPOSES; fail-closed. Direct generalization of clamp_phases / clamp_depth.
# --------------------------------------------------------------------------- #
def clamp_op(proposed: object, scope: EngagementScope) -> Optional[str]:
    """Clamp an arbitrary op proposal to a stage-enabled ``CHAIN_OPS`` key.

    Pure, no I/O. The returned value is ALWAYS drawn from ``CHAIN_OPS`` (never
    from ``proposed``): a ``str`` is a case-folded membership test against the
    ops whose stage the operator opted into; an ``int`` (not ``bool``) is an
    index into that same allowed tuple; anything else → ``None`` (fail-closed).
    Mirrors :func:`aegis.llm.clamp_phases` exactly — the stage gate is checked
    FIRST, so a disabled stage can never be selected, and a planner can never
    introduce an op.
    """
    allowed = tuple(k for k in CHAIN_OPS if CHAIN_OPS[k].gate(scope))
    if not allowed:
        return None
    if isinstance(proposed, bool):
        return None  # bool is an int subclass: never an index
    if isinstance(proposed, int):
        return allowed[proposed] if 0 <= proposed < len(allowed) else None
    if isinstance(proposed, str):
        key = proposed.strip().lower()
        return key if key in allowed else None
    return None


def match_trusted(candidate_host: str, trusted: Tuple[str, ...]) -> Optional[str]:
    """Return the TRUSTED element whose canonical host equals ``candidate_host``'s.

    NEVER returns its argument (like :func:`clamp_phases` returning
    ``allowed[i]``, never the proposed token). This is the chokepoint that makes
    an attacker-influenced host token only ever *select* a pre-existing operator
    entry — never author a new one. Returns ``None`` when no trusted element
    matches (fail-closed).
    """
    want = _canon_host(_host_of(candidate_host))
    if not want:
        return None
    for element in trusted:
        if _canon_host(_host_of(element)) == want:
            return element   # the OPERATOR's bytes, never the candidate's
    return None


@dataclass(frozen=True)
class _Cand:
    """A derived, already-vetted candidate step (code-built, never planner-text)."""
    op: str
    target: str
    param: str
    inputs: Tuple[Artifact, ...]
    kind: str = ""


def _host_of(target: str) -> str:
    t = (target or "").strip()
    if "://" in t:
        return urlparse(t).hostname or ""
    host = t.split("/", 1)[0]          # strip any path on a bare host[/path]
    if host.count(":") == 1:           # host:port (IPv6 has several colons)
        host = host.split(":", 1)[0]
    return host


def _dedup_key(op: str, target: str, param: str,
               inputs: Tuple[Artifact, ...]) -> tuple:
    return (op, target, param, tuple(sorted(a.role for a in inputs)))


def _in_trusted(target: str, scope: EngagementScope,
                trusted: Tuple[str, ...]) -> bool:
    """True iff ``target`` is in scope AND introduces no host not already in the
    frozen trusted set — the provable "never a new authority" membership."""
    if not scope.is_in_scope(target):
        return False
    host = _canon_host(_host_of(target))
    if not host:
        return False
    trusted_hosts = {_canon_host(_host_of(t)) for t in trusted}
    trusted_hosts.discard("")
    return host in trusted_hosts


def build_trusted(scope: EngagementScope) -> Tuple[str, ...]:
    """Compute the CLOSED trusted set ONCE from the frozen operator scope.

    Operator data only — the scope's own in-scope ``urls`` and ``hosts``. Never
    recomputed from an artifact and never grows (there is no mutator). An
    artifact can only ever *select* a member of this set (via ``scope.is_in_scope``
    + :func:`match_trusted`); it can never *add* one.
    """
    out: List[str] = []
    for u in scope.urls:
        if scope.is_in_scope(u) and u not in out:
            out.append(u)
    for h in scope.hosts:
        if h not in out:
            out.append(h)
    return tuple(out)


def derive_targets(op: str, parent: ChainStep, scope: EngagementScope,
                   trusted: Tuple[str, ...], seen: set) -> List[_Cand]:
    """Build candidate ``(op, target, param, inputs)`` for ``op`` from ``parent``.

    The trust boundary for the TARGET ITSELF: code — not the planner, not a
    response body — builds each candidate from a trusted source and re-checks it
    with ``scope.is_in_scope`` before admission. **Every returned target is in
    scope and introduces no host outside the frozen trusted set.** An attacker-
    influenced extracted value is only ever (a) pattern-classified into a role,
    (b) membership-tested against ``trusted``, or (c) carried as opaque
    evidence — never concatenated/formatted into a URL, command, argv, or scope.
    """
    built: List[_Cand] = []
    if op == "confirm":
        # Targets are `surface` artifacts the parent produced: a SCANNER-
        # STRUCTURED candidate component that is an http(s) URL AND in scope
        # (exactly attemptable()'s discipline). The URL is operator-host bytes
        # re-checked; kind/param ride in meta (engine-internal routing).
        for art in parent.produced:
            if art.role != "surface":
                continue
            tgt = art.value
            if not tgt.startswith(("http://", "https://")):
                continue
            built.append(_Cand("confirm", tgt, str(art.meta.get("param", "")),
                               (art,), kind=str(art.meta.get("kind", ""))))
    elif op == "extract":
        # Target/param are the parent FOOTHOLD's OWN already-confirmed-in-scope
        # (target, param). No new target is introduced.
        for art in parent.produced:
            if art.role != "foothold":
                continue
            built.append(_Cand("extract", art.meta.get("target", parent.target),
                               art.meta.get("param", parent.param), (art,)))
    elif op == "pivot":
        # One pivot step per foothold; its execution reuses move_laterally, which
        # draws its own targets from scope.urls (never a discovered token). The
        # step target is the foothold's own in-scope host.
        for art in parent.produced:
            if art.role != "foothold":
                continue
            built.append(_Cand("pivot", art.meta.get("target", parent.target),
                               art.meta.get("param", parent.param), (art,)))
    elif op == "retriage":
        # Target is a host_reach artifact RESOLVED to a member of `trusted` via
        # match_trusted — re-scan an ALREADY-in-scope host for fresh surface.
        for art in parent.produced:
            if art.role != "host_reach":
                continue
            resolved = match_trusted(art.value, trusted)   # operator bytes, not art's
            if resolved is None:
                continue
            built.append(_Cand("retriage", resolved, "", (art,)))

    # The one chokepoint, and the property the tests pin: provable set
    # membership + exact-bytes scope re-check + dedup. Fail-closed throughout.
    out: List[_Cand] = []
    for c in built:
        if not _in_trusted(c.target, scope, trusted):
            continue
        if _dedup_key(c.op, c.target, c.param, c.inputs) in seen:
            continue
        out.append(c)
    return out


def clamp_choice(proposed: object,
                 frontier: List[ChainStep]) -> Optional[ChainStep]:
    """Select a step from the CODE-BUILT frontier. The planner only orders.

    An ``int`` (not ``bool``) indexes the frontier; a ``str`` matches a step id;
    anything else → ``None``. So even "which to pursue next" is a selection among
    already-vetted, scope-checked options, never free text. Offline, the
    deterministic BFS order needs no planner (the caller just pops ``frontier[0]``).
    """
    if not frontier:
        return None
    if isinstance(proposed, bool):
        return None
    if isinstance(proposed, int):
        return frontier[proposed] if 0 <= proposed < len(frontier) else None
    if isinstance(proposed, str):
        for step in frontier:
            if step.id == proposed:
                return step
        return None
    return None


# --------------------------------------------------------------------------- #
# §3 — the graph.
# --------------------------------------------------------------------------- #
@dataclass
class ChainGraph:
    nodes: Dict[str, ChainStep] = field(default_factory=dict)
    edges: List[Tuple[str, str]] = field(default_factory=list)
    frontier: List[str] = field(default_factory=list)
    seen: set = field(default_factory=set)
    trusted: Tuple[str, ...] = ()
    budget: ChainBudget = field(default_factory=ChainBudget)
    discovered_refused: List[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        """The full attack tree → ``report.json`` ``metrics.agent.chain``.

        Every node, edge, per-step decision, every refused host "seen, refused,
        not touched", and every cap is reconstructable; artifact ``meta`` is
        never included.
        """
        return {
            "nodes": [self.nodes[i].as_dict() for i in self._order()],
            "edges": [list(e) for e in self.edges],
            "trusted": [sanitize_text(t, 256) for t in self.trusted],
            "budget": self.budget.as_dict(),
            "discovered_refused": list(self.discovered_refused),
            "counts": self._counts(),
        }

    def _order(self) -> List[str]:
        # deterministic: insertion order (dicts preserve it) is BFS discovery order
        return list(self.nodes.keys())

    def _counts(self) -> dict:
        c: Dict[str, int] = {}
        for s in self.nodes.values():
            c[s.status] = c.get(s.status, 0) + 1
        return {
            "steps": len(self.nodes),
            "requests": sum(s.requests for s in self.nodes.values()),
            "by_status": c,
            "flags": sum(1 for s in self.nodes.values()
                         for a in s.produced if a.role == "flag"),
            "footholds": sum(1 for s in self.nodes.values()
                             for a in s.produced if a.role == "foothold"),
            "max_depth_reached": max((s.depth for s in self.nodes.values()),
                                     default=0),
        }


# --------------------------------------------------------------------------- #
# §4/§6 — the bounded BFS driver. Every live action re-authorizes on the exact
# per-step target bytes; stage escalation is operator-opt-in via the frozen
# scope; the loop halts on an empty frontier or any hard bound.
# --------------------------------------------------------------------------- #
def run_chain(
    *,
    scope: EngagementScope,
    authorized: bool,
    engine,
    initial_leads: List[dict],
    budget: ChainBudget,
    scanner_fn: Optional[Callable[[str], Optional[list]]] = None,
    authorize_fn: Optional[Callable[[EngagementScope, bool, str],
                                    "tuple[bool, str]"]] = None,
    planner: Optional[Callable[[List[ChainStep]], object]] = None,
    sink=None,
    write: Optional[Callable[[str], None]] = None,
    now_fn: Callable[[], float] = time.monotonic,
) -> ChainGraph:
    """Run the bounded attack chain to completion; return the full graph.

    ``engine`` is a :class:`~aegis.redteam.engine.RedTeamEngine` (scope-gated).
    ``initial_leads`` are the TRIAGE leads (``{type,target,param,id}``) — each
    becomes a depth-0 ``confirm``. ``scanner_fn(target) -> candidates`` is the
    gated re-scan used by ``retriage`` (``None`` ⇒ retriage produces nothing;
    offline tests inject a fake). ``planner`` (optional) only ORDERS the
    code-built frontier via :func:`clamp_choice`; it never receives scope/auth
    and can never author a target. With ``budget.max_depth == 0`` this is
    byte-for-byte today's flat confirm loop (the regression lock).
    """
    authorize_fn = authorize_fn or _default_authorize
    graph = ChainGraph(trusted=build_trusted(scope), budget=budget)

    def _w(line: str) -> None:
        if write:
            write(line)

    def _emit(event: str, **kw) -> None:
        if sink is not None:
            sink.emit("a0005", event, **kw)

    def _bounds_hit() -> Optional[str]:
        if len(graph.nodes) >= budget.max_steps:
            return "max_steps"
        if sum(s.requests for s in graph.nodes.values()) >= budget.max_requests:
            return "max_requests"
        if budget.deadline is not None and now_fn() >= budget.deadline:
            return "deadline"
        return None

    _emit("chain_start", trusted=len(graph.trusted),
          max_depth=budget.max_depth, max_steps=budget.max_steps,
          max_requests=budget.max_requests)
    _w(f"  [chain] start — {len(graph.trusted)} trusted target(s), "
       f"max_depth={budget.max_depth}, max_steps={budget.max_steps}")

    seq = [0]

    def _new_id(depth: int) -> str:
        sid = f"c{depth:02d}-{seq[0]:03d}"
        seq[0] += 1
        return sid

    def _register(step: ChainStep) -> None:
        graph.nodes[step.id] = step
        if step.parent_id is not None:
            graph.edges.append((step.parent_id, step.id))
            _emit("chain_edge", parent=step.parent_id, child=step.id)

    # Seed the frontier with a depth-0 confirm per initial lead.
    for lead in initial_leads:
        sid = _new_id(0)
        step = ChainStep(id=sid, op="confirm", target=str(lead.get("target", "")),
                         param=str(lead.get("param", "")), depth=0,
                         kind=str(lead.get("type", "")))
        key = _dedup_key("confirm", step.target, step.param, ())
        if key in graph.seen:
            step.status = "skipped_dup"
            _register(step)
            continue
        graph.seen.add(key)
        _register(step)
        graph.frontier.append(sid)

    # The BFS loop. `seen` makes the frontier monotone; the hard caps and the
    # finite dedup-key space make termination provable.
    while graph.frontier:
        bound = _bounds_hit()
        if bound is not None:
            for sid in graph.frontier:
                graph.nodes[sid].status = "capped"
                graph.nodes[sid].note = f"capped: {bound}"
                _emit("chain_capped", step=sid, reason=bound)
            _w(f"  [chain] stopped: {bound} — "
               f"{len(graph.frontier)} pending step(s) capped")
            graph.frontier = []
            break

        # Planner (if any) ORDERS the frontier; offline it is strict BFS (pop 0).
        pending = [graph.nodes[i] for i in graph.frontier]
        chosen = None
        if planner is not None:
            try:
                chosen = clamp_choice(planner(list(pending)), pending)
            except Exception:  # noqa: BLE001 — a planner must never crash the loop
                chosen = None
        if chosen is None:
            chosen = pending[0]
        graph.frontier.remove(chosen.id)
        step = chosen

        _emit("chain_node_open", step=step.id, op=step.op, depth=step.depth,
              target=sanitize_text(step.target, 160))

        # §4(3): re-authorize on the EXACT per-step target bytes, every depth.
        ok, reason = authorize_fn(scope, authorized, step.target)
        if not ok:
            step.status = "refused_scope"
            step.note = f"refused: {reason}"
            _emit("chain_node_result", step=step.id, status=step.status,
                  reason=sanitize_text(reason, 160))
            _w(f"  [chain] {step.id} {step.op} REFUSED {step.target} — {reason}")
            continue

        _dispatch(step, scope, engine, scanner_fn, graph, _emit, _w)

        # Expand the frontier from this step's produced artifacts (if any), BFS.
        if step.depth < budget.max_depth and step.status == "confirmed":
            _expand(step, scope, graph, budget, _new_id, _register, _emit)

    _emit("chain_done", **graph._counts())
    _w(f"  [chain] done — {graph._counts()['steps']} step(s), "
       f"{graph._counts()['flags']} flag(s), "
       f"{graph._counts()['requests']} request(s)")
    return graph


def _default_authorize(scope: EngagementScope, authorized: bool, target: str):
    from aegis.shell import authorize
    return authorize(scope, authorized, target)


def _dispatch(step: ChainStep, scope: EngagementScope, engine, scanner_fn,
              graph: ChainGraph, emit, write) -> None:
    """Run one admissible step through its existing primitive, fold artifacts."""
    if step.op == "confirm":
        _run_confirm(step, engine, emit)
    elif step.op == "extract":
        _run_extract(step, emit)
    elif step.op == "pivot":
        _run_pivot(step, graph, emit)
    elif step.op == "retriage":
        _run_retriage(step, scope, scanner_fn, emit)
    else:  # unreachable: clamp_op/derive only ever yield CHAIN_OPS keys
        step.status = "refused_derivation"
        step.note = f"unknown op {step.op!r}"
    emit("chain_node_result", step=step.id, status=step.status,
         requests=step.requests,
         produced=[a.role for a in step.produced])
    write(f"  [chain] {step.id} {step.op} [{step.status}] "
          f"{sanitize_text(step.target, 120)}"
          + (f" → {[a.role for a in step.produced]}" if step.produced else ""))


def _run_confirm(step: ChainStep, engine, emit) -> None:
    res = engine.attempt(step.kind or "", step.target, step.param)
    rd = res.as_dict()
    step.requests = int(rd.get("requests", 0) or 0)
    if not rd.get("in_scope", False):
        step.status = "refused_scope"
        step.note = rd.get("note", "refused (out of scope)")
        return
    if not rd.get("attempted", False):
        step.status = "unconfirmed"
        step.note = rd.get("note", "not attempted")
        return
    if rd.get("verified"):
        step.status = "confirmed"
        step.note = sanitize_text(rd.get("proof", "") or rd.get("note", ""), 300)
        # Mint a foothold ONLY for a sequence-capable cmdi (the thing that drives
        # extract/pivot). The cached ExploitResult (incl. the stage-2/3 output the
        # engine already produced) rides in meta, engine-internal, never serialized.
        if rd.get("technique") == "cmdi":
            step.produced.append(make_artifact(
                "foothold", f"{step.target} ({step.param})", step.id,
                meta={"result": rd, "target": step.target, "param": step.param}))
    else:
        step.status = "unconfirmed"
        step.note = sanitize_text(rd.get("note", "not confirmed"), 300)
    # The ExploitResult carries attacker-influenced data; store the gated,
    # sanitized dict (never meta) as the step result for the audit.
    step.result = rd


def _run_extract(step: ChainStep, emit) -> None:
    """Re-feed the stage-2 post-exploit the engine already produced on the
    foothold (no new traffic, no re-plumbing): mint flag/file artifacts."""
    foothold = _first(step.inputs, "foothold")
    pe = (foothold.meta.get("result") or {}).get("post_exploit") if foothold else None
    if not pe:
        step.status = "unconfirmed"
        step.note = "post-exploit not available (scope off or not seq-capable)"
        step.result = {"post_exploit": None}
        return
    step.result = {"post_exploit": pe}
    if pe.get("flag"):
        step.produced.append(make_artifact(
            "flag", pe["flag"], step.id,
            meta={"flag_path": pe.get("flag_path", "")}))
    for f in pe.get("files_read", []) or []:
        step.produced.append(make_artifact(
            "file", f.get("content", ""), step.id,
            meta={"path": f.get("path", "")}))
    step.status = "confirmed" if step.produced else "unconfirmed"
    step.note = ("extracted " + ", ".join(sorted({a.role for a in step.produced}))
                 if step.produced else "post-exploit ran, nothing extracted")


def _run_pivot(step: ChainStep, graph: ChainGraph, emit) -> None:
    """Re-feed the stage-3 lateral movement the engine already produced: mint a
    host_reach artifact per REACHABLE in-scope host; record every out-of-scope
    host as "seen, refused, not touched" (scope unchanged)."""
    foothold = _first(step.inputs, "foothold")
    lat = (foothold.meta.get("result") or {}).get("lateral") if foothold else None
    if not lat:
        step.status = "unconfirmed"
        step.note = "lateral not available (scope off or not seq-capable)"
        step.result = {"lateral": None}
        return
    step.result = {"lateral": lat}
    for host in lat.get("refused_out_of_scope", []) or []:
        if host not in graph.discovered_refused:
            graph.discovered_refused.append(host)
            emit("discovered_refused", host=sanitize_text(str(host), 128))
    for p in lat.get("pivots", []) or []:
        if p.get("reachable"):
            step.produced.append(make_artifact(
                "host_reach", p.get("url", ""), step.id,
                meta={"host": p.get("host", "")}))
        if p.get("flag"):
            step.produced.append(make_artifact("flag", p["flag"], step.id))
    step.status = "confirmed" if step.produced else "unconfirmed"
    step.note = (f"pivot proved {sum(1 for a in step.produced if a.role == 'host_reach')}"
                 f" in-scope host(s) reachable; "
                 f"{len(lat.get('refused_out_of_scope', []) or [])} refused")


def _run_retriage(step: ChainStep, scope: EngagementScope, scanner_fn, emit) -> None:
    """Re-scan an ALREADY-in-scope host (gated) and mint `surface` artifacts
    ONLY from scanner-structured candidate components that are in scope — never
    from parsed body text."""
    if scanner_fn is None:
        step.status = "unconfirmed"
        step.note = "no scanner available for retriage"
        return
    cands = scanner_fn(step.target)
    if cands is None:
        step.status = "unconfirmed"
        step.note = "retriage scan errored/unavailable"
        return
    step.requests = 0  # the scanner's own egress; chain counts attempt traffic
    for cand in cands:
        lead = _lead_from_candidate(cand, scope)
        if lead is None:
            continue
        tech, url, param = lead
        step.produced.append(make_artifact(
            "surface", url, step.id, meta={"kind": tech, "param": param}))
    step.status = "confirmed" if step.produced else "unconfirmed"
    step.note = (f"retriage surfaced {len(step.produced)} in-scope lead(s)"
                 if step.produced else "retriage found no auto-targetable surface")
    step.result = {"surfaces": [a.value for a in step.produced]}


def _expand(step: ChainStep, scope: EngagementScope, graph: ChainGraph,
            budget: ChainBudget, new_id, register, emit) -> None:
    """Promote children for every op whose stage the operator enabled and whose
    required inputs this step produced (BFS, bounded by breadth/dedup)."""
    promoted = 0
    cap = max(0, budget.max_breadth)
    for op_name, op in CHAIN_OPS.items():
        if not op.gate(scope):          # stage opt-in FIRST (clamp_op discipline)
            continue
        if not op.needs:
            continue                    # confirm is only ever a seed/surface child
        # the step must have produced at least one artifact of each needed role
        if not all(any(a.role == r for a in step.produced) for r in op.needs):
            continue
        for cand in derive_targets(op_name, step, scope, graph.trusted, graph.seen):
            if promoted >= cap:
                emit("chain_capped", step=step.id, reason="max_breadth")
                return
            child = ChainStep(
                id=new_id(step.depth + 1), op=cand.op, target=cand.target,
                param=cand.param, inputs=cand.inputs, depth=step.depth + 1,
                parent_id=step.id, kind=cand.kind)
            graph.seen.add(_dedup_key(cand.op, cand.target, cand.param, cand.inputs))
            register(child)
            graph.frontier.append(child.id)
            promoted += 1
    # surface children (confirm) come from a retriage parent, which produces
    # `surface` artifacts; schedule a confirm per surface.
    if step.op == "retriage":
        for cand in derive_targets("confirm", step, scope, graph.trusted, graph.seen):
            if promoted >= cap:
                emit("chain_capped", step=step.id, reason="max_breadth")
                return
            child = ChainStep(
                id=new_id(step.depth + 1), op="confirm", target=cand.target,
                param=cand.param, inputs=cand.inputs, depth=step.depth + 1,
                parent_id=step.id, kind=cand.kind)
            graph.seen.add(_dedup_key("confirm", cand.target, cand.param, cand.inputs))
            register(child)
            graph.frontier.append(child.id)
            promoted += 1


def _first(inputs: Tuple[Artifact, ...], role: str) -> Optional[Artifact]:
    for a in inputs:
        if a.role == role:
            return a
    return None


def _lead_from_candidate(cand, scope: EngagementScope):
    """Candidate-level mirror of :func:`aegis.agent.attemptable`: a scanner-
    structured in-scope http(s) URL + a technique + a param, or ``None``."""
    tech = technique_for(getattr(cand, "cwe", "")) or technique_for(
        getattr(cand, "title", ""))
    if tech is None:
        return None
    target = getattr(cand, "component", "")
    if not isinstance(target, str) or not target.startswith(("http://", "https://")):
        return None
    if not scope.is_in_scope(target):   # re-check the scanner-structured bytes
        return None
    param = (getattr(cand, "metadata", {}) or {}).get("param")
    if not param:
        qs = parse_qs(urlparse(target).query, keep_blank_values=True)
        param = next(iter(qs), None)
    if not param:
        return None
    return (tech.name, target, str(param))


__all__ = [
    "ARTIFACT_ROLES", "Artifact", "make_artifact", "ChainStep", "ChainBudget",
    "ChainGraph", "CHAIN_OPS", "clamp_op", "clamp_choice", "match_trusted",
    "derive_targets", "build_trusted", "run_chain",
]
