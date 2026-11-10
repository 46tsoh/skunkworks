"""Stage-1 red-team engine: scope-gated exploit → verify, then stop at proof.

Given a weakness lead (a finding kind + a target URL + a parameter), the engine:

1. **Checks scope** — refuses and audits anything not in the engagement scope.
2. Picks the matching :mod:`~aegis.redteam.techniques` technique.
3. Sends a few bounded, non-destructive probes through a
   :class:`~aegis.redteam.http.ScopeGatedTransport` (a second scope check).
4. **Verifies** the result against an observable oracle and **stops at proof**.

No shell, no persistence, no lateral movement — those are later stages, gated by
the scope file's ``allow_post_exploit`` / ``allow_lateral`` switches (both
default off). Every decision and probe is recorded for the audit log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, List, Optional

from aegis.redteam.http import ScopeGatedTransport, Transport, UrllibTransport
from aegis.redteam.scope import EngagementScope, ScopeDecision
from aegis.redteam.techniques import Technique, VerifyResult, technique_for


@dataclass
class ExploitResult:
    target: str
    param: str
    kind: str
    in_scope: bool
    attempted: bool
    verified: bool
    technique: str = ""
    cwe: str = ""
    proof: str = ""
    evidence: List[str] = field(default_factory=list)
    requests: int = 0
    note: str = ""
    post_exploit: Optional[dict] = None   # stage-2 result, when it ran
    lateral: Optional[dict] = None        # stage-3 result, when it ran

    def as_dict(self) -> dict:
        return {"target": self.target, "param": self.param, "kind": self.kind,
                "in_scope": self.in_scope, "attempted": self.attempted,
                "verified": self.verified, "technique": self.technique,
                "cwe": self.cwe, "proof": self.proof, "evidence": self.evidence,
                "requests": self.requests, "note": self.note,
                "post_exploit": self.post_exploit, "lateral": self.lateral}


class RedTeamEngine:
    """Scope-gated stage-1 exploitation. Construct with a scope; attempt leads."""

    def __init__(self, scope: EngagementScope,
                 transport: Optional[Transport] = None,
                 on_event: Optional[Callable[[dict], None]] = None,
                 flag_paths: Optional[List[str]] = None) -> None:
        self._scope = scope
        self._on_event = on_event
        self._flag_paths = flag_paths
        # The network is reachable only through a scope-gated transport.
        inner = transport if transport is not None else UrllibTransport()
        self._transport = ScopeGatedTransport(
            inner, scope, on_refuse=lambda d: self._emit("scope_refused",
                                                         d.as_dict()))

    def _emit(self, kind: str, data: dict) -> None:
        if self._on_event:
            self._on_event({"event": kind, **data})

    def attempt(self, kind: str, target: str, param: str) -> ExploitResult:
        """Attempt to confirm one weakness ``kind`` on ``target``'s ``param``."""
        decision: ScopeDecision = self._scope.check(target)
        self._emit("scope_check", decision.as_dict())
        if not decision.in_scope:
            return ExploitResult(target, param, kind, in_scope=False,
                                 attempted=False, verified=False,
                                 note=f"refused (out of scope): {decision.reason}")

        tech: Optional[Technique] = technique_for(kind)
        if tech is None:
            return ExploitResult(target, param, kind, in_scope=True,
                                 attempted=False, verified=False,
                                 note=f"no stage-1 technique for kind {kind!r}")

        self._emit("exploit_start",
                   {"target": target, "param": param, "technique": tech.name})
        vr: VerifyResult = tech.run(self._transport, target, param)
        result = ExploitResult(
            target, param, kind, in_scope=True, attempted=True,
            verified=vr.verified, technique=vr.technique, cwe=vr.cwe,
            proof=vr.proof, evidence=list(vr.evidence), requests=vr.requests,
            note="" if vr.verified else "not confirmed")

        # Stage 2 — post-exploitation. Runs ONLY when the foothold is verified
        # AND the engagement scope opted in (allow_post_exploit, default off).
        # Currently: read-only flag retrieval through a command-injection
        # foothold with a sequence-capable payload.
        if result.verified and self._scope.allow_post_exploit:
            self._maybe_post_exploit(result, vr)
        elif result.verified and vr.context.get("seq"):
            result.note = ("foothold confirmed; post-exploit not run "
                           "(scope allow_post_exploit is off)")

        # Stage 3 — lateral movement. Runs ONLY on a sequence-capable cmdi
        # foothold AND when the scope opted in (allow_lateral, default off).
        # Pivots read-only to IN-SCOPE hosts only, bounded by max_hosts.
        if (result.verified and self._scope.allow_lateral
                and vr.technique == "cmdi" and vr.context.get("seq")):
            self._maybe_lateral(result, vr)
        elif (result.verified and self._scope.allow_post_exploit
              and vr.technique == "cmdi" and vr.context.get("seq")):
            result.note += " (lateral off)"

        self._emit("exploit_result", result.as_dict())
        return result

    def _foothold_runner(self, result: ExploitResult, vr: VerifyResult):
        """A callable that runs one command through the confirmed foothold, via
        the scope-gated transport."""
        from aegis.redteam.postexploit import run_command
        template = vr.context["template"]
        return lambda cmd: run_command(self._transport, result.target,
                                       result.param, template, cmd)

    def _maybe_post_exploit(self, result: ExploitResult,
                            vr: VerifyResult) -> None:
        # Only a sequence-capable command-injection foothold drives stage 2.
        if vr.technique != "cmdi" or not vr.context.get("seq"):
            return
        from aegis.redteam.postexploit import retrieve_flag
        self._emit("post_exploit_start",
                   {"target": result.target, "param": result.param})
        pe = retrieve_flag(self._transport, result.target, result.param,
                           template=vr.context["template"],
                           flag_paths=self._flag_paths)
        result.post_exploit = pe.as_dict()
        result.requests += pe.requests
        if pe.flag:
            result.note = (f"post-exploit: flag retrieved from "
                           f"{pe.flag_path or '?'}")
        else:
            result.note = f"post-exploit ran: {pe.note}"
        self._emit("post_exploit_result", pe.as_dict())

    def _maybe_lateral(self, result: ExploitResult, vr: VerifyResult) -> None:
        from urllib.parse import urlparse
        from aegis.redteam.lateral import move_laterally
        origin = urlparse(result.target).hostname or ""
        self._emit("lateral_start",
                   {"origin": origin, "max_hosts": self._scope.max_hosts})
        lat = move_laterally(self._scope, self._foothold_runner(result, vr),
                             origin_host=origin, max_hosts=self._scope.max_hosts)
        result.lateral = lat.as_dict()
        result.requests += lat.requests
        # Append — don't clobber the stage-2 post-exploit note when both ran.
        result.note = (f"{result.note} | lateral: {lat.note}".strip(" |")
                       if result.note else f"lateral: {lat.note}")
        self._emit("lateral_result", lat.as_dict())


__all__ = ["ExploitResult", "RedTeamEngine"]
