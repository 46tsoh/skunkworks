"""Stage-3 lateral movement: pivot ONLY to hosts already in the engagement scope.

Runs only when a command-injection foothold is confirmed AND the scope sets
``allow_lateral``. From the foothold it does read-only reconnaissance (which
other hosts are reachable) and then, for each **in-scope** pivot target, fetches
a page read-only *through the foothold* to prove network reach — bounded by
``max_hosts``.

The load-bearing guarantee: **scope never auto-expands.** A host discovered from
the compromised machine (e.g. in ``/etc/hosts``) is attacker-influenced data; it
is ACTED ON only if it is already in the scope file. Anything out of scope is
recorded as "seen, refused" and never touched — discovery can observe the wider
network, but action is confined to what the operator authorized. Pivot targets
come from the scope's own ``urls`` (operator-declared, port-complete, in-scope by
construction); discovery only ever adds evidence and refusals, never new targets.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, List, Optional
from urllib.parse import urlparse

from aegis.redteam.http import sanitize_text
from aegis.redteam.postexploit import _FLAG_RX
from aegis.redteam.scope import EngagementScope

# A URL we splice into a `curl '<url>'` command (single-quoted) must be printable
# ASCII with no whitespace and NO single-quote — single-quoting then neutralizes
# every other shell metacharacter, so a crafted URL can't break out of the quotes.
_SAFE_URL = re.compile(r"\A[\x21-\x7e]+\Z")
# Matches an IPv4/hostname token in `/etc/hosts`-style recon output.
_HOST_TOKEN = re.compile(r"\A[A-Za-z0-9_.:-]+\Z")
# RunCmd: run one command through the foothold, return stdout or None.
RunCmd = Callable[[str], Optional[str]]


@dataclass
class PivotResult:
    url: str
    host: str
    reachable: bool = False
    flag: str = ""
    detail: str = ""


@dataclass
class LateralResult:
    ran: bool = False
    discovered: List[str] = field(default_factory=list)       # hosts seen via recon
    refused_out_of_scope: List[str] = field(default_factory=list)
    pivots: List[PivotResult] = field(default_factory=list)   # in-scope, acted on
    capped: List[str] = field(default_factory=list)           # skipped by max_hosts
    requests: int = 0
    note: str = ""

    def as_dict(self) -> dict:
        return {"ran": self.ran, "discovered": self.discovered,
                "refused_out_of_scope": self.refused_out_of_scope,
                "pivots": [{"url": p.url, "host": p.host, "reachable": p.reachable,
                            "flag": p.flag, "detail": p.detail} for p in self.pivots],
                "capped": self.capped, "requests": self.requests, "note": self.note}


def _safe_url(url: str) -> bool:
    if not url or len(url) > 2048 or "'" in url or not _SAFE_URL.match(url):
        return False
    p = urlparse(url)
    return p.scheme in ("http", "https") and bool(p.hostname)


def discover_hosts(run_cmd: RunCmd) -> List[str]:
    """Read-only recon: enumerate hosts the foothold can see (parses /etc/hosts).

    Returns observed host tokens as DATA only — the caller decides what, if
    anything, is in scope. Never acts on the result directly.
    """
    out = run_cmd("cat /etc/hosts")
    hosts: List[str] = []
    for line in (out or "").splitlines():
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        for tok in line.split():              # address + all its names
            if _HOST_TOKEN.match(tok) and tok not in hosts:
                hosts.append(tok)
    return hosts[:64]


def _in_scope_url_hosts(scope: EngagementScope) -> set:
    """Lowercased hostnames of the scope's own in-scope urls (deny-respecting)."""
    out = set()
    for u in scope.urls:
        if scope.is_in_scope(u):           # honours deny + url-prefix match
            hn = urlparse(u).hostname
            if hn:
                out.add(hn.lower())
    return out


def move_laterally(scope: EngagementScope, run_cmd: RunCmd, origin_host: str,
                   max_hosts: int) -> LateralResult:
    """Pivot read-only to in-scope hosts reachable from the foothold."""
    res = LateralResult(ran=True)
    url_hosts = _in_scope_url_hosts(scope)

    def _host_in_scope(h: str) -> bool:
        # A discovered host is in scope if it matches a hosts/CIDR entry OR is
        # the host of one of the scope's own urls. (scope.is_in_scope on a BARE
        # host only consults scope.hosts, never scope.urls — so a url-only host
        # would otherwise be wrongly flagged out-of-scope AND still pivoted to.)
        return scope.is_in_scope(h) or (bool(h) and h.lower() in url_hosts)

    # 1) Recon (evidence only). Record which discovered hosts are OUT of scope
    #    so the "no auto-expand" guarantee is visible and auditable.
    seen = discover_hosts(run_cmd)
    res.requests += 1
    res.discovered = [sanitize_text(h, 128) for h in seen]
    for h in seen:
        if h and h != origin_host and not _host_in_scope(h):
            s = sanitize_text(h, 128)
            if s not in res.refused_out_of_scope:
                res.refused_out_of_scope.append(s)

    # 2) Actionable pivot targets come from the SCOPE's own urls (in-scope by
    #    construction, port-complete), excluding the origin host. Discovery never
    #    adds a target — it only observes and refuses.
    targets = []
    unsafe_skipped = 0
    for url in scope.urls:
        host = (urlparse(url).hostname or "")
        if not host or host == origin_host:
            continue
        # defense in depth: the target URL must itself be in scope
        if not scope.is_in_scope(url):
            continue
        if not _safe_url(url):
            unsafe_skipped += 1   # in scope but unsafe to splice into a command
            continue
        targets.append((url, host))

    # 3) Bound by max_hosts — never silently; the excess is logged.
    limit = max(0, int(max_hosts))
    if len(targets) > limit:
        for url, host in targets[limit:]:
            res.capped.append(sanitize_text(url, 256))
        targets = targets[:limit]

    # 4) Read-only reach proof through the foothold: fetch each target's page.
    #    The URL is single-quoted (and validated quote-free) so no shell
    #    metacharacter in it can break out of the curl command.
    for url, host in targets:
        body = run_cmd(f"curl -s -S --max-time 5 '{url}'")
        res.requests += 1
        pr = PivotResult(url=sanitize_text(url, 256), host=sanitize_text(host, 128))
        if body is not None and body.strip():
            pr.reachable = True
            pr.detail = sanitize_text(body.strip()[:160], 200)
            m = _FLAG_RX.search(body)
            if m:
                pr.flag = sanitize_text(m.group(0), 256)
        else:
            pr.detail = "no response via foothold"
        res.pivots.append(pr)

    reached = sum(1 for p in res.pivots if p.reachable)
    flags = sum(1 for p in res.pivots if p.flag)
    res.note = (f"pivoted to {len(res.pivots)} in-scope host(s): {reached} "
                f"reachable, {flags} flag(s); {len(res.refused_out_of_scope)} "
                f"out-of-scope host(s) refused")
    if unsafe_skipped:
        res.note += f"; skipped-unsafe-url x{unsafe_skipped}"
    return res


__all__ = ["PivotResult", "LateralResult", "discover_hosts", "move_laterally",
           "RunCmd"]
