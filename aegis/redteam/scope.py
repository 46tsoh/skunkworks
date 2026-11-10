"""Engagement scope — the load-bearing authorization control for offensive work.

Every offensive action in the red-team engine is checked against an operator-
declared :class:`EngagementScope` and **refused unless the target is explicitly
in scope**. There is no "attack everything" mode: an empty or missing scope
authorizes nothing (default-deny), an explicit deny always wins over any allow,
and host matching is by real subnet membership (``ipaddress``), never substring
(so ``target.htb.evil.com`` never matches ``target.htb``).

The scope is data the operator supplies, never something inferred from a page, a
finding, or tool output. See docs/specs/red-team-engine.md.
"""

from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse


class ScopeError(Exception):
    """A scope file is missing, malformed, or cannot be parsed."""


@dataclass(frozen=True)
class ScopeDecision:
    """The result of checking one target against the scope."""

    target: str
    in_scope: bool
    reason: str

    def as_dict(self) -> dict:
        return {"target": self.target, "in_scope": self.in_scope,
                "reason": self.reason}


def _canon_host(host: str) -> str:
    """Canonicalize a host for matching, or return "" if it is unusable.

    Lowercases, strips a single trailing dot (FQDN form), IDNA-encodes a unicode
    hostname, and refuses anything containing ``/``, ``@``, or whitespace (which
    would signal a malformed/smuggled host). "" means "no usable host" → the
    caller fails closed (refuses the target).
    """
    h = (host or "").strip()
    if not h:
        return ""
    if any(c.isspace() for c in h) or "/" in h or "@" in h:
        return ""
    h = h.rstrip(".").lower()
    if not h:
        return ""
    # Canonicalize an IP literal (incl. bracketed IPv6) to its canonical text so
    # it matches IP/CIDR rules; IDNA-encode a real hostname.
    ip = _as_ip(h.strip("[]"))
    if ip is not None:
        return str(ip)
    try:
        return h.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return ""  # un-encodable hostname → refuse


def _host_of(target: str) -> str:
    """Extract and canonicalize the host from a URL or a bare host[:port].

    Uses urlparse for URL forms so userinfo (``user@host``) and ports are
    handled correctly — ``http://target.htb@evil.com/`` yields ``evil.com``, not
    ``target.htb``. Returns "" when no usable host can be parsed.
    """
    t = (target or "").strip()
    if "://" in t:
        return _canon_host(urlparse(t).hostname or "")
    # Bare host[:port]. Bracketed IPv6 (``[::1]`` / ``[::1]:80``) vs host:port.
    if t.startswith("["):
        return _canon_host(t[1:].split("]", 1)[0])  # inside the brackets
    if t.count(":") == 1:  # exactly one colon ⇒ host:port (IPv6 has several)
        t = t.split(":", 1)[0]
    return _canon_host(t)


def _as_network(value: str):
    """Parse an allow entry as an IP network, or None if it is a hostname."""
    try:
        # strict=False so a host address like 10.0.0.5 is accepted as /32.
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None


def _as_ip(value: str):
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


_DEFAULT_PORTS = {"http": 80, "https": 443, "ftp": 21, "ws": 80, "wss": 443}


def _eff_port(parsed) -> Optional[int]:
    """Effective port: the explicit port, else the scheme's default."""
    try:
        if parsed.port is not None:
            return parsed.port
    except ValueError:
        return None  # malformed port
    return _DEFAULT_PORTS.get((parsed.scheme or "").lower())


def _norm_path(path: str) -> List[str]:
    """Percent-decode unreserved chars and resolve dot-segments to a seg list.

    Returns path segments (no empties), so a prefix check is segment-wise and a
    target cannot escape a prefix with ``..`` or sneak past it with ``%2e``.
    """
    from urllib.parse import unquote
    decoded = unquote(path or "")
    out: List[str] = []
    for seg in decoded.split("/"):
        if seg in ("", "."):
            continue
        if seg == "..":
            if out:
                out.pop()
            continue
        out.append(seg)
    return out


def _url_match(target: str, prefix: str) -> bool:
    """True iff ``target`` is within the URL ``prefix`` (scheme+host+port+path).

    Exact scheme, exact host (case-insensitive), equal effective port, and a
    segment-wise path prefix. Userinfo in the target is refused (an allowlist
    bypass vector). A prefix with no host never matches.
    """
    tu, pu = urlparse(target), urlparse(prefix)
    if not pu.hostname:
        return False
    if tu.username or tu.password:  # user@host smuggling → refuse
        return False
    if (tu.scheme or "").lower() != (pu.scheme or "").lower():
        return False
    if _canon_host(tu.hostname or "") != _canon_host(pu.hostname):
        return False
    if _eff_port(tu) != _eff_port(pu):
        return False
    tseg, pseg = _norm_path(tu.path), _norm_path(pu.path)
    return tseg[:len(pseg)] == pseg


@dataclass(frozen=True)
class EngagementScope:
    """What a red-team run is authorized to touch, and how far it may go.

    Default-deny: an instance with no allowed hosts/urls authorizes nothing.
    """

    engagement: str = ""
    authorized_by: str = ""
    expires: Optional[datetime] = None
    hosts: List[str] = field(default_factory=list)      # exact hosts / CIDRs
    urls: List[str] = field(default_factory=list)       # URL prefixes
    deny_hosts: List[str] = field(default_factory=list)  # never-touch (wins)
    max_hosts: int = 1
    allow_lateral: bool = False
    allow_post_exploit: bool = False

    # -- expiry -------------------------------------------------------------
    def is_expired(self, now: Optional[datetime] = None) -> bool:
        if self.expires is None:
            return False
        now = now or datetime.now(timezone.utc)
        exp = self.expires
        # Treat a naive expiry as UTC so comparison never raises.
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        return now > exp

    # -- the one question that gates every offensive action ----------------
    def check(self, target: str, *, now: Optional[datetime] = None) -> ScopeDecision:
        """Decide whether ``target`` may be acted on. Default-deny.

        Order: expiry → explicit deny → allow (host/CIDR or URL prefix) → deny.
        """
        host = _host_of(target)
        if self.is_expired(now):
            return ScopeDecision(target, False, "engagement scope has expired")
        if not host and "://" not in (target or ""):
            return ScopeDecision(target, False, "no host could be parsed from target")

        # Explicit deny wins over any allow.
        if host and self._host_matches(host, self.deny_hosts):
            return ScopeDecision(target, False, f"host {host!r} is explicitly denied")

        # URL-prefix allow (for web targets) — full parse, never substring.
        t = (target or "").strip()
        if "://" in t:
            for prefix in self.urls:
                if _url_match(t, prefix):
                    return ScopeDecision(target, True, f"matches url prefix {prefix!r}")

        # Host / CIDR allow.
        if host and self._host_matches(host, self.hosts):
            return ScopeDecision(target, True, f"host {host!r} is in scope")

        return ScopeDecision(target, False, "target is not in the engagement scope")

    def is_in_scope(self, target: str, *, now: Optional[datetime] = None) -> bool:
        return self.check(target, now=now).in_scope

    @staticmethod
    def _host_matches(host: str, entries: List[str]) -> bool:
        ip = _as_ip(host)
        for entry in entries:
            net = _as_network(entry)
            if net is not None:
                # entry is an IP or CIDR: match only real IP targets by membership.
                if ip is not None and ip in net:
                    return True
                continue
            # entry is a hostname: exact match on canonicalized forms.
            if host and host == _canon_host(entry):
                return True
        return False


def _coerce(raw: dict, source: str) -> EngagementScope:
    if not isinstance(raw, dict):
        raise ScopeError(f"{source}: scope must be a mapping/object")
    targets = raw.get("targets") or {}
    deny = raw.get("deny") or {}
    limits = raw.get("limits") or {}
    expires_raw = raw.get("expires")
    expires = None
    if expires_raw:
        try:
            # Accept a trailing 'Z' (UTC) that fromisoformat historically rejects.
            expires = datetime.fromisoformat(str(expires_raw).replace("Z", "+00:00"))
        except ValueError as exc:
            raise ScopeError(f"{source}: bad expires {expires_raw!r}: {exc}")

    def _list(d, key):
        v = (d or {}).get(key) or []
        if not isinstance(v, list):
            raise ScopeError(f"{source}: {key!r} must be a list")
        return [str(x).strip() for x in v if str(x).strip()]

    hosts = _list(targets, "hosts")
    urls = _list(targets, "urls")
    deny_hosts = _list(deny, "hosts")

    # Fail closed on an unusable host entry rather than silently dropping it
    # (a dropped allow would under-authorize; a dropped deny would OVER-authorize).
    def _ip_form(e):
        return _as_network(e) is not None

    for e in hosts + deny_hosts:
        if not _ip_form(e) and not _canon_host(e):
            raise ScopeError(f"{source}: unusable host entry {e!r}")

    # Every URL prefix must carry a host (else it would match by path alone).
    for u in urls:
        if not urlparse(u).hostname:
            raise ScopeError(f"{source}: url prefix {u!r} has no host")

    # Coherence: a deny entry can only restrict targets expressed in the same
    # form (we do not resolve DNS here, which would add a rebinding surface). So
    # refuse a scope that mixes an IP/CIDR deny with hostname allows, or a
    # hostname deny with IP/CIDR allows — otherwise the deny could be silently
    # unenforceable against a differently-expressed target.
    allow_ip = any(_ip_form(e) for e in hosts)
    allow_name = any(not _ip_form(e) for e in hosts)
    for e in deny_hosts:
        if _ip_form(e) and allow_name and not allow_ip:
            raise ScopeError(
                f"{source}: deny entry {e!r} is an IP/CIDR but allowed hosts are "
                f"names; express deny in the same form as the allow list")
        if not _ip_form(e) and allow_ip and not allow_name:
            raise ScopeError(
                f"{source}: deny entry {e!r} is a hostname but allowed hosts are "
                f"IPs/CIDRs; express deny in the same form as the allow list")

    return EngagementScope(
        engagement=str(raw.get("engagement", "")),
        authorized_by=str(raw.get("authorized_by", "")),
        expires=expires,
        hosts=hosts,
        urls=urls,
        deny_hosts=deny_hosts,
        max_hosts=int(limits.get("max_hosts", 1) or 1),
        allow_lateral=bool(limits.get("allow_lateral", False)),
        allow_post_exploit=bool(limits.get("allow_post_exploit", False)),
    )


def load_scope(path) -> EngagementScope:
    """Load an engagement scope from a JSON (always) or YAML (if available) file.

    Raises :class:`ScopeError` on anything wrong — a missing file, bad syntax, or
    a YAML file when PyYAML is not installed — so a run never silently proceeds
    with no real scope (which, being default-deny, would refuse everything).
    """
    p = Path(path)
    if not p.exists():
        raise ScopeError(f"scope file {p} not found")
    text = p.read_text(encoding="utf-8")
    suffix = p.suffix.lower()
    data = None
    if suffix in (".yaml", ".yml"):
        try:
            import yaml  # optional; JSON is always supported
        except ImportError:
            raise ScopeError(
                f"{p}: YAML scope files need PyYAML; install it or use JSON")
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise ScopeError(f"{p}: invalid YAML: {exc}")
    else:
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            # A JSON parse of a YAML file gives a confusing error; hint at it.
            raise ScopeError(f"{p}: invalid JSON: {exc} "
                             f"(use a .yaml/.yml extension for YAML)")
    if data is None:
        raise ScopeError(f"{p}: scope file is empty (default-deny authorizes "
                         f"nothing)")
    return _coerce(data, str(p))


__all__ = ["EngagementScope", "ScopeDecision", "ScopeError", "load_scope"]
