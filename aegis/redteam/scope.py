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


def _host_of(target: str) -> str:
    """Extract the host from a URL, or return the bare host/IP unchanged."""
    t = (target or "").strip()
    if "://" in t:
        return (urlparse(t).hostname or "").strip()
    # host:port or bare host/IP — drop a port if present (but not inside IPv6).
    if t.count(":") == 1:
        t = t.split(":", 1)[0]
    return t


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

        # URL-prefix allow (for web targets).
        t = (target or "").strip()
        if "://" in t:
            for prefix in self.urls:
                if t.startswith(prefix):
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
            # entry is a hostname: exact, case-insensitive match (no substring).
            if host.lower() == entry.strip().lower():
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

    return EngagementScope(
        engagement=str(raw.get("engagement", "")),
        authorized_by=str(raw.get("authorized_by", "")),
        expires=expires,
        hosts=_list(targets, "hosts"),
        urls=_list(targets, "urls"),
        deny_hosts=_list(deny, "hosts"),
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
