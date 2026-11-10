"""Tests for the engagement-scope authorization control (default-deny gate)."""

import json
from datetime import datetime, timedelta, timezone

import pytest

from aegis.redteam import EngagementScope, ScopeError, load_scope


def _scope(**kw) -> EngagementScope:
    return EngagementScope(**kw)


# -- default-deny ------------------------------------------------------------
def test_empty_scope_authorizes_nothing():
    s = _scope()
    assert not s.is_in_scope("target.htb")
    assert not s.is_in_scope("http://target.htb/")
    assert not s.is_in_scope("10.0.0.5")
    assert s.check("target.htb").reason  # a human-readable refusal reason


# -- hostname matching is exact, never substring -----------------------------
def test_hostname_exact_match_only():
    s = _scope(hosts=["target.htb"])
    assert s.is_in_scope("target.htb")
    assert s.is_in_scope("http://target.htb/path")
    # the classic bypass: a lookalike suffix must NOT match
    assert not s.is_in_scope("target.htb.evil.com")
    assert not s.is_in_scope("eviltarget.htb")
    assert not s.is_in_scope("nottarget.htb")


def test_hostname_match_is_case_insensitive():
    assert _scope(hosts=["Target.HTB"]).is_in_scope("target.htb")


# -- CIDR membership (not substring) -----------------------------------------
def test_cidr_membership():
    s = _scope(hosts=["10.129.0.0/24"])
    assert s.is_in_scope("10.129.0.5")
    assert s.is_in_scope("http://10.129.0.200:8080/")
    assert not s.is_in_scope("10.129.1.5")      # outside the /24
    assert not s.is_in_scope("10.130.0.5")


def test_single_ip_entry_is_slash32():
    s = _scope(hosts=["10.0.0.7"])
    assert s.is_in_scope("10.0.0.7")
    assert not s.is_in_scope("10.0.0.8")


def test_hostname_never_matches_a_cidr_entry():
    # a hostname target must not be considered in-scope by an IP/CIDR rule
    assert not _scope(hosts=["10.0.0.0/8"]).is_in_scope("target.htb")


# -- deny wins ---------------------------------------------------------------
def test_deny_overrides_allow():
    s = _scope(hosts=["10.129.0.0/24"], deny_hosts=["10.129.0.1"])
    assert s.is_in_scope("10.129.0.5")
    assert not s.is_in_scope("10.129.0.1")      # gateway explicitly denied
    assert "denied" in s.check("10.129.0.1").reason


# -- URL prefixes ------------------------------------------------------------
def test_url_prefix_allow():
    s = _scope(urls=["http://target.htb/app/"])
    assert s.is_in_scope("http://target.htb/app/login")
    assert not s.is_in_scope("http://target.htb/other")
    # even a url whose host is allowed is denied if it is explicitly in deny
    s2 = _scope(urls=["http://target.htb/"], deny_hosts=["target.htb"])
    assert not s2.is_in_scope("http://target.htb/x")


# -- expiry ------------------------------------------------------------------
def test_expired_scope_refuses_everything():
    past = datetime.now(timezone.utc) - timedelta(days=1)
    s = _scope(hosts=["target.htb"], expires=past)
    assert s.is_expired()
    assert not s.is_in_scope("target.htb")
    assert "expired" in s.check("target.htb").reason


def test_future_expiry_is_fine():
    future = datetime.now(timezone.utc) + timedelta(days=1)
    assert _scope(hosts=["target.htb"], expires=future).is_in_scope("target.htb")


# -- loader ------------------------------------------------------------------
def test_load_scope_json(tmp_path):
    p = tmp_path / "scope.json"
    p.write_text(json.dumps({
        "engagement": "ctf-1", "authorized_by": "op",
        "expires": "2999-01-01T00:00:00Z",
        "targets": {"hosts": ["10.129.0.0/24", "target.htb"],
                    "urls": ["http://target.htb/"]},
        "deny": {"hosts": ["10.129.0.1"]},
        "limits": {"max_hosts": 8, "allow_lateral": True,
                   "allow_post_exploit": True},
    }))
    s = load_scope(p)
    assert s.engagement == "ctf-1" and s.authorized_by == "op"
    assert s.max_hosts == 8 and s.allow_lateral and s.allow_post_exploit
    assert s.is_in_scope("10.129.0.50") and not s.is_in_scope("10.129.0.1")


def test_load_scope_missing_file_raises(tmp_path):
    with pytest.raises(ScopeError):
        load_scope(tmp_path / "nope.json")


def test_load_scope_empty_file_raises(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text("")
    with pytest.raises(ScopeError):
        load_scope(p)


def test_load_scope_bad_json_raises(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text("{not valid json")
    with pytest.raises(ScopeError):
        load_scope(p)


def test_load_scope_defaults_are_restrictive(tmp_path):
    # a minimal scope leaves the escalation switches OFF and max_hosts at 1
    p = tmp_path / "min.json"
    p.write_text(json.dumps({"targets": {"hosts": ["target.htb"]}}))
    s = load_scope(p)
    assert s.allow_lateral is False and s.allow_post_exploit is False
    assert s.max_hosts == 1


def test_load_scope_bad_expires_raises(tmp_path):
    p = tmp_path / "e.json"
    p.write_text(json.dumps({"expires": "not-a-date",
                             "targets": {"hosts": ["target.htb"]}}))
    with pytest.raises(ScopeError):
        load_scope(p)


def test_load_scope_non_list_targets_raises(tmp_path):
    p = tmp_path / "e.json"
    p.write_text(json.dumps({"targets": {"hosts": "target.htb"}}))  # str, not list
    with pytest.raises(ScopeError):
        load_scope(p)


def test_load_scope_yaml_without_pyyaml(tmp_path, monkeypatch):
    # If a .yaml scope is given but PyYAML is unavailable, fail closed with a
    # clear error rather than silently authorizing nothing or crashing.
    import builtins
    real_import = builtins.__import__

    def no_yaml(name, *a, **k):
        if name == "yaml":
            raise ImportError("no yaml")
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", no_yaml)
    p = tmp_path / "s.yaml"
    p.write_text("targets:\n  hosts: [target.htb]\n")
    with pytest.raises(ScopeError) as exc:
        load_scope(p)
    assert "PyYAML" in str(exc.value) or "YAML" in str(exc.value)


def test_target_with_no_host_is_refused():
    assert not _scope(hosts=["target.htb"]).is_in_scope("")
    assert not _scope(hosts=["target.htb"]).is_in_scope("   ")


def test_decision_as_dict_is_audit_ready():
    d = _scope(hosts=["target.htb"]).check("target.htb").as_dict()
    assert d["target"] == "target.htb" and d["in_scope"] is True and d["reason"]
