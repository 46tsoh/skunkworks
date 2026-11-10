"""Tests for AegisConfig — env loading, overrides, and the local_only guard."""

import pytest

from aegis.config import DEFAULT_THRESHOLDS, AegisConfig


def test_defaults_are_offline_and_local():
    cfg = AegisConfig()
    assert cfg.backend == "static"
    assert cfg.local_only is True
    assert cfg.thresholds == DEFAULT_THRESHOLDS
    # defaults must be a copy, not the shared module dict
    cfg.thresholds["triage.true_positive"] = 0.99
    assert DEFAULT_THRESHOLDS["triage.true_positive"] != 0.99


def test_local_only_blocks_remote_jev():
    with pytest.raises(ValueError):
        AegisConfig(backend="jev")  # local_only True by default


def test_jev_allowed_when_egress_enabled():
    cfg = AegisConfig(backend="jev", local_only=False)
    assert cfg.backend == "jev"


def test_unknown_backend_rejected():
    with pytest.raises(ValueError):
        AegisConfig(backend="nope")


def test_from_env_reads_overrides(monkeypatch):
    monkeypatch.setenv("AEGIS_BACKEND", "basal")
    monkeypatch.setenv("AEGIS_POSTERIOR_MIN", "0.7")
    monkeypatch.setenv("AEGIS_THRESHOLD_TRIAGE_TRUE_POSITIVE", "0.55")
    cfg = AegisConfig.from_env()
    assert cfg.backend == "basal"
    assert cfg.posterior_min == 0.7
    assert cfg.thresholds["triage.true_positive"] == 0.55


def test_from_env_explicit_override_wins(monkeypatch):
    monkeypatch.setenv("AEGIS_BACKEND", "basal")
    cfg = AegisConfig.from_env(backend="static")
    assert cfg.backend == "static"
