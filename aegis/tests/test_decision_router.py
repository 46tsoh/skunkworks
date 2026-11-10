"""Decision-layer tests against aegis.decision directly (offline, no network)."""

import json

import pytest

from aegis.decision import (
    BasalOmniBackend,
    DecisionBackend,
    DecisionClient,
    DecisionError,
    DecisionRouter,
    JevBackend,
    StaticBackend,
)
from aegis.decision.integrations.raptor_gates import (
    RAPTOR_VALIDATE_THRESHOLDS,
    RaptorValidateChain,
)
from aegis.decision.integrations.strix_decisions import (
    STRIX_THRESHOLDS,
    Finding,
    StrixDecisions,
)


class _BoomBackend:
    name = "boom"

    def choose(self, prompt, options):
        raise DecisionError("boom")

    def score(self, prompt, lo, hi):
        raise DecisionError("boom")

    def boolean(self, statement):
        raise DecisionError("boom")


def test_fallback_on_primary_failure():
    client = DecisionClient(_BoomBackend(), StaticBackend(boolean_fn=lambda s: 0.9))
    result = client.boolean("anything")
    assert result.backend == "static"
    assert result.probability == pytest.approx(0.9)


def test_no_fallback_reraises():
    with pytest.raises(DecisionError):
        DecisionClient(_BoomBackend()).boolean("anything")


def test_jev_unconfigured_is_decision_error():
    backend = JevBackend(api_key=None)
    assert backend.configured is False
    with pytest.raises(DecisionError):
        backend.boolean("x")


def test_basal_is_protocol_and_swap_in():
    backend = BasalOmniBackend(api_base="http://localhost:9/v1")
    assert isinstance(backend, DecisionBackend)
    assert backend.name == "basal-omni"
    client = DecisionClient(backend, StaticBackend(boolean_fn=lambda s: 0.7))
    assert client.boolean("s").backend == "static"


def _router(prob, thresholds=None, log_path=None):
    client = DecisionClient(StaticBackend(boolean_fn=lambda s: prob))
    return DecisionRouter(client, thresholds=thresholds, log_path=log_path)


def test_gate_respects_threshold():
    assert _router(0.4, {"k": 0.35}).gate("k", "stmt") is True
    assert _router(0.4, {"k": 0.5}).gate("k", "stmt") is False


def test_cache_hit_counts():
    r = _router(0.8, {"k": 0.5})
    r.gate("k", "same")
    r.gate("k", "same")
    assert r.metrics.calls == 2
    assert r.metrics.cache_hits == 1


def test_structured_log_and_calibration(tmp_path):
    log = tmp_path / "decisions.jsonl"
    r = _router(0.8, {"k": 0.5}, log_path=log)
    r.gate("k", "stmt")
    r.record_outcome("k", decided=True, truth=True)
    lines = log.read_text().strip().splitlines()
    assert len(lines) == 2
    assert json.loads(lines[0])["kind"] == "k"
    assert json.loads(lines[1])["type"] == "calibration"


def test_strix_triage_drops_and_sorts():
    client = DecisionClient(
        StaticBackend(
            boolean_fn=lambda s: 0.9 if "real" in s.lower() else 0.0,
            score_fn=lambda p, lo, hi: min(hi, len(p) / 20.0),
        )
    )
    strix = StrixDecisions(DecisionRouter(client, thresholds=STRIX_THRESHOLDS))
    kept = strix.triage([
        Finding("real sqli", "x" * 200, "/a"),
        Finding("false positive xss", "y", "/b"),
        Finding("real idor", "z" * 40, "/c"),
    ])
    assert [f.title for f in kept] == ["real sqli", "real idor"]


def test_raptor_validate_short_circuits():
    client = DecisionClient(
        StaticBackend(boolean_fn=lambda s: 0.1 if "satisfiable" in s else 0.9)
    )
    chain = RaptorValidateChain(DecisionRouter(client, thresholds=RAPTOR_VALIDATE_THRESHOLDS))
    result = chain.validate("summary")
    assert result.exploitable is False
    assert "satisfiable" in result.failed_stage
    assert result.stages_passed < 8


def test_raptor_validate_all_pass():
    client = DecisionClient(StaticBackend(boolean_fn=lambda s: 0.95))
    chain = RaptorValidateChain(DecisionRouter(client, thresholds=RAPTOR_VALIDATE_THRESHOLDS))
    result = chain.validate("strong")
    assert result.exploitable is True
    assert result.stages_passed == 8
