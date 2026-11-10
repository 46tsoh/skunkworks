"""Backend-level tests: LLM-judge parsing, static modes, HTTP response parsing.

No real network: HTTP backends are exercised by stubbing their ``_post`` method
(the one place that touches urllib), so response-parsing logic is covered
deterministically and offline.
"""

import io
import json

import pytest

from aegis.decision.client import (
    BasalOmniBackend,
    DecisionError,
    JevBackend,
    LLMJudgeBackend,
    StaticBackend,
)


# -- StaticBackend ------------------------------------------------------------
def test_static_choose_and_score_defaults():
    b = StaticBackend()
    assert b.choose("p", ["a", "b"]).index == 0
    assert b.score("p", 0.0, 10.0).value == 5.0
    assert b.boolean("s").probability == 0.5


def test_static_choose_clamps_out_of_range():
    b = StaticBackend(choose_fn=lambda p, opts: 99)
    assert b.choose("p", ["a", "b"]).index == 1


# -- LLMJudgeBackend (pure parsing) ------------------------------------------
def test_llm_judge_boolean_parses_json():
    b = LLMJudgeBackend(complete=lambda prompt: '{"probability": 0.8}')
    assert b.boolean("s").probability == pytest.approx(0.8)


def test_llm_judge_tolerates_prose_and_fences():
    b = LLMJudgeBackend(complete=lambda p: 'Sure!\n```json\n{"index": 1}\n```')
    assert b.choose("p", ["a", "b"]).index == 1


def test_llm_judge_score_clamps():
    b = LLMJudgeBackend(complete=lambda p: '{"value": 999}')
    assert b.score("p", 0.0, 10.0).value == 10.0


def test_llm_judge_non_json_raises():
    b = LLMJudgeBackend(complete=lambda p: "no json here")
    with pytest.raises(DecisionError):
        b.boolean("s")


# -- JevBackend response parsing (stubbed transport) -------------------------
def test_jev_parses_responses(monkeypatch):
    b = JevBackend(api_key="k")
    # Stub the typed-decision transport: return the answer the real
    # /v1/decisions endpoint gives for each question type.
    answers = {
        "choice": {"type": "choice", "choice": "b", "confidence": 0.9},
        "score": {"type": "score", "score": 4.5, "confidence": 0.8},  # level idx
        "predicate": {"type": "predicate", "probability": 0.9},
    }
    monkeypatch.setattr(b, "_decide", lambda input_text, question: (
        answers[question["type"]], 1.2, {"answers": [answers[question["type"]]]}))
    assert b.choose("p", ["a", "b"]).option == "b"
    # 10 levels across 0..10 → fractional level index 4.5 maps to 5.0
    assert b.score("p", 0.0, 10.0).value == pytest.approx(5.0)
    assert b.boolean("s").probability == pytest.approx(0.9)


def _stub_urlopen(monkeypatch, captured, response):
    """Patch urllib so JevBackend._decide runs against a canned response."""
    def fake(req, timeout=None):
        captured["url"] = req.full_url
        captured["body"] = json.loads(req.data.decode())
        return io.BytesIO(json.dumps(response).encode())
    monkeypatch.setattr("urllib.request.urlopen", fake)


def test_jev_builds_decisions_request(monkeypatch):
    """The wire request is {model, input, questions:[typed question]}."""
    b = JevBackend(api_key="k", model="typesafe/jev-1.14.0")
    captured = {}
    _stub_urlopen(monkeypatch, captured,
                  {"answers": [{"type": "choice", "choice": "probe",
                                "confidence": 0.7}]})
    res = b.choose("drive the test", ["probe", "finish"])
    assert res.option == "probe"
    assert captured["url"].endswith("/decisions")
    assert captured["body"]["model"] == "typesafe/jev-1.14.0"
    assert captured["body"]["input"] == "drive the test"
    q = captured["body"]["questions"][0]
    assert q["type"] == "choice"
    assert [c["value"] for c in q["choices"]] == ["probe", "finish"]


def test_jev_refusal_raises(monkeypatch):
    b = JevBackend(api_key="k")
    _stub_urlopen(monkeypatch, {}, {"answers": [{"type": "refusal"}]})
    with pytest.raises(DecisionError):
        b.boolean("s")


def test_jev_choose_requires_options():
    b = JevBackend(api_key="k")
    with pytest.raises(DecisionError):
        b.choose("p", [])


def test_basal_boolean_via_score_mode(monkeypatch):
    b = BasalOmniBackend()
    monkeypatch.setattr(b, "_post", lambda payload: ({"value": 0.3}, 0.5))
    assert b.boolean("s").probability == pytest.approx(0.3)
    # image_refs path for the multimodal choose
    assert b.choose("p", ["a"], image_refs=["img1"]).index == 0
