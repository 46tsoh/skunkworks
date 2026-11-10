"""Backend-level tests: LLM-judge parsing, static modes, HTTP response parsing.

No real network: HTTP backends are exercised by stubbing their ``_post`` method
(the one place that touches urllib), so response-parsing logic is covered
deterministically and offline.
"""

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
    monkeypatch.setattr(b, "_post", lambda path, payload: (
        {"choice_index": 1, "probability": 0.9, "value": 7.0}, 1.2))
    assert b.choose("p", ["a", "b"]).option == "b"
    assert b.score("p", 0.0, 10.0).value == 7.0
    assert b.boolean("s").probability == pytest.approx(0.9)


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
