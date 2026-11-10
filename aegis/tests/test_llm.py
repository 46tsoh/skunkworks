"""Tests for the standard-LLM provider and its decision-backend bridge."""

import json

import pytest

from aegis.analysis.backends import build_router
from aegis.config import AegisConfig
from aegis.decision import DecisionError
from aegis.llm import (
    LLMError,
    OpenAICompatProvider,
    TemplateLLM,
    build_llm,
    is_local_base,
    judge_backend,
    summarize,
)


def test_template_llm_is_deterministic_and_parseable():
    llm = TemplateLLM()
    a = llm.complete('Reply ONLY as JSON: {"probability": <0..1>}')
    b = llm.complete('Reply ONLY as JSON: {"probability": <0..1>}')
    assert a == b
    assert 0.0 <= json.loads(a)["probability"] <= 1.0


def test_template_llm_free_form_summary():
    out = TemplateLLM().complete("Summarize this finding: SQL injection in login")
    assert out.startswith("[template-llm summary]")


def test_is_local_base():
    assert is_local_base("http://localhost:11434/v1")
    assert is_local_base("http://127.0.0.1:8000/v1")
    assert not is_local_base("https://api.example.com/v1")


def test_openai_provider_refuses_remote_when_local_only():
    with pytest.raises(LLMError):
        OpenAICompatProvider(api_base="https://api.openai.com/v1", local_only=True)


def test_openai_provider_allows_remote_with_egress():
    p = OpenAICompatProvider(api_base="https://api.openai.com/v1",
                             model="gpt-x", local_only=False)
    assert p.name == "llm:gpt-x"


def test_build_llm_defaults_to_template_offline(monkeypatch):
    monkeypatch.delenv("AEGIS_LLM", raising=False)
    monkeypatch.delenv("AEGIS_LLM_API_BASE", raising=False)
    monkeypatch.delenv("AEGIS_LLM_API_KEY", raising=False)
    assert isinstance(build_llm(), TemplateLLM)


def test_build_llm_builds_provider_when_configured():
    llm = build_llm(model="llama3.1", api_base="http://localhost:11434/v1")
    assert isinstance(llm, OpenAICompatProvider)


def test_judge_backend_drives_decisions_via_llm():
    backend = judge_backend(TemplateLLM())
    # Deterministic, parseable probability -> a valid BooleanResult.
    result = backend.boolean("The finding is a true positive.")
    assert 0.0 <= result.probability <= 1.0
    assert result.backend == "llm-judge"


def test_judge_backend_non_json_is_decision_error():
    # A model that returns prose (no JSON) surfaces as DecisionError, which a
    # fallback backend would then catch.
    backend = judge_backend(_ConstLLM("I cannot help with that."))
    with pytest.raises(DecisionError):
        backend.boolean("statement")


class _ConstLLM:
    name = "const"

    def __init__(self, text):
        self._text = text

    def complete(self, prompt):
        return self._text

    def chat(self, messages):
        return self._text


def test_llm_backend_runs_pipeline_offline():
    # Selecting the 'llm' backend must run end-to-end with no server (TemplateLLM
    # as the primary, HintBackend as the offline fallback).
    from aegis.knowledge.loader import load_candidates
    from aegis.cli import _DEFAULT_INPUT
    from aegis.analysis.pipeline import run

    cands = load_candidates(_DEFAULT_INPUT)
    router = build_router(cands, config=AegisConfig(backend="llm"))
    kb = run(router, cands)
    assert "llm-judge" in kb.metrics["decisions_by_backend"]


def test_openai_provider_chat_parses_response(monkeypatch):
    import io
    import aegis.llm as llm_mod

    class _Resp:
        def __init__(self, payload):
            self._b = json.dumps(payload).encode("utf-8")
        def read(self):
            return self._b
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    payload = {"choices": [{"message": {"content": "hello from local llm"}}],
               "usage": {"prompt_tokens": 12, "completion_tokens": 5}}
    monkeypatch.setattr(llm_mod.urllib.request, "urlopen",
                        lambda req, timeout=0: _Resp(payload))
    p = OpenAICompatProvider(model="m", api_base="http://localhost:11434/v1",
                             api_key="k")
    assert p.complete("hi") == "hello from local llm"
    # token usage is metered cumulatively across calls
    p.complete("again")
    assert p.usage == {"input_tokens": 24, "output_tokens": 10, "calls": 2}


def test_openai_provider_chat_error_wrapped(monkeypatch):
    import aegis.llm as llm_mod
    import urllib.error

    def _boom(req, timeout=0):
        raise urllib.error.URLError("refused")

    monkeypatch.setattr(llm_mod.urllib.request, "urlopen", _boom)
    p = OpenAICompatProvider(api_base="http://localhost:1/v1")
    with pytest.raises(LLMError):
        p.complete("hi")


def test_summarize_falls_back_on_llm_error():
    class Boom:
        name = "boom"
        def complete(self, p):
            raise LLMError("down")
        def chat(self, m):
            raise LLMError("down")

    out = summarize(Boom(), "SQLi", "login handler concatenates input")
    assert out.startswith("SQLi —")
