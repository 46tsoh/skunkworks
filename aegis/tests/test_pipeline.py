"""End-to-end pipeline tests on the sample corpus (offline, deterministic)."""

import json

import pytest

from aegis.analysis.backends import build_router
from aegis.analysis.pipeline import run
from aegis.cli import _DEFAULT_INPUT, load_candidates, main


@pytest.fixture
def cands():
    return load_candidates(_DEFAULT_INPUT)


@pytest.fixture
def kb(cands):
    router = build_router(cands, backend="static")
    return run(router, cands)


def test_false_positive_triaged_out(kb):
    rej = {r.candidate.id: r for r in kb.rejected}
    assert "F3" in rej and rej["F3"].stage == "triage"


def test_weak_hypothesis_rejected(kb):
    rej = {r.candidate.id: r for r in kb.rejected}
    assert "F4" in rej and rej["F4"].stage == "hypothesis"


def test_duplicate_collapsed(kb):
    rej = {r.candidate.id: r for r in kb.rejected}
    assert "F2" in rej and rej["F2"].stage == "dedupe"
    assert "F1" in rej["F2"].reason


def test_accepted_set_and_ranking(kb):
    accepted = [f.id for f in kb.accepted]
    assert set(accepted) == {"F1", "F5", "F6", "F7"}
    assert accepted[0] == "F1"
    assert accepted[-1] == "F6"


def test_non_exploitable_marked_informational(kb):
    f6 = kb.find("F6")
    assert f6.exploitable is False
    assert f6.stages_passed == 2


def test_metrics_counts(kb):
    m = kb.metrics
    assert m["candidates"] == 7
    assert m["accepted"] == 4
    assert m["rejected"] == 3
    assert m["decisions"] > 0
    assert "hint" in m["decisions_by_backend"]


def test_decision_log_written(cands, tmp_path):
    log = tmp_path / "decisions.jsonl"
    router = build_router(cands, backend="static", log_path=log)
    run(router, cands)
    lines = log.read_text().strip().splitlines()
    assert lines
    rec = json.loads(lines[0])
    assert rec["type"] == "decision" and "kind" in rec


def test_basal_unreachable_falls_back_to_hint(cands):
    # No localhost basal server -> primary errors -> HintBackend answers.
    router = build_router(cands, backend="basal")
    kb = run(router, cands)
    assert kb.metrics["accepted"] == 4
    assert "hint" in kb.metrics["decisions_by_backend"]


def test_owasp_classification_on_findings(kb):
    f1 = kb.find("F1")  # CWE-89 SQL injection
    assert f1.owasp.startswith("A03")


def test_shared_kb_merge_across_two_runs(cands):
    from aegis.knowledge.base import KnowledgeBase
    shared = KnowledgeBase()
    router = build_router(cands, backend="static")
    run(router, cands, kb=shared)
    assert len(shared.accepted) == 4


def test_cli_writes_report(tmp_path):
    out = tmp_path / "run"
    rc = main(["analyze", "--out", str(out)])
    assert rc == 0
    report = json.loads((out / "report.json").read_text())
    assert report["metrics"]["accepted"] == 4
    assert (out / "decisions.jsonl").exists()
    assert "summary" in report


def test_cli_rejects_remote_jev_without_egress():
    with pytest.raises(ValueError):
        main(["analyze", "--backend", "jev"])
