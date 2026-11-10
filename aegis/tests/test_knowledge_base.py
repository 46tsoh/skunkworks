"""Tests for the unified knowledge model and KnowledgeBase."""

from aegis.knowledge import Candidate, Finding, KnowledgeBase, Severity, owasp_for_cwe


def _cand(cid, cwe="CWE-89", engine="static"):
    return Candidate(
        id=cid, title=f"t-{cid}", cwe=cwe, component="x.py:1",
        cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", source_engine=engine,
    )


def _finding(cid, score, exploitable=True, posterior=0.9, engine="static",
             cwe="CWE-89"):
    return Finding(
        candidate=_cand(cid, cwe=cwe, engine=engine),
        posterior=posterior, cvss_score=score, severity="High",
        exploitable=exploitable, stages_passed=8,
    )


def test_owasp_mapping():
    assert owasp_for_cwe("CWE-89").startswith("A03")
    assert owasp_for_cwe("cwe-89").startswith("A03")  # case-insensitive
    assert owasp_for_cwe("CWE-99999") is None


def test_candidate_owasp_property():
    assert _cand("F1", cwe="CWE-79").owasp.startswith("A03")


def test_finding_exposes_candidate_fields_and_serializes():
    f = _finding("F1", 9.8)
    assert f.id == "F1"
    assert f.title == "t-F1"
    assert f.owasp.startswith("A03")
    d = f.as_dict()
    assert d["id"] == "F1"
    assert d["owasp"].startswith("A03")
    assert d["source_engine"] == "static"


def test_ranking_exploitable_then_cvss():
    kb = KnowledgeBase()
    kb.add_finding(_finding("low", 5.0, exploitable=True))
    kb.add_finding(_finding("info", 9.9, exploitable=False))
    kb.add_finding(_finding("high", 9.0, exploitable=True))
    ranked = [f.id for f in kb.rank()]
    # exploitable first (ordered by CVSS), non-exploitable last despite high CVSS
    assert ranked == ["high", "low", "info"]


def test_queries_and_counts():
    kb = KnowledgeBase()
    kb.add_finding(_finding("a", 9.0, engine="dynamic", cwe="CWE-89"))
    kb.add_finding(_finding("b", 8.0, engine="static", cwe="CWE-798"))
    assert [f.id for f in kb.by_engine("dynamic")] == ["a"]
    assert kb.engine_counts() == {"dynamic": 1, "static": 1}
    assert kb.severity_counts()["High"] == 2
    assert kb.find("b").id == "b"
    assert kb.find("missing") is None


def test_merge_folds_two_engines():
    a = KnowledgeBase()
    a.add_finding(_finding("a", 9.0, engine="dynamic"))
    a.add_rejection(_cand("r1"), "triage", "fp")
    b = KnowledgeBase()
    b.add_finding(_finding("b", 8.0, engine="static"))
    a.merge(b)
    assert len(a.accepted) == 2
    assert len(a.rejected) == 1


def test_severity_enum_order():
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.LOW.rank


def test_as_dict_shape():
    kb = KnowledgeBase()
    kb.add_finding(_finding("a", 9.0))
    kb.metrics = {"candidates": 1}
    d = kb.as_dict()
    assert set(d) == {"accepted", "rejected", "metrics", "summary"}
    assert "severity_counts" in d["summary"]
