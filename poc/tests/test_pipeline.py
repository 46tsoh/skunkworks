"""Offline, deterministic tests for the triage POC (stdlib + unittest).

Run from the repo root:
    python -m unittest discover -s poc/tests
"""

import json
import tempfile
import unittest
from pathlib import Path

from poc import cvss
from poc.backends import build_router
from poc.cli import load_candidates, _DEFAULT_INPUT
from poc.models import Candidate
from poc.pipeline import run


class TestCVSS(unittest.TestCase):
    def test_known_anchors(self):
        # Published CVSS v3.1 reference values.
        self.assertEqual(cvss.base_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"), 9.8)
        self.assertEqual(cvss.base_score("AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"), 10.0)
        self.assertEqual(cvss.base_score("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N"), 3.1)

    def test_severity_bands(self):
        self.assertEqual(cvss.severity_band(9.8), "Critical")
        self.assertEqual(cvss.severity_band(7.0), "High")
        self.assertEqual(cvss.severity_band(4.0), "Medium")
        self.assertEqual(cvss.severity_band(0.1), "Low")
        self.assertEqual(cvss.severity_band(0.0), "None")

    def test_missing_metric_raises(self):
        with self.assertRaises(ValueError):
            cvss.base_score("AV:N/AC:L")


class TestPipeline(unittest.TestCase):
    def setUp(self):
        self.cands = load_candidates(_DEFAULT_INPUT)
        self.router = build_router(self.cands, backend="static")
        self.result = run(self.router, self.cands)

    def _ids(self, items):
        return [i.candidate.id for i in items]

    def test_false_positive_triaged_out(self):
        # F3 is a documented public test key -> low true-positive prob.
        rej = {r.candidate.id: r for r in self.result.rejected}
        self.assertIn("F3", rej)
        self.assertEqual(rej["F3"].stage, "triage")

    def test_weak_hypothesis_rejected(self):
        # F4 has unconfirmed evidence -> posterior below threshold.
        rej = {r.candidate.id: r for r in self.result.rejected}
        self.assertIn("F4", rej)
        self.assertEqual(rej["F4"].stage, "hypothesis")

    def test_duplicate_collapsed(self):
        # F2 is the same vuln as F1 (same sink/component) -> deduped.
        rej = {r.candidate.id: r for r in self.result.rejected}
        self.assertIn("F2", rej)
        self.assertEqual(rej["F2"].stage, "dedupe")
        self.assertIn("F1", rej["F2"].reason)

    def test_accepted_set_and_ranking(self):
        accepted = self._ids(self.result.accepted)
        # F1, F5, F6, F7 survive; F2/F3/F4 are dropped.
        self.assertEqual(set(accepted), {"F1", "F5", "F6", "F7"})
        # Exploitable + critical first; the non-exploitable F6 ranks last.
        self.assertEqual(accepted[0], "F1")
        self.assertEqual(accepted[-1], "F6")

    def test_non_exploitable_marked_informational(self):
        f6 = next(f for f in self.result.accepted if f.candidate.id == "F6")
        self.assertFalse(f6.exploitable)
        self.assertEqual(f6.stages_passed, 2)  # short-circuited at stage 2

    def test_metrics_counts(self):
        m = self.result.metrics
        self.assertEqual(m["candidates"], 7)
        self.assertEqual(m["accepted"], 4)
        self.assertEqual(m["rejected"], 3)
        self.assertGreater(m["decisions"], 0)
        self.assertIn("hint", m["decisions_by_backend"])

    def test_decision_log_written(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "decisions.jsonl"
            router = build_router(self.cands, backend="static", log_path=log)
            run(router, self.cands)
            lines = log.read_text().strip().splitlines()
            self.assertGreater(len(lines), 0)
            rec = json.loads(lines[0])
            self.assertIn(rec["type"], {"decision"})
            self.assertIn("kind", rec)


class TestBackendFallback(unittest.TestCase):
    def test_basal_unreachable_falls_back_to_hint(self):
        # No local basal server -> primary errors -> HintBackend answers, so the
        # demo still completes and produces the same deterministic result.
        cands = load_candidates(_DEFAULT_INPUT)
        router = build_router(cands, backend="basal")
        result = run(router, cands)
        self.assertEqual(result.metrics["accepted"], 4)
        self.assertIn("hint", result.metrics["decisions_by_backend"])


if __name__ == "__main__":
    unittest.main()
