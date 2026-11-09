"""Offline tests: no network, no Jev key, pure stdlib + unittest.

These demonstrate the key engineering win — agent decision logic becomes
deterministic and assertable once it goes through the decision layer. Run with:

    python -m unittest discover -s reference/jev/tests
or
    python -m pytest reference/jev/tests
"""

import json
import tempfile
import unittest
from pathlib import Path

from reference.jev.decision_client import (
    DecisionClient,
    DecisionError,
    JevBackend,
    StaticBackend,
)
from reference.jev.router import DecisionRouter
from reference.jev.integrations.raptor_gates import (
    RAPTOR_VALIDATE_THRESHOLDS,
    RaptorValidateChain,
)
from reference.jev.integrations.strix_decisions import (
    STRIX_THRESHOLDS,
    Finding,
    StrixDecisions,
)


class _BoomBackend:
    """Primary that always fails, to exercise fallback."""

    name = "boom"

    def choose(self, prompt, options):
        raise DecisionError("boom")

    def score(self, prompt, lo, hi):
        raise DecisionError("boom")

    def boolean(self, statement):
        raise DecisionError("boom")


class TestDecisionClient(unittest.TestCase):
    def test_fallback_on_primary_failure(self):
        fallback = StaticBackend(boolean_fn=lambda s: 0.9)
        client = DecisionClient(primary=_BoomBackend(), fallback=fallback)
        result = client.boolean("anything")
        self.assertEqual(result.backend, "static")
        self.assertAlmostEqual(result.probability, 0.9)

    def test_no_fallback_reraises(self):
        client = DecisionClient(primary=_BoomBackend())
        with self.assertRaises(DecisionError):
            client.boolean("anything")

    def test_jev_unconfigured_is_decision_error(self):
        # No API key -> JevBackend degrades to a DecisionError (caught by client
        # fallback in real use). Here we assert it does not try the network.
        backend = JevBackend(api_key=None)
        self.assertFalse(backend.configured)
        with self.assertRaises(DecisionError):
            backend.boolean("x")


class TestRouterGate(unittest.TestCase):
    def _router(self, prob, thresholds=None, log_path=None):
        client = DecisionClient(StaticBackend(boolean_fn=lambda s: prob))
        return DecisionRouter(client, thresholds=thresholds, log_path=log_path)

    def test_gate_respects_threshold(self):
        r = self._router(0.4, thresholds={"k": 0.35})
        self.assertTrue(r.gate("k", "stmt"))
        r2 = self._router(0.4, thresholds={"k": 0.5})
        self.assertFalse(r2.gate("k", "stmt"))

    def test_cache_hit_counts(self):
        r = self._router(0.8, thresholds={"k": 0.5})
        r.gate("k", "same")
        r.gate("k", "same")
        self.assertEqual(r.metrics.calls, 2)
        self.assertEqual(r.metrics.cache_hits, 1)

    def test_structured_log_written(self):
        with tempfile.TemporaryDirectory() as d:
            log = Path(d) / "decisions.jsonl"
            r = self._router(0.8, thresholds={"k": 0.5}, log_path=log)
            r.gate("k", "stmt")
            r.record_outcome("k", decided=True, truth=True)
            lines = log.read_text().strip().splitlines()
            self.assertEqual(len(lines), 2)
            rec = json.loads(lines[0])
            self.assertEqual(rec["kind"], "k")
            self.assertEqual(rec["outcome"]["decision"], True)
            self.assertEqual(json.loads(lines[1])["type"], "calibration")


class TestStrixTriage(unittest.TestCase):
    def test_triage_drops_false_positives_and_sorts(self):
        # Boolean: only findings whose title contains "real" are true positives.
        # Score: longer evidence => higher severity.
        client = DecisionClient(
            StaticBackend(
                boolean_fn=lambda s: 0.9 if "real" in s.lower() else 0.0,
                score_fn=lambda p, lo, hi: min(hi, len(p) / 20.0),
            )
        )
        router = DecisionRouter(client, thresholds=STRIX_THRESHOLDS)
        strix = StrixDecisions(router)
        findings = [
            Finding("real sqli", "x" * 200, "/a"),
            Finding("false positive xss", "y", "/b"),
            Finding("real idor", "z" * 40, "/c"),
        ]
        kept = strix.triage(findings)
        self.assertEqual([f.title for f in kept], ["real sqli", "real idor"])


class TestRaptorValidate(unittest.TestCase):
    def test_short_circuits_on_failing_stage(self):
        # Fail the 3rd stage ("constraints_satisfiable"); earlier ones pass.
        failing = "constraints_satisfiable"

        def boolean_fn(stmt):
            return 0.1 if "satisfiable" in stmt else 0.9

        client = DecisionClient(StaticBackend(boolean_fn=boolean_fn))
        router = DecisionRouter(client, thresholds=RAPTOR_VALIDATE_THRESHOLDS)
        chain = RaptorValidateChain(router)
        result = chain.validate("candidate finding summary")
        self.assertFalse(result.exploitable)
        self.assertIn(failing, result.failed_stage)
        # Short-circuit: did not run all eight stages.
        self.assertLess(result.stages_passed, 8)

    def test_all_stages_pass(self):
        client = DecisionClient(StaticBackend(boolean_fn=lambda s: 0.95))
        router = DecisionRouter(client, thresholds=RAPTOR_VALIDATE_THRESHOLDS)
        chain = RaptorValidateChain(router)
        result = chain.validate("strong candidate")
        self.assertTrue(result.exploitable)
        self.assertEqual(result.stages_passed, 8)


if __name__ == "__main__":
    unittest.main()
