"""Contract tests for the protected promotion guard: no skipped stages."""
import json
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "governance" / "promotion_guard.py"
POLICY = ROOT / "governance" / "promotion-policy.json"


class GovernedPromotionChainTests(unittest.TestCase):
    def assert_promotion(self, head, base, *, accepted):
        run = subprocess.run(
            [sys.executable, str(SCRIPT), "--head", head, "--base", base],
            cwd=ROOT, text=True, capture_output=True, timeout=5, check=False,
        )
        self.assertEqual(run.returncode == 0, accepted, (head, base, run.stdout, run.stderr))

    def test_six_step_canonical_chain(self):
        for head, base in [
            ("subsection/kc-08-release--security", "section/kc-08-release"),
            ("section/kc-08-release", "development"),
            ("development", "testing"),
            ("testing", "staging"),
            ("staging", "production"),
            ("production", "main"),
        ]:
            with self.subTest(head=head, base=base):
                self.assert_promotion(head, base, accepted=True)

    def test_invalid_and_skipped_stages_are_denied(self):
        for head, base in [
            ("subsection/kc-08-release--security", "section/kc-02-organization"),
            ("subsection/kc-08-release--security", "development"),
            ("subsection/kc-08-release--Security", "section/kc-08-release"),
            ("subsection/../--security", "section/.."),
            ("section/kc-08-release", "main"),
            ("section/other", "development"),
            ("development", "production"),
            ("testing", "main"),
            ("staging", "main"),
            ("integration/keycloak-convergence-20261009", "main"),
        ]:
            with self.subTest(head=head, base=base):
                self.assert_promotion(head, base, accepted=False)

    def test_single_bootstrap_exception(self):
        self.assert_promotion("governance/development-control-plane-v1", "main", accepted=True)
        self.assert_promotion("governance/agent-hierarchy-main-v1", "main", accepted=False)

    def test_live_effects_remain_disabled(self):
        policy = json.loads(POLICY.read_text())
        self.assertEqual(policy["production_defaults"], {
            "PRODUCTION_GO": "NO",
            "LIVE_CAPABILITIES_ENABLED": "NO",
            "EXTERNAL_EFFECTS": "false",
        })
        self.assertEqual(policy["accepted_promotions"][-1], {"head":"production","base":"main"})
