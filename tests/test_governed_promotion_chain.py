"""Contract tests for the protected promotion guard: no skipped stages."""
import json
from pathlib import Path
import subprocess
import sys
import unittest
import yaml

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
            ("subsection/kc-08-release--02-security-certification", "section/kc-08-release"),
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

    def test_only_registered_workstations_can_promote(self):
        product_map = json.loads((ROOT / "governance/product-map.json").read_text())
        for section in product_map["sections"]:
            for task in section["subsections"]:
                self.assert_promotion(
                    f"subsection/{section['section']}--{task}", section["branch"], accepted=True,
                )
        for head, base in [
            ("subsection/kc-01-realm--unassigned", "section/kc-01-realm"),
            ("subsection/kc-01-realm", "section/kc-01-realm"),
            ("subsection/kc-99-unknown--01-realm-baseline", "section/kc-99-unknown"),
            ("section/kc-99-unknown", "development"),
        ]:
            with self.subTest(head=head, base=base):
                self.assert_promotion(head, base, accepted=False)

    def test_live_effects_remain_disabled(self):
        policy = json.loads(POLICY.read_text())
        self.assertEqual(policy["production_defaults"], {
            "PRODUCTION_GO": "NO",
            "LIVE_CAPABILITIES_ENABLED": "NO",
            "EXTERNAL_EFFECTS": "false",
        })
        self.assertEqual(policy["accepted_promotions"][-1], {"head":"production","base":"main"})

    def test_workflow_uses_trusted_base_and_env_for_refs(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/codestra-hierarchy-governance.yml").read_text())
        events = workflow.get("on", workflow.get(True))
        self.assertIsNone(events["pull_request"])
        guard = workflow["jobs"]["promotion-guard"]
        steps = guard["steps"]
        checkout = next(step for step in steps if step.get("uses", "").startswith("actions/checkout@"))
        self.assertEqual(checkout["with"]["ref"], "${{ github.event.pull_request.base.sha }}")
        self.assertIs(checkout["with"]["persist-credentials"], False)
        for job in workflow["jobs"].values():
            for step in job["steps"]:
                self.assertNotIn("${{ github.", step.get("run", ""))
        runner_step = workflow["jobs"]["control-plane-certification"]["steps"][0]
        self.assertEqual(runner_step["env"]["HEAD_REF"], "${{ github.head_ref }}")
        self.assertIn('--head-ref "$HEAD_REF"', runner_step["run"])
