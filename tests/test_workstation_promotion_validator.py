"""Contract tests for Keycloak's protected branch promotion sequence."""
import os
from pathlib import Path
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / ".codestra" / "validate-promotion.py"


class WorkstationPromotionValidatorTests(unittest.TestCase):
    def check(self, head, base, *, expected, repository="appolon1908/Keycloak"):
        env = dict(os.environ, GITHUB_REPOSITORY=repository)
        res = subprocess.run(
            [sys.executable, str(SCRIPT), head, base],
            cwd=ROOT, env=env, text=True, capture_output=True, timeout=5,
            check=False,
        )
        self.assertEqual(res.returncode == 0, expected, (head, base, res.stdout, res.stderr))
        self.assertIn("PROMOTION_ALLOWED=YES" if expected else "PROMOTION_ALLOWED=NO", res.stdout)

    def test_six_hop_promotion_chain(self):
        for head, base in [
            ("subsection/kc-08-release--security", "section/kc-08-release"),
            ("section/kc-08-release", "development"),
            ("development", "testing"),
            ("testing", "staging"),
            ("staging", "production"),
            ("production", "main"),
        ]:
            with self.subTest(head=head, base=base):
                self.check(head, base, expected=True)

    def test_narrow_bootstraps(self):
        for head, base in [
            ("governance/agent-hierarchy-main-v1", "main"),
            ("governance/development-control-plane-v1", "main"),
            ("governance/agent-hierarchy-v1", "development"),
        ]:
            with self.subTest(head=head, base=base):
                self.check(head, base, expected=True)

    def test_reject_mismatched_and_shortcut_promotions(self):
        for head, base in [
            ("subsection/kc-08-release--security", "section/kc-07-reconciliation"),
            ("subsection/kc-08-release--security", "development"),
            ("subsection/kc-08-release--security", "kc-08-release"),
            ("subsection/../--escape", "section/.."),
            ("section/kc-08-release", "main"),
            ("kc-08-release", "development"),
            ("development", "main"),
            ("staging", "main"),
            ("integration/keycloak-convergence-20261009", "main"),
            ("governance/agent-hierarchy-main-v1", "production"),
            ("production", "development"),
        ]:
            with self.subTest(head=head, base=base):
                self.check(head, base, expected=False)

    def test_unknown_repository_fail_closed(self):
        self.check("production", "main", expected=False, repository="appolon1908/unknown")
