"""The native identity result must reject every unsuccessful bridge result."""
import os
from pathlib import Path
import subprocess
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[2]


class NativeIdentityResultTests(unittest.TestCase):
    def identity_job(self):
        workflow = yaml.safe_load(
            (ROOT / ".github/workflows/codestra-control-plane.yml").read_text()
        )
        self.assertIn("native_identity", workflow["jobs"], "native identity result job is missing")
        return workflow, workflow["jobs"]["native_identity"]

    def test_result_is_bound_to_the_actual_identity_job(self):
        workflow, job = self.identity_job()
        self.assertEqual(job["name"], "keycloak/native-identity")
        self.assertEqual(job["needs"], ["codestra_control_plane"])
        self.assertEqual(job["if"], "${{ always() }}")
        self.assertEqual(workflow["permissions"], {"contents": "read"})
        self.assertNotIn("permissions", job)
        self.assertNotIn("continue-on-error", job)
        self.assertNotIn("continue-on-error", workflow["jobs"]["codestra_control_plane"])
        self.assertEqual(len(job["steps"]), 1)
        step = job["steps"][0]
        self.assertEqual(step["env"], {
            "IDENTITY_RESULT": "${{ needs.codestra_control_plane.result }}"
        })
        self.assertNotIn("continue-on-error", step)

    def test_only_a_successful_identity_job_passes(self):
        _, job = self.identity_job()
        script = job["steps"][0]["run"]
        cases = [
            ("success", True),
            ("failure", False),
            ("skipped", False),
            ("cancelled", False),
            ("", False),
            (None, False),
            ("unknown", False),
        ]
        for state, accepted in cases:
            with self.subTest(identity_result=state):
                environment = dict(os.environ)
                environment.pop("IDENTITY_RESULT", None)
                if state is not None:
                    environment["IDENTITY_RESULT"] = state
                result = subprocess.run(
                    ["bash", "-c", script],
                    env=environment,
                    capture_output=True,
                )
                self.assertEqual(result.returncode == 0, accepted, result.stderr)


if __name__ == "__main__":
    unittest.main()
