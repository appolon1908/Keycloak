"""The deploy workflow's rollback export selects the same client set that apply accepts."""
from __future__ import annotations
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
STEP = "Export client-specific allowlisted rollback overlay"


def selector_script() -> str:
    workflow = yaml.safe_load((ROOT / ".github" / "workflows" / "deploy.yml").read_text(encoding="utf-8"))
    steps = [s for job in workflow["jobs"].values() for s in job.get("steps", []) if s.get("name") == STEP]
    assert len(steps) == 1, "exactly one rollback export step"
    script = steps[0]["run"]
    selection, marker, _ = script.partition("./scripts/export-client.sh")
    assert marker, "rollback export must call export-client.sh"
    return selection + 'printf "%s\\n" "${clients[@]}"\n'


def exported(environment: str) -> list[str]:
    bash = shutil.which("bash")
    if not bash or not shutil.which("jq"):
        pytest.skip("bash and jq are required to execute the workflow selector")
    result = subprocess.run([bash, "-c", selector_script()], cwd=ROOT, capture_output=True, text=True,
                            env={"DEPLOY_ENVIRONMENT": environment, "PATH": os.environ["PATH"]})
    assert result.returncode == 0, result.stderr
    return [line for line in result.stdout.splitlines() if line]


def policy(name: str) -> dict:
    return json.loads((ROOT / "config" / "policy" / name).read_text(encoding="utf-8"))


def test_production_rollback_export_excludes_staging_only_clients():
    managed = policy("managed-clients.json")["clients"]
    scoped = policy("environment-scoped-clients.json")["clients"]
    production = exported("production")
    assert "klyrow-staging-portal" not in production
    assert production == [c for c in managed if "production" in scoped.get(c, ["production"])]


def test_staging_rollback_export_keeps_every_managed_client_allowed_in_staging():
    scopes = policy("environment-scoped-clients.json")["clients"]
    allowed = [c for c in policy("managed-clients.json")["clients"] if "staging" in scopes.get(c, ["staging"])]
    assert exported("staging") == allowed
    assert "klyrow-staging-portal" in allowed and "monitoring-readonly" not in allowed


def test_unknown_environment_exports_no_scoped_client():
    assert "klyrow-staging-portal" not in exported("lab")
