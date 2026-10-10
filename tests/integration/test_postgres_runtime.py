"""Exercise the production PostgreSQL service with disposable Compose resources.

Run explicitly with a working Docker daemon. No production service or host port
is used; each run owns its project name and removes only that project's volumes.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import subprocess
import uuid

import pytest


ROOT = Path(__file__).resolve().parents[2]


class PostgresStack:
    def __init__(self) -> None:
        self.project = f"keycloak-pg-test-{uuid.uuid4().hex[:12]}"
        self.password = secrets.token_urlsafe(32)
        self.env = dict(os.environ)
        self.env.update(
            POSTGRES_DB="keycloak_test",
            POSTGRES_USER="keycloak_test",
            POSTGRES_PASSWORD=self.password,
            KEYCLOAK_IMAGE=(
                "ghcr.io/appolon1908-hue/codestra-keycloak:"
                + "a" * 40 + "@sha256:" + "b" * 64
            ),
            KC_BOOTSTRAP_ADMIN_USERNAME="ci-bootstrap-admin",
            KC_BOOTSTRAP_ADMIN_PASSWORD=secrets.token_urlsafe(32),
            MONEYBEE_EMAIL_OTP_HMAC_KEY=secrets.token_urlsafe(48),
        )

    def compose(self, *args: str) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["docker", "compose", "--project-name", self.project,
             "--file", str(ROOT / "compose.yaml"), *args],
            cwd=ROOT, env=self.env, text=True, capture_output=True, timeout=180,
        )
        # Keep generated fixture credentials out of assertion diagnostics.
        for name in ("POSTGRES_PASSWORD", "KC_BOOTSTRAP_ADMIN_PASSWORD",
                     "MONEYBEE_EMAIL_OTP_HMAC_KEY"):
            result.stdout = result.stdout.replace(self.env[name], "[redacted]")
            result.stderr = result.stderr.replace(self.env[name], "[redacted]")
        return result

    def start(self) -> subprocess.CompletedProcess[str]:
        return self.compose("up", "--detach", "--wait", "--wait-timeout", "45", "postgres")

    def require_ready(self, result: subprocess.CompletedProcess[str]) -> None:
        if result.returncode:
            logs = self.compose("logs", "--no-color", "postgres")
            pytest.fail(f"PostgreSQL failed to become healthy:\n{result.stderr}\n{logs.stdout}")

    def query(self, sql: str) -> str:
        result = self.compose(
            "exec", "--no-TTY", "postgres", "psql", "--username", "keycloak_test",
            "--dbname", "keycloak_test", "--no-psqlrc", "--set", "ON_ERROR_STOP=1",
            "--tuples-only", "--no-align", "--command", sql,
        )
        assert result.returncode == 0, result.stderr
        return result.stdout.strip()


@pytest.fixture(scope="module")
def postgres_stack():
    stack = PostgresStack()
    try:
        yield stack
    finally:
        cleanup = stack.compose("down", "--volumes", "--remove-orphans")
        assert cleanup.returncode == 0, cleanup.stderr


def test_empty_volume_initializes(postgres_stack):
    postgres_stack.require_ready(postgres_stack.start())
    assert postgres_stack.query("SELECT 1") == "1"
    result = postgres_stack.compose("exec", "--no-TTY", "postgres", "id", "-u")
    assert result.returncode == 0
    assert result.stdout.strip() == "70"


def test_restart_preserves_row(postgres_stack):
    postgres_stack.require_ready(postgres_stack.start())
    postgres_stack.query("CREATE TABLE IF NOT EXISTS startup_probe (id integer PRIMARY KEY)")
    postgres_stack.query("INSERT INTO startup_probe VALUES (17) ON CONFLICT DO NOTHING")
    stopped = postgres_stack.compose("stop", "postgres")
    assert stopped.returncode == 0, stopped.stderr
    # Recreate the runtime and rerun one-shot dependencies against the same data.
    result = postgres_stack.compose(
        "up", "--detach", "--force-recreate", "--wait", "--wait-timeout", "45", "postgres",
    )
    postgres_stack.require_ready(result)
    assert postgres_stack.query("SELECT id FROM startup_probe") == "17"


def test_runtime_remains_unprivileged(postgres_stack):
    rendered = postgres_stack.compose("config", "--format", "json")
    assert rendered.returncode == 0, rendered.stderr
    services = json.loads(rendered.stdout)["services"]
    postgres = services["postgres"]
    assert postgres.get("user") == "70:70"
    assert postgres["cap_drop"] == ["ALL"]
    assert not postgres.get("cap_add")
    assert not postgres.get("privileged")
    assert postgres["read_only"] is True
    assert postgres["security_opt"] == ["no-new-privileges:true"]
    assert not postgres.get("ports")
    initializer = services["postgres-volume-init"]
    assert initializer["user"] == "0:0"
    assert initializer["network_mode"] == "none"
    assert initializer["cap_drop"] == ["ALL"]
    assert set(initializer["cap_add"]) == {"CHOWN", "FOWNER"}
    assert initializer["restart"] == "no"
    assert initializer["read_only"] is True
    assert not initializer.get("privileged")
    assert not initializer.get("ports")
    assert not initializer.get("environment")
    postgres_stack.require_ready(postgres_stack.start())
    cid = postgres_stack.compose("ps", "--quiet", "postgres").stdout.strip()
    inspected = subprocess.run(
        ["docker", "inspect", cid], text=True, capture_output=True, check=True, timeout=30,
    )
    container = json.loads(inspected.stdout)[0]
    container["Config"].pop("Env", None)
    assert container["Config"]["User"] == "70:70"
    assert container["HostConfig"]["CapDrop"] == ["ALL"]
    assert not container["HostConfig"]["CapAdd"]
    assert container["HostConfig"]["ReadonlyRootfs"]
    assert not container["HostConfig"]["Privileged"]
    assert not container["HostConfig"]["PortBindings"]
