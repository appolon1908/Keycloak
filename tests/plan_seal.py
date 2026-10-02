"""Seal a hand-built plan the way plan() does, so a test exercises the path after integrity checks."""
from __future__ import annotations
from typing import Any
from keycloak_reconciliation import digest, normalize_state


def sealed(plan_doc: dict[str, Any], desired: dict[str, Any], live: dict[str, Any]) -> dict[str, Any]:
    doc = {k: v for k, v in plan_doc.items() if k != "planSha256"}
    doc["desiredSha256"] = digest(normalize_state(desired))
    doc["liveSha256"] = digest(normalize_state(live))
    doc["planSha256"] = digest(doc)
    return doc
