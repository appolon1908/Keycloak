"""Safely compile a separate Keycloak staging import candidate without applying it.

No privileged Keycloak Admin API call is made. Existing client/realm scope
definitions with a mismatched security contract fail closed.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def build(base: dict, contract: dict) -> dict:
    if base.get("realm") != contract["realm"]:
        raise ValueError("wrong_realm")
    if contract["environment"] != "staging" or contract["runtime_apply_authorized"]:
        raise ValueError("runtime_apply_not_permitted")
    if contract["client"]["attributes"]["pkce.code.challenge.method"] != "S256":
        raise ValueError("pkce_s256_required")
    if contract["backend_requirements"]["audience"] != "mission-control-backend":
        raise ValueError("backend_audience_mismatch")
    merged = json.loads(json.dumps(base))
    for key, item, field in (
        ("clients", contract["client"], "clientId"),
        ("clientScopes", contract["clientScope"], "name"),
    ):
        items = merged.setdefault(key, [])
        existing = next((x for x in items if x.get(field) == item[field]), None)
        if existing is None:
            items.append(item)
        elif existing != item:
            raise ValueError("conflicting_" + key)
    return merged


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", required=True, type=Path)
    opts = parser.parse_args()
    base = json.loads((ROOT / "config/realms/codestra.json").read_text())
    contract = json.loads((ROOT / "staging/mission-control-oidc.v1.json").read_text())
    compiled = build(base, contract)
    opts.output.parent.mkdir(parents=True, exist_ok=True)
    opts.output.write_text(json.dumps(compiled, indent=2) + "\n")
    print("KEYCLOAK_STAGING_CANDIDATE=GENERATED_NO_APPLY")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
