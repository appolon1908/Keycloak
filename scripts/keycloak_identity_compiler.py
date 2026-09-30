#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
REALM = ROOT / "config" / "realms" / "codestra.json"
CLIENTS = ROOT / "config" / "clients"
SCOPES = ROOT / "config" / "client-scopes"
CONTRACTS = ROOT / "config" / "contracts"
DESIRED_STATE = ROOT / "config" / "desired-state"
ENVIRONMENT_SCOPES = ROOT / "config" / "policy" / "environment-scoped-clients.json"
OUT = ROOT / "generated" / "keycloak-identity-authority.v1.json"
ENVIRONMENT_SCOPES_SCHEMA = "codestra.keycloak.environment-scoped-clients.v1"
# Every environment a protected client may be planned into. A client absent from the
# scope policy is allowed everywhere; a scoped client is planned only where listed.
ENVIRONMENTS = ("production", "staging", "test-syn")
SECRET_CONFIG_KEYS = {"secret", "client_secret", "password", "credential"}


class IdentityModelError(ValueError):
    pass


def load_json(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise IdentityModelError(f"load_failed:{path.name}:{exc}") from exc
    if not isinstance(value, dict):
        raise IdentityModelError(f"not_object:{path.name}")
    return value


def canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def validate_client(client: dict[str, Any]) -> None:
    client_id = str(client.get("clientId") or "")
    if not client_id:
        raise IdentityModelError("client_missing_id")

    redirects = list(client.get("redirectUris") or [])
    origins = list(client.get("webOrigins") or [])
    for value in redirects + origins:
        if value in {"*", "+"} or value.endswith("/*"):
            raise IdentityModelError(f"{client_id}:unsafe_redirect_or_origin")

    if client.get("directAccessGrantsEnabled") is True:
        raise IdentityModelError(f"{client_id}:direct_grants_forbidden")

    if client.get("serviceAccountsEnabled") is True:
        if client.get("publicClient") is not False or client.get("standardFlowEnabled") is not False:
            raise IdentityModelError(f"{client_id}:invalid_service_client")
        if redirects or origins:
            raise IdentityModelError(f"{client_id}:service_client_redirects_forbidden")
        if client.get("fullScopeAllowed") is not False:
            raise IdentityModelError(f"{client_id}:service_full_scope_forbidden")
    elif client.get("publicClient") is True and client.get("standardFlowEnabled") is not True:
        raise IdentityModelError(f"{client_id}:public_client_requires_code_flow")

    validate_mappers(client_id, client.get("protocolMappers"))


def validate_mappers(label: str, mappers: Any) -> None:
    """Mapper names are unique per owner and no two mappers write the same claim.

    Keycloak refuses a duplicate mapper name only at apply time, after earlier
    writes, and lets whichever of two mappers runs last win a shared claim.
    """
    names: set[str] = set()
    claims: set[str] = set()
    for mapper in mappers or []:
        config = mapper.get("config") or {}
        if any(
            key.lower() in SECRET_CONFIG_KEYS and config.get(key)
            for key in config
        ):
            raise IdentityModelError(f"{label}:secret_in_mapper")
        name = str(mapper.get("name") or "")
        if not name:
            raise IdentityModelError(f"{label}:protocol_mapper_missing_name")
        if name in names:
            raise IdentityModelError(f"{label}:duplicate_protocol_mapper:{name}")
        names.add(name)
        claim = str(config.get("claim.name") or "")
        if claim:
            if claim in claims:
                raise IdentityModelError(f"{label}:conflicting_protocol_mapper_claim:{claim}")
            claims.add(claim)


def validate_scope_mappings(
    mappings: list[dict[str, Any]],
    roles_by_name: dict[str, dict[str, Any]],
    known_client_ids: set[str],
) -> None:
    """A role scope mapping may only carry compiled realm roles of one family into a known client."""
    for mapping in mappings:
        client_id = str(mapping.get("clientId") or "")
        if client_id not in known_client_ids:
            raise IdentityModelError(f"scope_mapping_unknown_client:{client_id}")
        if mapping.get("fullScopeAllowed") is not False:
            raise IdentityModelError(f"scope_mapping_full_scope_forbidden:{client_id}")
        names = mapping.get("realmRoles")
        if not isinstance(names, list) or not names or len(set(names)) != len(names):
            raise IdentityModelError(f"scope_mapping_roles_invalid:{client_id}")
        unknown = sorted(name for name in names if name not in roles_by_name)
        if unknown:
            raise IdentityModelError(f"scope_mapping_role_unknown:{client_id}:{','.join(unknown)}")
        if mapping.get("crossFamilyRolesAllowed") is not False:
            raise IdentityModelError(f"scope_mapping_cross_family_flag_required:{client_id}")
        families = {
            tuple((roles_by_name[name].get("attributes") or {}).get("codestra.role.family") or [])
            for name in names
        }
        if len(families) > 1:
            raise IdentityModelError(f"scope_mapping_cross_family_roles:{client_id}")


def validate_role(role: Any, label: str, *, client_role: bool) -> dict[str, Any]:
    if not isinstance(role, dict) or not str(role.get("name") or "").strip():
        raise IdentityModelError(f"{label}:role_missing_name")
    name = str(role["name"])
    if role.get("composite") is True:
        raise IdentityModelError(f"{label}:{name}:composite_role_forbidden")
    if role.get("clientRole") not in (None, client_role):
        raise IdentityModelError(f"{label}:{name}:role_kind_mismatch")
    attributes = role.get("attributes") or {}
    if not isinstance(attributes, dict) or any(
        key.lower() in SECRET_CONFIG_KEYS and value for key, value in attributes.items()
    ):
        raise IdentityModelError(f"{label}:{name}:secret_in_role")
    return role


def _client_roles(
    documents: list[tuple[Path, dict[str, Any]]],
    known_client_ids: set[str],
) -> list[dict[str, Any]]:
    """Client roles are declared once per client under desired-state/**/client-roles.

    The client must be compiled here, otherwise reconciliation could never create
    the role and the declaration would silently satisfy nothing.
    """
    output: list[dict[str, Any]] = []
    for path, document in _unique_by_path(documents, "clientId", "client_roles"):
        client_id = str(document["clientId"])
        label = path.relative_to(ROOT).as_posix()
        if client_id not in known_client_ids:
            raise IdentityModelError(f"client_roles_unknown_client:{client_id}")
        roles = document.get("roles")
        if not isinstance(roles, list) or not roles:
            raise IdentityModelError(f"client_roles_empty:{client_id}")
        names: set[str] = set()
        for role in roles:
            validate_role(role, label, client_role=True)
            if role["name"] in names:
                raise IdentityModelError(f"duplicate_client_role:{client_id}:{role['name']}")
            names.add(role["name"])
        output.append(
            {
                "clientId": client_id,
                "roles": sorted(roles, key=lambda item: str(item["name"])),
            }
        )
    return sorted(output, key=lambda item: item["clientId"])


def _environment_scopes(protected_ids: set[str]) -> dict[str, list[str]]:
    """Return {clientId: [environments]} for clients that must never leave those environments."""
    if not ENVIRONMENT_SCOPES.exists():
        raise IdentityModelError("environment_scopes_missing")
    policy = load_json(ENVIRONMENT_SCOPES)
    if policy.get("schema") != ENVIRONMENT_SCOPES_SCHEMA:
        raise IdentityModelError("environment_scopes_schema_invalid")
    if list(policy.get("environments") or []) != list(ENVIRONMENTS):
        raise IdentityModelError("environment_scopes_environments_invalid")
    clients = policy.get("clients")
    if not isinstance(clients, dict):
        raise IdentityModelError("environment_scopes_clients_invalid")
    scopes: dict[str, list[str]] = {}
    for client_id, environments in clients.items():
        if client_id not in protected_ids:
            raise IdentityModelError(f"environment_scope_unmanaged_client:{client_id}")
        if (
            not isinstance(environments, list)
            or not environments
            or len(set(environments)) != len(environments)
            or any(env not in ENVIRONMENTS for env in environments)
            or environments != sorted(environments)
        ):
            raise IdentityModelError(f"environment_scope_invalid_environment:{client_id}")
        scopes[client_id] = list(environments)
    return dict(sorted(scopes.items()))


def _validate_contract_roles(
    realm_roles: set[str],
    client_roles: dict[str, set[str]],
    clients_by_id: dict[str, dict[str, Any]],
    scope_mapping_roles: dict[str, set[str]],
) -> None:
    """Every role a checked-in client contract requires must be compiled and reach the token."""
    for path in sorted(CONTRACTS.glob("*.json")):
        document = load_json(path)
        label = path.relative_to(ROOT).as_posix()
        required_realm_roles = document.get("requiredRealmRoles") or []
        for name in required_realm_roles:
            if name not in realm_roles:
                raise IdentityModelError(f"contract_realm_role_unprovisioned:{label}:{name}")
        required_client_roles = document.get("requiredClientRoles") or {}
        if not isinstance(required_client_roles, dict):
            raise IdentityModelError(f"contract_client_roles_invalid:{label}")
        for client_id, names in required_client_roles.items():
            for name in names or []:
                if name not in client_roles.get(str(client_id), set()):
                    raise IdentityModelError(
                        f"contract_client_role_unprovisioned:{label}:{client_id}:{name}"
                    )
        # A client without full scope only puts its own client roles and the realm roles
        # in its role scope mapping into a token; anything else never reaches the consumer.
        token_client = str(document.get("clientId") or "")
        if token_client and (required_realm_roles or required_client_roles):
            client = clients_by_id.get(token_client)
            if client is None:
                raise IdentityModelError(f"contract_client_unknown:{label}:{token_client}")
            if client.get("fullScopeAllowed") is False:
                mapped = set(scope_mapping_roles.get(token_client, set()))
                for name in required_realm_roles:
                    if name not in mapped:
                        raise IdentityModelError(
                            f"contract_realm_role_not_in_token_scope:{label}:{token_client}:{name}"
                        )
                for client_id in required_client_roles:
                    if str(client_id) != token_client:
                        raise IdentityModelError(
                            f"contract_client_role_not_in_token_scope:{label}:{token_client}:{client_id}"
                        )
        if path.name.endswith("-client-roles.json"):
            client_id = str(document.get("clientId") or "")
            for role in document.get("roles") or []:
                if str(role.get("name") or "") not in client_roles.get(client_id, set()):
                    raise IdentityModelError(
                        f"contract_client_role_unprovisioned:{label}:{client_id}:{role.get('name')}"
                    )


def _unique_by_path(
    documents: list[tuple[Path, dict[str, Any]]],
    key: str,
    label: str,
) -> list[tuple[Path, dict[str, Any]]]:
    seen: dict[str, str] = {}
    output: list[tuple[Path, dict[str, Any]]] = []
    for path, document in documents:
        resource_id = str(document.get(key) or "")
        if not resource_id:
            raise IdentityModelError(f"{label}_missing_id:{path.relative_to(ROOT).as_posix()}")
        fingerprint = canonical(document)
        if resource_id in seen and seen[resource_id] != fingerprint:
            raise IdentityModelError(f"conflicting_{label}:{resource_id}")
        if resource_id in seen:
            continue
        seen[resource_id] = fingerprint
        output.append((path, document))
    return output


def _unique_by(
    documents: list[tuple[Path, dict[str, Any]]],
    key: str,
    label: str,
) -> list[dict[str, Any]]:
    seen: dict[str, str] = {}
    output: list[dict[str, Any]] = []
    for path, document in documents:
        resource_id = str(document.get(key) or "")
        if not resource_id:
            raise IdentityModelError(f"{label}_missing_id:{path.relative_to(ROOT).as_posix()}")
        fingerprint = canonical(document)
        if resource_id in seen and seen[resource_id] != fingerprint:
            raise IdentityModelError(f"conflicting_{label}:{resource_id}")
        if resource_id in seen:
            continue
        seen[resource_id] = fingerprint
        output.append(document)
    return sorted(output, key=lambda item: str(item.get(key) or ""))


def _nested_documents(directory_name: str) -> list[tuple[Path, dict[str, Any]]]:
    rows: list[tuple[Path, dict[str, Any]]] = []
    if not DESIRED_STATE.exists():
        return rows
    for path in sorted(DESIRED_STATE.rglob("*.json")):
        if path.parent.name == directory_name:
            rows.append((path, load_json(path)))
    return rows


def compile_identity() -> dict[str, Any]:
    realm = load_json(REALM)
    protected_client_docs = [(path, load_json(path)) for path in sorted(CLIENTS.glob("*.json"))]
    staged_client_docs = _nested_documents("clients")
    top_scope_docs = [(path, load_json(path)) for path in sorted(SCOPES.glob("*.json"))]
    nested_scope_docs = _nested_documents("client-scopes")
    role_docs = _nested_documents("realm-roles")
    client_role_docs = _nested_documents("client-roles")
    scope_mapping_docs = _nested_documents("scope-mappings")

    if realm.get("realm") != "codestra" or realm.get("enabled") is not True:
        raise IdentityModelError("realm_invalid")

    protected_clients = _unique_by(protected_client_docs, "clientId", "client")
    for client in protected_clients:
        validate_client(client)

    protected_ids = {client["clientId"] for client in protected_clients}
    scopes = _unique_by(top_scope_docs + nested_scope_docs, "name", "scope")
    roles = _unique_by(role_docs, "name", "realm_role")
    for role in roles:
        validate_role(role, "realm-roles", client_role=False)
    for scope in scopes:
        validate_mappers(f"scope:{scope['name']}", scope.get("protocolMappers"))
    scope_mappings = _unique_by(scope_mapping_docs, "clientId", "scope_mapping")
    environment_scopes = _environment_scopes(protected_ids)

    staged_with_provenance = []
    staged_group_ids: set[tuple[str, str]] = set()
    for path, client in staged_client_docs:
        validate_client(client)
        group = path.parents[1].name
        client_id = str(client["clientId"])
        group_key = (group, client_id)
        if group_key in staged_group_ids:
            raise IdentityModelError(f"duplicate_staged_client:{group}:{client_id}")
        staged_group_ids.add(group_key)
        if client_id in protected_ids:
            raise IdentityModelError(f"protected_staged_client_overlap:{client_id}")
        staged_with_provenance.append(
            {
                "authorityGroup": group,
                "sourcePath": path.relative_to(ROOT).as_posix(),
                "client": client,
            }
        )
    staged_with_provenance.sort(key=lambda item: (item["authorityGroup"], item["client"]["clientId"]))

    known_client_ids = protected_ids | {item["client"]["clientId"] for item in staged_with_provenance}
    clients_by_id: dict[str, dict[str, Any]] = {}
    for client in protected_clients + [item["client"] for item in staged_with_provenance]:
        clients_by_id.setdefault(str(client["clientId"]), client)
    validate_scope_mappings(scope_mappings, {role["name"]: role for role in roles}, known_client_ids)
    client_roles = _client_roles(client_role_docs, known_client_ids)
    _validate_contract_roles(
        {role["name"] for role in roles},
        {entry["clientId"]: {role["name"] for role in entry["roles"]} for entry in client_roles},
        clients_by_id,
        {str(m["clientId"]): set(m.get("realmRoles") or []) for m in scope_mappings},
    )

    model: dict[str, Any] = {
        "schema": "codestra.keycloak.identity-authority.v1",
        "realm": {
            "realm": realm["realm"],
            "enabled": realm["enabled"],
            "sslRequired": realm.get("sslRequired"),
            "verifyEmail": realm.get("verifyEmail"),
            "resetPasswordAllowed": realm.get("resetPasswordAllowed"),
            "bruteForceProtected": realm.get("bruteForceProtected"),
            "accessTokenLifespan": realm.get("accessTokenLifespan"),
        },
        "clients": protected_clients,
        "stagedClients": staged_with_provenance,
        "clientScopes": scopes,
        "realmRoles": roles,
        "clientRoles": client_roles,
        "scopeMappings": scope_mappings,
        "environmentScopes": environment_scopes,
        "environmentBoundaries": {
            "production": {"issuer": "https://auth.codestra.co/realms/codestra"},
            "staging": {"issuer": "https://auth-staging.codestra.co/realms/codestra"},
            "testSyn": {"namingPrefix": "test-syn-", "productionPromotion": False},
        },
    }
    model["sourceSha256"] = sha(model)
    return model


def scoped_for_environment(model: dict[str, Any], environment: Any) -> dict[str, Any]:
    """Return the desired state that may be planned into one environment.

    A scoped client, its roles and its scope mapping are dropped unless the
    environment is one it is listed for. An unknown environment therefore never
    carries a scoped client anywhere, and a live copy of it is left unmanaged.
    """
    env = str(environment or "").strip().lower().replace("_", "-")
    env = "test-syn" if env == "testsyn" else env
    scopes = model.get("environmentScopes") or {}
    excluded = {client_id for client_id, envs in scopes.items() if env not in envs}
    if not excluded:
        return model
    scoped = dict(model)
    scoped["clients"] = [c for c in model.get("clients", []) if c.get("clientId") not in excluded]
    scoped["clientRoles"] = [
        r for r in model.get("clientRoles", []) if r.get("clientId") not in excluded
    ]
    scoped["scopeMappings"] = [
        m for m in model.get("scopeMappings", []) if m.get("clientId") not in excluded
    ]
    scoped["excludedClients"] = sorted(excluded)
    return scoped


def write_output(check: bool = False) -> dict[str, Any]:
    model = compile_identity()
    text = json.dumps(model, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    if check:
        if not OUT.exists() or OUT.read_text(encoding="utf-8") != text:
            raise IdentityModelError("generated_identity_drift")
    else:
        OUT.parent.mkdir(parents=True, exist_ok=True)
        OUT.write_text(text, encoding="utf-8")
    return model


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    try:
        model = write_output(args.check)
    except IdentityModelError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, sort_keys=True))
        return 2
    print(
        json.dumps(
            {
                "ok": True,
                "clients": len(model["clients"]),
                "stagedClients": len(model["stagedClients"]),
                "scopes": len(model["clientScopes"]),
                "roles": len(model["realmRoles"]),
                "clientRoles": sum(len(entry["roles"]) for entry in model["clientRoles"]),
                "environmentScopedClients": len(model["environmentScopes"]),
                "sha256": model["sourceSha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
