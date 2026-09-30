#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import re
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
SECURITY = ROOT / "config" / "security"
REALM_SECURITY_POLICY = SECURITY / "realm-security-policy.json"
REQUIRED_ACTIONS = SECURITY / "required-actions.json"
USER_PROFILE = SECURITY / "user-profile.json"
REQUIRED_ACTIONS_SCHEMA = "codestra.keycloak.required-actions.v1"
USER_PROFILE_SCHEMA = "codestra.keycloak.user-profile-attributes.v1"
REQUIRED_ACTION_FIELDS = {"alias", "policyKey", "enabled", "defaultAction"}
PROFILE_ATTRIBUTE_FIELDS = {"name", "displayName", "multivalued", "permissions", "validations", "annotations"}
# Keycloak's own profile attributes belong to the realm configuration, not to this declaration.
BUILT_IN_PROFILE_ATTRIBUTES = {"username", "email", "firstName", "lastName"}
ATTRIBUTE_MAPPERS = {"oidc-usermodel-attribute-mapper", "saml-user-attribute-mapper"}
# Keycloak stores these fields in varchar(255) columns; a longer value fails its write
# with a database error after earlier writes have already landed.
KEYCLOAK_COLUMN_LIMIT = 255
COLUMN_LIMITED_FIELDS = ("clientId", "name", "description", "rootUrl", "baseUrl")


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


def _required_actions(realm_model: dict[str, Any]) -> list[dict[str, Any]]:
    """Compile required actions from the realm security policy, one switch at a time.

    Each policy switch is either a required-action provider with the same enabled
    state or a managed realm setting with the same value, so the policy and the
    reconciled realm cannot disagree without failing here.
    """
    document = load_json(REQUIRED_ACTIONS)
    if document.get("schema") != REQUIRED_ACTIONS_SCHEMA:
        raise IdentityModelError("required_actions_schema_invalid")
    policy = load_json(REALM_SECURITY_POLICY).get("requiredActions")
    if not isinstance(policy, dict) or not policy or not all(isinstance(v, bool) for v in policy.values()):
        raise IdentityModelError("required_actions_policy_invalid")
    covered: set[str] = set()
    output: list[dict[str, Any]] = []
    for entry in document.get("requiredActions") or []:
        if not isinstance(entry, dict) or set(entry) != REQUIRED_ACTION_FIELDS:
            raise IdentityModelError("required_action_fields_invalid")
        alias = entry["alias"]
        key = entry["policyKey"]
        if not isinstance(alias, str) or not alias.strip():
            raise IdentityModelError("required_action_missing_alias")
        if any(row["alias"] == alias for row in output):
            raise IdentityModelError(f"duplicate_required_action:{alias}")
        if key not in policy:
            raise IdentityModelError(f"required_action_policy_key_unknown:{alias}:{key}")
        if key in covered:
            raise IdentityModelError(f"required_action_policy_key_duplicate:{key}")
        enabled = entry["enabled"]
        default_action = entry["defaultAction"]
        if not isinstance(enabled, bool) or not isinstance(default_action, bool):
            raise IdentityModelError(f"required_action_flags_invalid:{alias}")
        if enabled is not policy[key]:
            raise IdentityModelError(f"required_action_policy_mismatch:{alias}")
        if default_action and not enabled:
            raise IdentityModelError(f"required_action_default_disabled:{alias}")
        covered.add(key)
        output.append({"alias": alias, "enabled": enabled, "defaultAction": default_action})
    settings = document.get("realmSettings")
    if not isinstance(settings, dict):
        raise IdentityModelError("required_actions_realm_settings_invalid")
    for key, field in settings.items():
        if key not in policy:
            raise IdentityModelError(f"required_action_policy_key_unknown:realm:{key}")
        if key in covered:
            raise IdentityModelError(f"required_action_policy_key_duplicate:{key}")
        if field not in realm_model or realm_model.get(field) is not policy[key]:
            raise IdentityModelError(f"required_action_realm_setting_mismatch:{key}")
        covered.add(key)
    uncovered = sorted(set(policy) - covered)
    if uncovered:
        raise IdentityModelError(f"required_action_policy_uncovered:{','.join(uncovered)}")
    return sorted(output, key=lambda row: row["alias"])


def validate_service_account_roles(
    entries: list[dict[str, Any]],
    roles_by_name: dict[str, dict[str, Any]],
    protected_by_id: dict[str, dict[str, Any]],
    scope_mapping_roles: dict[str, set[str]],
) -> None:
    """A service account may hold only active service roles of one family that reach its token."""
    for entry in entries:
        client_id = str(entry.get("clientId") or "")
        if set(entry) != {"clientId", "realmRoles"}:
            raise IdentityModelError(f"service_account_roles_fields_invalid:{client_id}")
        client = protected_by_id.get(client_id)
        if client is None:
            raise IdentityModelError(f"service_account_roles_client_not_protected:{client_id}")
        if client.get("serviceAccountsEnabled") is not True:
            raise IdentityModelError(f"service_account_roles_client_not_service:{client_id}")
        names = entry.get("realmRoles")
        if (
            not isinstance(names, list)
            or not names
            or not all(isinstance(name, str) and name for name in names)
            or len(set(names)) != len(names)
        ):
            raise IdentityModelError(f"service_account_roles_invalid:{client_id}")
        unknown = sorted(name for name in names if name not in roles_by_name)
        if unknown:
            raise IdentityModelError(f"service_account_role_unknown:{client_id}:{','.join(unknown)}")
        for name in names:
            attributes = roles_by_name[name].get("attributes") or {}
            # A human role on a machine identity is exactly the leakage the model forbids.
            if attributes.get("codestra.actor.kind") != ["service"]:
                raise IdentityModelError(f"service_account_role_not_service:{client_id}:{name}")
            if "PREPARED_DISABLED" in (attributes.get("codestra.activation") or []):
                raise IdentityModelError(f"service_account_role_not_active:{client_id}:{name}")
        families = {
            tuple((roles_by_name[name].get("attributes") or {}).get("codestra.role.family") or [])
            for name in names
        }
        if len(families) > 1:
            raise IdentityModelError(f"service_account_roles_cross_family:{client_id}")
        # Service clients never have full scope, so a role outside the client's role
        # scope mapping would be granted without ever reaching its access token.
        mapped = scope_mapping_roles.get(client_id, set())
        for name in names:
            if name not in mapped:
                raise IdentityModelError(f"service_account_role_not_in_token_scope:{client_id}:{name}")


def _admin_edit_only(attribute: Any) -> bool:
    permissions = attribute.get("permissions") if isinstance(attribute, dict) else None
    return (
        isinstance(permissions, dict)
        and permissions.get("edit") == ["admin"]
        and isinstance(permissions.get("view"), list)
        and set(permissions["view"]) <= {"admin", "user"}
    )


def _contains_secret(value: Any) -> bool:
    if isinstance(value, dict):
        return any(
            (str(key).lower() in SECRET_CONFIG_KEYS and bool(item)) or _contains_secret(item)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return any(_contains_secret(item) for item in value)
    return False


def _token_attribute_owners(documents: list[tuple[str, dict[str, Any]]]) -> dict[str, set[str]]:
    """Map each user attribute that a protocol mapper copies into a token to its owners."""
    owners: dict[str, set[str]] = {}
    for label, document in documents:
        for mapper in document.get("protocolMappers") or []:
            if mapper.get("protocolMapper") not in ATTRIBUTE_MAPPERS:
                continue
            attribute = str((mapper.get("config") or {}).get("user.attribute") or "")
            if attribute:
                owners.setdefault(attribute, set()).add(label)
    return owners


def _user_profile_attributes(token_owners: dict[str, set[str]]) -> list[dict[str, Any]]:
    """Declared user-profile attributes, and the rule that token claims are admin-edited.

    A claim copied from a user attribute is only as trustworthy as the attribute:
    if the user could edit it, the user could choose the claim. Every such
    attribute must therefore be declared, here or by the family that owns it,
    with edit rights for administrators only.
    """
    document = load_json(USER_PROFILE)
    if document.get("schema") != USER_PROFILE_SCHEMA:
        raise IdentityModelError("user_profile_schema_invalid")
    family: dict[str, dict[str, Any]] = {}
    for _path, fragment in _nested_documents("user-profile"):
        for attribute in fragment.get("attributes") or []:
            if isinstance(attribute, dict) and attribute.get("name"):
                family[str(attribute["name"])] = attribute
    output: list[dict[str, Any]] = []
    for attribute in document.get("attributes") or []:
        name = attribute.get("name") if isinstance(attribute, dict) else None
        if (
            not isinstance(attribute, dict)
            or not set(attribute) <= PROFILE_ATTRIBUTE_FIELDS
            or not {"name", "permissions"} <= set(attribute)
        ):
            raise IdentityModelError(f"user_profile_attribute_fields_invalid:{name}")
        if not isinstance(name, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", name):
            raise IdentityModelError(f"user_profile_attribute_name_invalid:{name}")
        if any(row["name"] == name for row in output):
            raise IdentityModelError(f"duplicate_user_profile_attribute:{name}")
        if name in BUILT_IN_PROFILE_ATTRIBUTES:
            raise IdentityModelError(f"user_profile_attribute_built_in:{name}")
        # A family reconciler owns its own attributes; declaring them here as well
        # would make two reconcilers write the same attribute.
        if name in family:
            raise IdentityModelError(f"user_profile_attribute_family_owned:{name}")
        if not _admin_edit_only(attribute):
            raise IdentityModelError(f"user_profile_attribute_user_editable:{name}")
        if _contains_secret(attribute):
            raise IdentityModelError(f"user_profile_attribute_secret:{name}")
        output.append(attribute)
    admin_only = {row["name"] for row in output} | {
        name for name, attribute in family.items() if _admin_edit_only(attribute)
    }
    for attribute, owners in sorted(token_owners.items()):
        if attribute not in admin_only:
            raise IdentityModelError(
                f"token_claim_attribute_not_admin_only:{sorted(owners)[0]}:{attribute}"
            )
    return sorted(output, key=lambda row: row["name"])


def validate_column_limits(label: str, document: dict[str, Any]) -> None:
    for field in COLUMN_LIMITED_FIELDS:
        value = document.get(field)
        if isinstance(value, str) and len(value) > KEYCLOAK_COLUMN_LIMIT:
            raise IdentityModelError(f"keycloak_column_too_long:{label}:{field}:{len(value)}")


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
    service_account_role_docs = _nested_documents("service-account-roles")

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
    service_account_roles = _unique_by(service_account_role_docs, "clientId", "service_account_roles")
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
    validate_service_account_roles(
        service_account_roles,
        {role["name"]: role for role in roles},
        {client["clientId"]: client for client in protected_clients},
        {str(m["clientId"]): set(m.get("realmRoles") or []) for m in scope_mappings},
    )
    token_owners = _token_attribute_owners(
        [(f"client:{client['clientId']}", client) for client in protected_clients]
        + [(f"client:{item['client']['clientId']}", item["client"]) for item in staged_with_provenance]
        + [(f"scope:{scope['name']}", scope) for scope in scopes]
    )
    user_profile_attributes = _user_profile_attributes(token_owners)
    for client in protected_clients + [item["client"] for item in staged_with_provenance]:
        validate_column_limits(f"client:{client['clientId']}", client)
    for scope in scopes:
        validate_column_limits(f"scope:{scope['name']}", scope)
    for role in roles:
        validate_column_limits(f"realm_role:{role['name']}", role)
    for entry in client_roles:
        for role in entry["roles"]:
            validate_column_limits(f"client_role:{entry['clientId']}:{role['name']}", role)
    realm_model = {
        "realm": realm["realm"],
        "enabled": realm["enabled"],
        "sslRequired": realm.get("sslRequired"),
        "verifyEmail": realm.get("verifyEmail"),
        "resetPasswordAllowed": realm.get("resetPasswordAllowed"),
        "bruteForceProtected": realm.get("bruteForceProtected"),
        "accessTokenLifespan": realm.get("accessTokenLifespan"),
    }
    required_actions = _required_actions(realm_model)

    model: dict[str, Any] = {
        "schema": "codestra.keycloak.identity-authority.v1",
        "realm": realm_model,
        "clients": protected_clients,
        "stagedClients": staged_with_provenance,
        "clientScopes": scopes,
        "realmRoles": roles,
        "clientRoles": client_roles,
        "scopeMappings": scope_mappings,
        "serviceAccountRoles": [
            {"clientId": entry["clientId"], "realmRoles": sorted(entry["realmRoles"])}
            for entry in service_account_roles
        ],
        "requiredActions": required_actions,
        "userProfileAttributes": user_profile_attributes,
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
    scoped["serviceAccountRoles"] = [
        m for m in model.get("serviceAccountRoles", []) if m.get("clientId") not in excluded
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
                "requiredActions": len(model["requiredActions"]),
                "serviceAccountRoles": len(model["serviceAccountRoles"]),
                "userProfileAttributes": len(model["userProfileAttributes"]),
                "sha256": model["sourceSha256"],
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
