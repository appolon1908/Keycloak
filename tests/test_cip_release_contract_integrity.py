"""Integrity of the CIP release contract, the compiled authority digest and CIP scope semantics."""
from __future__ import annotations

import hashlib
import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from keycloak_identity_compiler import compile_identity, sha  # noqa: E402

CIP = ROOT / "config" / "desired-state" / "cip-tenant-identity"
RELEASE = ROOT / "release" / "cip-tenant-identity"
GATEWAY = RELEASE / "keycloak-cip-gateway-identity-contract.v1.json"
USER_CONTEXT = "cip.user.context"
TOKEN_AUTHORITY_CLAIMS = {"scope", "realm_access", "resource_access", "roles", "groups"}


def _reject_duplicates(pairs):
    keys = [key for key, _ in pairs]
    duplicates = sorted({key for key in keys if keys.count(key) > 1})
    if duplicates:
        raise ValueError(f"duplicate keys: {duplicates}")
    return dict(pairs)


def strict_load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_reject_duplicates)


def canonical_sha(document) -> str:
    return hashlib.sha256(json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()


def lf_bytes(path: Path) -> bytes:
    return path.read_bytes().replace(b"\r\n", b"\n")


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


# --- JSON structure and digests -----------------------------------------------

def test_no_tracked_json_file_has_duplicate_keys():
    tracked = subprocess.check_output(["git", "ls-files", "*.json"], cwd=ROOT, text=True).split()
    failures = []
    for name in tracked:
        try:
            strict_load(ROOT / name)
        except ValueError as exc:
            failures.append(f"{name}: {exc}")
    assert len(tracked) > 100 and failures == []


def test_gateway_contract_attests_its_sources_without_a_source_sha_field():
    contract = strict_load(GATEWAY)
    authority = contract["authority"]
    assert "sourceSha256" not in json.dumps(contract)
    assert authority["repository"] == "appolon1908/Keycloak"
    assert authority["contractSha256"] == canonical_sha(load(ROOT / authority["contract"]))
    assert authority["tokenMatrixSha256"] == canonical_sha(load(ROOT / authority["tokenMatrix"]))
    assert authority["parityEvidenceSha256"] == canonical_sha(load(ROOT / authority["parityEvidence"]))
    plan_path = ROOT / authority["desiredStatePlan"]
    assert authority["desiredStatePlanSha256"] == hashlib.sha256(lf_bytes(plan_path)).hexdigest()
    assert authority["configurationChecksum"] == load(plan_path)["configurationChecksum"]
    pinned = (RELEASE / "keycloak-cip-gateway-identity-contract.v1.sha256").read_text(encoding="utf-8").split()[0]
    assert pinned == hashlib.sha256(lf_bytes(GATEWAY)).hexdigest()


def test_compiled_authority_has_one_source_digest_derived_from_the_final_model():
    generated = ROOT / "generated" / "keycloak-identity-authority.v1.json"
    assert generated.read_text(encoding="utf-8").count('"sourceSha256"') == 1
    model = compile_identity()
    unsealed = {key: value for key, value in model.items() if key != "sourceSha256"}
    assert model["sourceSha256"] == sha(unsealed) == strict_load(generated)["sourceSha256"]


# --- cip.user.context is context, never authorization -------------------------

def test_client_context_is_not_an_authorization_scope():
    contract = load(CIP / "contract.json")
    scope = strict_load(CIP / "client-scopes" / f"{USER_CONTEXT}.json")
    assert scope["protocol"] == "openid-connect"
    assert scope["attributes"]["include.in.token.scope"] == "false"
    assert USER_CONTEXT not in {s["name"] for s in contract["productScopes"]}
    mappings = load(CIP / "scope-role-mappings" / "cip-product-scopes.json")["scopeMappings"]
    assert USER_CONTEXT not in {m["clientScope"] for m in mappings}
    assert f'"{USER_CONTEXT}"' not in json.dumps(load(ROOT / "config" / "contracts" / "middleware-api-access.v3.json"))
    edge = ROOT / "config" / "desired-state" / "edge-integration-certification"
    assert f'"{USER_CONTEXT}"' not in json.dumps(load(edge / "middleware-public-api-route-contract.v2.json"))
    for path in ROOT.glob("config/**/clients/*.json"):
        client = load(path)
        assert USER_CONTEXT not in (client.get("optionalClientScopes") or []), path.name
        if USER_CONTEXT in (client.get("defaultClientScopes") or []):
            assert client.get("publicClient") is True and client.get("serviceAccountsEnabled") is False, path.name


def test_client_context_mappers_are_access_token_context_claims_only():
    mappers = strict_load(CIP / "client-scopes" / f"{USER_CONTEXT}.json")["protocolMappers"]
    names = [m["name"] for m in mappers]
    assert len(names) == len(set(names)) == 3
    by_name = {m["name"]: m for m in mappers}
    assert by_name["tenant-id-from-admin-attribute"]["config"]["claim.name"] == "tenant_id"
    assert by_name["project-ids-from-admin-attribute"]["config"]["claim.name"] == "project_ids"
    assert by_name["amr"]["protocolMapper"] == "oidc-amr-mapper"
    for mapper in mappers:
        config = mapper["config"]
        assert mapper["protocol"] == "openid-connect" and mapper["consentRequired"] is False
        assert (config["access.token.claim"], config["id.token.claim"], config["userinfo.token.claim"]) == ("true", "false", "false")
        assert config.get("claim.name") not in TOKEN_AUTHORITY_CLAIMS
    attributes = {m["config"].get("user.attribute") for m in mappers} - {None}
    profile = {a["name"]: a for a in load(CIP / "user-profile" / "cip-tenant-attributes.json")["attributes"]}
    assert attributes == {"codestra_tenant_id", "codestra_project_ids"}
    assert all(profile[name]["permissions"]["edit"] == ["admin"] for name in attributes)


def test_cip_clients_do_not_emit_one_claim_from_two_owners():
    scopes = {load(p)["name"]: load(p) for p in ROOT.glob("config/**/client-scopes/*.json")}
    for path in sorted((CIP / "clients").glob("*.json")):
        client = load(path)
        owners: dict[str, str] = {}
        sources = [("client", client)] + [(name, scopes[name]) for name in client.get("defaultClientScopes") or [] if name in scopes]
        for owner, document in sources:
            for mapper in document.get("protocolMappers") or []:
                claim = (mapper.get("config") or {}).get("claim.name")
                if claim:
                    assert claim not in owners, f"{client['clientId']}: {claim} from {owners.get(claim)} and {owner}"
                    owners[claim] = owner


# --- fail-closed production portal and unbound scopes ------------------------

def test_production_cip_portal_stays_blocked():
    entry = next(c for c in load(CIP / "contract.json")["clients"] if c["clientId"] == "cip-portal")
    assert entry["status"] == "BLOCKED_ORIGIN_UNRESOLVED" and entry["rendered"] is False
    assert not any(load(p).get("clientId") == "cip-portal" for p in ROOT.glob("config/**/clients/*.json"))
    for policy in ("managed-clients.json", "creatable-clients.json", "environment-scoped-clients.json"):
        assert '"cip-portal"' not in json.dumps(load(ROOT / "config" / "policy" / policy))
    model = compile_identity()
    compiled = {c["clientId"] for c in model["clients"]} | {s["client"]["clientId"] for s in model["stagedClients"]}
    assert "cip-portal" not in compiled
    assert "blocked" in json.dumps(strict_load(GATEWAY)["activationPreconditions"]).lower()


def test_unbound_scopes_stay_unbound_until_middleware_routes_exist():
    contract = load(CIP / "contract.json")
    access = json.dumps(load(ROOT / "config" / "contracts" / "middleware-api-access.v3.json"))
    unbound = [s for s in contract["productScopes"] if s["routeBinding"]["status"] == "UNBOUND_PENDING_MIDDLEWARE_ROUTE"]
    assert {s["name"] for s in unbound} == {"cip.tenant.admin", "cip.connector.admin", "cip.usage.read", "cip.audit.read"}
    for scope in unbound:
        assert scope["routeBinding"]["routes"] == []
        assert f'"{scope["name"]}"' not in access, scope["name"]
    for scope in contract["productScopes"]:
        if scope["routeBinding"]["status"] == "BOUND":
            assert scope["routeBinding"]["routes"] and f'"{scope["name"]}"' in access


# --- one owner per identity object --------------------------------------------

def _owners(pattern: str, key: str) -> dict[str, set[str]]:
    owners: dict[str, set[str]] = {}
    for path in sorted(ROOT.glob(pattern)):
        owners.setdefault(load(path).get(key), set()).add(path.relative_to(ROOT).as_posix())
    return owners


@pytest.mark.parametrize("pattern,key", [
    ("config/**/clients/*.json", "clientId"),
    ("config/**/client-scopes/*.json", "name"),
    ("config/**/realm-roles/*.json", "name"),
])
def test_identity_authority_single_owner(pattern, key):
    assert {value: files for value, files in _owners(pattern, key).items() if len(files) > 1} == {}


def test_ownership_registry_traces_every_compiled_object_to_one_source():
    model = compile_identity()
    registry = {(e["resourceType"], e["resourceId"]): e for e in model["ownership"]}
    assert len(registry) == len(model["ownership"])
    for client in model["clients"]:
        assert registry[("client", client["clientId"])]["authorityGroup"] == "protected"
        for mapper in client.get("protocolMappers") or []:
            assert ("protocol_mapper", f"client:{client['clientId']}/{mapper['name']}") in registry
    for staged in model["stagedClients"]:
        entry = registry[("client", staged["client"]["clientId"])]
        assert (entry["authorityGroup"], entry["source"]) == (staged["authorityGroup"], staged["sourcePath"])
    for scope in model["clientScopes"]:
        assert ("client_scope", scope["name"]) in registry
    for role in model["realmRoles"]:
        assert ("realm_role", role["name"]) in registry
    for attribute in model["userProfileAttributes"]:
        assert registry[("user_profile_attribute", attribute["name"])]["authorityGroup"] == "realm-security"
    for entry in model["ownership"]:
        assert (ROOT / entry["source"]).is_file()


@pytest.mark.parametrize("directory,document,error", [
    ("clients", "test-syn-cip-portal", "identity_multiple_owners:client:test-syn-cip-portal"),
    ("client-scopes", "cip.user.context", "duplicate_scope:cip.user.context"),
    ("realm-roles", "cip-audit-viewer", "duplicate_realm_role:cip-audit-viewer"),
])
def test_a_second_owner_anywhere_fails_compilation(monkeypatch, directory, document, error):
    import keycloak_identity_compiler as compiler
    source = CIP / directory / f"{document}.json"
    copy_path = ROOT / "config" / "desired-state" / "edge-integration-certification" / directory / source.name
    original = compiler._nested_documents
    monkeypatch.setattr(compiler, "_nested_documents", lambda name: original(name) + ([(copy_path, load(source))] if name == directory else []))
    with pytest.raises(compiler.IdentityModelError, match=error):
        compile_identity()


def test_cip_staged_clients_belong_to_the_cip_authority_group():
    staged = [s for s in compile_identity()["stagedClients"] if s["client"]["clientId"].startswith("test-syn-cip-")]
    assert len(staged) == 4
    assert all(s["authorityGroup"] == "cip-tenant-identity" for s in staged)
    assert all(s["sourcePath"].startswith("config/desired-state/cip-tenant-identity/clients/") for s in staged)
