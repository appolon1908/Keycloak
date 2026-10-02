"""Invariants of the canonical identity flow: determinism, digests, plan integrity, ordering, isolation."""
from __future__ import annotations
import copy,json,re,subprocess,sys
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts")); sys.path.insert(0,str(ROOT/"tests"))
import keycloak_identity_compiler as compiler
from keycloak_identity_compiler import IdentityModelError,compile_identity,scoped_for_environment,sha
from keycloak_reconciliation import RESOURCE_ORDER,apply_plan,digest,normalize_state,plan
from test_pas237_keycloak_control_plane import FakeAdminAPI,enable_staging_mutation,live_fixture,make_service

def load(path): return json.loads(Path(path).read_text(encoding="utf-8"))

def mutated_model(monkeypatch,relative,mutate):
    target=(ROOT/relative).resolve(); doc=load(target); mutate(doc); original=compiler.load_json
    monkeypatch.setattr(compiler,"load_json",lambda p: copy.deepcopy(doc) if Path(p).resolve()==target else original(p))
    return compile_identity()

# --- determinism and hash order -------------------------------------------------

def test_compilation_is_byte_deterministic_and_matches_the_committed_authority():
    first=json.dumps(compile_identity(),indent=2,sort_keys=True,ensure_ascii=False)+"\n"
    second=json.dumps(compile_identity(),indent=2,sort_keys=True,ensure_ascii=False)+"\n"
    assert first==second
    assert first==(ROOT/"generated"/"keycloak-identity-authority.v1.json").read_text(encoding="utf-8")

def test_source_digest_is_the_last_step_over_the_complete_model():
    model=compile_identity()
    assert list(model)[-1]=="sourceSha256"
    assert model["sourceSha256"]==sha({k:v for k,v in model.items() if k!="sourceSha256"})
    for section in ("clients","stagedClients","clientScopes","realmRoles","clientRoles","scopeMappings","serviceAccountRoles","requiredActions","userProfileAttributes","environmentScopes","ownership","environmentBoundaries"):
        assert section in model

# --- every security-relevant mutation moves the digest -------------------------

AGENT="config/clients/codestra-agent-desktop.json"
SERVICE="config/clients/middleware-api.json"
CIP_CLIENT="config/desired-state/cip-tenant-identity/clients/test-syn-cip-tenant-a-automation.json"
MUTATIONS={
    "client_enabled":(AGENT,lambda d: d.update(enabled=not d.get("enabled",True))),
    "redirect_uri":(AGENT,lambda d: d["redirectUris"].append("https://other.example/cb")),
    "web_origin":(AGENT,lambda d: d["webOrigins"].append("https://other.example")),
    "audience_mapper":(SERVICE,lambda d: d["protocolMappers"][0]["config"].update({"included.custom.audience":"other-api"})),
    "token_lifetime":(SERVICE,lambda d: d.setdefault("attributes",{}).update({"access.token.lifespan":"299"})),
    "default_scope":(AGENT,lambda d: d["defaultClientScopes"].append("email")),
    "grant_type":(SERVICE,lambda d: d.update(standardFlowEnabled=True)),
    "tenant_claim":(CIP_CLIENT,lambda d: next(m for m in d["protocolMappers"] if (m.get("config") or {}).get("claim.name")=="tenant_id")["config"].update({"claim.value":"OTHER_TENANT"})),
    "realm_role":("config/desired-state/agent-desktop-identity/realm-roles/telephony.webphone.use.json",lambda d: d["attributes"].update({"codestra.mfa.required":["true"]})),
    "client_role":("config/desired-state/agent-desktop-identity/client-roles/codestra-agent-desktop.json",lambda d: d["roles"][0].update(description="changed")),
    "scope_mapping":("config/desired-state/agent-desktop-identity/scope-mappings/codestra-agent-desktop.json",lambda d: d.update(crossFamilyRolesAllowed=False,fullScopeAllowed=False)),
    "scope_mapper":("config/desired-state/cip-tenant-identity/client-scopes/cip.user.context.json",lambda d: d["protocolMappers"][0]["config"].update({"access.token.claim":"false"})),
    "environment":("config/policy/environment-scoped-clients.json",lambda d: d["clients"].update({"klyrow-staging-portal":["staging","test-syn"]})),
    "required_action":("config/security/required-actions.json",lambda d: d["requiredActions"][0].update(defaultAction=True)),
    "profile_attribute":("config/security/user-profile.json",lambda d: d["attributes"][0]["validations"]["length"].update(max=64)),
}

@pytest.mark.parametrize("name",sorted(MUTATIONS))
def test_every_security_relevant_mutation_changes_the_digest(monkeypatch,name):
    """A security change either moves the digest or fails validation; it never passes silently."""
    base=compile_identity()["sourceSha256"]
    relative,mutate=MUTATIONS[name]
    if name=="scope_mapping":
        mutate=lambda d: d.update(realmRoles=[])
    try:
        changed=mutated_model(monkeypatch,relative,mutate)["sourceSha256"]
    except IdentityModelError:
        return
    assert changed!=base

def test_identical_sources_give_identical_digests():
    assert compile_identity()["sourceSha256"]==compile_identity()["sourceSha256"]

def test_planned_desired_digest_covers_every_planned_resource_type():
    model=scoped_for_environment(compile_identity(),"staging"); base=digest(normalize_state(model))
    for key,change in (("clients",lambda m: m["clients"][0].update(enabled=False)),("clientScopes",lambda m: m["clientScopes"][0].update(description="x")),
                       ("realmRoles",lambda m: m["realmRoles"][0].update(description="x")),("clientRoles",lambda m: m["clientRoles"][0]["roles"][0].update(description="x")),
                       ("scopeMappings",lambda m: m["scopeMappings"][0]["realmRoles"].append("x")),("serviceAccountRoles",lambda m: m["serviceAccountRoles"].append({"clientId":"x","realmRoles":["y"]})),
                       ("requiredActions",lambda m: m["requiredActions"][0].update(enabled=False)),("userProfileAttributes",lambda m: m["userProfileAttributes"][0].update(multivalued=True)),
                       ("realm",lambda m: m["realm"].update(accessTokenLifespan=600))):
        changed=copy.deepcopy(model); change(changed)
        assert digest(normalize_state(changed))!=base,key

# --- plan integrity and stale plans --------------------------------------------

DESIRED={"realm":{"realm":"codestra","enabled":True},"clients":[{"clientId":"a","enabled":True,"redirectUris":["https://a.example/cb"]}],"realmRoles":[{"name":"r"}]}
LIVE={"realm":{"realm":"codestra","enabled":True},"clients":[],"realmRoles":[]}

class Recorder:
    def __init__(self): self.calls=[]
    def __getattr__(self,name): return lambda *a,**k: self.calls.append(name)

TAMPERS={
    "changed_client":lambda p: p["actions"].__setitem__(0,{**p["actions"][0],"resource_id":"b"}),
    "added_action":lambda p: p["actions"].append({"kind":"CREATE","resource_type":"realm_role","resource_id":"admin","reason":"x","managed":True}),
    "removed_action":lambda p: p["actions"].pop(),
    "changed_kind":lambda p: p["actions"][-1].update(kind="DELETE"),
    "changed_environment":lambda p: p.update(environment="production"),
    "changed_digest":lambda p: p.update(desiredSha256="0"*64),
}

@pytest.mark.parametrize("name",sorted(TAMPERS))
def test_a_tampered_plan_is_rejected_before_any_write(name):
    doc=plan(DESIRED,LIVE,environment="staging"); TAMPERS[name](doc); api=Recorder()
    if name=="changed_environment":
        with pytest.raises(RuntimeError,match="environment_mismatch"): apply_plan(doc,DESIRED,LIVE,api,enabled=True,environment="staging")
    else:
        out=apply_plan(doc,DESIRED,LIVE,api,enabled=True,environment="staging")
        assert (out["status"],out["error"])==("REJECTED","plan_integrity_mismatch")
    assert api.calls==[]

def test_a_plan_is_stale_once_desired_or_live_state_changes():
    doc=plan(DESIRED,LIVE,environment="staging")
    newer=copy.deepcopy(DESIRED); newer["clients"][0]["redirectUris"].append("https://evil.example/cb")
    out=apply_plan(doc,newer,LIVE,Recorder(),enabled=True,environment="staging")
    assert (out["status"],out["error"])==("REJECTED","plan_stale_desired_state")
    moved=copy.deepcopy(LIVE); moved["realmRoles"].append({"name":"r"})
    out=apply_plan(doc,DESIRED,moved,Recorder(),enabled=True,environment="staging")
    assert (out["status"],out["error"])==("REJECTED","plan_stale_live_state")

def test_an_untampered_current_plan_applies():
    api=Recorder(); out=apply_plan(plan(DESIRED,LIVE,environment="staging"),DESIRED,LIVE,api,enabled=True,environment="staging")
    assert out["status"]=="APPLIED" and api.calls==["create_realm_role","create_client"]

# --- idempotency -------------------------------------------------------------------

def test_an_idempotency_key_cannot_be_replayed_for_a_different_desired_state(tmp_path,monkeypatch):
    enable_staging_mutation(monkeypatch)
    from test_pas237_keycloak_control_plane import DESIRED as BASE
    api=FakeAdminAPI(live_fixture()); service=make_service(tmp_path,api,BASE)
    first=service.apply("key-1")
    assert service.apply("key-1")["executionId"]==first["executionId"]
    changed=copy.deepcopy(BASE); changed["clients"][0]["enabled"]=not changed["clients"][0].get("enabled",True)
    other=make_service(tmp_path,api,changed); other.store=service.store
    from keycloak_admin_api import KeycloakAdminError
    with pytest.raises(KeycloakAdminError) as exc: other.apply("key-1")
    assert (exc.value.code,exc.value.status)==("idempotency_key_conflict",409)

# --- dependency order, cycles and unknown references ------------------------------

def test_plan_orders_dependencies_before_dependents():
    desired={"realm":{"realm":"codestra"},"userProfileAttributes":[{"name":"tenant_ids","permissions":{"view":["admin"],"edit":["admin"]}}],
             "clientScopes":[{"name":"s"}],"realmRoles":[{"name":"r"}],"clients":[{"clientId":"c","serviceAccountsEnabled":True}],
             "clientRoles":[{"clientId":"c","roles":[{"name":"cr"}]}],"scopeMappings":[{"clientId":"c","fullScopeAllowed":False,"realmRoles":["r"],"crossFamilyRolesAllowed":False}],
             "serviceAccountRoles":[{"clientId":"c","realmRoles":["r"]}],"requiredActions":[{"alias":"CONFIGURE_TOTP","enabled":True,"defaultAction":False}]}
    live={"realm":{"realm":"codestra"},"requiredActions":[{"alias":"CONFIGURE_TOTP","enabled":False,"defaultAction":False}]}
    types=[a["resource_type"] for a in plan(desired,live)["actions"] if a["kind"]!="KEEP"]
    assert types==sorted(types,key=RESOURCE_ORDER.index)
    assert types.index("realm_role")<types.index("client")<types.index("client_role")<types.index("scope_mapping")<types.index("service_account_roles")

def test_composite_roles_are_rejected_so_role_cycles_cannot_exist():
    with pytest.raises(IdentityModelError,match="composite_role_forbidden"):
        compiler.validate_role({"name":"loop","composite":True},"test",client_role=False)

def test_unknown_references_are_errors_not_writes():
    desired={"clients":[{"clientId":"c"}],"realmRoles":[],"scopeMappings":[{"clientId":"c","fullScopeAllowed":False,"realmRoles":["ghost"],"crossFamilyRolesAllowed":False}],
             "serviceAccountRoles":[{"clientId":"c","realmRoles":["ghost"]},{"clientId":"nobody","realmRoles":["r"]}],
             "clientRoles":[{"clientId":"missing","roles":[{"name":"x"}]}]}
    errors={(a["resource_type"],a["reason"].split(":")[0]) for a in plan(desired,{"clients":[]})["actions"] if a["kind"]=="ERROR"}
    assert errors=={("scope_mapping","scope_mapping_role_missing"),("service_account_roles","service_account_role_missing"),
                    ("service_account_roles","service_account_client_missing"),("client_role","client_role_client_missing")}

# --- environment isolation and unmanaged preservation -----------------------------

def test_environment_scoping_keeps_staging_and_test_syn_identities_out_of_production():
    model=compile_identity()
    production=scoped_for_environment(model,"production")
    assert "klyrow-staging-portal" not in {c["clientId"] for c in production["clients"]}
    assert not any(c["clientId"].startswith("test-syn-") for c in production["clients"])
    assert all(item["client"]["clientId"] not in {c["clientId"] for c in model["clients"]} for item in model["stagedClients"])

def test_unmanaged_live_resources_are_kept_not_deleted():
    live={"clients":[{"id":"1","clientId":"foreign"}],"clientScopes":[{"id":"2","name":"foreign"}],"realmRoles":[{"name":"foreign"}],
          "clientRoles":[{"clientId":"foreign","name":"x"}],"scopeMappings":[{"clientId":"foreign","realmRoles":["foreign"]}],
          "serviceAccountRoles":[{"clientId":"foreign","realmRoles":["foreign"]}],"userProfileAttributes":[{"name":"foreign"}],
          "requiredActions":[{"alias":"foreign","enabled":True}]}
    desired={"clients":[],"clientScopes":[],"realmRoles":[],"userProfileAttributes":[],"requiredActions":[]}
    actions=[a for a in plan(desired,live)["actions"] if a["resource_type"]!="realm"]
    assert actions and all(a["kind"]=="KEEP" and a["managed"] is False for a in actions)

# --- one canonical writer -----------------------------------------------------------

WRITE=re.compile(r'"(POST|PUT|DELETE)"|-X (POST|PUT|DELETE)|keycloak_api (POST|PUT|DELETE)|method="(POST|PUT|DELETE)"|kcadm\.sh (create|update|delete)|\.(create_client|update_client|delete_client|update_realm)\(')
ADMIN=re.compile(r"admin/realms|KeycloakAdminAPI|kcadm")

def test_every_keycloak_writer_is_registered_and_one_adapter_is_canonical():
    registry=load(ROOT/"config"/"policy"/"identity-emitters.json")
    registered={e["path"]:e["role"] for e in registry["emitters"]}
    tracked=subprocess.check_output(["git","ls-files","scripts/*.py","scripts/*.sh"],cwd=ROOT,text=True).split()
    found={p for p in tracked if ADMIN.search((ROOT/p).read_text(encoding="utf-8",errors="replace")) and WRITE.search((ROOT/p).read_text(encoding="utf-8",errors="replace"))}
    assert found==set(registered),(sorted(found-set(registered)),sorted(set(registered)-found))
    assert [p for p,role in registered.items() if role=="canonical_adapter"]==["scripts/keycloak_admin_api.py"]
    assert {e["role"] for e in registry["emitters"]}<={"canonical_adapter","legacy_production_reconciler","family_staging_reconciler","read_only_probe"}
    for entry in registry["emitters"]:
        if entry["role"]=="family_staging_reconciler": assert entry["environments"]==["staging"],entry["path"]
