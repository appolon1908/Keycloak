from __future__ import annotations
import copy,json,sys
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts")); sys.path.insert(0,str(ROOT/"tests"))
import keycloak_identity_compiler as compiler
from keycloak_identity_compiler import IdentityModelError,compile_identity,scoped_for_environment
from keycloak_reconciliation import apply_plan,plan,verify_readback
from test_pas237_keycloak_control_plane import DESIRED,FakeAdminAPI,enable_staging_mutation,live_fixture,make_service

POLICY_SCHEMA="codestra.keycloak.environment-scoped-clients.v1"
ALL_ENVIRONMENTS=["production","staging","test-syn"]

# --- compiler -----------------------------------------------------------------

def test_compiler_scopes_staging_portal_and_provisions_agent_desktop_roles():
    model=compile_identity()
    assert model["environmentScopes"]=={"klyrow-staging-portal":["staging"]}
    roles={entry["clientId"]:{role["name"] for role in entry["roles"]} for entry in model["clientRoles"]}
    assert roles=={"codestra-agent-desktop":{"realtime.agent.connect"}}
    realm_roles={role["name"] for role in model["realmRoles"]}
    assert "telephony.webphone.use" in realm_roles
    contract=json.loads((ROOT/"config"/"contracts"/"agent-desktop-realtime-client.json").read_text(encoding="utf-8"))
    assert set(contract["requiredRealmRoles"])<=realm_roles
    for client_id,names in contract["requiredClientRoles"].items(): assert set(names)<=roles[client_id]
    desk=next(entry for entry in model["clientRoles"] if entry["clientId"]=="codestra-agent-desktop")["roles"][0]
    assert desk["clientRole"] is True and desk["composite"] is False

def test_scoped_for_environment_drops_scoped_client_roles_and_mappings_outside_its_environments():
    model={"clients":[{"clientId":"a"},{"clientId":"s"}],"clientRoles":[{"clientId":"s","roles":[{"name":"r"}]},{"clientId":"a","roles":[{"name":"x"}]}],"scopeMappings":[{"clientId":"s","realmRoles":[]}],"environmentScopes":{"s":["staging"]}}
    production=scoped_for_environment(model,"production")
    assert [c["clientId"] for c in production["clients"]]==["a"]
    assert production["clientRoles"]==[{"clientId":"a","roles":[{"name":"x"}]}] and production["scopeMappings"]==[]
    assert production["excludedClients"]==["s"]
    assert scoped_for_environment(model,"staging") is model
    # An unknown or foreign environment never carries a scoped client anywhere.
    for environment in ("unknown","",None,"test-syn","TEST_SYN","lab"):
        assert scoped_for_environment(model,environment)["excludedClients"]==["s"]

@pytest.mark.parametrize("policy,error",[
    ({"schema":POLICY_SCHEMA,"environments":ALL_ENVIRONMENTS,"clients":{"ghost":["staging"]}},"environment_scope_unmanaged_client:ghost"),
    ({"schema":POLICY_SCHEMA,"environments":ALL_ENVIRONMENTS,"clients":{"klyrow-staging-portal":["lab"]}},"environment_scope_invalid_environment"),
    ({"schema":POLICY_SCHEMA,"environments":ALL_ENVIRONMENTS,"clients":{"klyrow-staging-portal":[]}},"environment_scope_invalid_environment"),
    ({"schema":POLICY_SCHEMA,"environments":ALL_ENVIRONMENTS,"clients":{"klyrow-staging-portal":["staging","production"]}},"environment_scope_invalid_environment"),
    ({"schema":POLICY_SCHEMA,"environments":ALL_ENVIRONMENTS,"clients":{"klyrow-staging-portal":["staging","staging"]}},"environment_scope_invalid_environment"),
    ({"schema":POLICY_SCHEMA,"environments":ALL_ENVIRONMENTS,"clients":[]},"environment_scopes_clients_invalid"),
    ({"schema":"other","environments":ALL_ENVIRONMENTS,"clients":{}},"environment_scopes_schema_invalid"),
    ({"schema":POLICY_SCHEMA,"environments":["production"],"clients":{}},"environment_scopes_environments_invalid"),
])
def test_environment_scope_policy_fails_closed(tmp_path,monkeypatch,policy,error):
    path=tmp_path/"scopes.json"; path.write_text(json.dumps(policy),encoding="utf-8")
    monkeypatch.setattr(compiler,"ENVIRONMENT_SCOPES",path)
    with pytest.raises(IdentityModelError,match=error): compile_identity()
    monkeypatch.setattr(compiler,"ENVIRONMENT_SCOPES",tmp_path/"missing.json")
    with pytest.raises(IdentityModelError,match="environment_scopes_missing"): compile_identity()

def test_contract_roles_must_be_compiled_and_client_roles_need_a_compiled_client(monkeypatch):
    original=compiler._nested_documents
    monkeypatch.setattr(compiler,"_nested_documents",lambda name: [] if name=="client-roles" else original(name))
    with pytest.raises(IdentityModelError,match="contract_client_role_unprovisioned:.*codestra-agent-desktop:realtime.agent.connect"): compile_identity()
    monkeypatch.setattr(compiler,"_nested_documents",lambda name: [(p,d) for p,d in original(name) if d.get("name")!="telephony.webphone.use"] if name=="realm-roles" else original(name))
    # The desktop's scope mapping names the role too, so that reference fails closed first.
    with pytest.raises(IdentityModelError,match="scope_mapping_role_unknown:codestra-agent-desktop:telephony.webphone.use"): compile_identity()
    def without_role_or_mapping(name):
        rows=original(name)
        if name=="realm-roles": return [(p,d) for p,d in rows if d.get("name")!="telephony.webphone.use"]
        if name=="scope-mappings": return [(p,d) for p,d in rows if d.get("clientId")!="codestra-agent-desktop"]
        return rows
    monkeypatch.setattr(compiler,"_nested_documents",without_role_or_mapping)
    with pytest.raises(IdentityModelError,match="contract_realm_role_unprovisioned:.*telephony.webphone.use"): compile_identity()
    ghost=(ROOT/"config"/"desired-state"/"ghost"/"client-roles"/"ghost.json",{"clientId":"ghost","roles":[{"name":"r"}]})
    monkeypatch.setattr(compiler,"_nested_documents",lambda name: original(name)+[ghost] if name=="client-roles" else original(name))
    with pytest.raises(IdentityModelError,match="client_roles_unknown_client:ghost"): compile_identity()
    composite=(ROOT/"config"/"desired-state"/"x"/"client-roles"/"desk.json",{"clientId":"codestra-agent-desktop","roles":[{"name":"realtime.agent.connect","composite":True}]})
    monkeypatch.setattr(compiler,"_nested_documents",lambda name: [composite] if name=="client-roles" else original(name))
    with pytest.raises(IdentityModelError,match="composite_role_forbidden"): compile_identity()

# --- reconciliation -------------------------------------------------------------

def test_plan_creates_client_roles_after_their_client_and_keeps_foreign_roles():
    desired={"clients":[{"clientId":"desk","enabled":True}],"clientRoles":[{"clientId":"desk","roles":[{"name":"connect","description":"d"}]}]}
    live={"clients":[],"clientRoles":[]}
    ordered=[(a["resource_type"],a["resource_id"],a["kind"]) for a in plan(desired,live,environment="staging")["actions"]]
    assert ordered.index(("client","desk","CREATE"))<ordered.index(("client_role","desk:connect","CREATE"))
    live={"clients":[{"id":"1","clientId":"desk","enabled":True}],"clientRoles":[{"clientId":"desk","id":"r1","name":"connect","description":"old"},{"clientId":"desk","id":"r2","name":"legacy","description":"x"}]}
    by={a["resource_id"]:a for a in plan(desired,live)["actions"] if a["resource_type"]=="client_role"}
    assert by["desk:connect"]["kind"]=="UPDATE" and by["desk:legacy"]["kind"]=="KEEP" and by["desk:legacy"]["managed"] is False
    assert verify_readback(desired,live)["equal"] is False
    live["clientRoles"][0]["description"]="d"
    assert verify_readback(desired,live)["equal"] is True
    # A role is only deleted when it was created by the apply being rolled back, and never
    # separately from a client that is deleted in the same plan.
    inventory={"clients":["desk"],"clientRoles":["desk:legacy"]}
    by={a["resource_id"]:a for a in plan({"clients":[]},live,managed_inventory=inventory)["actions"] if a["resource_type"]=="client_role"}
    assert by["desk:legacy"]=={"kind":"KEEP","resource_type":"client_role","resource_id":"desk:legacy","reason":"deleted_with_client","managed":True}
    by={a["resource_id"]:a for a in plan({"clients":[{"clientId":"desk","enabled":True}]},live,managed_inventory={"clientRoles":["desk:legacy"]})["actions"] if a["resource_type"]=="client_role"}
    assert by["desk:legacy"]["kind"]=="DELETE" and by["desk:connect"]["kind"]=="KEEP" and by["desk:connect"]["managed"] is False

def test_client_role_for_absent_client_is_rejected_before_mutation():
    desired={"clients":[],"clientRoles":[{"clientId":"ghost","roles":[{"name":"r"}]}]}
    live={"clients":[],"clientRoles":[]}
    class API:
        def __init__(self): self.calls=[]
        def client_by_client_id(self,client_id): self.calls.append(client_id); return None
        def create_client_role(self,*args): self.calls.append(args)
    api=API()
    out=apply_plan(plan(desired,live,environment="staging"),desired,live,api,enabled=True,environment="staging")
    assert out["status"]=="REJECTED" and out["error"]=="client_role_client_missing:ghost:r" and api.calls==[]
    malformed={"environment":"staging","actions":[{"kind":"CREATE","resource_type":"client_role","resource_id":"no-separator","managed":True}]}
    out=apply_plan(malformed,desired,live,api,enabled=True,environment="staging")
    assert out["status"]=="REJECTED" and out["error"]=="invalid_client_role_id:no-separator"

# --- control API -----------------------------------------------------------------

class RoleAPI(FakeAdminAPI):
    def __init__(self,state):
        super().__init__(state); self.state.setdefault("clientRoles",{})
    def client_by_client_id(self,client_id): return copy.deepcopy(next((c for c in self.state["clients"] if c["clientId"]==client_id),None))
    def client_roles(self,internal_id): return copy.deepcopy(self.state["clientRoles"].get(internal_id,[]))
    def create_client_role(self,internal_id,payload):
        self._mutate("create_client_role",internal_id,payload["name"])
        self.state["clientRoles"].setdefault(internal_id,[]).append({"id":f"role-{payload['name']}",**copy.deepcopy(payload)})
    def update_client_role(self,internal_id,name,payload):
        self._mutate("update_client_role",internal_id,name)
        for role in self.state["clientRoles"].get(internal_id,[]):
            if role["name"]==name: role.update(copy.deepcopy(payload))
    def delete_client_role(self,internal_id,name):
        self._mutate("delete_client_role",internal_id,name)
        self.state["clientRoles"][internal_id]=[r for r in self.state["clientRoles"].get(internal_id,[]) if r["name"]!=name]
    def delete_client(self,internal_id):
        super().delete_client(internal_id); self.state["clientRoles"].pop(internal_id,None)

DESK={"clientId":"desk","enabled":True,"protocol":"openid-connect","publicClient":True,"standardFlowEnabled":True,"directAccessGrantsEnabled":False,"serviceAccountsEnabled":False,"fullScopeAllowed":False,"redirectUris":["https://desk.example/cb"],"webOrigins":["https://desk.example"],"defaultClientScopes":["profile"],"optionalClientScopes":[],"attributes":{"pkce.code.challenge.method":"S256"},"protocolMappers":[]}
DESK_ROLE={"name":"realtime.agent.connect","description":"connect","composite":False,"attributes":{"codestra.role.family":["agent-desktop"]}}

def desk_desired():
    desired=copy.deepcopy(DESIRED); desired["clients"].append(copy.deepcopy(DESK))
    desired["clientRoles"]=[{"clientId":"desk","roles":[copy.deepcopy(DESK_ROLE)]}]
    return desired

def test_apply_provisions_client_roles_and_rollback_removes_them_with_their_client(tmp_path,monkeypatch):
    enable_staging_mutation(monkeypatch)
    api=RoleAPI(live_fixture()); service=make_service(tmp_path,api,desk_desired())
    record=service.apply("roles-1")
    assert record["status"]=="COMPLETED" and record["readback"]["equal"] is True and record["mutationPerformed"] is True
    assert api.calls.index(("create_client","desk"))<api.calls.index(("create_client_role","id-desk","realtime.agent.connect"))
    stored=api.state["clientRoles"]["id-desk"]
    assert [r["name"] for r in stored]==["realtime.agent.connect"] and stored[0]["clientRole"] is True and stored[0]["description"]=="connect"
    assert {("CREATE","desk"),("CREATE","desk:realtime.agent.connect")}<={(j["kind"],j["resourceId"]) for j in record["actionJournal"]}
    assert service.apply("roles-converged")["mutationPerformed"] is False
    api.calls.clear(); result=service.rollback(record["executionId"])
    assert result["status"]=="COMPLETED" and ("delete_client","id-desk") in api.calls
    assert not any(call[0]=="delete_client_role" for call in api.calls)
    assert [a for a in result["plan"]["actions"] if a["resource_type"]=="client_role"]==[{"kind":"KEEP","resource_type":"client_role","resource_id":"desk:realtime.agent.connect","reason":"deleted_with_client","managed":True}]
    assert "id-desk" not in api.state["clientRoles"]

def test_apply_adds_a_role_to_an_existing_client_and_rollback_deletes_only_that_role(tmp_path,monkeypatch):
    enable_staging_mutation(monkeypatch)
    live=live_fixture(); live["clients"].append({"id":"id-desk","secret":"desk-secret","attributes":{"pkce.code.challenge.method":"S256","client.secret.creation.time":"5"},**{k:v for k,v in DESK.items() if k!="attributes"}})
    live["clientRoles"]={"id-desk":[{"id":"role-legacy","name":"legacy","description":"keep me","clientRole":True}]}
    api=RoleAPI(live); service=make_service(tmp_path,api,desk_desired())
    record=service.apply("roles-existing")
    assert record["status"]=="COMPLETED" and ("create_client_role","id-desk","realtime.agent.connect") in api.calls
    assert not any(call[0]=="create_client" and call[1]=="desk" for call in api.calls)
    assert {r["name"] for r in api.state["clientRoles"]["id-desk"]}=={"legacy","realtime.agent.connect"}
    assert "desk-secret" not in json.dumps(service.evidence(record["executionId"]))
    api.calls.clear(); result=service.rollback(record["executionId"])
    assert result["status"]=="COMPLETED" and ("delete_client_role","id-desk","realtime.agent.connect") in api.calls
    assert ("delete_client","id-desk") not in api.calls and [r["name"] for r in api.state["clientRoles"]["id-desk"]]==["legacy"]
    # Drift on a managed role is corrected without touching the foreign role.
    record=service.apply("roles-again"); api.state["clientRoles"]["id-desk"][-1]["description"]="tampered"
    assert service.drift()["actions"] and [a["resource_id"] for a in service.drift()["actions"] if a["kind"]=="UPDATE"]==["desk:realtime.agent.connect"]
    fixed=service.apply("roles-fix")
    assert fixed["status"]=="COMPLETED" and ("update_client_role","id-desk","realtime.agent.connect") in api.calls
    assert next(r for r in api.state["clientRoles"]["id-desk"] if r["name"]=="legacy")["description"]=="keep me"

def test_apply_and_drift_exclude_environment_scoped_clients_outside_their_environments(tmp_path,monkeypatch):
    enable_staging_mutation(monkeypatch)
    desired=copy.deepcopy(DESIRED)
    desired["clients"].append({**copy.deepcopy(DESK),"clientId":"staging-only","redirectUris":["https://staging.example/cb"],"webOrigins":["https://staging.example"]})
    desired["environmentScopes"]={"staging-only":["staging"]}
    api=FakeAdminAPI(live_fixture()); service=make_service(tmp_path,api,desired)
    assert any(a["resource_id"]=="staging-only" and a["kind"]=="CREATE" for a in service.drift()["actions"])
    assert service.apply("staging-apply")["status"]=="COMPLETED" and ("create_client","staging-only") in api.calls
    # The same authority in production never plans, creates, updates or deletes the scoped client.
    monkeypatch.setenv("KEYCLOAK_ENVIRONMENT","production"); monkeypatch.setenv("KEYCLOAK_ADMIN_BASE_URL","https://auth.codestra.co")
    production=FakeAdminAPI(live_fixture())
    production.state["clients"].append({"id":"id-staging-only","clientId":"staging-only","enabled":False,"publicClient":True,"attributes":{},"protocolMappers":[]})
    production_service=make_service(tmp_path/"production",production,desired)
    actions={a["resource_id"]:a for a in production_service.drift()["actions"] if a["resource_type"]=="client"}
    assert actions["staging-only"]["kind"]=="KEEP" and actions["staging-only"]["managed"] is False and actions["svc-a"]["kind"]=="CREATE"
    record=production_service.apply("production-apply")
    assert record["status"]=="COMPLETED" and record["environment"]=="production"
    assert not any(call[0] in {"create_client","update_client","delete_client"} and call[1] in {"staging-only","id-staging-only"} for call in production.calls)
    assert production_service.observability_status()["configurationDrift"] is False
    monkeypatch.delenv("KEYCLOAK_ENVIRONMENT")
    assert not any(a["resource_id"]=="staging-only" and a["kind"]!="KEEP" for a in production_service.drift()["actions"])
    assert production_service.validate()["environmentScopedClients"]==["klyrow-staging-portal"]
