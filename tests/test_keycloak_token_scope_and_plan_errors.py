from __future__ import annotations
import copy,json,sys
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts")); sys.path.insert(0,str(ROOT/"tests"))
from plan_seal import sealed
import keycloak_identity_compiler as compiler
from keycloak_identity_compiler import IdentityModelError,compile_identity
from keycloak_reconciliation import apply_plan,plan,verify_readback
from test_pas237_keycloak_control_plane import DESIRED,enable_staging_mutation,live_fixture,make_service
from test_keycloak_environment_scope_and_client_roles import DESK,RoleAPI,desk_desired

# --- token scope, mapper and scope-mapping fail-closed rules --------------------

def test_agent_desktop_realm_role_reaches_its_token_scope():
    model=compile_identity()
    desk=next(c for c in model["clients"] if c["clientId"]=="codestra-agent-desktop")
    assert desk["fullScopeAllowed"] is False
    mapping=next(m for m in model["scopeMappings"] if m["clientId"]=="codestra-agent-desktop")
    assert mapping["realmRoles"]==["telephony.webphone.use"]
    assert mapping["fullScopeAllowed"] is False and mapping["crossFamilyRolesAllowed"] is False

def test_contract_role_outside_a_restricted_clients_token_scope_fails_closed(monkeypatch):
    original=compiler._nested_documents
    def without_desk(name):
        rows=original(name)
        return [(p,d) for p,d in rows if d.get("clientId")!="codestra-agent-desktop"] if name=="scope-mappings" else rows
    monkeypatch.setattr(compiler,"_nested_documents",without_desk)
    with pytest.raises(IdentityModelError,match="contract_realm_role_not_in_token_scope:.*codestra-agent-desktop:telephony.webphone.use"):
        compile_identity()

def test_contract_naming_another_clients_roles_or_an_unknown_client_fails_closed(monkeypatch):
    target=(ROOT/"config"/"contracts"/"agent-desktop-realtime-client.json").resolve()
    doc=json.loads(target.read_text(encoding="utf-8")); original=compiler.load_json
    monkeypatch.setattr(compiler,"load_json",lambda path: copy.deepcopy(doc) if Path(path).resolve()==target else original(path))
    doc["requiredClientRoles"]={"middleware-api":["anything"]}
    with pytest.raises(IdentityModelError,match="contract_client_role_unprovisioned"): compile_identity()
    doc["requiredClientRoles"]={}; doc["clientId"]="ghost-desktop"
    with pytest.raises(IdentityModelError,match="contract_client_unknown:.*ghost-desktop"): compile_identity()

@pytest.mark.parametrize("mapping,error",[
    ({"clientId":"ghost","fullScopeAllowed":False,"realmRoles":["telephony.webphone.use"],"crossFamilyRolesAllowed":False},"scope_mapping_unknown_client:ghost"),
    ({"clientId":"codestra-agent-desktop","fullScopeAllowed":True,"realmRoles":["telephony.webphone.use"],"crossFamilyRolesAllowed":False},"scope_mapping_full_scope_forbidden"),
    ({"clientId":"codestra-agent-desktop","fullScopeAllowed":False,"realmRoles":["realm-admin"],"crossFamilyRolesAllowed":False},"scope_mapping_role_unknown:codestra-agent-desktop:realm-admin"),
    ({"clientId":"codestra-agent-desktop","fullScopeAllowed":False,"realmRoles":["telephony.webphone.use","telephony.webphone.use"],"crossFamilyRolesAllowed":False},"scope_mapping_roles_invalid"),
    ({"clientId":"codestra-agent-desktop","fullScopeAllowed":False,"realmRoles":[],"crossFamilyRolesAllowed":False},"scope_mapping_roles_invalid"),
    ({"clientId":"codestra-agent-desktop","fullScopeAllowed":False,"realmRoles":["telephony.webphone.use"]},"scope_mapping_cross_family_flag_required"),
    ({"clientId":"codestra-agent-desktop","fullScopeAllowed":False,"realmRoles":["telephony.webphone.use","observability-viewer"],"crossFamilyRolesAllowed":False},"scope_mapping_cross_family_roles"),
])
def test_scope_mapping_cannot_broaden_privileges(monkeypatch,mapping,error):
    original=compiler._nested_documents
    extra=(ROOT/"config"/"desired-state"/"agent-desktop-identity"/"scope-mappings"/"codestra-agent-desktop.json",mapping)
    def replaced(name):
        rows=original(name)
        if name!="scope-mappings": return rows
        return [(p,d) for p,d in rows if d.get("clientId")!="codestra-agent-desktop"]+[extra]
    monkeypatch.setattr(compiler,"_nested_documents",replaced)
    with pytest.raises(IdentityModelError,match=error): compile_identity()

@pytest.mark.parametrize("mappers,error",[
    ([{"name":"a","config":{"claim.name":"x"}},{"name":"a","config":{"claim.name":"y"}}],"duplicate_protocol_mapper:a"),
    ([{"name":"a","config":{"claim.name":"tenant_ids"}},{"name":"b","config":{"claim.name":"tenant_ids"}}],"conflicting_protocol_mapper_claim:tenant_ids"),
    ([{"config":{"claim.name":"x"}}],"protocol_mapper_missing_name"),
    ([{"name":"a","config":{"client_secret":"s3cr3t"}}],"secret_in_mapper"),
])
def test_conflicting_protocol_mappers_fail_closed(mappers,error):
    client={"clientId":"desk","redirectUris":["https://desk.example/cb"],"webOrigins":["https://desk.example"],
            "publicClient":True,"standardFlowEnabled":True,"protocolMappers":mappers}
    with pytest.raises(IdentityModelError,match=error): compiler.validate_client(client)
    with pytest.raises(IdentityModelError,match=error): compiler.validate_mappers("scope:roles",mappers)

def test_audience_mappers_without_a_claim_name_may_coexist_with_claim_mappers():
    compiler.validate_mappers("scope:ok",[{"name":"aud","config":{"included.custom.audience":"x"}},
                                          {"name":"aud-2","config":{"included.custom.audience":"y"}},
                                          {"name":"b","config":{"claim.name":"x"}}])

def test_client_role_declarations_fail_closed(monkeypatch):
    base=ROOT/"config"/"desired-state"/"agent-desktop-identity"/"client-roles"/"codestra-agent-desktop.json"
    good=json.loads(base.read_text(encoding="utf-8")); original=compiler._nested_documents
    def with_docs(docs):
        monkeypatch.setattr(compiler,"_nested_documents",lambda name: docs if name=="client-roles" else original(name))
    duplicate=copy.deepcopy(good); duplicate["roles"].append(copy.deepcopy(good["roles"][0])); with_docs([(base,duplicate)])
    with pytest.raises(IdentityModelError,match="identity_multiple_owners:client_role:codestra-agent-desktop:realtime.agent.connect"): compile_identity()
    other=copy.deepcopy(good); other["roles"][0]["description"]="a second, conflicting declaration"
    with_docs([(base,good),(base.with_name("other.json"),other)])
    with pytest.raises(IdentityModelError,match="identity_multiple_owners:client_role:codestra-agent-desktop:realtime.agent.connect"): compile_identity()
    realm_kind=copy.deepcopy(good); realm_kind["roles"][0]["clientRole"]=False; with_docs([(base,realm_kind)])
    with pytest.raises(IdentityModelError,match="role_kind_mismatch"): compile_identity()
    secret=copy.deepcopy(good); secret["roles"][0]["attributes"]["password"]=["x"]; with_docs([(base,secret)])
    with pytest.raises(IdentityModelError,match="secret_in_role"): compile_identity()
    with pytest.raises(IdentityModelError,match="role_kind_mismatch"):
        compiler.validate_role({"name":"r","clientRole":True},"realm-roles",client_role=False)

# --- ERROR classification --------------------------------------------------------

def test_plan_reports_unreconcilable_resources_as_error_and_apply_refuses_them():
    desired={"clients":[{"clientId":"a","enabled":True},{"clientId":"b","enabled":True}],"realmRoles":[{"name":"known"}],
             "clientRoles":[{"clientId":"ghost","roles":[{"name":"r"}]}],
             "scopeMappings":[{"clientId":"a","fullScopeAllowed":False,"realmRoles":["known","missing-role"],"crossFamilyRolesAllowed":False}]}
    live={"clients":[{"clientId":"a","enabled":False},{"id":"2","clientId":"b","enabled":True}],"realmRoles":[],"scopeMappings":[]}
    actions={(a["resource_type"],a["resource_id"]):a for a in plan(desired,live,environment="staging")["actions"]}
    assert actions[("client","a")]["kind"]=="ERROR" and actions[("client","a")]["reason"]=="missing_internal_id:a"
    assert actions[("client","b")]["kind"]=="KEEP"
    assert actions[("client_role","ghost:r")]["kind"]=="ERROR"
    assert actions[("client_role","ghost:r")]["reason"]=="client_role_client_missing:ghost:r"
    assert actions[("scope_mapping","a")]["kind"]=="ERROR"
    assert actions[("scope_mapping","a")]["reason"]=="scope_mapping_role_missing:missing-role"
    calls=[]
    class API:
        def __getattr__(self,name): return lambda *a,**k: calls.append(name)
    out=apply_plan(plan(desired,live,environment="staging"),desired,live,API(),enabled=True,environment="staging")
    assert out["status"]=="REJECTED" and out["journal"]==[] and calls==[]
    result=verify_readback(desired,live)
    assert result["equal"] is False and "ERROR" in {a["kind"] for a in result["pendingActions"]}
    # A managed delete of a live row without an internal id is reported the same way.
    actions={(a["resource_type"],a["resource_id"]):a for a in plan({"clients":[]},{"clients":[{"clientId":"old"}]},managed_inventory={"clients":["old"]})["actions"]}
    assert actions[("client","old")]["kind"]=="ERROR" and actions[("client","old")]["reason"]=="missing_internal_id:old"

def test_error_actions_are_never_applied_even_when_validation_is_bypassed():
    class API:
        def __init__(self): self.calls=[]
        def __getattr__(self,name): return lambda *a,**k: self.calls.append(name)
    api=API(); desired={"clients":[{"clientId":"a","enabled":True}]}; live={"clients":[{"id":"1","clientId":"a","enabled":False}]}
    forged={"environment":"staging","actions":[{"kind":"ERROR","resource_type":"client","resource_id":"a","reason":"missing_internal_id:a","managed":True}]}
    out=apply_plan(sealed(forged,desired,live),desired,live,api,enabled=True,environment="staging")
    assert out["status"]=="REJECTED" and out["error"]=="missing_internal_id:a" and api.calls==[]

def test_control_api_surfaces_error_in_drift_and_rejects_apply_without_mutation(tmp_path,monkeypatch):
    enable_staging_mutation(monkeypatch)
    desired=copy.deepcopy(DESIRED); desired["clients"].append(copy.deepcopy(DESK))
    desired["scopeMappings"]=[{"clientId":"desk","fullScopeAllowed":False,"realmRoles":["not-provisioned"],"crossFamilyRolesAllowed":False}]
    api=RoleAPI(live_fixture()); service=make_service(tmp_path,api,desired)
    errors=[a for a in service.drift()["actions"] if a["kind"]=="ERROR"]
    assert errors==[{"kind":"ERROR","resource_type":"scope_mapping","resource_id":"desk",
                     "reason":"scope_mapping_role_missing:not-provisioned","managed":True}]
    assert any(a["kind"]=="ERROR" for a in service.dry_run()["plan"]["actions"])
    record=service.apply("error-plan")
    assert record["status"]=="REJECTED" and record["error"]=="scope_mapping_role_missing:not-provisioned"
    assert record["mutationPerformed"] is False and api.calls==[]
    assert service.observability_status()["configurationDrift"] is True

class MappingAPI(RoleAPI):
    def __init__(self,state):
        super().__init__(state); self.state.setdefault("clientScopeMappings",{})
    def create_realm_role(self,payload):
        self._mutate("create_realm_role",payload["name"])
        self.state["realmRoles"].append({"id":f"r-{payload['name']}",**copy.deepcopy(payload)})
    def delete_realm_role(self,name):
        self._mutate("delete_realm_role",name)
        self.state["realmRoles"]=[r for r in self.state["realmRoles"] if r["name"]!=name]
        for rows in self.state["clientScopeMappings"].values(): rows[:]=[r for r in rows if r["name"]!=name]
    def client_realm_role_mappings(self,internal_id): return copy.deepcopy(self.state["clientScopeMappings"].get(internal_id,[]))
    def add_client_realm_role_mappings(self,internal_id,roles):
        self._mutate("add_client_realm_role_mappings",internal_id,tuple(r["name"] for r in roles))
        self.state["clientScopeMappings"].setdefault(internal_id,[]).extend(copy.deepcopy(roles))
    def delete_client(self,internal_id):
        super().delete_client(internal_id); self.state["clientScopeMappings"].pop(internal_id,None)

def test_agent_desktop_style_contract_is_provisioned_end_to_end_and_rolled_back(tmp_path,monkeypatch):
    enable_staging_mutation(monkeypatch)
    desired=desk_desired()
    desired["realmRoles"]=[{"name":"telephony.webphone.use","description":"webphone","composite":False,
                            "attributes":{"codestra.role.family":["agent-desktop"]}}]
    desired["scopeMappings"]=[{"clientId":"desk","fullScopeAllowed":False,"realmRoles":["telephony.webphone.use"],"crossFamilyRolesAllowed":False}]
    api=MappingAPI(live_fixture()); service=make_service(tmp_path,api,desired)
    record=service.apply("desk-contract")
    assert record["status"]=="COMPLETED" and record["readback"]["equal"] is True
    order=[c[0] for c in api.calls]
    assert order.index("create_realm_role")<order.index("create_client")<order.index("create_client_role")<order.index("add_client_realm_role_mappings")
    assert [r["name"] for r in api.state["clientScopeMappings"]["id-desk"]]==["telephony.webphone.use"]
    assert service.apply("desk-contract-again")["mutationPerformed"] is False
    api.calls.clear(); result=service.rollback(record["executionId"])
    assert result["status"]=="COMPLETED"
    assert ("delete_realm_role","telephony.webphone.use") in api.calls and ("delete_client","id-desk") in api.calls
    assert "id-desk" not in api.state["clientScopeMappings"]
    assert {r["name"] for r in api.state["realmRoles"]}=={"offline_access"}
