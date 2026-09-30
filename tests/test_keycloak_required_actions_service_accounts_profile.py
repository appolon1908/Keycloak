from __future__ import annotations
import copy,json,sys
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts")); sys.path.insert(0,str(ROOT/"tests"))
import keycloak_identity_compiler as compiler
from keycloak_identity_compiler import IdentityModelError,compile_identity
from keycloak_reconciliation import apply_plan,plan,rollback_plan,created_inventory,verify_readback
from test_pas237_keycloak_control_plane import FakeAdminAPI,enable_staging_mutation,live_fixture,make_service

REQUIRED=ROOT/"config"/"security"/"required-actions.json"
PROFILE=ROOT/"config"/"security"/"user-profile.json"

def override(monkeypatch,path,mutate):
    doc=json.loads(path.read_text(encoding="utf-8")); mutate(doc); original=compiler.load_json
    monkeypatch.setattr(compiler,"load_json",lambda p: copy.deepcopy(doc) if Path(p).resolve()==path.resolve() else original(p))

def add_nested(monkeypatch,directory,document):
    original=compiler._nested_documents
    fake=ROOT/"config"/"desired-state"/"test-family"/directory/"fixture.json"
    monkeypatch.setattr(compiler,"_nested_documents",lambda name: original(name)+([(fake,document)] if name==directory else []))

# --- required actions follow the realm security policy -----------------------

def test_required_actions_compile_one_to_one_from_the_security_policy():
    model=compile_identity()
    assert model["requiredActions"]==[
        {"alias":"CONFIGURE_TOTP","enabled":True,"defaultAction":False},
        {"alias":"UPDATE_PASSWORD","enabled":True,"defaultAction":False},
        {"alias":"moneybee-verify-email-otp","enabled":True,"defaultAction":False},
        {"alias":"webauthn-register","enabled":True,"defaultAction":False},
    ]
    assert model["realm"]["verifyEmail"] is False

@pytest.mark.parametrize("mutate,error",[
    (lambda d: d["requiredActions"][0].update(enabled=False),"required_action_policy_mismatch:CONFIGURE_TOTP"),
    (lambda d: d["requiredActions"].pop(),"required_action_policy_uncovered:webauthnRegistrationForPrivilegedUsers"),
    (lambda d: d["requiredActions"][0].update(policyKey="unknownSwitch"),"required_action_policy_key_unknown:CONFIGURE_TOTP:unknownSwitch"),
    (lambda d: d["requiredActions"].append(dict(d["requiredActions"][0])),"duplicate_required_action:CONFIGURE_TOTP"),
    (lambda d: d["requiredActions"][0].update(priority=10),"required_action_fields_invalid"),
    (lambda d: d["requiredActions"][1].update(policyKey="configureTotp"),"required_action_policy_key_duplicate:configureTotp"),
    (lambda d: d.update(realmSettings={}),"required_action_policy_uncovered:verifyEmail"),
    (lambda d: d.update(realmSettings={"verifyEmail":"enabled"}),"required_action_realm_setting_mismatch:verifyEmail"),
    (lambda d: d.update(schema="other"),"required_actions_schema_invalid"),
])
def test_required_action_declarations_fail_closed(monkeypatch,mutate,error):
    override(monkeypatch,REQUIRED,mutate)
    with pytest.raises(IdentityModelError,match=error): compile_identity()

def test_unregistered_required_action_is_an_error_and_apply_refuses_before_writes():
    desired={"requiredActions":[{"alias":"moneybee-verify-email-otp","enabled":True,"defaultAction":False}]}
    live={"requiredActions":[{"alias":"VERIFY_EMAIL","name":"Verify Email","enabled":True,"defaultAction":False,"priority":50,"config":{}}]}
    doc=plan(desired,live,environment="staging")
    rows={(a["resource_id"],a["kind"],a["reason"]) for a in doc["actions"] if a["resource_type"]=="required_action"}
    assert ("moneybee-verify-email-otp","ERROR","required_action_not_registered:moneybee-verify-email-otp") in rows
    assert ("VERIFY_EMAIL","KEEP","unmanaged_live_resource") in rows
    calls=[]
    class API:
        def __getattr__(self,name): return lambda *a,**k: calls.append(name)
    out=apply_plan(doc,desired,live,API(),enabled=True,environment="staging")
    assert out["status"]=="REJECTED" and calls==[]

def test_required_action_update_keeps_undeclared_provider_fields():
    desired={"requiredActions":[{"alias":"CONFIGURE_TOTP","enabled":True,"defaultAction":False}]}
    live={"requiredActions":[{"alias":"CONFIGURE_TOTP","name":"Configure OTP","providerId":"CONFIGURE_TOTP","enabled":False,"defaultAction":False,"priority":10,"config":{}}]}
    doc=plan(desired,live,environment="staging")
    assert [a["kind"] for a in doc["actions"] if a["resource_type"]=="required_action"]==["UPDATE"]
    sent=[]
    class API:
        def update_required_action(self,alias,payload): sent.append((alias,payload))
    out=apply_plan(doc,desired,live,API(),enabled=True,environment="staging")
    assert out["status"]=="APPLIED"
    assert sent==[("CONFIGURE_TOTP",{"alias":"CONFIGURE_TOTP","name":"Configure OTP","providerId":"CONFIGURE_TOTP","enabled":True,"defaultAction":False,"priority":10,"config":{}})]
    assert verify_readback(desired,{"requiredActions":[sent[0][1]]})["equal"] is True

# --- service-account role mappings -------------------------------------------

SERVICE_ROLE={"name":"svc-reader","description":"reader","composite":False,
              "attributes":{"codestra.actor.kind":["service"],"codestra.role.family":["test-family"]}}

def service_model(monkeypatch,entry,*,role_attributes=None,mapped=True):
    role=copy.deepcopy(SERVICE_ROLE)
    if role_attributes is not None: role["attributes"]=role_attributes
    original=compiler._nested_documents
    base=ROOT/"config"/"desired-state"/"test-family"
    def nested(name):
        rows=original(name)
        if name=="realm-roles": rows=rows+[(base/"realm-roles"/"svc-reader.json",role)]
        if name=="scope-mappings" and mapped:
            rows=rows+[(base/"scope-mappings"/"middleware-api.json",{"clientId":"middleware-api","fullScopeAllowed":False,"realmRoles":["svc-reader"],"crossFamilyRolesAllowed":False})]
        if name=="service-account-roles": rows=rows+[(base/"service-account-roles"/"fixture.json",entry)]
        return rows
    monkeypatch.setattr(compiler,"_nested_documents",nested)

def test_existing_scope_mapping_does_not_block_the_fixture():
    model=compile_identity()
    assert not any(m["clientId"]=="middleware-api" for m in model["scopeMappings"])
    client=next(c for c in model["clients"] if c["clientId"]=="middleware-api")
    assert client["serviceAccountsEnabled"] is True and client["fullScopeAllowed"] is False

def test_valid_service_account_roles_compile(monkeypatch):
    service_model(monkeypatch,{"clientId":"middleware-api","realmRoles":["svc-reader"]})
    model=compile_identity()
    assert model["serviceAccountRoles"]==[{"clientId":"middleware-api","realmRoles":["svc-reader"]}]

@pytest.mark.parametrize("entry,kwargs,error",[
    ({"clientId":"ghost","realmRoles":["svc-reader"]},{},"service_account_roles_client_not_protected:ghost"),
    ({"clientId":"codestra-agent-desktop","realmRoles":["svc-reader"]},{},"service_account_roles_client_not_service:codestra-agent-desktop"),
    ({"clientId":"middleware-api","realmRoles":[]},{},"service_account_roles_invalid:middleware-api"),
    ({"clientId":"middleware-api","realmRoles":["svc-reader","svc-reader"]},{},"service_account_roles_invalid:middleware-api"),
    ({"clientId":"middleware-api","realmRoles":["realm-admin"]},{},"service_account_role_unknown:middleware-api:realm-admin"),
    ({"clientId":"middleware-api","realmRoles":["svc-reader"],"extra":True},{},"service_account_roles_fields_invalid:middleware-api"),
    ({"clientId":"middleware-api","realmRoles":["svc-reader"]},{"role_attributes":{"codestra.actor.kind":["user"],"codestra.role.family":["test-family"]}},"service_account_role_not_service:middleware-api:svc-reader"),
    ({"clientId":"middleware-api","realmRoles":["svc-reader"]},{"role_attributes":{"codestra.role.family":["test-family"]}},"service_account_role_not_service:middleware-api:svc-reader"),
    ({"clientId":"middleware-api","realmRoles":["svc-reader"]},{"role_attributes":{"codestra.actor.kind":["service"],"codestra.activation":["PREPARED_DISABLED"]}},"service_account_role_not_active:middleware-api:svc-reader"),
    ({"clientId":"middleware-api","realmRoles":["svc-reader"]},{"mapped":False},"service_account_role_not_in_token_scope:middleware-api:svc-reader"),
])
def test_service_account_roles_fail_closed(monkeypatch,entry,kwargs,error):
    service_model(monkeypatch,entry,**kwargs)
    with pytest.raises(IdentityModelError,match=error): compile_identity()

def test_service_account_roles_across_families_are_rejected():
    roles={"a":{"attributes":{"codestra.actor.kind":["service"],"codestra.role.family":["one"]}},
           "b":{"attributes":{"codestra.actor.kind":["service"],"codestra.role.family":["two"]}}}
    client={"clientId":"svc","serviceAccountsEnabled":True}
    with pytest.raises(IdentityModelError,match="service_account_roles_cross_family:svc"):
        compiler.validate_service_account_roles([{"clientId":"svc","realmRoles":["a","b"]}],roles,{"svc":client},{"svc":{"a","b"}})

class ServiceAccountAPI(FakeAdminAPI):
    def __init__(self,state):
        super().__init__(state); self.state.setdefault("serviceUsers",{}); self.state.setdefault("userRoles",{})
    def client_by_client_id(self,client_id):
        rows=[c for c in self.state["clients"] if c.get("clientId")==client_id]
        return copy.deepcopy(rows[0]) if len(rows)==1 else None
    def service_account_user(self,internal_id):
        user=self.state["serviceUsers"].get(internal_id)
        if user is None:
            from keycloak_admin_api import KeycloakAdminError
            raise KeycloakAdminError("admin_http_error","Keycloak Admin API returned HTTP 404",404)
        return {"id":user}
    def user_realm_role_mappings(self,user_id): return copy.deepcopy(self.state["userRoles"].get(user_id,[]))
    def add_user_realm_role_mappings(self,user_id,roles):
        self._mutate("add_user_realm_role_mappings",user_id,tuple(r["name"] for r in roles))
        self.state["userRoles"].setdefault(user_id,[]).extend(copy.deepcopy(roles))
    def delete_user_realm_role_mappings(self,user_id,roles):
        self._mutate("delete_user_realm_role_mappings",user_id,tuple(r["name"] for r in roles))
        gone={r["name"] for r in roles}
        self.state["userRoles"][user_id]=[r for r in self.state["userRoles"].get(user_id,[]) if r["name"] not in gone]

SVC_CLIENT={"clientId":"svc-a","enabled":True,"serviceAccountsEnabled":True,"publicClient":False,"standardFlowEnabled":False,"fullScopeAllowed":False}

def service_state():
    state=live_fixture()
    state["clients"].append({"id":"id-svc-a",**copy.deepcopy(SVC_CLIENT)})
    state["realmRoles"]+= [{"id":"r-reader","name":"svc-reader"},{"id":"r-writer","name":"svc-writer"},{"id":"r-default","name":"default-roles-codestra"}]
    state["serviceUsers"]={"id-svc-a":"user-svc-a"}
    state["userRoles"]={"user-svc-a":[{"id":"r-default","name":"default-roles-codestra"},{"id":"r-writer","name":"svc-writer"}]}
    return state

def service_desired():
    return {"realm":copy.deepcopy(live_fixture()["realm"]),"clients":[copy.deepcopy(SVC_CLIENT)],
            "realmRoles":[{"name":"svc-reader"},{"name":"svc-writer"}],
            "serviceAccountRoles":[{"clientId":"svc-a","realmRoles":["svc-reader"]}]}

def test_service_account_roles_apply_exactly_keep_the_default_role_and_roll_back(tmp_path,monkeypatch):
    enable_staging_mutation(monkeypatch)
    api=ServiceAccountAPI(service_state()); service=make_service(tmp_path,api,service_desired())
    drift=[a for a in service.drift()["actions"] if a["resource_type"]=="service_account_roles"]
    assert [(a["kind"],a["reason"]) for a in drift]==[("UPDATE","managed_fields_drift")]
    record=service.apply("svc-roles")
    assert record["status"]=="COMPLETED" and record["readback"]["equal"] is True
    assert {r["name"] for r in api.state["userRoles"]["user-svc-a"]}=={"default-roles-codestra","svc-reader"}
    assert service.apply("svc-roles-again")["mutationPerformed"] is False
    result=service.rollback(record["executionId"])
    assert result["status"]=="COMPLETED"
    assert {r["name"] for r in api.state["userRoles"]["user-svc-a"]}=={"default-roles-codestra","svc-writer"}

def test_service_account_role_missing_everywhere_is_an_error():
    desired=service_desired(); desired["serviceAccountRoles"][0]["realmRoles"]=["not-provisioned"]
    live={"clients":[{"id":"id-svc-a",**SVC_CLIENT}],"realmRoles":[],"serviceAccountRoles":[]}
    errors=[a for a in plan(desired,live)["actions"] if a["kind"]=="ERROR"]
    assert [(a["resource_id"],a["reason"]) for a in errors]==[("svc-a","service_account_role_missing:not-provisioned")]

def test_service_account_without_user_is_read_as_absent(tmp_path,monkeypatch):
    enable_staging_mutation(monkeypatch)
    state=service_state(); state["serviceUsers"]={}
    service=make_service(tmp_path,ServiceAccountAPI(state),service_desired())
    assert service.live()["serviceAccountRoles"]==[]

# --- user-profile attributes and token claims --------------------------------

def test_tenant_claim_attributes_are_declared_admin_only():
    model=compile_identity()
    by_name={a["name"]:a for a in model["userProfileAttributes"]}
    assert set(by_name)=={"tenant_id","tenant_ids"}
    for attribute in by_name.values():
        assert attribute["permissions"]=={"view":["admin"],"edit":["admin"]}
    assert by_name["tenant_ids"]["multivalued"] is True and by_name["tenant_ids"]["validations"]["multivalued"]["max"]=="64"

@pytest.mark.parametrize("mutate,error",[
    (lambda d: d["attributes"][1]["permissions"].update(edit=["admin","user"]),"user_profile_attribute_user_editable:tenant_ids"),
    (lambda d: d["attributes"].pop(1),"token_claim_attribute_not_admin_only:client:codestra-agent-desktop:tenant_ids"),
    (lambda d: d["attributes"].pop(0),"token_claim_attribute_not_admin_only:client:beyvra-backend:tenant_id"),
    (lambda d: d["attributes"].append({"name":"codestra_tenant_id","permissions":{"view":["admin"],"edit":["admin"]}}),"user_profile_attribute_family_owned:codestra_tenant_id"),
    (lambda d: d["attributes"].append({"name":"email","permissions":{"view":["admin"],"edit":["admin"]}}),"user_profile_attribute_built_in:email"),
    (lambda d: d["attributes"].append(dict(d["attributes"][0])),"duplicate_user_profile_attribute:tenant_id"),
    (lambda d: d["attributes"][0].update(required={"roles":["user"]}),"user_profile_attribute_fields_invalid:tenant_id"),
    (lambda d: d["attributes"][0].update(name="bad name"),"user_profile_attribute_name_invalid:bad name"),
    (lambda d: d["attributes"][0]["annotations"].update(secret="x"),"user_profile_attribute_secret:tenant_id"),
    (lambda d: d.update(schema="other"),"user_profile_schema_invalid"),
])
def test_user_profile_declarations_fail_closed(monkeypatch,mutate,error):
    override(monkeypatch,PROFILE,mutate)
    with pytest.raises(IdentityModelError,match=error): compile_identity()

def test_a_new_token_claim_from_an_undeclared_attribute_fails_closed(monkeypatch):
    scope={"name":"test-scope","protocol":"openid-connect","protocolMappers":[{"name":"department","protocol":"openid-connect",
           "protocolMapper":"oidc-usermodel-attribute-mapper","config":{"user.attribute":"department","claim.name":"department"}}]}
    add_nested(monkeypatch,"client-scopes",scope)
    with pytest.raises(IdentityModelError,match="token_claim_attribute_not_admin_only:scope:test-scope:department"): compile_identity()

TENANT=json.loads(PROFILE.read_text(encoding="utf-8"))["attributes"]

def profile_state(attributes):
    state=live_fixture()
    state["userProfile"]={"unmanagedAttributePolicy":"ADMIN_EDIT","groups":[{"name":"user-metadata"}],
                          "attributes":[{"name":"username","permissions":{"view":["admin","user"],"edit":["admin","user"]}}]+attributes}
    return state

def profile_desired():
    return {"realm":copy.deepcopy(live_fixture()["realm"]),"userProfileAttributes":copy.deepcopy(TENANT)}

def test_profile_attributes_are_appended_and_rollback_removes_only_them(tmp_path,monkeypatch):
    enable_staging_mutation(monkeypatch)
    api=FakeAdminAPI(profile_state([])); service=make_service(tmp_path,api,profile_desired())
    kinds={(a["resource_id"],a["kind"]) for a in service.drift()["actions"] if a["resource_type"]=="user_profile_attribute"}
    assert kinds=={("tenant_id","CREATE"),("tenant_ids","CREATE"),("username","KEEP")}
    record=service.apply("profile")
    assert record["status"]=="COMPLETED" and record["readback"]["equal"] is True
    profile=api.state["userProfile"]
    assert [a["name"] for a in profile["attributes"]]==["username","tenant_id","tenant_ids"]
    assert profile["unmanagedAttributePolicy"]=="ADMIN_EDIT" and profile["groups"]==[{"name":"user-metadata"}]
    assert service.apply("profile-again")["mutationPerformed"] is False
    result=service.rollback(record["executionId"])
    assert result["status"]=="COMPLETED"
    assert [a["name"] for a in api.state["userProfile"]["attributes"]]==["username"]

def test_user_editable_live_attribute_is_replaced_and_rollback_restores_it(tmp_path,monkeypatch):
    enable_staging_mutation(monkeypatch)
    editable={"name":"tenant_ids","multivalued":True,"permissions":{"view":["admin","user"],"edit":["admin","user"]},"group":"user-metadata"}
    api=FakeAdminAPI(profile_state([copy.deepcopy(editable)]))
    service=make_service(tmp_path,api,profile_desired())
    record=service.apply("profile-fix")
    assert record["status"]=="COMPLETED"
    live={a["name"]:a for a in api.state["userProfile"]["attributes"]}
    assert live["tenant_ids"]==TENANT[1]
    service.rollback(record["executionId"])
    live={a["name"]:a for a in api.state["userProfile"]["attributes"]}
    assert live["tenant_ids"]==editable and "tenant_id" not in live

def test_undeclared_live_profile_attributes_are_never_deleted():
    desired={"userProfileAttributes":copy.deepcopy(TENANT)}
    live={"userProfileAttributes":copy.deepcopy(TENANT)+[{"name":"department","permissions":{"view":["admin"],"edit":["admin"]}}]}
    rows=[a for a in plan(desired,live)["actions"] if a["resource_type"]=="user_profile_attribute"]
    assert {(a["resource_id"],a["kind"]) for a in rows}=={("tenant_id","KEEP"),("tenant_ids","KEEP"),("department","KEEP")}
    inventory=created_inventory([{"kind":"CREATE","resourceType":"user_profile_attribute","resourceId":"tenant_id"}])
    assert inventory["userProfileAttributes"]==["tenant_id"]
    back=rollback_plan({"userProfileAttributes":[]},live,created_inventory=inventory)
    kinds={(a["resource_id"],a["kind"]) for a in back["actions"] if a["resource_type"]=="user_profile_attribute"}
    assert kinds=={("tenant_id","DELETE"),("tenant_ids","KEEP"),("department","KEEP")}

# --- adapter paths ------------------------------------------------------------

def test_admin_adapter_uses_the_documented_endpoints():
    from keycloak_admin_api import KeycloakAdminAPI
    api=KeycloakAdminAPI("http://127.0.0.1:1","codestra","token"); seen=[]
    api.request=lambda method,suffix,body=None,expected=None: seen.append((method,suffix,expected)) or []
    api.service_account_user("c 1"); api.user_realm_role_mappings("u1"); api.add_user_realm_role_mappings("u1",[{"name":"r"}])
    api.delete_user_realm_role_mappings("u1",[{"name":"r"}]); api.user_profile(); api.update_user_profile({"attributes":[]})
    assert seen==[("GET","/clients/c%201/service-account-user",None),("GET","/users/u1/role-mappings/realm",None),
                  ("POST","/users/u1/role-mappings/realm",{204}),("DELETE","/users/u1/role-mappings/realm",{204}),
                  ("GET","/users/profile",None),("PUT","/users/profile",{200})]

class RegistrationAPI(FakeAdminAPI):
    def register_required_action(self,payload):
        self._mutate("register_required_action",payload["providerId"])
        self.state["unregisteredRequiredActions"]=[r for r in self.state["unregisteredRequiredActions"] if r["providerId"]!=payload["providerId"]]
        self.state["requiredActions"].append({"alias":payload["providerId"],"name":payload["name"],"providerId":payload["providerId"],"enabled":True,"defaultAction":False,"priority":140,"config":{}})
    def required_action(self,alias): return copy.deepcopy(next((r for r in self.state["requiredActions"] if r["alias"]==alias),None))
    def update_required_action(self,alias,payload):
        self._mutate("update_required_action",alias)
        self.state["requiredActions"]=[copy.deepcopy(payload) if r["alias"]==alias else r for r in self.state["requiredActions"]]
    def delete_required_action(self,alias):
        self._mutate("delete_required_action",alias)
        row=next(r for r in self.state["requiredActions"] if r["alias"]==alias)
        self.state["requiredActions"]=[r for r in self.state["requiredActions"] if r["alias"]!=alias]
        self.state["unregisteredRequiredActions"].append({"providerId":alias,"name":row["name"]})

def test_deployed_unregistered_provider_is_registered_and_rollback_unregisters_it(tmp_path,monkeypatch):
    enable_staging_mutation(monkeypatch)
    state=live_fixture(); state["unregisteredRequiredActions"]=[{"providerId":"moneybee-verify-email-otp","name":"Verify email with MoneyBee code"}]
    api=RegistrationAPI(state)
    desired={"realm":copy.deepcopy(state["realm"]),"requiredActions":[{"alias":"moneybee-verify-email-otp","enabled":True,"defaultAction":False}]}
    service=make_service(tmp_path,api,desired)
    rows=[(a["kind"],a["reason"]) for a in service.drift()["actions"] if a["resource_id"]=="moneybee-verify-email-otp"]
    assert rows==[("CREATE","provider_unregistered")]
    record=service.apply("register-otp")
    assert record["status"]=="COMPLETED" and record["readback"]["equal"] is True
    assert ("register_required_action","moneybee-verify-email-otp") in api.calls
    row=next(r for r in api.state["requiredActions"] if r["alias"]=="moneybee-verify-email-otp")
    assert row["name"]=="Verify email with MoneyBee code" and row["priority"]==140
    assert service.apply("register-otp-again")["mutationPerformed"] is False
    result=service.rollback(record["executionId"])
    assert result["status"]=="COMPLETED"
    assert all(r["alias"]!="moneybee-verify-email-otp" for r in api.state["requiredActions"])
    assert ("delete_required_action","VERIFY_EMAIL") not in api.calls

def test_values_longer_than_keycloak_columns_are_errors_before_any_write():
    desired={"clientScopes":[{"name":"long","description":"x"*256},{"name":"short","description":"x"*255}],
             "realmRoles":[{"name":"role","description":"y"*300}]}
    live={"clientScopes":[],"realmRoles":[{"name":"role","description":"old"}]}
    doc=plan(desired,live,environment="staging")
    rows={(a["resource_id"],a["kind"],a["reason"]) for a in doc["actions"] if a["resource_type"] in {"client_scope","realm_role"}}
    assert ("long","ERROR","keycloak_column_too_long:description:256") in rows
    assert ("short","CREATE","missing_live") in rows
    assert ("role","ERROR","keycloak_column_too_long:description:300") in rows
    calls=[]
    class API:
        def __getattr__(self,name): return lambda *a,**k: calls.append(name)
    assert apply_plan(doc,desired,live,API(),enabled=True,environment="staging")["status"]=="REJECTED" and calls==[]

def test_compiled_authority_fits_keycloak_columns():
    model=compile_identity()
    rows=model["clients"]+[s["client"] for s in model["stagedClients"]]+model["clientScopes"]+model["realmRoles"]
    over=[(r.get("clientId") or r.get("name"),f) for r in rows for f in compiler.COLUMN_LIMITED_FIELDS if len(str(r.get(f) or ""))>255]
    assert over==[]

@pytest.mark.parametrize("directory,document,label",[
    ("client-scopes",{"name":"long-scope","protocol":"openid-connect","description":"d"*256},"scope:long-scope:description:256"),
    ("realm-roles",{"name":"long-role","description":"d"*300},"realm_role:long-role:description:300"),
])
def test_over_length_values_fail_compilation(monkeypatch,directory,document,label):
    add_nested(monkeypatch,directory,document)
    with pytest.raises(IdentityModelError,match="keycloak_column_too_long:"+label): compile_identity()

# --- representation differences seen on Keycloak 26.7.2 ------------------------

def test_live_representation_defaults_do_not_read_as_drift():
    desired={"clients":[{"clientId":"svc","serviceAccountsEnabled":True,"authorizationServicesEnabled":False,"defaultClientScopes":[],
                         "protocolMappers":[{"name":"aud","protocolMapper":"oidc-audience-mapper","config":{"included.custom.audience":"svc","access.token.claim":"true"}}]}]}
    live={"clients":[{"id":"1","clientId":"svc","serviceAccountsEnabled":True,"defaultClientScopes":["service_account"],
                      "protocolMappers":[{"id":"m1","name":"aud","protocolMapper":"oidc-audience-mapper","config":{"access.token.claim":"true","included.custom.audience":"svc","userinfo.token.claim":"false","introspection.token.claim":"true"}}]}]}
    assert [a["kind"] for a in plan(desired,live)["actions"] if a["resource_type"]=="client"]==["KEEP"]

@pytest.mark.parametrize("change",[
    lambda c: c.update(defaultClientScopes=["service_account","profile"]),
    lambda c: c["protocolMappers"][0]["config"].update({"included.custom.audience":"other"}),
    lambda c: c["protocolMappers"].append({"name":"extra","protocolMapper":"oidc-audience-mapper","config":{}}),
    lambda c: c.update(authorizationServicesEnabled=True),
])
def test_real_drift_is_still_detected(change):
    desired={"clients":[{"clientId":"svc","serviceAccountsEnabled":True,"authorizationServicesEnabled":False,"defaultClientScopes":[],
                         "protocolMappers":[{"name":"aud","protocolMapper":"oidc-audience-mapper","config":{"included.custom.audience":"svc"}}]}]}
    live=copy.deepcopy(desired); live["clients"][0]["id"]="1"; change(live["clients"][0])
    assert [a["kind"] for a in plan(desired,live)["actions"] if a["resource_type"]=="client"]==["UPDATE"]

def test_role_reads_request_full_representations():
    from keycloak_admin_api import KeycloakAdminAPI
    api=KeycloakAdminAPI("http://127.0.0.1:1","codestra","token"); seen=[]
    api.request=lambda method,suffix,body=None,expected=None: seen.append(suffix) or []
    api.realm_roles(); api.client_roles("c1")
    assert seen==["/roles?briefRepresentation=false","/clients/c1/roles?briefRepresentation=false"]

def test_empty_mapper_config_value_matches_its_absence_but_not_a_value():
    want={"clients":[{"clientId":"svc","protocolMappers":[{"name":"m","config":{"claim.name":"scope","claim.value":""}}]}]}
    stored={"clients":[{"id":"1","clientId":"svc","protocolMappers":[{"id":"x","name":"m","config":{"claim.name":"scope"}}]}]}
    assert [a["kind"] for a in plan(want,stored)["actions"] if a["resource_type"]=="client"]==["KEEP"]
    stored["clients"][0]["protocolMappers"][0]["config"]["claim.value"]="admin"
    assert [a["kind"] for a in plan(want,stored)["actions"] if a["resource_type"]=="client"]==["UPDATE"]
