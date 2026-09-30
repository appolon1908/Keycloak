from __future__ import annotations
import copy,http.client,json,sys,threading
from http.server import ThreadingHTTPServer
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts"))
from keycloak_identity_compiler import IdentityModelError,compile_identity,validate_client,write_output
from keycloak_reconciliation import apply_plan,plan
from keycloak_control_api import Handler,Service

def test_compiler_is_deterministic_and_complete():
    first=compile_identity(); second=compile_identity()
    assert first==second
    assert first["schema"]=="codestra.keycloak.identity-authority.v1"
    assert len(first["clients"])>=30
    assert first["sourceSha256"]==second["sourceSha256"]

def test_generated_identity_matches_check():
    write_output(False); write_output(True)

def test_wildcard_redirect_rejected():
    c={"clientId":"x","redirectUris":["https://x.example/*"],"webOrigins":[],"directAccessGrantsEnabled":False,
       "serviceAccountsEnabled":False,"publicClient":True,"standardFlowEnabled":True,"fullScopeAllowed":False}
    with pytest.raises(IdentityModelError,match="unsafe_redirect"): validate_client(c)

def test_direct_grant_rejected():
    c={"clientId":"x","redirectUris":[],"webOrigins":[],"directAccessGrantsEnabled":True,
       "serviceAccountsEnabled":True,"publicClient":False,"standardFlowEnabled":False,"fullScopeAllowed":False}
    with pytest.raises(IdentityModelError,match="direct_grants_forbidden"): validate_client(c)

def test_service_client_redirect_rejected():
    c={"clientId":"x","redirectUris":["https://x.example/cb"],"webOrigins":[],"directAccessGrantsEnabled":False,
       "serviceAccountsEnabled":True,"publicClient":False,"standardFlowEnabled":False,"fullScopeAllowed":False}
    with pytest.raises(IdentityModelError,match="service_client_redirects_forbidden"): validate_client(c)

def test_plan_create_update_keep_and_preserve_unmanaged():
    desired={"clients":[{"clientId":"a","enabled":True},{"clientId":"b","enabled":True},{"clientId":"c","enabled":True}]}
    live={"clients":[{"id":"1","clientId":"a","enabled":True},{"id":"2","clientId":"b","enabled":False},{"id":"9","clientId":"unmanaged","enabled":True}]}
    kinds={(a["resource_id"],a["kind"]) for a in plan(desired,live)["actions"]}
    assert ("a","KEEP") in kinds
    assert ("b","UPDATE") in kinds
    assert ("c","CREATE") in kinds
    assert ("unmanaged","KEEP") in kinds

class FakeAPI:
    def __init__(self): self.calls=[]
    def create_client(self,p): self.calls.append(("create",p["clientId"]))
    def update_client(self,i,p): self.calls.append(("update",i,p["clientId"]))

def test_apply_disabled_by_default():
    p={"actions":[]}
    with pytest.raises(RuntimeError,match="apply_disabled"): apply_plan(p,{"clients":[]},{"clients":[]},FakeAPI())

def test_apply_executes_only_managed_create_update_keep():
    desired={"clients":[{"clientId":"a","enabled":True},{"clientId":"b","enabled":True}]}
    live={"clients":[{"id":"2","clientId":"b","enabled":False}]}
    p=plan(desired,live,environment="test"); api=FakeAPI()
    out=apply_plan(p,desired,live,api,enabled=True,environment="test")
    assert out["applied"] is True
    assert ("create","a") in api.calls
    assert any(c[0]=="update" and c[1]=="2" for c in api.calls)

def test_control_api_health_and_apply_denial():
    class T(Handler): service=Service()
    server=ThreadingHTTPServer(("127.0.0.1",0),T); th=threading.Thread(target=server.serve_forever,daemon=True); th.start()
    try:
        conn=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=3)
        conn.request("GET","/platform/v1/keycloak/health",headers={"X-Correlation-ID":"abc"})
        r=conn.getresponse(); body=json.loads(r.read()); assert r.status==200 and body["applyEnabled"] is False and r.getheader("X-Correlation-ID")=="abc"
        conn.request("POST","/platform/v1/keycloak/reconcile/apply")
        r=conn.getresponse(); body=json.loads(r.read()); assert r.status==403 and body["error"]["code"]=="apply_disabled"
    finally:
        server.shutdown(); server.server_close()

def test_control_api_refuses_public_bind_source():
    src=(ROOT/"scripts"/"keycloak_control_api.py").read_text()
    assert 'a.host not in {"127.0.0.1","::1","localhost"}' in src


def test_admin_adapter_rejects_unsafe_http_url():
    from keycloak_admin_api import KeycloakAdminAPI, KeycloakAdminError
    with pytest.raises(KeycloakAdminError, match="admin API must use HTTPS or loopback"):
        KeycloakAdminAPI("http://keycloak.internal","codestra","token")


def test_dry_run_execution_has_readback(monkeypatch):
    class LocalService(Service):
        def live(self):
            return {"clients": [], "realm": {}, "clientScopes": [], "realmRoles": []}
    service=LocalService()
    record=service.dry_run()
    assert record["mode"]=="DRY_RUN"
    assert record["mutationPerformed"] is False
    assert service.execution(record["executionId"])["executionId"]==record["executionId"]


def test_missing_execution_is_404_error():
    from keycloak_admin_api import KeycloakAdminError
    service=Service()
    with pytest.raises(KeycloakAdminError) as exc:
        service.execution("missing")
    assert exc.value.code=="execution_not_found"
    assert exc.value.status==404


# --- live mutation contracts -------------------------------------------------
# A fake Admin API with realistic Keycloak representations: server-populated
# attributes, secret material on confidential clients and realm SMTP settings.

BOUNDARIES={"production":{"issuer":"https://auth.codestra.co/realms/codestra"},"staging":{"issuer":"https://auth-staging.codestra.co/realms/codestra"},"testSyn":{"namingPrefix":"test-syn-","productionPromotion":False}}
DESIRED={"sourceSha256":"x","realm":{"realm":"codestra","enabled":True,"sslRequired":"external","verifyEmail":True,"resetPasswordAllowed":True,"bruteForceProtected":True,"accessTokenLifespan":300},
         "clients":[{"clientId":"svc-a","enabled":True,"protocol":"openid-connect","publicClient":False,"standardFlowEnabled":False,"serviceAccountsEnabled":True,"fullScopeAllowed":False,"redirectUris":[],"webOrigins":[],"defaultClientScopes":["basic"],"optionalClientScopes":[],"attributes":{"access.token.lifespan":"300","oauth2.device.authorization.grant.enabled":"false"},"protocolMappers":[{"name":"aud","protocol":"openid-connect","protocolMapper":"oidc-audience-mapper","config":{"included.custom.audience":"middleware-api","access.token.claim":"true"}}]}],
         "stagedClients":[],"clientScopes":[],"realmRoles":[],"scopeMappings":[],"environmentBoundaries":BOUNDARIES}

def live_fixture():
    return {"realm":{"realm":"codestra","enabled":True,"sslRequired":"external","verifyEmail":True,"resetPasswordAllowed":False,"bruteForceProtected":True,"accessTokenLifespan":300,"otpPolicyType":"totp","passwordPolicy":"length(12)","smtpServer":{"host":"mail.internal","password":"hunter2"}},
            "clients":[{"id":"id-account","clientId":"account","enabled":True,"publicClient":True,"secret":"account-secret-value","attributes":{"client.secret.creation.time":"1700000000"},"protocolMappers":[]}],
            "clientScopes":[{"id":"s-profile","name":"profile","protocol":"openid-connect"}],
            "realmRoles":[{"id":"r-offline","name":"offline_access"}],
            "requiredActions":[{"alias":"VERIFY_EMAIL","name":"Verify Email","enabled":True}]}

class FakeAdminAPI:
    def __init__(self,state):
        self.state=state; self.calls=[]; self.on_mutate=None; self.fail_reads=False
    def _mutate(self,*call):
        if self.on_mutate: self.on_mutate()
        self.calls.append(call)
    def _read(self,key):
        from keycloak_admin_api import KeycloakAdminError
        if self.fail_reads: raise KeycloakAdminError("admin_transport_error","Keycloak Admin API transport failed")
        return copy.deepcopy(self.state[key])
    def realm_state(self): return self._read("realm")
    def clients(self): return self._read("clients")
    def client_scopes(self): return self._read("clientScopes")
    def realm_roles(self): return self._read("realmRoles")
    def required_actions(self): return self._read("requiredActions")
    def unregistered_required_actions(self): return copy.deepcopy(self.state.get("unregisteredRequiredActions",[]))
    def user_profile(self):
        if self.fail_reads: return self._read("userProfile")
        return copy.deepcopy(self.state.get("userProfile",{"attributes":[]}))
    def update_user_profile(self,config): self._mutate("update_user_profile"); self.state["userProfile"]=copy.deepcopy(config)
    def client_realm_role_mappings(self,internal_id): return []
    def events(self,**_): return []
    def update_realm(self,payload): self._mutate("update_realm"); self.state["realm"].update(payload)
    def create_client(self,payload):
        self._mutate("create_client",payload["clientId"])
        self.state["clients"].append({"id":f"id-{payload['clientId']}","secret":"live-secret-value",**copy.deepcopy(payload)})
    def update_client(self,internal_id,payload):
        self._mutate("update_client",internal_id)
        for c in self.state["clients"]:
            if c["id"]==internal_id: c.update(copy.deepcopy(payload))
    def delete_client(self,internal_id):
        self._mutate("delete_client",internal_id); self.state["clients"]=[c for c in self.state["clients"] if c["id"]!=internal_id]

def make_service(tmp_path,api,desired=DESIRED):
    from keycloak_execution_store import EvidenceStore
    class Local(Service):
        def __init__(self): super().__init__(EvidenceStore(tmp_path/"store"))
        def desired(self): return copy.deepcopy(desired)
        def _api(self): return api
    return Local()

def enable_staging_mutation(monkeypatch):
    monkeypatch.setenv("KEYCLOAK_MUTATION_ENABLED","true")
    monkeypatch.setenv("KEYCLOAK_ENVIRONMENT","staging")
    monkeypatch.setenv("KEYCLOAK_ADMIN_BASE_URL","https://auth-staging.codestra.co")
    monkeypatch.setenv("KEYCLOAK_ADMIN_BEARER","unused-by-fake")
    monkeypatch.delenv("KEYCLOAK_DELETE_ENABLED",raising=False)

def test_apply_persists_redacted_evidence_before_any_mutation(tmp_path,monkeypatch):
    enable_staging_mutation(monkeypatch)
    api=FakeAdminAPI(live_fixture()); service=make_service(tmp_path,api)
    seen=[]
    api.on_mutate=lambda: seen.append([(r["payload"]["status"],bool(r["payload"].get("preState"))) for r in service.store.list("executions")])
    record=service.apply("apply-key-1")
    assert seen and all(rows==[("IN_PROGRESS",True)] for rows in seen)
    assert record["status"]=="COMPLETED" and record["mutationPerformed"] is True and record["environment"]=="staging"
    assert ("update_realm",) in api.calls and ("create_client","svc-a") in api.calls
    stored=service.evidence(record["executionId"])["payload"]
    assert stored==record and stored["readback"]["equal"] is True and stored["error"] is None
    pre=stored["preState"]
    assert pre["realm"]["resetPasswordAllowed"] is False and "password" not in pre["realm"]["smtpServer"]
    assert "secret" not in pre["clients"][0] and pre["clients"][0]["attributes"]["client.secret.creation.time"]=="1700000000"
    assert "root.realm.smtpServer.password" in stored["preStateRedactedPaths"] and "root.clients[0].secret" in stored["preStateRedactedPaths"]
    raw=json.dumps(stored)
    assert "hunter2" not in raw and "account-secret-value" not in raw and "live-secret-value" not in raw

def test_apply_replays_idempotency_key_without_mutating_again(tmp_path,monkeypatch):
    enable_staging_mutation(monkeypatch)
    api=FakeAdminAPI(live_fixture()); service=make_service(tmp_path,api)
    first=service.apply("same-key"); calls=len(api.calls)
    second=service.apply("same-key")
    assert second["executionId"]==first["executionId"] and len(api.calls)==calls
    # A converged realm applies as a no-op with no mutation recorded.
    third=service.apply("other-key")
    assert third["status"]=="COMPLETED" and third["mutationPerformed"] is False and len(api.calls)==calls

def test_apply_refuses_unknown_environment_and_foreign_issuer(tmp_path,monkeypatch):
    from keycloak_admin_api import KeycloakAdminError
    enable_staging_mutation(monkeypatch)
    api=FakeAdminAPI(live_fixture()); service=make_service(tmp_path,api)
    cases=[({"KEYCLOAK_ENVIRONMENT":None},"environment_unknown"),
           ({"KEYCLOAK_ENVIRONMENT":"lab"},"environment_unknown"),
           ({"KEYCLOAK_ENVIRONMENT":"production"},"environment_issuer_mismatch"),
           ({"KEYCLOAK_ENVIRONMENT":"test-syn"},"environment_issuer_mismatch"),
           ({"KEYCLOAK_ENVIRONMENT":"TEST_SYN","KEYCLOAK_ADMIN_BASE_URL":"https://auth.codestra.co"},"environment_issuer_mismatch")]
    for env,code in cases:
        for name,value in env.items():
            if value is None: monkeypatch.delenv(name,raising=False)
            else: monkeypatch.setenv(name,value)
        with pytest.raises(KeycloakAdminError) as exc: service.apply(f"key-{code}")
        assert exc.value.code==code and exc.value.status==409
    assert api.calls==[] and service.store.list("executions")==[]
    monkeypatch.setenv("KEYCLOAK_ENVIRONMENT","test-syn"); monkeypatch.setenv("KEYCLOAK_ADMIN_BASE_URL","http://127.0.0.1:8080")
    assert service.apply("loopback-test-syn")["environment"]=="test-syn"

def test_apply_rejects_unexecutable_plan_before_mutation():
    desired={"clients":[{"clientId":"a","enabled":True}],"scopeMappings":[]}
    live={"clients":[{"id":"9","clientId":"stale","enabled":True}]}
    api=FakeAPI()
    bad=plan(desired,live,environment="test")
    bad["actions"].append({"kind":"CREATE","resource_type":"scope_mapping","resource_id":"ghost","reason":"x","managed":True})
    out=apply_plan(bad,desired,live,api,enabled=True,environment="test")
    assert out["status"]=="REJECTED" and out["applied"] is False and out["journal"]==[] and api.calls==[]
    unauthorized=plan(desired,live,managed_inventory={"clients":["stale"]},environment="test")
    out=apply_plan(unauthorized,desired,live,api,enabled=True,environment="test")
    assert out["status"]=="REJECTED" and "delete_not_authorized" in out["error"] and api.calls==[]
    with pytest.raises(RuntimeError,match="environment_mismatch"):
        apply_plan(plan(desired,live,environment="staging"),desired,live,api,enabled=True,environment="production")
    with pytest.raises(RuntimeError,match="environment_unknown"):
        apply_plan(plan(desired,live),desired,live,api,enabled=True,environment="unknown")

def test_rollback_restores_pre_state_and_deletes_only_what_apply_created(tmp_path,monkeypatch):
    enable_staging_mutation(monkeypatch)
    api=FakeAdminAPI(live_fixture()); service=make_service(tmp_path,api)
    record=service.apply("rollback-me")
    api.state["clients"].append({"id":"id-foreign","clientId":"foreign","enabled":True,"publicClient":True,"attributes":{},"protocolMappers":[]})
    api.calls.clear()
    result=service.rollback(record["executionId"])
    assert result["status"]=="COMPLETED" and result["mutationPerformed"] is True
    assert ("delete_client","id-svc-a") in api.calls and ("delete_client","id-foreign") not in api.calls and ("update_realm",) in api.calls
    assert api.state["realm"]["resetPasswordAllowed"] is False
    assert {c["clientId"] for c in api.state["clients"]}=={"account","foreign"}
    original=service.execution(record["executionId"])
    assert original["rollbackStatus"]=="ROLLED_BACK" and original["rollbackExecutionId"]==result["executionId"]

def test_readback_ignores_unmanaged_live_resources():
    from keycloak_reconciliation import verify_readback
    live=live_fixture(); live["realm"]["resetPasswordAllowed"]=True
    live["clients"].append({"id":"id-svc-a","secret":"s","attributes":{"access.token.lifespan":"300","oauth2.device.authorization.grant.enabled":"false","client.secret.creation.time":"1"},"protocolMappers":[{"id":"m1",**DESIRED["clients"][0]["protocolMappers"][0]}],**{k:v for k,v in DESIRED["clients"][0].items() if k not in {"attributes","protocolMappers"}}})
    result=verify_readback(DESIRED,live)
    assert result["equal"] is True and result["pendingActions"]==[]
    live["clients"][-1]["attributes"]["access.token.lifespan"]="60"
    result=verify_readback(DESIRED,live)
    assert result["equal"] is False and [a["resource_id"] for a in result["pendingActions"]]==["svc-a"]

def test_control_api_apply_over_http_never_returns_secret_material(tmp_path,monkeypatch):
    enable_staging_mutation(monkeypatch)
    api=FakeAdminAPI(live_fixture()); service=make_service(tmp_path,api)
    class T(Handler): pass
    T.service=service
    server=ThreadingHTTPServer(("127.0.0.1",0),T); threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        conn=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=3)
        conn.request("POST","/platform/v1/keycloak/reconcile/apply",headers={"X-Idempotency-Key":"http-1"})
        r=conn.getresponse(); raw=r.read().decode(); body=json.loads(raw)
        assert r.status==200 and body["execution"]["status"]=="COMPLETED"
        assert "hunter2" not in raw and "live-secret-value" not in raw and "account-secret-value" not in raw
        conn.request("GET",f"/platform/v1/keycloak/reconcile/executions/{body['execution']['executionId']}/evidence")
        r=conn.getresponse(); evidence=json.loads(r.read()); assert r.status==200 and evidence["evidence"]["sha256"]
        conn.request("GET","/platform/v1/keycloak/reconcile/executions/missing/evidence")
        r=conn.getresponse(); missing=json.loads(r.read()); assert r.status==404 and missing["error"]["code"]=="execution_not_found"
        conn.request("GET","/platform/v1/keycloak/reconcile/rollbacks/missing")
        r=conn.getresponse(); missing=json.loads(r.read()); assert r.status==404 and missing["error"]["code"]=="rollback_not_found"
        conn.request("POST","/platform/v1/keycloak/reconcile/rollback",body=b"{}",headers={"Content-Length":"abc"})
        r=conn.getresponse(); bad=json.loads(r.read()); assert r.status==400 and bad["error"]["code"]=="invalid_request"
    finally:
        server.shutdown(); server.server_close()

def test_apply_journal_survives_readback_failure_and_rollback_uses_it(tmp_path,monkeypatch):
    from keycloak_admin_api import KeycloakAdminError
    enable_staging_mutation(monkeypatch)
    api=FakeAdminAPI(live_fixture()); service=make_service(tmp_path,api)
    api.on_mutate=lambda: setattr(api,"fail_reads",True)
    record=service.apply("readback-fails")
    assert record["status"]=="READBACK_UNAVAILABLE" and record["error"]=="admin_transport_error"
    assert record["mutationPerformed"] is True and {(j["kind"],j["resourceId"]) for j in record["actionJournal"]}>={("CREATE","svc-a"),("UPDATE","codestra")}
    assert service.evidence(record["executionId"])["payload"]["actionJournal"]==record["actionJournal"]
    # The finalized record answers a replay; nothing is applied again until an operator chooses a new key.
    calls=len(api.calls)
    assert service.apply("readback-fails")["executionId"]==record["executionId"] and len(api.calls)==calls
    api.fail_reads=False; api.on_mutate=None; api.calls.clear()
    assert service.metrics()["keycloak_readback_failures"]==1
    result=service.rollback(record["executionId"])
    assert result["status"]=="COMPLETED" and ("delete_client","id-svc-a") in api.calls
    assert {c["clientId"] for c in api.state["clients"]}=={"account"} and api.state["realm"]["resetPasswordAllowed"] is False

def test_apply_replay_ignores_failed_record_only_by_design_and_is_not_capped_by_retention(tmp_path,monkeypatch):
    from keycloak_execution_store import EvidenceStore
    enable_staging_mutation(monkeypatch)
    api=FakeAdminAPI(live_fixture())
    class Local(Service):
        def __init__(self): super().__init__(EvidenceStore(tmp_path/"store",retention=10))
        def desired(self): return copy.deepcopy(DESIRED)
        def _api(self): return api
    service=Local()
    first=service.apply("durable-key"); calls=len(api.calls)
    for _ in range(12): service.dry_run()
    assert len(list((tmp_path/"store"/"executions").glob("*.json")))<=11
    again=service.apply("durable-key")
    assert again["executionId"]==first["executionId"] and len(api.calls)==calls

def test_rollback_removes_attributes_the_apply_added_and_refuses_a_second_rollback(tmp_path,monkeypatch):
    from keycloak_admin_api import KeycloakAdminError
    enable_staging_mutation(monkeypatch)
    desired=copy.deepcopy(DESIRED)
    desired["clients"].append({"clientId":"account","enabled":True,"publicClient":True,"attributes":{"pkce.code.challenge.method":"S256"},"protocolMappers":[]})
    api=FakeAdminAPI(live_fixture()); service=make_service(tmp_path,api,desired)
    record=service.apply("attr-key")
    account=next(c for c in api.state["clients"] if c["clientId"]=="account")
    assert record["status"]=="COMPLETED" and account["attributes"]["pkce.code.challenge.method"]=="S256"
    assert record["attributeAdditions"]=={"account":["pkce.code.challenge.method"]}
    # The desired state moves on after the apply; rollback relies on the recorded additions, not on it.
    desired["clients"][-1]["attributes"]={}
    result=service.rollback(record["executionId"])
    account=next(c for c in api.state["clients"] if c["clientId"]=="account")
    assert result["status"]=="COMPLETED" and "pkce.code.challenge.method" not in account["attributes"]
    assert account["attributes"]["client.secret.creation.time"]=="1700000000" and account["secret"]=="account-secret-value"
    with pytest.raises(KeycloakAdminError) as exc: service.rollback(record["executionId"])
    assert exc.value.code=="rollback_already_applied" and exc.value.status==409

def converged_svc_a():
    return {"id":"id-svc-a","secret":"s","attributes":{"access.token.lifespan":"300","oauth2.device.authorization.grant.enabled":"false","client.secret.creation.time":"1"},"protocolMappers":[{"id":"m1",**DESIRED["clients"][0]["protocolMappers"][0]}],**{k:v for k,v in DESIRED["clients"][0].items() if k not in {"attributes","protocolMappers"}}}

def test_observability_status_reports_managed_drift_only():
    from keycloak_observability import status
    live=live_fixture(); live["realm"]["resetPasswordAllowed"]=True; live["clients"].append(converged_svc_a())
    st=status(DESIRED,live)
    assert st["realm"]=="codestra" and st["configurationDrift"] is False and st["pendingMutations"]==0 and st["eventsEnabled"] is False
    live["clients"][-1]["enabled"]=False; live["realm"]["eventsEnabled"]=True
    st=status(DESIRED,live)
    assert st["configurationDrift"] is True and st["pendingMutations"]==1 and st["eventsEnabled"] is True

def test_rollback_journal_survives_readback_failure_and_can_be_retried(tmp_path,monkeypatch):
    from keycloak_admin_api import KeycloakAdminError
    enable_staging_mutation(monkeypatch)
    api=FakeAdminAPI(live_fixture()); service=make_service(tmp_path,api)
    record=service.apply("rollback-readback")
    assert record["status"]=="COMPLETED"
    seen=[]
    api.on_mutate=lambda: (seen.append([r["payload"]["status"] for r in service.store.list("rollbacks")]),setattr(api,"fail_reads",True))
    first=service.rollback(record["executionId"])
    assert seen and all(rows==["IN_PROGRESS"] for rows in seen)
    assert first["status"]=="READBACK_UNAVAILABLE" and first["error"]=="admin_transport_error" and first["mutationPerformed"] is True
    assert ("delete_client","id-svc-a") in api.calls and first["plan"]["planSha256"]
    stored=service.rollback_evidence(first["executionId"])["payload"]
    assert stored==first and stored["actionJournal"]==first["actionJournal"] and "hunter2" not in json.dumps(stored)
    original=service.execution(record["executionId"])
    assert original["rollbackStatus"]=="ROLLBACK_FAILED" and original["rollbackExecutionId"]==first["executionId"]
    with pytest.raises(KeycloakAdminError) as exc: service.rollback_evidence("missing")
    assert exc.value.code=="rollback_not_found" and exc.value.status==404
    # With reads restored the second attempt finds the realm already restored and confirms it.
    api.fail_reads=False; api.on_mutate=None; api.calls.clear()
    second=service.rollback(record["executionId"])
    assert second["status"]=="COMPLETED" and second["mutationPerformed"] is False and api.calls==[]
    assert service.execution(record["executionId"])["rollbackStatus"]=="ROLLED_BACK"
    assert {c["clientId"] for c in api.state["clients"]}=={"account"} and api.state["realm"]["resetPasswordAllowed"] is False

def test_compile_endpoint_is_read_only():
    generated=ROOT/"generated"/"keycloak-identity-authority.v1.json"
    before=generated.read_bytes(); stamp=generated.stat().st_mtime_ns
    result=Service().compile()
    assert result["compiled"] is True and result["generatedDrift"] is False
    assert generated.read_bytes()==before and generated.stat().st_mtime_ns==stamp
