from __future__ import annotations
import hashlib,json,sys,time
from pathlib import Path
import pytest
ROOT=Path(__file__).resolve().parents[1]; sys.path.insert(0,str(ROOT/"scripts"))
from keycloak_execution_store import EvidenceStore,EvidenceStoreError
from keycloak_recovery_controller import RecoveryController
from keycloak_event_redaction import redact_event
from keycloak_observability import normalize_events,metrics,ObservabilityError
from keycloak_environment_promotion import promotion_plan

def test_store_atomic_duplicate_and_corruption(tmp_path):
    s=EvidenceStore(tmp_path,retention=10); s.put("executions","a",{"status":"ok"})
    assert s.get("executions","a")["payload"]["status"]=="ok"
    with pytest.raises(EvidenceStoreError,match="duplicate"): s.put("executions","a",{})
    p=tmp_path/"executions"/"a.json"; p.write_text('{"bad":true}')
    with pytest.raises(EvidenceStoreError,match="corrupt"): s.get("executions","a")

def test_recovery_valid_stale_invalid_and_missing(tmp_path,monkeypatch):
    b=tmp_path/"b"; r=tmp_path/"r"; b.mkdir(); r.mkdir()
    ctl=RecoveryController(b,r); assert ctl.status()["state"]=="UNKNOWN"
    f=b/"backup.sql.gpg"; f.write_bytes(b"safe")
    Path(str(f)+".sha256").write_text(hashlib.sha256(b"safe").hexdigest()+"  backup.sql.gpg\\n")
    (r/"restore.json").write_text(json.dumps({"isolated":True,"success":True}))
    assert ctl.status()["state"]=="HEALTHY"
    Path(str(f)+".sha256").write_text("0"*64+"  backup.sql.gpg\\n")
    assert ctl.status()["state"]=="INVALID"

def test_event_redaction_and_metrics():
    e={"event_id":"1","event_type":"LOGIN_ERROR","timestamp":1,"realm":"codestra","client_id":"x","access_token":"NO","password":"NO","authorization":"NO"}
    clean=redact_event(e); assert "access_token" not in clean and "password" not in clean
    assert metrics([clean])["authentication_failures"]==1
    with pytest.raises(ObservabilityError): normalize_events([clean],limit=501)

def test_promotion_blocks_testsyn_and_is_deterministic():
    desired={"sourceSha256":"abc","clients":[],"stagedClients":[{"authorityGroup":"TEST_SYN","client":{"clientId":"test-syn-a","redirectUris":[],"webOrigins":[]}}]}
    req={"promotionId":"p1","sourceAuthorityGroup":"TEST_SYN","targetEnvironment":"production","targetIssuer":"https://auth.codestra.co/realms/codestra","targetMapping":{"test-syn-a":"a"}}
    a=promotion_plan(desired,req); b=promotion_plan(desired,req)
    assert a["promotionStatus"]=="BLOCK" and "test_syn_production_forbidden" in a["blockers"] and a["packetSha256"]==b["packetSha256"]

def test_promotion_requires_mapping():
    desired={"clients":[],"stagedClients":[{"authorityGroup":"stage","client":{"clientId":"a"}}]}
    assert promotion_plan(desired,{"promotionId":"p","sourceAuthorityGroup":"stage","targetEnvironment":"staging"})["promotionStatus"]=="BLOCK"


def test_reconciliation_delete_only_for_explicit_managed_inventory():
    from keycloak_reconciliation import plan
    desired={"clients":[]}
    live={"clients":[{"id":"1","clientId":"managed"},{"id":"2","clientId":"foreign"}]}
    actions={a["resource_id"]:a for a in plan(desired,live,managed_inventory={"clients":["managed"]})["actions"]}
    assert actions["managed"]["kind"]=="DELETE" and actions["managed"]["managed"] is True
    assert actions["foreign"]["kind"]=="KEEP" and actions["foreign"]["managed"] is False

def test_readback_mismatch_is_detected():
    from keycloak_reconciliation import verify_readback
    desired={"realm":{"enabled":True},"clients":[]}
    live={"realm":{"enabled":False},"clients":[]}
    assert verify_readback(desired,live)["equal"] is False

def test_partial_failure_journals_completed_actions():
    from keycloak_reconciliation import apply_plan
    class API:
        def create_client(self,p): raise RuntimeError("boom")
    desired={"clients":[{"clientId":"x","enabled":True}]}; live={"clients":[]}
    p={"environment":"test","actions":[{"kind":"CREATE","resource_type":"client","resource_id":"x","managed":True}]}
    out=apply_plan(p,desired,live,API(),enabled=True,environment="test")
    assert out["status"]=="PARTIAL_FAILURE" and out["applied"] is False

def test_api_recovery_promotion_and_oversize(tmp_path):
    import http.client,threading
    from http.server import ThreadingHTTPServer
    from keycloak_control_api import Handler,Service
    class Local(Service):
        def __init__(self): super().__init__(EvidenceStore(tmp_path/"store"))
        def desired(self): return {"sourceSha256":"x","clients":[],"stagedClients":[]}
        def recovery(self): return RecoveryController(tmp_path/"backups",tmp_path/"restores")
    class T(Handler): service=Local()
    server=ThreadingHTTPServer(("127.0.0.1",0),T); th=threading.Thread(target=server.serve_forever,daemon=True); th.start()
    try:
        c=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=3)
        c.request("GET","/platform/v1/keycloak/recovery/status"); r=c.getresponse(); body=json.loads(r.read()); assert r.status==200 and body["recovery"]["state"]=="UNKNOWN"
        payload=json.dumps({"promotionId":"p1","sourceAuthorityGroup":"missing","targetEnvironment":"staging","targetMapping":{"x":"y"}})
        c.request("POST","/platform/v1/keycloak/promotion/plan",body=payload,headers={"Content-Type":"application/json"}); r=c.getresponse(); body=json.loads(r.read()); assert r.status==200 and body["promotion"]["promotionStatus"]=="BLOCK"
        c.request("POST","/platform/v1/keycloak/promotion/plan",body=b"x",headers={"Content-Length":"70000"}); r=c.getresponse(); body=json.loads(r.read()); assert r.status==413 and body["error"]["code"]=="request_too_large"
    finally:
        server.shutdown(); server.server_close()


def test_store_rejects_nested_secret_material(tmp_path):
    s=EvidenceStore(tmp_path)
    with pytest.raises(EvidenceStoreError,match="secret_material_forbidden"):
        s.put("executions","secret",{"nested":{"access_token":"do-not-store"}})

def test_promotion_collision_blocks_policy_mismatch():
    desired={"sourceSha256":"x","clients":[{"clientId":"target","redirectUris":["https://prod/cb"],"webOrigins":["https://prod"],"serviceAccountsEnabled":False}],"stagedClients":[{"authorityGroup":"stage","client":{"clientId":"source","redirectUris":["https://stage/cb"],"webOrigins":["https://stage"],"serviceAccountsEnabled":False}}]}
    req={"promotionId":"p2","sourceAuthorityGroup":"stage","targetEnvironment":"production","targetIssuer":"https://auth.codestra.co/realms/codestra","targetMapping":{"source":"target"}}
    out=promotion_plan(desired,req)
    assert out["promotionStatus"]=="BLOCK" and "protected_client_collision:target" in out["blockers"]


def test_api_rejects_bad_observability_limit(tmp_path):
    import http.client,threading
    from http.server import ThreadingHTTPServer
    from keycloak_control_api import Handler,Service
    class Local(Service):
        def __init__(self): super().__init__(EvidenceStore(tmp_path/"store"))
        def events(self,limit=100): return []
    class T(Handler): service=Local()
    server=ThreadingHTTPServer(("127.0.0.1",0),T); threading.Thread(target=server.serve_forever,daemon=True).start()
    try:
        c=http.client.HTTPConnection("127.0.0.1",server.server_port,timeout=3)
        for route in ("events","metrics"):
            for value in ("nope","0","501"):
                c.request("GET",f"/platform/v1/keycloak/observability/{route}?limit={value}")
                r=c.getresponse(); body=json.loads(r.read())
                assert r.status==400 and body["error"]["code"]=="invalid_query"
    finally:
        server.shutdown(); server.server_close()

def test_dry_run_persists_evidence(tmp_path):
    from keycloak_control_api import Service
    class Local(Service):
        def __init__(self): super().__init__(EvidenceStore(tmp_path/"store"))
        def drift(self): return {"planSha256":"p","desiredSha256":"d","liveSha256":"l","actions":[]}
    s=Local(); rec=s.dry_run("idem")
    evidence=s.evidence(rec["executionId"])
    assert evidence["payload"]["idempotencyKey"]=="idem" and evidence["sha256"]


def test_compiler_includes_explicit_scope_mappings():
    from keycloak_identity_compiler import compile_identity
    d=compile_identity()
    ids={x["clientId"] for x in d["scopeMappings"]}
    assert {"grafana-observability","openbao-secrets","superset-analytics"} <= ids

def test_scope_mapping_authority_is_explicit_and_fail_closed():
    from keycloak_identity_compiler import compile_identity
    d=compile_identity()
    for m in d["scopeMappings"]:
        assert m["fullScopeAllowed"] is False
        assert m.get("crossFamilyRolesAllowed") is False
        assert isinstance(m.get("realmRoles"),list)


def test_scope_mapping_plan_detects_role_drift():
    from keycloak_reconciliation import plan
    desired={"realmRoles":[{"name":"viewer"}],"scopeMappings":[{"clientId":"grafana","fullScopeAllowed":False,"realmRoles":["viewer"],"crossFamilyRolesAllowed":False}]}
    live={"scopeMappings":[{"clientId":"grafana","fullScopeAllowed":False,"realmRoles":[],"crossFamilyRolesAllowed":False}]}
    a=[x for x in plan(desired,live)["actions"] if x["resource_type"]=="scope_mapping"]
    assert len(a)==1 and a[0]["kind"]=="UPDATE"

def test_scope_mapping_apply_adds_and_removes_exact_roles():
    from keycloak_reconciliation import apply_plan
    class API:
        def __init__(self): self.added=[]; self.removed=[]
        def client_by_client_id(self,x): return {"id":"c1","clientId":x}
        def client_realm_role_mappings(self,x): return [{"id":"r2","name":"old"}]
        def realm_roles(self): return [{"id":"r1","name":"viewer"},{"id":"r2","name":"old"}]
        def add_client_realm_role_mappings(self,x,roles): self.added=roles
        def delete_client_realm_role_mappings(self,x,roles): self.removed=roles
    api=API()
    desired={"scopeMappings":[{"clientId":"grafana","realmRoles":["viewer"],"fullScopeAllowed":False,"crossFamilyRolesAllowed":False}]}
    live={"scopeMappings":[{"clientId":"grafana","realmRoles":["old"],"fullScopeAllowed":False,"crossFamilyRolesAllowed":False}]}
    p={"environment":"test","actions":[{"kind":"UPDATE","resource_type":"scope_mapping","resource_id":"grafana","managed":True}]}
    out=apply_plan(p,desired,live,api,enabled=True,environment="test")
    assert out["status"]=="APPLIED"
    assert [x["name"] for x in api.added]==["viewer"] and [x["name"] for x in api.removed]==["old"]


def test_scope_mapping_for_absent_unmanaged_client_stays_unmanaged():
    from keycloak_reconciliation import plan
    desired={"clients":[{"clientId":"middleware-api"}],"realmRoles":[{"name":"viewer"}],"scopeMappings":[{"clientId":"grafana-observability","realmRoles":["viewer"],"fullScopeAllowed":False,"crossFamilyRolesAllowed":False}]}
    live={"clients":[{"id":"1","clientId":"middleware-api"}],"scopeMappings":[]}
    a=[x for x in plan(desired,live)["actions"] if x["resource_type"]=="scope_mapping"]
    assert len(a)==1 and a[0]["kind"]=="KEEP" and a[0]["managed"] is False and a[0]["reason"]=="scope_mapping_client_not_managed"
    live["clients"].append({"id":"2","clientId":"grafana-observability"})
    a=[x for x in plan(desired,live)["actions"] if x["resource_type"]=="scope_mapping"]
    assert a[0]["kind"]=="UPDATE"


def test_store_accepts_keycloak_configuration_keys_and_rejects_secret_values(tmp_path):
    from keycloak_execution_store import redact_secret_material
    s=EvidenceStore(tmp_path)
    s.put("executions","config",{"realm":{"resetPasswordAllowed":True,"otpPolicyDigits":6,"accessTokenLifespan":300,"passwordPolicy":""},
                                  "client":{"attributes":{"access.token.lifespan":"300","oauth2.device.authorization.grant.enabled":"false","client.secret.creation.time":"1700000000","jwt.credential.certificate":"MIICertificate"}}})
    for payload in ({"secret":"abc"},{"registrationAccessToken":"x"},{"attributes":{"client.secret.rotated":"zzz"}},{"smtpServer":{"password":"p"}},{"credentials":[{"value":"x"}]},{"attributes":{"saml.signing.private.key":"MIIE"}}):
        with pytest.raises(EvidenceStoreError,match="secret_material_forbidden"): s.put("executions","bad",payload)
    live={"realm":{"resetPasswordAllowed":False,"otpPolicyType":"totp","smtpServer":{"host":"mail","password":"hunter2"}},"clients":[{"clientId":"c","secret":"s3","attributes":{"client.secret.creation.time":"1","client.secret.rotated":"old"}}]}
    clean,dropped=redact_secret_material(live)
    assert "password" not in clean["realm"]["smtpServer"] and clean["realm"]["smtpServer"]["host"]=="mail"
    assert "secret" not in clean["clients"][0] and clean["clients"][0]["attributes"]=={"client.secret.creation.time":"1"}
    assert set(dropped)=={"root.realm.otpPolicyType","root.realm.smtpServer.password","root.clients[0].secret","root.clients[0].attributes.client.secret.rotated"}
    s.put("executions","clean",clean)


def test_store_prune_keeps_mutation_evidence(tmp_path):
    import os
    s=EvidenceStore(tmp_path,retention=10)
    base=1_700_000_000
    s.put("executions","apply-old",{"mode":"APPLY","status":"COMPLETED"}); os.utime(tmp_path/"executions"/"apply-old.json",(base,base))
    for i in range(12):
        s.put("executions",f"dry-{i}",{"mode":"DRY_RUN"}); os.utime(tmp_path/"executions"/f"dry-{i}.json",(base+1+i,base+1+i))
    s.put("executions","dry-last",{"mode":"DRY_RUN"})
    names={p.stem for p in (tmp_path/"executions").glob("*.json")}
    assert "apply-old" in names and "dry-0" not in names and len(names)<=11


def test_promotion_blocks_test_syn_prefix_regardless_of_group_and_target_case():
    boundaries={"production":{"issuer":"https://auth.codestra.co/realms/codestra"},"staging":{"issuer":"https://auth-staging.codestra.co/realms/codestra"},"testSyn":{"namingPrefix":"test-syn-","productionPromotion":False}}
    desired={"sourceSha256":"abc","clients":[],"environmentBoundaries":boundaries,
             "stagedClients":[{"authorityGroup":"edge-integration-certification","client":{"clientId":"test-syn-portal","redirectUris":[],"webOrigins":[]}},
                              {"authorityGroup":"observability","client":{"clientId":"grafana-observability","redirectUris":[],"webOrigins":[]}}]}
    prod="https://auth.codestra.co/realms/codestra"
    out=promotion_plan(desired,{"promotionId":"p","sourceAuthorityGroup":"edge-integration-certification","targetEnvironment":"Production","targetIssuer":prod,"targetMapping":{"test-syn-portal":"portal"}})
    assert out["promotionStatus"]=="BLOCK" and "test_syn_production_forbidden" in out["blockers"] and out["targetEnvironment"]=="production"
    out=promotion_plan(desired,{"promotionId":"p","sourceAuthorityGroup":"observability","targetEnvironment":"production","targetIssuer":prod,"targetMapping":{"grafana-observability":"test-syn-grafana"}})
    assert "test_syn_production_forbidden" in out["blockers"]
    out=promotion_plan(desired,{"promotionId":"p","sourceAuthorityGroup":"observability","targetEnvironment":"production","targetIssuer":"https://auth-staging.codestra.co/realms/codestra","targetMapping":{"grafana-observability":"grafana"}})
    assert out["blockers"]==["target_issuer_mismatch"]
    out=promotion_plan(desired,{"promotionId":"p","sourceAuthorityGroup":"observability","targetEnvironment":"production","targetMapping":{"grafana-observability":"grafana"}})
    assert out["blockers"]==["target_issuer_required"]
    out=promotion_plan(desired,{"promotionId":"p","sourceAuthorityGroup":"observability","targetEnvironment":"production","targetIssuer":prod,"targetMapping":{"grafana-observability":"grafana"}})
    assert out["promotionStatus"]=="PROMOTE"
    out=promotion_plan(desired,{"promotionId":"p","sourceAuthorityGroup":"edge-integration-certification","targetEnvironment":"staging","targetIssuer":"https://auth-staging.codestra.co/realms/codestra","targetMapping":{"test-syn-portal":"test-syn-portal"}})
    assert out["promotionStatus"]=="PROMOTE"
    out=promotion_plan(desired,{"promotionId":"p","sourceAuthorityGroup":"observability","targetEnvironment":"lab","targetMapping":{"grafana-observability":"grafana"}})
    assert "target_environment_invalid" in out["blockers"]
    desired["stagedClients"].append({"authorityGroup":"mixed","client":{"clientId":"TEST-SYN-Upper","redirectUris":[],"webOrigins":[]}})
    out=promotion_plan(desired,{"promotionId":"p","sourceAuthorityGroup":"mixed","targetEnvironment":"production","targetIssuer":prod,"targetMapping":{"TEST-SYN-Upper":"upper"}})
    assert "test_syn_production_forbidden" in out["blockers"]


def test_undeclared_client_fields_are_not_drift_and_are_not_sent():
    from keycloak_reconciliation import apply_plan,plan
    desired={"clients":[{"clientId":"a","enabled":True,"attributes":{"x":"1"}}]}
    live={"clients":[{"id":"1","clientId":"a","enabled":True,"fullScopeAllowed":False,"defaultClientScopes":["basic"],"attributes":{"x":"1","client.secret.creation.time":"9"},"protocolMappers":[{"id":"m","name":"n"}]}]}
    assert [a["kind"] for a in plan(desired,live)["actions"] if a["resource_type"]=="client"]==["KEEP"]
    desired["clients"][0]["enabled"]=False
    class API:
        def __init__(self): self.payload=None
        def update_client(self,i,p): self.payload=p
    api=API(); p=plan(desired,live,environment="test")
    assert apply_plan(p,desired,live,api,enabled=True,environment="test")["status"]=="APPLIED"
    assert api.payload["enabled"] is False and api.payload["fullScopeAllowed"] is False and api.payload["defaultClientScopes"]==["basic"]
    assert None not in api.payload.values() and api.payload["attributes"]=={"x":"1","client.secret.creation.time":"9"}


def test_recovery_list_typed_evidence_is_invalid_not_a_crash(tmp_path):
    b=tmp_path/"b"; r=tmp_path/"r"; b.mkdir(); r.mkdir()
    f=b/"backup.sql.gpg"; f.write_bytes(b"safe")
    Path(str(f)+".sha256").write_text(hashlib.sha256(b"safe").hexdigest()+"  backup.sql.gpg\n")
    (r/"restore.json").write_text(json.dumps([{"isolated":True,"success":True}]))
    ctl=RecoveryController(b,r)
    assert ctl.restores()[0]["evidence"]=={"valid":False,"error":"invalid_evidence"}
    assert ctl.status()["state"]=="INVALID"


def test_admin_adapter_rejects_lookalike_loopback_hosts():
    from keycloak_admin_api import KeycloakAdminAPI,KeycloakAdminError,is_safe_admin_url
    for url in ("http://127.0.0.1.attacker.example","http://localhost.attacker.example","http://auth.codestra.co","ftp://127.0.0.1"):
        with pytest.raises(KeycloakAdminError,match="HTTPS or loopback"): KeycloakAdminAPI(url,"codestra","token")
    assert is_safe_admin_url("http://127.0.0.1:8080") and is_safe_admin_url("http://[::1]:8080") and is_safe_admin_url("https://auth.codestra.co")


def test_recovery_restore_evidence_is_redacted(tmp_path):
    b=tmp_path/"b"; r=tmp_path/"r"; b.mkdir(); r.mkdir()
    f=b/"backup.sql.gpg"; f.write_bytes(b"safe")
    Path(str(f)+".sha256").write_text(hashlib.sha256(b"safe").hexdigest()+"  backup.sql.gpg\n")
    (r/"restore.json").write_text(json.dumps({"isolated":True,"success":True,"dbPassword":"x","notes":{"token":"abc","host":"db"}}))
    ctl=RecoveryController(b,r)
    evidence=ctl.restores()[0]["evidence"]
    assert evidence=={"isolated":True,"success":True,"notes":{"host":"db"}}
    assert ctl.status()["state"]=="HEALTHY"
