#!/usr/bin/env python3
from __future__ import annotations
import argparse, json, os, sys, threading, uuid
from pathlib import Path
from urllib.parse import parse_qs,urlsplit
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from keycloak_admin_api import KeycloakAdminAPI,KeycloakAdminError
from keycloak_identity_compiler import OUT as GENERATED_AUTHORITY,compile_identity,scoped_for_environment
from keycloak_reconciliation import DEFAULT_ROLE_PREFIX,plan,apply_plan,verify_readback,rollback_plan,rollback_attribute_removals,created_inventory,mutation_performed,normalize_environment,digest
from keycloak_execution_store import EvidenceStore,EvidenceStoreError,redact_secret_material
from keycloak_recovery_controller import RecoveryController
from keycloak_observability import normalize_events,metrics as event_metrics,status as observability_status,ObservabilityError
from keycloak_environment_promotion import POLICY as PROMOTION_POLICY,promotion_plan

HOST="127.0.0.1"
PORT=8785
MUTATION_ENVIRONMENTS={"production","staging","test-syn"}
IN_FLIGHT_STATUSES={"IN_PROGRESS","APPLIED_PENDING_READBACK"}
READBACK_FAILURE_STATUSES={"READBACK_MISMATCH","READBACK_UNAVAILABLE"}

def _flag(name:str)->bool: return os.environ.get(name,"").strip().lower()=="true"

def _service_account_roles(api,client_internal_id):
    try: user=api.service_account_user(client_internal_id)
    except KeycloakAdminError as exc:
        # A client whose service account does not exist yet has no grants to read.
        if exc.status==404: return None
        raise
    if not user or not user.get("id"): return None
    return sorted(str(r["name"]) for r in api.user_realm_role_mappings(str(user["id"])) if r.get("name") and not str(r["name"]).startswith(DEFAULT_ROLE_PREFIX))

class Service:
    def __init__(self,store=None):
        root=Path(os.environ.get("KEYCLOAK_CONTROL_EVIDENCE_DIR","/tmp/codestra-keycloak-control"))
        self.store=store or EvidenceStore(root)
        self._lock=threading.Lock()

    def desired(self): return compile_identity()
    def environment(self):
        return normalize_environment(os.environ.get("KEYCLOAK_ENVIRONMENT")) or "unknown"
    def _api(self):
        base=os.environ.get("KEYCLOAK_ADMIN_BASE_URL",""); token=os.environ.get("KEYCLOAK_ADMIN_BEARER","")
        if not base or not token: raise KeycloakAdminError("admin_not_configured","admin readback is not configured")
        return KeycloakAdminAPI(base,"codestra",token)
    def live(self):
        api=self._api()
        clients=api.clients()
        mappings=[]; client_roles=[]; service_roles=[]
        desired=self.desired()
        desired_ids={x.get("clientId") for x in desired.get("scopeMappings",[])}
        role_clients={str(x.get("clientId")) for x in desired.get("clientRoles",[])}
        service_clients={str(x.get("clientId")) for x in desired.get("serviceAccountRoles",[])}
        for client in clients:
            if not client.get("id"): continue
            if client.get("clientId") in desired_ids:
                roles=api.client_realm_role_mappings(str(client["id"]))
                mappings.append({"clientId":client["clientId"],"fullScopeAllowed":bool(client.get("fullScopeAllowed",False)),"realmRoles":sorted(r.get("name") for r in roles if r.get("name")),"crossFamilyRolesAllowed":False})
            # Client roles are read only for clients that declare them; the roles of every
            # other client stay unmanaged and never enter a plan.
            if client.get("clientId") in role_clients:
                for role in api.client_roles(str(client["id"])): client_roles.append({"clientId":client["clientId"],**role})
            # Service-account grants are read only for declared service clients, like scope mappings.
            if client.get("clientId") in service_clients and client.get("serviceAccountsEnabled"):
                roles=_service_account_roles(api,str(client["id"]))
                if roles is not None: service_roles.append({"clientId":client["clientId"],"realmRoles":roles})
        # The whole user profile is read so a rollback can restore any attribute an apply touched.
        profile=api.user_profile() or {}
        return {"realm":api.realm_state(),"clients":clients,"clientScopes":api.client_scopes(),"realmRoles":api.realm_roles(),"clientRoles":client_roles,"scopeMappings":mappings,"serviceAccountRoles":service_roles,"userProfileAttributes":list(profile.get("attributes") or []),"requiredActions":api.required_actions()}
    def scoped_desired(self,environment=None):
        # Only the desired state that may live in this environment is planned; a scoped
        # client (klyrow-staging-portal) never reaches a production or TEST_SYN plan.
        return scoped_for_environment(self.desired(),environment if environment is not None else self.environment())
    def drift(self):
        env=self.environment(); return plan(self.scoped_desired(env),self.live(),environment=env)
    def compile(self):
        # Compilation over HTTP is read-only: it reports drift against the checked-in
        # authority but never rewrites repository files.
        model=compile_identity(); text=json.dumps(model,indent=2,sort_keys=True,ensure_ascii=False)+"\n"
        drift=(not GENERATED_AUTHORITY.exists()) or GENERATED_AUTHORITY.read_text(encoding="utf-8")!=text
        return {"compiled":True,"generatedDrift":drift,"identity":model}
    def validate(self):
        d=compile_identity()
        return {"valid":True,"clients":len(d["clients"]),"scopes":len(d["clientScopes"]),"clientRoles":sum(len(e["roles"]) for e in d.get("clientRoles",[])),"environmentScopedClients":sorted(d.get("environmentScopes",{}))}

    def dry_run(self,idempotency_key=None):
        result=self.drift(); key=idempotency_key or result["planSha256"]
        record={"executionId":str(uuid.uuid4()),"idempotencyKey":key,"mode":"DRY_RUN","status":"COMPLETED","mutationPerformed":False,"desiredStateDigest":result["desiredSha256"],"preStateDigest":result["liveSha256"],"resultDigest":digest(result),"plan":result}
        self.store.put("executions",record["executionId"],record); return record

    def _require_mutation_enabled(self):
        if not _flag("KEYCLOAK_MUTATION_ENABLED"): raise KeycloakAdminError("apply_disabled","live apply is disabled by default",403)

    def _mutation_environment(self,desired):
        env=self.environment()
        if env not in MUTATION_ENVIRONMENTS: raise KeycloakAdminError("environment_unknown","KEYCLOAK_ENVIRONMENT must name production, staging or test-syn before live mutation",409)
        admin_host=(urlsplit(os.environ.get("KEYCLOAK_ADMIN_BASE_URL","")).hostname or "").lower()
        issuer_hosts={}
        for name,value in (desired.get("environmentBoundaries") or {}).items():
            issuer=value.get("issuer") if isinstance(value,dict) else None
            if issuer: issuer_hosts[normalize_environment(name)]=(urlsplit(str(issuer)).hostname or "").lower()
        expected=issuer_hosts.get(env)
        # The admin endpoint must belong to the environment being mutated: production and
        # staging bind to their issuer host, and TEST_SYN may never target either of them.
        if expected and admin_host!=expected: raise KeycloakAdminError("environment_issuer_mismatch","admin API host does not match the target environment issuer",409)
        if not expected and admin_host in set(issuer_hosts.values()): raise KeycloakAdminError("environment_issuer_mismatch","test-syn mutation cannot target a production or staging issuer",409)
        return env

    def apply(self,idempotency_key):
        self._require_mutation_enabled()
        if not idempotency_key: raise KeycloakAdminError("idempotency_key_required","X-Idempotency-Key is required",400)
        with self._lock:
            for row in self.store.list("executions"):
                old=row["payload"]
                if old.get("idempotencyKey")!=idempotency_key or old.get("mode")!="APPLY": continue
                if old.get("status") in IN_FLIGHT_STATUSES: raise KeycloakAdminError("apply_in_progress","an apply with this idempotency key has not finalized; inspect its evidence before retrying",409)
                return old
            desired=self.desired(); env=self._mutation_environment(desired); api=self._api()
            desired=scoped_for_environment(desired,env)
            pre=self.live(); p=plan(desired,pre,environment=env)
            execution_id=str(uuid.uuid4()); pre_state,redacted=redact_secret_material(pre)
            record={"executionId":execution_id,"idempotencyKey":idempotency_key,"mode":"APPLY","environment":env,"status":"IN_PROGRESS","mutationPerformed":False,"desiredStateDigest":p["desiredSha256"],"preStateDigest":p["liveSha256"],"plan":p,"actionJournal":[],"preState":pre_state,"preStateRedactedPaths":redacted,"rollbackStatus":"NOT_RUN"}
            # Evidence is durable before the first mutation; if it cannot be written nothing is applied.
            self.store.put("executions",execution_id,record)
            try: outcome=apply_plan(p,desired,pre,api,enabled=True,allow_delete=_flag("KEYCLOAK_DELETE_ENABLED"),environment=env)
            except Exception as exc:
                record.update({"status":"FAILED","error":str(exc)}); self.store.put("executions",execution_id,record,replace=True); raise
            journal=outcome.get("journal",[])
            # The attributes this apply introduced are evidence: a later rollback must not
            # infer them from a desired state that may have changed since.
            record.update({"actionJournal":journal,"mutationPerformed":mutation_performed(journal),"attributeAdditions":rollback_attribute_removals(pre,desired,journal),"error":outcome.get("error"),"readback":None,"resultDigest":p["liveSha256"]})
            if outcome.get("status")=="REJECTED":
                record["status"]="REJECTED"
            else:
                # The journal is durable before readback, so a readback failure can never hide what was applied.
                record["status"]="APPLIED_PENDING_READBACK"; self.store.put("executions",execution_id,record,replace=True)
                try: post=self.live(); readback=verify_readback(desired,post); result_digest=digest(post)
                except KeycloakAdminError as exc:
                    record.update({"status":"READBACK_UNAVAILABLE","error":exc.code})
                else:
                    status="COMPLETED" if outcome.get("applied") and readback["equal"] else ("READBACK_MISMATCH" if outcome.get("applied") else "PARTIAL_FAILURE")
                    record.update({"status":status,"resultDigest":result_digest,"readback":readback})
            self.store.put("executions",execution_id,record,replace=True); return record

    def rollback(self,execution_id):
        self._require_mutation_enabled()
        with self._lock:
            original=self.execution(execution_id)
            if original.get("mode")!="APPLY" or not original.get("preState"): raise KeycloakAdminError("rollback_not_available","rollback evidence is not available",409)
            if original.get("rollbackStatus")=="ROLLED_BACK": raise KeycloakAdminError("rollback_already_applied","this execution was already rolled back",409)
            if original.get("status")=="IN_PROGRESS": raise KeycloakAdminError("rollback_not_available","the apply never journaled its actions; inspect live state manually",409)
            desired=self.desired(); env=self._mutation_environment(desired); desired=scoped_for_environment(desired,env)
            if normalize_environment(original.get("environment"))!=env: raise KeycloakAdminError("environment_mismatch","rollback must run in the environment the apply targeted",409)
            api=self._api(); current=self.live(); pre=original["preState"]; journal_before=original.get("actionJournal")
            removals=original.get("attributeAdditions")
            if removals is None: removals=rollback_attribute_removals(pre,desired,journal_before)
            p=rollback_plan(pre,current,created_inventory=created_inventory(journal_before),attribute_removals=removals,environment=env)
            rollback_id=str(uuid.uuid4())
            record={"executionId":rollback_id,"mode":"ROLLBACK","sourceExecutionId":execution_id,"environment":env,"status":"IN_PROGRESS","mutationPerformed":False,"targetStateDigest":p["desiredSha256"],"preStateDigest":p["liveSha256"],"plan":p,"attributeRemovals":removals,"actionJournal":[],"readback":None,"error":None}
            # The rollback plan is durable before the first mutation, exactly like an apply.
            self.store.put("rollbacks",rollback_id,record)
            try: outcome=apply_plan(p,pre,current,api,enabled=True,allow_delete=True,environment=env,attribute_removals=removals)
            except Exception as exc:
                record.update({"status":"FAILED","error":str(exc)}); self.store.put("rollbacks",rollback_id,record,replace=True); raise
            journal=outcome.get("journal",[])
            record.update({"status":"APPLIED_PENDING_READBACK","actionJournal":journal,"mutationPerformed":mutation_performed(journal),"error":outcome.get("error")})
            self.store.put("rollbacks",rollback_id,record,replace=True)
            try: after=self.live(); check=verify_readback(pre,after)
            except KeycloakAdminError as exc:
                record.update({"status":"READBACK_UNAVAILABLE","error":exc.code})
            else:
                record.update({"status":"COMPLETED" if outcome.get("applied") and check["equal"] else "ROLLBACK_FAILED","readback":check})
            self.store.put("rollbacks",rollback_id,record,replace=True)
            # Only a read-back restore counts as rolled back; anything else leaves the apply eligible for another attempt.
            original["rollbackStatus"]="ROLLED_BACK" if record["status"]=="COMPLETED" else "ROLLBACK_FAILED"; original["rollbackExecutionId"]=rollback_id
            self.store.put("executions",execution_id,original,replace=True)
            return record

    def execution(self,execution_id):
        try: return self.store.get("executions",execution_id)["payload"]
        except EvidenceStoreError as exc:
            raise KeycloakAdminError("execution_not_found","reconciliation execution not found",404) from exc
    def evidence(self,execution_id):
        try: return self.store.get("executions",execution_id)
        except EvidenceStoreError as exc:
            raise KeycloakAdminError("execution_not_found","reconciliation execution not found",404) from exc
    def rollback_evidence(self,rollback_id):
        try: return self.store.get("rollbacks",rollback_id)
        except EvidenceStoreError as exc:
            raise KeycloakAdminError("rollback_not_found","rollback execution not found",404) from exc

    def recovery(self):
        return RecoveryController(os.environ.get("KEYCLOAK_BACKUP_DIR","/var/backups/keycloak"),os.environ.get("KEYCLOAK_RESTORE_EVIDENCE_DIR","/var/lib/keycloak/recovery-evidence"))
    def recovery_validate(self):
        result=self.recovery().validate(); rid=str(uuid.uuid4()); self.store.put("recovery",rid,result); return {"validationId":rid,**result}

    def observability_status(self): return observability_status(self.scoped_desired(),self.live())
    def events(self,limit=100):
        api=self._api(); raw=api.events(max_results=limit)
        return normalize_events([{"event_id":e.get("id"),"timestamp":e.get("time"),"event_type":e.get("type"),"outcome":"ERROR" if str(e.get("type","")).endswith("_ERROR") else "SUCCESS","realm":"codestra","client_id":e.get("clientId"),"subject_ref":e.get("userId")} for e in raw],limit=limit)
    def readback_failures(self):
        # Applies whose readback mismatched or never ran are durable evidence, so the count is exact.
        return sum(1 for row in self.store.list("executions") if row["payload"].get("mode")=="APPLY" and row["payload"].get("status") in READBACK_FAILURE_STATUSES)
    def metrics(self,limit=100):
        events=self.events(limit); st=self.observability_status()
        return event_metrics(events,configuration_drift=st["configurationDrift"],readback_failures=self.readback_failures())

    def promotion(self,body):
        result=promotion_plan(self.desired(),body); self.store.put("promotions",result["promotionId"],result); return result
    def promotion_get(self,pid):
        try:return self.store.get("promotions",pid)["payload"]
        except EvidenceStoreError as exc: raise KeycloakAdminError("promotion_not_found","promotion plan not found",404) from exc
    def health(self): return {"service":"keycloak-control-api","status":"ok","applyEnabled":_flag("KEYCLOAK_MUTATION_ENABLED"),"environment":self.environment()}

class Handler(BaseHTTPRequestHandler):
    service=Service()

    def log_message(self,*_):
        return

    def rid(self):
        return (self.headers.get("X-Correlation-ID") or str(uuid.uuid4()))[:128]

    def send_json(self,status:int,body:dict,rid:str):
        raw=json.dumps(body,sort_keys=True,separators=(",",":")).encode()
        self.send_response(status)
        self.send_header("Content-Type","application/json; charset=utf-8")
        self.send_header("Content-Length",str(len(raw)))
        self.send_header("Cache-Control","no-store")
        self.send_header("X-Correlation-ID",rid)
        self.send_header("X-Content-Type-Options","nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def body(self,max_bytes=65536):
        try: length=int(self.headers.get("Content-Length") or "0")
        except ValueError as exc: raise KeycloakAdminError("invalid_request","Content-Length must be an integer",400) from exc
        if length<0 or length>max_bytes: raise KeycloakAdminError("request_too_large","request body exceeds limit",413)
        if not length:return {}
        try:value=json.loads(self.rfile.read(length))
        except Exception as exc: raise KeycloakAdminError("invalid_json","request body must be valid JSON",400) from exc
        if not isinstance(value,dict): raise KeycloakAdminError("invalid_request","request body must be an object",400)
        return value

    def bounded_int(self,query,name,default,minimum,maximum):
        raw=query.get(name,[str(default)])[0]
        try:value=int(raw)
        except (TypeError,ValueError) as exc: raise KeycloakAdminError("invalid_query",f"{name} must be an integer",400) from exc
        if value<minimum or value>maximum: raise KeycloakAdminError("invalid_query",f"{name} must be between {minimum} and {maximum}",400)
        return value

    def runfn(self,fn):
        rid=self.rid()
        try:
            result=fn()
        except KeycloakAdminError as exc:
            status=exc.status if exc.status and 400 <= exc.status < 600 else 503
            return self.send_json(status,{"ok":False,"error":{"code":exc.code,"message":str(exc)}},rid)
        except Exception as exc:
            # The response stays generic; the operator log carries the class and message keyed by correlation id.
            sys.stderr.write(f"keycloak-control-api correlation_id={rid.replace(chr(13),' ').replace(chr(10),' ')} error={type(exc).__name__}: {exc}\n")
            return self.send_json(500,{"ok":False,"error":{"code":"internal_error","message":"control operation failed"}},rid)
        self.send_json(200,{"ok":True,**result},rid)

    def do_GET(self):
        u=urlsplit(self.path); p=u.path; q=parse_qs(u.query)
        if p=="/platform/v1/keycloak/desired-state": return self.runfn(lambda:{"desired":self.service.desired()})
        if p=="/platform/v1/keycloak/drift": return self.runfn(lambda:{"plan":self.service.drift()})
        if p=="/platform/v1/keycloak/recovery/status": return self.runfn(lambda:{"recovery":self.service.recovery().status()})
        if p=="/platform/v1/keycloak/recovery/backups": return self.runfn(lambda:{"backups":self.service.recovery().backups()})
        if p=="/platform/v1/keycloak/recovery/restores": return self.runfn(lambda:{"restores":self.service.recovery().restores()})
        if p=="/platform/v1/keycloak/observability/status": return self.runfn(lambda:{"observability":self.service.observability_status()})
        if p=="/platform/v1/keycloak/observability/events":
            return self.runfn(lambda:{"events":self.service.events(self.bounded_int(q,"limit",100,1,500))})
        if p=="/platform/v1/keycloak/observability/metrics": return self.runfn(lambda:{"metrics":self.service.metrics(self.bounded_int(q,"limit",100,1,500))})
        if p=="/platform/v1/keycloak/promotion/policy": return self.runfn(lambda:{"policy":PROMOTION_POLICY})
        if p.startswith("/platform/v1/keycloak/promotion/plans/"): return self.runfn(lambda:{"promotion":self.service.promotion_get(p.rsplit("/",1)[-1])})
        if p.startswith("/platform/v1/keycloak/reconcile/rollbacks/"):
            return self.runfn(lambda:{"evidence":self.service.rollback_evidence(p.rsplit("/",1)[-1])})
        if p.startswith("/platform/v1/keycloak/reconcile/executions/"):
            evidence=p.endswith("/evidence"); eid=p.split("/reconcile/executions/",1)[1].split("/",1)[0]
            return self.runfn(lambda:{"evidence":self.service.evidence(eid)} if evidence else {"execution":self.service.execution(eid)})
        if p in {"/platform/v1/keycloak/health","/health"}: return self.runfn(self.service.health)
        self.send_json(404,{"ok":False,"error":{"code":"not_found","message":"route not found"}},self.rid())

    def do_POST(self):
        p=urlsplit(self.path).path
        if p=="/platform/v1/keycloak/compile": return self.runfn(self.service.compile)
        if p=="/platform/v1/keycloak/validate": return self.runfn(self.service.validate)
        if p=="/platform/v1/keycloak/reconcile/dry-run": return self.runfn(lambda:{"execution":self.service.dry_run(self.headers.get("X-Idempotency-Key"))})
        if p=="/platform/v1/keycloak/reconcile/apply": return self.runfn(lambda:{"execution":self.service.apply(self.headers.get("X-Idempotency-Key"))})
        if p=="/platform/v1/keycloak/reconcile/rollback": return self.runfn(lambda:{"rollback":self.service.rollback(str(self.body().get("executionId") or ""))})
        if p=="/platform/v1/keycloak/recovery/validate": return self.runfn(lambda:{"validation":self.service.recovery_validate()})
        if p=="/platform/v1/keycloak/promotion/plan": return self.runfn(lambda:{"promotion":self.service.promotion(self.body())})
        self.send_json(404,{"ok":False,"error":{"code":"not_found","message":"route not found"}},self.rid())

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument("--host",default=HOST)
    ap.add_argument("--port",type=int,default=PORT)
    a=ap.parse_args()
    if a.host not in {"127.0.0.1","::1","localhost"}:
        raise SystemExit("refusing non-loopback bind")
    ThreadingHTTPServer((a.host,a.port),Handler).serve_forever()

if __name__=="__main__":
    main()
