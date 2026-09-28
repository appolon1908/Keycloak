#!/usr/bin/env python3
from __future__ import annotations
import hashlib
from dataclasses import dataclass
from typing import Any
from keycloak_identity_compiler import canonical

CLIENT_FIELDS=("clientId","name","description","enabled","protocol","publicClient","bearerOnly","consentRequired","standardFlowEnabled","implicitFlowEnabled","directAccessGrantsEnabled","serviceAccountsEnabled","authorizationServicesEnabled","frontchannelLogout","fullScopeAllowed","rootUrl","baseUrl","redirectUris","webOrigins","defaultClientScopes","optionalClientScopes","attributes","protocolMappers")
REALM_FIELDS=("enabled","sslRequired","verifyEmail","resetPasswordAllowed","bruteForceProtected","accessTokenLifespan")
SCOPE_FIELDS=("name","description","protocol","attributes","protocolMappers")
ROLE_FIELDS=("name","description","composite","attributes")
ACTION_FIELDS=("alias","name","enabled","defaultAction","priority","config")
MAPPING_FIELDS=("clientId","fullScopeAllowed","realmRoles","crossFamilyRolesAllowed")
RESOURCE_ORDER=("realm","client_scope","realm_role","client","scope_mapping","required_action")
MUTATION_KINDS={"CREATE","UPDATE","DELETE"}
UNORDERED_LIST_FIELDS={"redirectUris","webOrigins","defaultClientScopes","optionalClientScopes"}
COLLECTION_KEYS={"client":"clients","client_scope":"clientScopes","realm_role":"realmRoles"}

@dataclass(frozen=True)
class Action:
    kind:str; resource_type:str; resource_id:str; reason:str; managed:bool=True

def digest(value:Any)->str: return hashlib.sha256(canonical(value).encode()).hexdigest()
def projection(value:dict[str,Any],fields)->dict[str,Any]: return {k:value.get(k) for k in fields}
def _index(rows:list[dict[str,Any]],key:str)->dict[str,dict[str,Any]]: return {str(r.get(key)):r for r in rows if r.get(key)}
def normalize_environment(value:Any)->str:
    env=str(value or "").strip().lower().replace("_","-")
    return "test-syn" if env=="testsyn" else env

def normalize_state(state:dict[str,Any])->dict[str,Any]:
    realm=projection(state.get("realm") or {},REALM_FIELDS)
    return {"realm":realm,"clients":[projection(x,CLIENT_FIELDS) for x in state.get("clients",[])],"clientScopes":[projection(x,SCOPE_FIELDS) for x in state.get("clientScopes",[])],"realmRoles":[projection(x,ROLE_FIELDS) for x in state.get("realmRoles",[])],"scopeMappings":[_mapping_view(x) for x in state.get("scopeMappings",[])],"requiredActions":[projection(x,ACTION_FIELDS) for x in state.get("requiredActions",[])]}

def _mapping_view(row:dict[str,Any])->dict[str,Any]:
    return {"clientId":row.get("clientId"),"fullScopeAllowed":bool(row.get("fullScopeAllowed",False)),"realmRoles":sorted(str(r) for r in row.get("realmRoles",[]) or []),"crossFamilyRolesAllowed":bool(row.get("crossFamilyRolesAllowed",False))}

def _mappers_view(rows:Any)->list[dict[str,Any]]:
    # Keycloak assigns ids to protocol mappers; identity is the mapper name.
    return sorted(({k:v for k,v in (row or {}).items() if k!="id"} for row in (rows or [])),key=lambda m:str(m.get("name") or ""))

def managed_fields_match(desired_row:dict[str,Any],live_row:dict[str,Any],fields)->bool:
    """Compare only the fields the desired state manages.

    Keycloak populates server-side attributes (client.secret.creation.time, rotated
    secrets, ...) and mapper ids that desired state never declares; those must not
    read as drift or the apply could never converge.
    """
    for field in fields:
        want=desired_row.get(field); have=live_row.get(field)
        # A field the desired document does not declare is not managed; Keycloak always
        # serialises it, so comparing it (or sending None back) could never converge.
        if want is None: continue
        if field=="attributes":
            want=want or {}; have=have or {}
            if canonical({k:have.get(k) for k in want})!=canonical(want): return False
        elif field=="protocolMappers":
            if canonical(_mappers_view(want))!=canonical(_mappers_view(have)): return False
        elif field in UNORDERED_LIST_FIELDS:
            if sorted(str(x) for x in (want or []))!=sorted(str(x) for x in (have or [])): return False
        elif canonical(want)!=canonical(have): return False
    return True

def _plan_collection(actions:list[Action],rtype:str,desired_rows:list[dict[str,Any]],live_rows:list[dict[str,Any]],key:str,fields,managed_ids:set[str]|None=None):
    d=_index(desired_rows,key); l=_index(live_rows,key)
    for rid in sorted(d):
        if rid not in l: actions.append(Action("CREATE",rtype,rid,"missing_live"))
        elif not managed_fields_match(d[rid],l[rid],fields): actions.append(Action("UPDATE",rtype,rid,"managed_fields_drift"))
        else: actions.append(Action("KEEP",rtype,rid,"in_sync"))
    for rid in sorted(set(l)-set(d)):
        if managed_ids is not None and rid in managed_ids: actions.append(Action("DELETE",rtype,rid,"managed_resource_removed"))
        else: actions.append(Action("KEEP",rtype,rid,"unmanaged_live_resource",False))

def _plan_scope_mappings(actions:list[Action],desired:dict[str,Any],live:dict[str,Any]):
    d=_index(desired.get("scopeMappings",[]),"clientId"); l=_index(live.get("scopeMappings",[]),"clientId")
    desired_clients={str(c.get("clientId")) for c in desired.get("clients",[]) if c.get("clientId")}
    live_clients={str(c.get("clientId")) for c in live.get("clients",[]) if c.get("clientId")}
    for rid in sorted(d):
        # A mapping whose client is neither managed here nor present live has no
        # target; it stays unmanaged instead of failing the apply half-way through.
        if rid not in desired_clients and rid not in live_clients and rid not in l:
            actions.append(Action("KEEP","scope_mapping",rid,"scope_mapping_client_not_managed",False)); continue
        if rid not in l: actions.append(Action("UPDATE","scope_mapping",rid,"missing_live"))
        elif canonical(_mapping_view(d[rid]))!=canonical(_mapping_view(l[rid])): actions.append(Action("UPDATE","scope_mapping",rid,"managed_fields_drift"))
        else: actions.append(Action("KEEP","scope_mapping",rid,"in_sync"))
    for rid in sorted(set(l)-set(d)): actions.append(Action("KEEP","scope_mapping",rid,"unmanaged_live_resource",False))

def plan(desired:dict[str,Any],live:dict[str,Any],*,managed_inventory:dict[str,list[str]]|None=None,environment:str="unknown")->dict[str,Any]:
    actions:list[Action]=[]; managed_inventory=managed_inventory or {}
    if canonical(projection(desired.get("realm") or {},REALM_FIELDS))!=canonical(projection(live.get("realm") or {},REALM_FIELDS)):
        actions.append(Action("UPDATE","realm",str((desired.get("realm") or {}).get("realm") or "codestra"),"managed_fields_drift"))
    else: actions.append(Action("KEEP","realm",str((desired.get("realm") or {}).get("realm") or "codestra"),"in_sync"))
    _plan_collection(actions,"client_scope",desired.get("clientScopes",[]),live.get("clientScopes",[]),"name",SCOPE_FIELDS,set(managed_inventory.get("clientScopes",[])))
    _plan_collection(actions,"realm_role",desired.get("realmRoles",[]),live.get("realmRoles",[]),"name",ROLE_FIELDS,set(managed_inventory.get("realmRoles",[])))
    _plan_collection(actions,"client",desired.get("clients",[]),live.get("clients",[]),"clientId",CLIENT_FIELDS,set(managed_inventory.get("clients",[])))
    _plan_scope_mappings(actions,desired,live)
    if desired.get("requiredActions") is not None:
        _plan_collection(actions,"required_action",desired.get("requiredActions",[]),live.get("requiredActions",[]),"alias",ACTION_FIELDS,set())
    actions.sort(key=lambda a:(RESOURCE_ORDER.index(a.resource_type),a.resource_id,a.kind))
    payload={"schema":"codestra.keycloak.reconciliation-plan.v2","environment":environment,"desiredSha256":digest(normalize_state(desired)),"liveSha256":digest(normalize_state(live)),"actions":[a.__dict__ for a in actions],"mutationEnabled":False}
    payload["planSha256"]=digest(payload); return payload

def _rows(state,key): return _index(state.get(key,[]),"clientId" if key=="clients" else ("alias" if key=="requiredActions" else "name"))

def validate_plan(plan_doc:dict[str,Any],desired:dict[str,Any],live:dict[str,Any],*,allow_delete:bool=False)->None:
    """Reject the whole plan before any mutation when one action could not execute."""
    maps={k:_rows(desired,k) for k in ("clients","clientScopes","realmRoles","requiredActions")}
    live_maps={k:_rows(live,k) for k in ("clients","clientScopes","realmRoles","requiredActions")}
    mappings=_index(desired.get("scopeMappings",[]),"clientId")
    for action in plan_doc.get("actions",[]):
        kind=action.get("kind"); rt=action.get("resource_type"); rid=str(action.get("resource_id") or "")
        if kind=="KEEP": continue
        if kind not in MUTATION_KINDS: raise RuntimeError(f"unsupported_action:{kind}")
        if kind=="DELETE" and (not allow_delete or not action.get("managed",False)): raise RuntimeError(f"delete_not_authorized:{rt}:{rid}")
        if rt=="realm":
            if kind!="UPDATE" or not desired.get("realm"): raise RuntimeError("unsupported_realm_action")
        elif rt in COLLECTION_KEYS:
            key=COLLECTION_KEYS[rt]
            if kind in {"CREATE","UPDATE"} and rid not in maps[key]: raise RuntimeError(f"desired_resource_missing:{rt}:{rid}")
            if kind in {"UPDATE","DELETE"}:
                cur=live_maps[key].get(rid)
                if cur is None: raise RuntimeError(f"live_resource_missing:{rt}:{rid}")
                if rt!="realm_role" and not cur.get("id"): raise RuntimeError(f"missing_internal_id:{rid}")
        elif rt=="scope_mapping":
            if kind!="UPDATE": raise RuntimeError(f"unsupported_scope_mapping:{kind}")
            if rid not in mappings: raise RuntimeError(f"scope_mapping_missing:{rid}")
        elif rt=="required_action":
            if kind!="UPDATE" or rid not in maps["requiredActions"]: raise RuntimeError(f"unsupported_required_action:{kind}")
        else: raise RuntimeError(f"unsupported_resource:{rt}")

def apply_plan(plan_doc:dict[str,Any],desired:dict[str,Any],live:dict[str,Any],api,*,enabled:bool=False,allow_delete:bool=False,environment:str|None=None,attribute_removals:dict[str,list[str]]|None=None)->dict[str,Any]:
    if not enabled: raise RuntimeError("apply_disabled")
    env=normalize_environment(environment)
    if not env or env=="unknown": raise RuntimeError("environment_unknown")
    if normalize_environment(plan_doc.get("environment"))!=env: raise RuntimeError("environment_mismatch")
    try: validate_plan(plan_doc,desired,live,allow_delete=allow_delete)
    except RuntimeError as exc:
        return {"schema":"codestra.keycloak.reconciliation-execution.v2","applied":False,"status":"REJECTED","journal":[],"error":str(exc)}
    maps={k:_rows(desired,k) for k in ("clients","clientScopes","realmRoles","requiredActions")}
    live_maps={k:_rows(live,k) for k in ("clients","clientScopes","realmRoles","requiredActions")}
    journal=[]
    try:
        for action in plan_doc["actions"]:
            kind=action["kind"]; rt=action["resource_type"]; rid=action["resource_id"]
            if kind=="KEEP": journal.append({"kind":kind,"resourceType":rt,"resourceId":rid}); continue
            if kind=="DELETE" and (not allow_delete or not action.get("managed",False)): raise RuntimeError(f"delete_not_authorized:{rt}:{rid}")
            if rt=="realm":
                if kind!="UPDATE": raise RuntimeError("unsupported_realm_action")
                api.update_realm(projection(desired["realm"],REALM_FIELDS))
            elif rt=="client":
                d=maps["clients"].get(rid); cur=live_maps["clients"].get(rid)
                if kind=="CREATE": api.create_client(d)
                elif kind=="UPDATE":
                    internal=str((cur or {}).get("id") or "")
                    if not internal: raise RuntimeError(f"missing_internal_id:{rid}")
                    merged=dict(cur); merged.update({k:v for k,v in projection(d,CLIENT_FIELDS).items() if v is not None})
                    # Server-populated attributes that desired state does not declare are preserved;
                    # a rollback names the attributes its apply added so they can be removed again.
                    attributes={**(cur.get("attributes") or {}),**(d.get("attributes") or {})}
                    for key in (attribute_removals or {}).get(rid,[]): attributes.pop(key,None)
                    merged["attributes"]=attributes
                    api.update_client(internal,merged)
                elif kind=="DELETE":
                    internal=str((cur or {}).get("id") or "")
                    if not internal: raise RuntimeError(f"missing_internal_id:{rid}")
                    api.delete_client(internal)
            elif rt=="client_scope":
                d=maps["clientScopes"].get(rid); cur=live_maps["clientScopes"].get(rid)
                if kind=="CREATE": api.create_client_scope(d)
                elif kind=="UPDATE": api.update_client_scope(str((cur or {}).get("id") or ""),d)
                elif kind=="DELETE": api.delete_client_scope(str((cur or {}).get("id") or ""))
            elif rt=="realm_role":
                d=maps["realmRoles"].get(rid)
                if kind=="CREATE": api.create_realm_role(d)
                elif kind=="UPDATE": api.update_realm_role(rid,d)
                elif kind=="DELETE": api.delete_realm_role(rid)
            elif rt=="scope_mapping":
                if kind!="UPDATE": raise RuntimeError(f"unsupported_scope_mapping:{kind}")
                mapping=next((x for x in desired.get("scopeMappings",[]) if x.get("clientId")==rid),None)
                client=api.client_by_client_id(rid)
                if not mapping or not client or not client.get("id"): raise RuntimeError(f"scope_mapping_client_missing:{rid}")
                existing=api.client_realm_role_mappings(str(client["id"]))
                existing_by={r.get("name"):r for r in existing if r.get("name")}
                wanted=set(mapping.get("realmRoles",[])); current=set(existing_by)
                realm_by={r.get("name"):r for r in api.realm_roles() if r.get("name")}
                add=[]
                for name in sorted(wanted-current):
                    role=realm_by.get(name)
                    if not role: raise RuntimeError(f"scope_mapping_role_missing:{name}")
                    add.append(role)
                remove=[existing_by[name] for name in sorted(current-wanted)]
                if add: api.add_client_realm_role_mappings(str(client["id"]),add)
                if remove: api.delete_client_realm_role_mappings(str(client["id"]),remove)
            elif rt=="required_action":
                if kind!="UPDATE": raise RuntimeError(f"unsupported_required_action:{kind}")
                api.update_required_action(rid,maps["requiredActions"][rid])
            else: raise RuntimeError(f"unsupported_resource:{rt}")
            journal.append({"kind":kind,"resourceType":rt,"resourceId":rid})
    except Exception as exc:
        return {"schema":"codestra.keycloak.reconciliation-execution.v2","applied":False,"status":"PARTIAL_FAILURE","journal":journal,"error":str(exc)}
    return {"schema":"codestra.keycloak.reconciliation-execution.v2","journal":journal,"applied":True,"status":"APPLIED"}

def mutation_performed(journal:list[dict[str,Any]]|None)->bool:
    return any(entry.get("kind") in MUTATION_KINDS for entry in journal or [])

def verify_readback(desired:dict[str,Any],live_after:dict[str,Any])->dict[str,Any]:
    # Readback is converged when no managed resource still needs a mutation; live
    # built-ins that desired state never declares are unmanaged and do not count.
    expected=normalize_state(desired); actual=normalize_state(live_after)
    pending=[a for a in plan(desired,live_after)["actions"] if a["kind"] in MUTATION_KINDS]
    return {"equal":not pending,"desiredDigest":digest(expected),"liveDigest":digest(actual),"pendingActions":pending}

def created_inventory(journal:list[dict[str,Any]]|None)->dict[str,list[str]]:
    out:dict[str,list[str]]={"clients":[],"clientScopes":[],"realmRoles":[]}
    for entry in journal or []:
        if entry.get("kind")=="CREATE" and entry.get("resourceType") in COLLECTION_KEYS:
            out[COLLECTION_KEYS[str(entry["resourceType"])]].append(str(entry.get("resourceId")))
    return out

def rollback_attribute_removals(pre_state:dict[str,Any],desired:dict[str,Any],journal:list[dict[str,Any]]|None)->dict[str,list[str]]:
    # Attributes the apply introduced on an updated client are absent from the pre-state
    # and present in the desired document; restoring the pre-state must drop them.
    pre=_rows(pre_state,"clients"); want=_rows(desired,"clients"); out:dict[str,list[str]]={}
    for entry in journal or []:
        if entry.get("kind")!="UPDATE" or entry.get("resourceType")!="client": continue
        rid=str(entry.get("resourceId")); before=(pre.get(rid) or {}).get("attributes") or {}; after=(want.get(rid) or {}).get("attributes") or {}
        removals=sorted(k for k in after if k not in before)
        if removals: out[rid]=removals
    return out

def rollback_plan(pre_state:dict[str,Any],current_state:dict[str,Any],*,created_inventory:dict[str,list[str]]|None=None,attribute_removals:dict[str,list[str]]|None=None,environment:str="unknown")->dict[str,Any]:
    # Only resources the original apply created may be deleted; anything that appeared
    # since is unmanaged and is preserved.
    inventory={k:[str(x) for x in v] for k,v in (created_inventory or {}).items()}
    payload=plan(pre_state,current_state,managed_inventory=inventory,environment=environment)
    live=_rows(current_state,"clients")
    for action in payload["actions"]:
        # Pre-state comparison only sees declared attributes, so an attribute the apply
        # added still needs an UPDATE to be removed.
        rid=action["resource_id"]; extra=(attribute_removals or {}).get(rid,[])
        if action["resource_type"]=="client" and action["kind"]=="KEEP" and action.get("managed",True) and any(k in ((live.get(rid) or {}).get("attributes") or {}) for k in extra):
            action.update({"kind":"UPDATE","reason":"apply_added_attributes"})
    payload.pop("planSha256",None); payload["planSha256"]=digest(payload); return payload
