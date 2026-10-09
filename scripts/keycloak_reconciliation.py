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
CLIENT_ROLE_FIELDS=("clientId","name","description","composite","attributes")
ACTION_FIELDS=("alias","name","enabled","defaultAction","priority","config")
MAPPING_FIELDS=("clientId","fullScopeAllowed","realmRoles","crossFamilyRolesAllowed")
SERVICE_ACCOUNT_FIELDS=("clientId","realmRoles")
PROFILE_FIELDS=("name","displayName","multivalued","permissions","validations","annotations","required","selector","group")
RESOURCE_ORDER=("realm","user_profile_attribute","client_scope","realm_role","client","client_role","scope_mapping","service_account_roles","required_action")
# Keycloak grants every user, service accounts included, the realm's default composite
# role; it is realm configuration, not a grant the service-account declaration manages.
DEFAULT_ROLE_PREFIX="default-roles-"
# Keycloak stores these fields in varchar(255) columns; a longer value fails its write
# with a database error after earlier writes have already landed.
COLUMN_LIMIT=255
COLUMN_FIELDS=("clientId","name","description","rootUrl","baseUrl")
ROW_KEYS={"clients":"clientId","requiredActions":"alias","serviceAccountRoles":"clientId"}
STATE_KEYS=("clients","clientScopes","realmRoles","clientRoles","requiredActions","serviceAccountRoles","userProfileAttributes")
MUTATION_KINDS={"CREATE","UPDATE","DELETE"}
# ERROR marks a managed resource the plan cannot reconcile; it is never applied and
# counts as unconverged, so a plan that carries one is refused before any write.
UNCONVERGED_KINDS=MUTATION_KINDS|{"ERROR"}
INTERNAL_ID_TYPES={"client","client_scope"}
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

def client_role_rows(state:dict[str,Any])->list[dict[str,Any]]:
    """Flatten client roles to one row per role.

    The compiled authority nests roles under their client; a live readback lists
    them flat with the clientId attached. Both shapes compare the same way.
    """
    rows=[]
    for entry in state.get("clientRoles",[]) or []:
        if "roles" in entry:
            for role in entry.get("roles") or []: rows.append({"clientId":entry.get("clientId"),**role})
        else: rows.append(dict(entry))
    return rows

def client_role_key(row:dict[str,Any])->str: return f"{row.get('clientId')}:{row.get('name')}"

def normalize_state(state:dict[str,Any])->dict[str,Any]:
    realm=projection(state.get("realm") or {},REALM_FIELDS)
    return {"realm":realm,"clients":[projection(x,CLIENT_FIELDS) for x in state.get("clients",[])],"clientScopes":[projection(x,SCOPE_FIELDS) for x in state.get("clientScopes",[])],"realmRoles":[projection(x,ROLE_FIELDS) for x in state.get("realmRoles",[])],"clientRoles":[projection(x,CLIENT_ROLE_FIELDS) for x in client_role_rows(state)],"scopeMappings":[_mapping_view(x) for x in state.get("scopeMappings",[])],"serviceAccountRoles":[_service_account_view(x) for x in state.get("serviceAccountRoles",[])],"userProfileAttributes":[projection(x,PROFILE_FIELDS) for x in state.get("userProfileAttributes",[])],"requiredActions":[projection(x,ACTION_FIELDS) for x in state.get("requiredActions",[])]}

def _service_account_view(row:dict[str,Any])->dict[str,Any]:
    return {"clientId":row.get("clientId"),"realmRoles":sorted(str(r) for r in row.get("realmRoles",[]) or [] if not str(r).startswith(DEFAULT_ROLE_PREFIX))}

def _mapping_view(row:dict[str,Any])->dict[str,Any]:
    return {"clientId":row.get("clientId"),"fullScopeAllowed":bool(row.get("fullScopeAllowed",False)),"realmRoles":sorted(str(r) for r in row.get("realmRoles",[]) or []),"crossFamilyRolesAllowed":bool(row.get("crossFamilyRolesAllowed",False))}

def _mappers_view(rows:Any)->list[dict[str,Any]]:
    # Keycloak assigns ids to protocol mappers; identity is the mapper name.
    return sorted(({k:v for k,v in (row or {}).items() if k!="id"} for row in (rows or [])),key=lambda m:str(m.get("name") or ""))

def _mappers_match(want:Any,have:Any)->bool:
    # Keycloak fills in mapper config keys a declaration omits (userinfo.token.claim,
    # introspection.token.claim, ...); only the declared keys are managed.
    w={str(m.get("name")):m for m in _mappers_view(want)}; h={str(m.get("name")):m for m in _mappers_view(have)}
    if set(w)!=set(h): return False
    for name,mapper in w.items():
        live=h[name]
        for key,value in mapper.items():
            if key=="config":
                config=live.get("config") or {}
                # Keycloak also drops empty-string config values when it stores a mapper.
                if any(canonical(config.get(k))!=canonical(v) and not (v=="" and k not in config) for k,v in (value or {}).items()): return False
            elif canonical(live.get(key))!=canonical(value): return False
    return True

# Keycloak attaches this built-in scope to every service-account client by itself.
SERVICE_ACCOUNT_SCOPE="service_account"

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
        # Keycloak omits a false flag such as authorizationServicesEnabled from its representation.
        if want is False and have is None: continue
        if field=="defaultClientScopes" and live_row.get("serviceAccountsEnabled") and SERVICE_ACCOUNT_SCOPE not in (want or []):
            have=[x for x in (have or []) if x!=SERVICE_ACCOUNT_SCOPE]
        if field=="attributes":
            want=want or {}; have=have or {}
            if canonical({k:have.get(k) for k in want})!=canonical(want): return False
        elif field=="protocolMappers":
            if not _mappers_match(want,have): return False
        elif field in UNORDERED_LIST_FIELDS:
            if sorted(str(x) for x in (want or []))!=sorted(str(x) for x in (have or [])): return False
        elif canonical(want)!=canonical(have): return False
    return True

def _plan_collection(actions:list[Action],rtype:str,desired_rows:list[dict[str,Any]],live_rows:list[dict[str,Any]],key:str,fields,managed_ids:set[str]|None=None):
    d=_index(desired_rows,key); l=_index(live_rows,key)
    for rid in sorted(d):
        if rid not in l: actions.append(Action("CREATE",rtype,rid,"missing_live"))
        elif not managed_fields_match(d[rid],l[rid],fields): actions.append(_mutation_or_error("UPDATE",rtype,rid,"managed_fields_drift",l[rid]))
        else: actions.append(Action("KEEP",rtype,rid,"in_sync"))
    for rid in sorted(set(l)-set(d)):
        if managed_ids is not None and rid in managed_ids: actions.append(_mutation_or_error("DELETE",rtype,rid,"managed_resource_removed",l[rid]))
        else: actions.append(Action("KEEP",rtype,rid,"unmanaged_live_resource",False))

def _mutation_or_error(kind:str,rtype:str,rid:str,reason:str,live_row:dict[str,Any])->Action:
    # Keycloak addresses clients and client scopes by internal id; a live row without
    # one cannot be updated or deleted, so the plan reports it instead of failing mid-apply.
    if rtype in INTERNAL_ID_TYPES and not live_row.get("id"): return Action("ERROR",rtype,rid,f"missing_internal_id:{rid}")
    return Action(kind,rtype,rid,reason)

def _plan_client_roles(actions:list[Action],desired:dict[str,Any],live:dict[str,Any],managed_ids:set[str]):
    d={client_role_key(r):r for r in client_role_rows(desired)}; l={client_role_key(r):r for r in client_role_rows(live)}
    known_clients={str(c.get("clientId")) for c in (desired.get("clients") or [])+(live.get("clients") or []) if c.get("clientId")}
    for rid in sorted(d):
        if rid.partition(":")[0] not in known_clients: actions.append(Action("ERROR","client_role",rid,f"client_role_client_missing:{rid}"))
        elif rid not in l: actions.append(Action("CREATE","client_role",rid,"missing_live"))
        elif not managed_fields_match(d[rid],l[rid],CLIENT_ROLE_FIELDS): actions.append(Action("UPDATE","client_role",rid,"managed_fields_drift"))
        else: actions.append(Action("KEEP","client_role",rid,"in_sync"))
    for rid in sorted(set(l)-set(d)):
        if rid in managed_ids: actions.append(Action("DELETE","client_role",rid,"managed_resource_removed"))
        else: actions.append(Action("KEEP","client_role",rid,"unmanaged_live_resource",False))

def _plan_scope_mappings(actions:list[Action],desired:dict[str,Any],live:dict[str,Any]):
    d=_index(desired.get("scopeMappings",[]),"clientId"); l=_index(live.get("scopeMappings",[]),"clientId")
    desired_clients={str(c.get("clientId")) for c in desired.get("clients",[]) if c.get("clientId")}
    live_clients={str(c.get("clientId")) for c in live.get("clients",[]) if c.get("clientId")}
    known_roles={str(r.get("name")) for r in (desired.get("realmRoles") or [])+(live.get("realmRoles") or []) if r.get("name")}
    for rid in sorted(d):
        # A mapping whose client is neither managed here nor present live has no
        # target; it stays unmanaged instead of failing the apply half-way through.
        if rid not in desired_clients and rid not in live_clients and rid not in l:
            actions.append(Action("KEEP","scope_mapping",rid,"scope_mapping_client_not_managed",False)); continue
        if rid in l and canonical(_mapping_view(d[rid]))==canonical(_mapping_view(l[rid])):
            actions.append(Action("KEEP","scope_mapping",rid,"in_sync")); continue
        # Realm roles are created earlier in the same apply, so a role that is neither
        # desired nor live would only fail after those earlier writes.
        missing=sorted(set(str(x) for x in d[rid].get("realmRoles") or [])-known_roles)
        if missing: actions.append(Action("ERROR","scope_mapping",rid,f"scope_mapping_role_missing:{','.join(missing)}"))
        else: actions.append(Action("UPDATE","scope_mapping",rid,"missing_live" if rid not in l else "managed_fields_drift"))
    for rid in sorted(set(l)-set(d)): actions.append(Action("KEEP","scope_mapping",rid,"unmanaged_live_resource",False))

def _plan_service_account_roles(actions:list[Action],desired:dict[str,Any],live:dict[str,Any]):
    d=_index(desired.get("serviceAccountRoles",[]),"clientId"); l=_index(live.get("serviceAccountRoles",[]),"clientId")
    clients={str(c.get("clientId")) for c in (desired.get("clients") or [])+(live.get("clients") or []) if c.get("clientId")}
    known_roles={str(r.get("name")) for r in (desired.get("realmRoles") or [])+(live.get("realmRoles") or []) if r.get("name")}
    for rid in sorted(d):
        if rid not in clients: actions.append(Action("ERROR","service_account_roles",rid,f"service_account_client_missing:{rid}")); continue
        if rid in l and canonical(_service_account_view(d[rid]))==canonical(_service_account_view(l[rid])):
            actions.append(Action("KEEP","service_account_roles",rid,"in_sync")); continue
        missing=sorted(set(_service_account_view(d[rid])["realmRoles"])-known_roles)
        if missing: actions.append(Action("ERROR","service_account_roles",rid,f"service_account_role_missing:{','.join(missing)}"))
        else: actions.append(Action("UPDATE","service_account_roles",rid,"missing_live" if rid not in l else "managed_fields_drift"))
    for rid in sorted(set(l)-set(d)): actions.append(Action("KEEP","service_account_roles",rid,"unmanaged_live_resource",False))

def _plan_required_actions(actions:list[Action],desired_rows:list[dict[str,Any]],live_rows:list[dict[str,Any]],deployed:set[str],managed_ids:set[str]):
    d=_index(desired_rows,"alias"); l=_index(live_rows,"alias")
    for rid in sorted(d):
        if rid in l:
            actions.append(Action("KEEP","required_action",rid,"in_sync") if managed_fields_match(d[rid],l[rid],ACTION_FIELDS) else Action("UPDATE","required_action",rid,"managed_fields_drift"))
        # A deployed provider that the realm has not registered yet can be registered;
        # one the server does not ship at all can never be applied.
        elif rid in deployed: actions.append(Action("CREATE","required_action",rid,"provider_unregistered"))
        else: actions.append(Action("ERROR","required_action",rid,f"required_action_not_registered:{rid}"))
    for rid in sorted(set(l)-set(d)):
        if rid in managed_ids: actions.append(Action("DELETE","required_action",rid,"managed_resource_removed"))
        else: actions.append(Action("KEEP","required_action",rid,"unmanaged_live_resource",False))

def unregistered_providers(state:dict[str,Any])->set[str]:
    return {str(r.get("providerId")) for r in state.get("unregisteredRequiredActions",[]) or [] if r.get("providerId")}

def apply_holds(actions:list[Action],holds:list[dict[str,Any]]|None)->list[Action]:
    """Turn every write or error on an object another writer owns into HOLD.

    In-sync objects stay KEEP so readback still shows them converged; a held object
    is never written, never counted as unconverged and never deleted.
    """
    def owner(a:Action)->str|None: return hold_owner(holds,a.resource_type,a.resource_id)
    return [Action("HOLD",a.resource_type,a.resource_id,f"owned_by:{owner(a)}",False) if a.kind in UNCONVERGED_KINDS and owner(a) else a for a in actions]

def hold_owner(holds:list[dict[str,Any]]|None,resource_type:str,resource_id:str)->str|None:
    owners={}
    for hold in holds or []:
        for rid in hold.get("resourceIds") or []: owners[(str(hold.get("resourceType")),str(rid))]=str(hold.get("owner"))
    return owners.get((resource_type,resource_id)) or owners.get((resource_type,"*"))

def plan(desired:dict[str,Any],live:dict[str,Any],*,managed_inventory:dict[str,list[str]]|None=None,environment:str="unknown",holds:list[dict[str,Any]]|None=None)->dict[str,Any]:
    actions:list[Action]=[]; managed_inventory=managed_inventory or {}
    desired_realm=desired.get("realm") or {}
    live_realm=live.get("realm") or {}
    realm_id=str(desired_realm.get("realm") or "codestra")
    if desired_realm and not live_realm:
        actions.append(Action("CREATE","realm",realm_id,"missing_live"))
    elif canonical(projection(desired_realm,REALM_FIELDS))!=canonical(projection(live_realm,REALM_FIELDS)):
        actions.append(Action("UPDATE","realm",realm_id,"managed_fields_drift"))
    else:
        actions.append(Action("KEEP","realm",realm_id,"in_sync"))
    _plan_collection(actions,"client_scope",desired.get("clientScopes",[]),live.get("clientScopes",[]),"name",SCOPE_FIELDS,set(managed_inventory.get("clientScopes",[])))
    _plan_collection(actions,"realm_role",desired.get("realmRoles",[]),live.get("realmRoles",[]),"name",ROLE_FIELDS,set(managed_inventory.get("realmRoles",[])))
    _plan_collection(actions,"client",desired.get("clients",[]),live.get("clients",[]),"clientId",CLIENT_FIELDS,set(managed_inventory.get("clients",[])))
    _plan_client_roles(actions,desired,live,set(managed_inventory.get("clientRoles",[])))
    _plan_scope_mappings(actions,desired,live)
    _plan_service_account_roles(actions,desired,live)
    if desired.get("userProfileAttributes") is not None:
        _plan_collection(actions,"user_profile_attribute",desired.get("userProfileAttributes",[]),live.get("userProfileAttributes",[]),"name",PROFILE_FIELDS,set(managed_inventory.get("userProfileAttributes",[])))
    if desired.get("requiredActions") is not None:
        _plan_required_actions(actions,desired.get("requiredActions",[]),live.get("requiredActions",[]),unregistered_providers(live),set(managed_inventory.get("requiredActions",[])))
    too_long={}
    for rtype,rows in (("client",[(str(r.get("clientId")),r) for r in desired.get("clients",[])]),("client_scope",[(str(r.get("name")),r) for r in desired.get("clientScopes",[])]),("realm_role",[(str(r.get("name")),r) for r in desired.get("realmRoles",[])]),("client_role",[(client_role_key(r),r) for r in client_role_rows(desired)])):
        for rid,row in rows:
            over=next((f"{f}:{len(row[f])}" for f in COLUMN_FIELDS if isinstance(row.get(f),str) and len(row[f])>COLUMN_LIMIT),None)
            if over: too_long[(rtype,rid)]=over
    actions=[Action("ERROR",a.resource_type,a.resource_id,f"keycloak_column_too_long:{too_long[(a.resource_type,a.resource_id)]}") if a.kind in {"CREATE","UPDATE"} and (a.resource_type,a.resource_id) in too_long else a for a in actions]
    # Deleting a client removes its roles with it; a separate role delete would then
    # fail against a client that no longer exists.
    deleting_clients={a.resource_id for a in actions if a.resource_type=="client" and a.kind=="DELETE"}
    actions=[Action("KEEP",a.resource_type,a.resource_id,"deleted_with_client") if a.resource_type=="client_role" and a.kind=="DELETE" and a.resource_id.partition(":")[0] in deleting_clients else a for a in actions]
    actions=apply_holds(actions,holds)
    actions.sort(key=lambda a:(RESOURCE_ORDER.index(a.resource_type),a.resource_id,a.kind))
    payload={"schema":"codestra.keycloak.reconciliation-plan.v2","environment":environment,"desiredSha256":digest(normalize_state(desired)),"liveSha256":digest(normalize_state(live)),"actions":[a.__dict__ for a in actions],"mutationEnabled":False}
    payload["planSha256"]=digest(payload); return payload

def _rows(state,key):
    if key=="clientRoles": return {client_role_key(r):r for r in client_role_rows(state)}
    return _index(state.get(key,[]),ROW_KEYS.get(key,"name"))

def _role_payload(row:dict[str,Any],*,client_role:bool)->dict[str,Any]:
    payload={k:v for k,v in projection(row,ROLE_FIELDS).items() if v is not None}
    payload["clientRole"]=client_role
    return payload

def plan_integrity_error(plan_doc:dict[str,Any],desired:dict[str,Any],live:dict[str,Any])->str|None:
    """A plan applies only as computed and only to the exact states it was computed from."""
    sealed={k:v for k,v in plan_doc.items() if k!="planSha256"}
    if plan_doc.get("planSha256")!=digest(sealed): return "plan_integrity_mismatch"
    if plan_doc.get("desiredSha256")!=digest(normalize_state(desired)): return "plan_stale_desired_state"
    if plan_doc.get("liveSha256")!=digest(normalize_state(live)): return "plan_stale_live_state"
    return None

def validate_plan(plan_doc:dict[str,Any],desired:dict[str,Any],live:dict[str,Any],*,allow_delete:bool=False)->None:
    """Reject the whole plan before any mutation when one action could not execute."""
    maps={k:_rows(desired,k) for k in STATE_KEYS}
    live_maps={k:_rows(live,k) for k in STATE_KEYS}
    mappings=_index(desired.get("scopeMappings",[]),"clientId")
    for action in plan_doc.get("actions",[]):
        kind=action.get("kind"); rt=action.get("resource_type"); rid=str(action.get("resource_id") or "")
        if kind in {"KEEP","HOLD"}: continue
        if kind=="ERROR": raise RuntimeError(str(action.get("reason") or f"plan_error:{rt}:{rid}"))
        if kind not in MUTATION_KINDS: raise RuntimeError(f"unsupported_action:{kind}")
        if kind=="DELETE" and (not allow_delete or not action.get("managed",False)): raise RuntimeError(f"delete_not_authorized:{rt}:{rid}")
        if rt=="realm":
            if kind not in {"CREATE","UPDATE"} or not desired.get("realm"): raise RuntimeError("unsupported_realm_action")
            if kind=="CREATE" and live.get("realm"): raise RuntimeError("realm_already_exists")
            if kind=="UPDATE" and not live.get("realm"): raise RuntimeError("realm_missing")
        elif rt in COLLECTION_KEYS:
            key=COLLECTION_KEYS[rt]
            if kind in {"CREATE","UPDATE"} and rid not in maps[key]: raise RuntimeError(f"desired_resource_missing:{rt}:{rid}")
            if kind in {"UPDATE","DELETE"}:
                cur=live_maps[key].get(rid)
                if cur is None: raise RuntimeError(f"live_resource_missing:{rt}:{rid}")
                if rt!="realm_role" and not cur.get("id"): raise RuntimeError(f"missing_internal_id:{rid}")
        elif rt=="client_role":
            client_id,sep,name=rid.partition(":")
            if not sep or not client_id or not name: raise RuntimeError(f"invalid_client_role_id:{rid}")
            if kind in {"CREATE","UPDATE"} and rid not in maps["clientRoles"]: raise RuntimeError(f"desired_resource_missing:{rt}:{rid}")
            if kind in {"UPDATE","DELETE"} and rid not in live_maps["clientRoles"]: raise RuntimeError(f"live_resource_missing:{rt}:{rid}")
            # The client is resolved at apply time so a role may follow its client's CREATE,
            # but a role on a client that is neither desired nor live can never be applied.
            if client_id not in maps["clients"] and client_id not in live_maps["clients"]: raise RuntimeError(f"client_role_client_missing:{rid}")
        elif rt=="scope_mapping":
            if kind!="UPDATE": raise RuntimeError(f"unsupported_scope_mapping:{kind}")
            if rid not in mappings: raise RuntimeError(f"scope_mapping_missing:{rid}")
        elif rt=="service_account_roles":
            if kind!="UPDATE": raise RuntimeError(f"unsupported_service_account_roles:{kind}")
            if rid not in maps["serviceAccountRoles"]: raise RuntimeError(f"service_account_roles_missing:{rid}")
        elif rt=="user_profile_attribute":
            if kind in {"CREATE","UPDATE"} and rid not in maps["userProfileAttributes"]: raise RuntimeError(f"desired_resource_missing:{rt}:{rid}")
            if kind in {"UPDATE","DELETE"} and rid not in live_maps["userProfileAttributes"]: raise RuntimeError(f"live_resource_missing:{rt}:{rid}")
        elif rt=="required_action":
            if kind in {"CREATE","UPDATE"} and rid not in maps["requiredActions"]: raise RuntimeError(f"desired_resource_missing:{rt}:{rid}")
            if kind=="CREATE" and live.get("realm") and rid not in unregistered_providers(live): raise RuntimeError(f"required_action_not_registered:{rid}")
            if kind in {"UPDATE","DELETE"} and rid not in live_maps["requiredActions"]: raise RuntimeError(f"live_resource_missing:{rt}:{rid}")
        else: raise RuntimeError(f"unsupported_resource:{rt}")

def apply_plan(plan_doc:dict[str,Any],desired:dict[str,Any],live:dict[str,Any],api,*,enabled:bool=False,allow_delete:bool=False,environment:str|None=None,attribute_removals:dict[str,list[str]]|None=None)->dict[str,Any]:
    if not enabled: raise RuntimeError("apply_disabled")
    env=normalize_environment(environment)
    if not env or env=="unknown": raise RuntimeError("environment_unknown")
    if normalize_environment(plan_doc.get("environment"))!=env: raise RuntimeError("environment_mismatch")
    integrity=plan_integrity_error(plan_doc,desired,live)
    if integrity: return {"schema":"codestra.keycloak.reconciliation-execution.v2","applied":False,"status":"REJECTED","journal":[],"error":integrity}
    try: validate_plan(plan_doc,desired,live,allow_delete=allow_delete)
    except RuntimeError as exc:
        return {"schema":"codestra.keycloak.reconciliation-execution.v2","applied":False,"status":"REJECTED","journal":[],"error":str(exc)}
    maps={k:_rows(desired,k) for k in STATE_KEYS}
    live_maps={k:_rows(live,k) for k in STATE_KEYS}
    journal=[]
    try:
        for action in plan_doc["actions"]:
            kind=action["kind"]; rt=action["resource_type"]; rid=action["resource_id"]
            if kind in {"KEEP","HOLD"}: journal.append({"kind":kind,"resourceType":rt,"resourceId":rid}); continue
            if kind not in MUTATION_KINDS: raise RuntimeError(str(action.get("reason") or f"unsupported_action:{kind}"))
            if kind=="DELETE" and (not allow_delete or not action.get("managed",False)): raise RuntimeError(f"delete_not_authorized:{rt}:{rid}")
            if rt=="realm":
                if kind=="CREATE":
                    api.create_realm(dict(desired["realm"]))
                elif kind=="UPDATE":
                    api.update_realm(projection(desired["realm"],REALM_FIELDS))
                else:
                    raise RuntimeError("unsupported_realm_action")
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
            elif rt=="client_role":
                client_id,_,name=rid.partition(":")
                d=maps["clientRoles"].get(rid); cur=live_maps["clientRoles"].get(rid)
                # The owning client may have been created earlier in this same plan, so its
                # internal id is looked up now rather than taken from the pre-apply live state.
                client=api.client_by_client_id(client_id)
                if not client or not client.get("id"): raise RuntimeError(f"client_role_client_missing:{rid}")
                internal=str(client["id"])
                if kind=="CREATE": api.create_client_role(internal,_role_payload(d,client_role=True))
                elif kind=="UPDATE": api.update_client_role(internal,name,{**{k:v for k,v in (cur or {}).items() if k!="clientId"},**_role_payload(d,client_role=True)})
                elif kind=="DELETE": api.delete_client_role(internal,name)
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
            elif rt=="service_account_roles":
                if kind!="UPDATE": raise RuntimeError(f"unsupported_service_account_roles:{kind}")
                client=api.client_by_client_id(rid)
                if not client or not client.get("id"): raise RuntimeError(f"service_account_client_missing:{rid}")
                user=api.service_account_user(str(client["id"]))
                if not user or not user.get("id"): raise RuntimeError(f"service_account_user_missing:{rid}")
                user_id=str(user["id"])
                existing={r.get("name"):r for r in api.user_realm_role_mappings(user_id) if r.get("name") and not str(r["name"]).startswith(DEFAULT_ROLE_PREFIX)}
                wanted=set(_service_account_view(maps["serviceAccountRoles"][rid])["realmRoles"]); current=set(existing)
                realm_by={r.get("name"):r for r in api.realm_roles() if r.get("name")}
                add=[]
                for name in sorted(wanted-current):
                    role=realm_by.get(name)
                    if not role: raise RuntimeError(f"service_account_role_missing:{name}")
                    add.append(role)
                remove=[existing[name] for name in sorted(current-wanted)]
                if add: api.add_user_realm_role_mappings(user_id,add)
                if remove: api.delete_user_realm_role_mappings(user_id,remove)
            elif rt=="user_profile_attribute":
                config=api.user_profile() or {}
                rows=[dict(a) for a in (config.get("attributes") or [])]
                index=next((i for i,a in enumerate(rows) if a.get("name")==rid),None)
                if kind=="CREATE":
                    if index is not None: raise RuntimeError(f"user_profile_attribute_exists:{rid}")
                    rows.append(dict(maps["userProfileAttributes"][rid]))
                elif index is None: raise RuntimeError(f"live_resource_missing:{rt}:{rid}")
                # A declared attribute is managed whole, so a rollback restores it exactly.
                elif kind=="UPDATE": rows[index]=dict(maps["userProfileAttributes"][rid])
                elif kind=="DELETE": rows.pop(index)
                # Groups and the unmanaged-attribute policy travel back unchanged.
                api.update_user_profile({**config,"attributes":rows})
            elif rt=="required_action":
                if kind=="DELETE": api.delete_required_action(rid)
                else:
                    if kind=="CREATE":
                        provider=next((r for r in live.get("unregisteredRequiredActions",[]) if r.get("providerId")==rid),None)
                        if provider is None:
                            provider=next((r for r in api.unregistered_required_actions() if r.get("providerId")==rid),None)
                        if provider is None: raise RuntimeError(f"required_action_not_registered:{rid}")
                        api.register_required_action({"providerId":rid,"name":provider.get("name") or rid})
                        current=api.required_action(rid)
                    else: current=live_maps["requiredActions"].get(rid)
                    if not current: raise RuntimeError(f"live_resource_missing:{rt}:{rid}")
                    # The Admin API replaces the whole provider record; undeclared fields keep their live values.
                    api.update_required_action(rid,{**current,**{k:v for k,v in maps["requiredActions"][rid].items() if v is not None}})
            else: raise RuntimeError(f"unsupported_resource:{rt}")
            journal.append({"kind":kind,"resourceType":rt,"resourceId":rid})
    except Exception as exc:
        return {"schema":"codestra.keycloak.reconciliation-execution.v2","applied":False,"status":"PARTIAL_FAILURE","journal":journal,"error":str(exc)}
    return {"schema":"codestra.keycloak.reconciliation-execution.v2","journal":journal,"applied":True,"status":"APPLIED"}

def mutation_performed(journal:list[dict[str,Any]]|None)->bool:
    return any(entry.get("kind") in MUTATION_KINDS for entry in journal or [])

def verify_readback(desired:dict[str,Any],live_after:dict[str,Any],*,holds:list[dict[str,Any]]|None=None)->dict[str,Any]:
    # Readback is converged when no managed resource still needs a mutation or cannot be
    # reconciled; live built-ins that desired state never declares are unmanaged.
    expected=normalize_state(desired); actual=normalize_state(live_after)
    pending=[a for a in plan(desired,live_after,holds=holds)["actions"] if a["kind"] in UNCONVERGED_KINDS]
    return {"equal":not pending,"desiredDigest":digest(expected),"liveDigest":digest(actual),"pendingActions":pending}

def created_inventory(journal:list[dict[str,Any]]|None)->dict[str,list[str]]:
    out:dict[str,list[str]]={"clients":[],"clientScopes":[],"realmRoles":[],"clientRoles":[],"userProfileAttributes":[],"requiredActions":[]}
    for entry in journal or []:
        if entry.get("kind")!="CREATE": continue
        rt=str(entry.get("resourceType"))
        if rt in COLLECTION_KEYS: out[COLLECTION_KEYS[rt]].append(str(entry.get("resourceId")))
        elif rt=="client_role": out["clientRoles"].append(str(entry.get("resourceId")))
        elif rt=="user_profile_attribute": out["userProfileAttributes"].append(str(entry.get("resourceId")))
        elif rt=="required_action": out["requiredActions"].append(str(entry.get("resourceId")))
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

def rollback_plan(pre_state:dict[str,Any],current_state:dict[str,Any],*,created_inventory:dict[str,list[str]]|None=None,attribute_removals:dict[str,list[str]]|None=None,environment:str="unknown",holds:list[dict[str,Any]]|None=None)->dict[str,Any]:
    # Only resources the original apply created may be deleted; anything that appeared
    # since is unmanaged and is preserved.
    inventory={k:[str(x) for x in v] for k,v in (created_inventory or {}).items()}
    payload=plan(pre_state,current_state,managed_inventory=inventory,environment=environment,holds=holds)
    live=_rows(current_state,"clients")
    for action in payload["actions"]:
        # Pre-state comparison only sees declared attributes, so an attribute the apply
        # added still needs an UPDATE to be removed.
        rid=action["resource_id"]; extra=(attribute_removals or {}).get(rid,[])
        if action["resource_type"]=="client" and action["kind"]=="KEEP" and action.get("managed",True) and any(k in ((live.get(rid) or {}).get("attributes") or {}) for k in extra):
            owner=hold_owner(holds,"client",rid)
            action.update({"kind":"HOLD","reason":f"owned_by:{owner}","managed":False} if owner else {"kind":"UPDATE","reason":"apply_added_attributes"})
    payload.pop("planSha256",None); payload["planSha256"]=digest(payload); return payload
