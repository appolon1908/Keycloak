#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, uuid
from typing import Any
from keycloak_identity_compiler import canonical
from keycloak_reconciliation import normalize_environment
POLICY={"schema":"codestra.keycloak.promotion-policy.v1","testSynProductionBlocked":True,"explicitTargetMappingRequired":True,"targetIssuerBindingRequired":True,"weakenProductionPolicyBlocked":True}
COMPARE=("redirectUris","webOrigins","defaultClientScopes","optionalClientScopes","protocolMappers","serviceAccountsEnabled","publicClient","directAccessGrantsEnabled")
ENVIRONMENTS={"production","staging","test-syn"}
DEFAULT_BOUNDARIES={"production":{"issuer":"https://auth.codestra.co/realms/codestra"},"staging":{"issuer":"https://auth-staging.codestra.co/realms/codestra"},"testSyn":{"namingPrefix":"test-syn-","productionPromotion":False}}
def _sha(v:Any)->str: return hashlib.sha256(canonical(v).encode()).hexdigest()
def promotion_plan(desired:dict[str,Any],request:dict[str,Any],protected:dict[str,Any]|None=None)->dict[str,Any]:
    source=str(request.get("sourceAuthorityGroup") or ""); target=normalize_environment(request.get("targetEnvironment"))
    boundaries={**DEFAULT_BOUNDARIES,**{k:v for k,v in (desired.get("environmentBoundaries") or {}).items() if isinstance(v,dict)}}
    prefix=str((boundaries.get("testSyn") or {}).get("namingPrefix") or "test-syn-")
    mapping=request.get("targetMapping"); issuer=request.get("targetIssuer")
    blockers=[]; candidates=[]
    if target not in ENVIRONMENTS: blockers.append("target_environment_invalid")
    if not isinstance(mapping,dict) or not mapping: blockers.append("explicit_target_mapping_required")
    expected_issuer=(boundaries.get(target) or {}).get("issuer") if target in {"production","staging"} else None
    if expected_issuer and issuer!=expected_issuer: blockers.append("target_issuer_mismatch" if issuer else "target_issuer_required")
    # TEST_SYN identities are recognised by the naming prefix, not by the directory
    # they were staged under, so no authority group can carry them into production.
    if target=="production" and normalize_environment(source)=="test-syn": blockers.append("test_syn_production_forbidden")
    staged=[x for x in desired.get("stagedClients",[]) if x.get("authorityGroup")==source]
    if not staged: blockers.append("source_authority_group_not_found")
    protected_by={c.get("clientId"):c for c in (protected or desired).get("clients",[]) if c.get("clientId")}
    for item in staged:
        c=item["client"]; src=str(c.get("clientId") or ""); target_id=(mapping or {}).get(src) if isinstance(mapping,dict) else None
        if target=="production" and (src.lower().startswith(prefix.lower()) or str(target_id or "").lower().startswith(prefix.lower())): blockers.append("test_syn_production_forbidden")
        if not target_id: blockers.append(f"missing_mapping:{src}"); continue
        target_c=protected_by.get(target_id); changes=[]
        if target_c:
            for field in COMPARE:
                if canonical(c.get(field))!=canonical(target_c.get(field)): changes.append(field)
            if changes: blockers.append(f"protected_client_collision:{target_id}")
        candidates.append({"sourceClientId":src,"targetClientId":target_id,"requiredChanges":changes})
    packet={"schema":"codestra.keycloak.promotion-plan.v1","promotionId":str(request.get("promotionId") or uuid.uuid4()),"sourceAuthorityGroup":source,"sourceDesiredStateSha":desired.get("sourceSha256") or _sha(desired),"targetEnvironment":target,"targetIssuer":issuer,"candidateResources":candidates,"blockers":sorted(set(blockers))}
    packet["promotionStatus"]="BLOCK" if blockers else "PROMOTE"
    stable={k:v for k,v in packet.items() if k not in {"promotionId","packetSha256"}}
    packet["packetSha256"]=_sha(stable)
    return packet
