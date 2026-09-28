#!/usr/bin/env python3
from __future__ import annotations
import hashlib, json, os, stat, tempfile, threading
from pathlib import Path
from typing import Any
from keycloak_identity_compiler import canonical

class EvidenceStoreError(RuntimeError): pass
# Keycloak representations legitimately carry non-secret keys such as
# resetPasswordAllowed, otpPolicyType, access.token.lifespan and
# oauth2.device.authorization.grant.enabled. Secret material is identified by a
# secret-bearing key name combined with a free-form value; boolean, numeric and
# empty values are configuration, never credentials.
SECRET_KEY_MARKERS=("secret","password","passwd","token","otp","credential","authorization","cookie","privatekey","apikey","bearer")
SECRET_KEYS={"password","access_token","refresh_token","id_token","authorization","cookie","client_secret","secret","reset_token","otp","credential","credentials"}
_SAFE_STRINGS={"","true","false","on","off","yes","no"}
PROTECTED_MODES={"APPLY","ROLLBACK"}

def _normalize_key(key:Any)->str:
    return "".join(c for c in str(key).lower() if c.isalnum())

def is_secret_bearing_key(key:Any)->bool:
    n=_normalize_key(key)
    # Public certificates and public keys (jwt.credential.certificate, saml.signing.certificate)
    # are verification material, not credentials.
    if n.endswith(("certificate","publickey")): return False
    return n in SECRET_KEYS or any(marker in n for marker in SECRET_KEY_MARKERS)

def _is_configuration_scalar(value:Any)->bool:
    if value is None or isinstance(value,(bool,int,float)): return True
    if isinstance(value,str):
        v=value.strip().lower()
        return v in _SAFE_STRINGS or v.replace(".","",1).isdigit()
    return False

def _assert_secret_free(value:Any,path:str="root")->None:
    if isinstance(value,dict):
        for k,v in value.items():
            if is_secret_bearing_key(k):
                if isinstance(v,(dict,list)) and v: raise EvidenceStoreError(f"secret_material_forbidden:{path}.{k}")
                if not _is_configuration_scalar(v): raise EvidenceStoreError(f"secret_material_forbidden:{path}.{k}")
                continue
            _assert_secret_free(v,f"{path}.{k}")
    elif isinstance(value,list):
        for i,v in enumerate(value): _assert_secret_free(v,f"{path}[{i}]")

def redact_secret_material(value:Any,path:str="root",dropped:list[str]|None=None)->tuple[Any,list[str]]:
    """Return a copy of value with secret-bearing entries removed, plus the dropped paths.

    The result always satisfies _assert_secret_free, so live Keycloak state can be
    persisted as evidence without ever writing credential material.
    """
    dropped=[] if dropped is None else dropped
    if isinstance(value,dict):
        clean={}
        for k,v in value.items():
            if is_secret_bearing_key(k) and not (_is_configuration_scalar(v) and not isinstance(v,(dict,list))):
                dropped.append(f"{path}.{k}"); continue
            if is_secret_bearing_key(k): clean[k]=v; continue
            clean[k]=redact_secret_material(v,f"{path}.{k}",dropped)[0]
        return clean,dropped
    if isinstance(value,list):
        return [redact_secret_material(v,f"{path}[{i}]",dropped)[0] for i,v in enumerate(value)],dropped
    return value,dropped


class EvidenceStore:
    def __init__(self, root:Path|str, *, retention:int=200):
        self.root=Path(root); self.retention=max(10,min(int(retention),5000)); self._lock=threading.RLock()
        self._prepare_root()

    def _prepare_root(self)->None:
        existed=self.root.exists()
        self.root.mkdir(parents=True,exist_ok=True)
        if os.name!="posix": return
        if not existed: os.chmod(self.root,0o700)
        info=self.root.stat()
        if info.st_uid!=os.getuid(): raise EvidenceStoreError("evidence_root_not_owned")
        if info.st_mode&(stat.S_IWGRP|stat.S_IWOTH): raise EvidenceStoreError("evidence_root_writable_by_others")

    @staticmethod
    def _digest(payload:Any)->str:
        return hashlib.sha256(canonical(payload).encode()).hexdigest()

    @staticmethod
    def _safe_id(value:str)->str:
        if not value or len(value)>128 or any(c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._" for c in value):
            raise EvidenceStoreError("invalid_record_id")
        return value

    def _path(self,kind:str,record_id:str)->Path:
        self._safe_id(kind); self._safe_id(record_id)
        d=self.root/kind; d.mkdir(parents=True,exist_ok=True)
        return d/(record_id+".json")

    def put(self,kind:str,record_id:str,payload:dict[str,Any],*,replace:bool=False)->dict[str,Any]:
        path=self._path(kind,record_id)
        _assert_secret_free(payload)
        body={"schema":"codestra.keycloak.evidence-envelope.v1","kind":kind,"recordId":record_id,"payload":payload}
        body["sha256"]=self._digest(body)
        raw=(json.dumps(body,sort_keys=True,indent=2,ensure_ascii=False)+"\n").encode()
        with self._lock:
            if path.exists() and not replace: raise EvidenceStoreError("duplicate_record")
            fd,tmp=tempfile.mkstemp(prefix="."+path.name+".",dir=path.parent)
            try:
                with os.fdopen(fd,"wb") as fh: fh.write(raw); fh.flush(); os.fsync(fh.fileno())
                os.replace(tmp,path)
            finally:
                if os.path.exists(tmp): os.unlink(tmp)
            self._prune(path.parent)
        return body

    def get(self,kind:str,record_id:str)->dict[str,Any]:
        path=self._path(kind,record_id)
        if not path.exists(): raise EvidenceStoreError("record_not_found")
        try: body=json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc: raise EvidenceStoreError("corrupt_record") from exc
        digest=body.pop("sha256",None); actual=self._digest(body); body["sha256"]=digest
        if not digest or digest!=actual: raise EvidenceStoreError("corrupt_record")
        return body

    def list(self,kind:str)->list[dict[str,Any]]:
        d=self.root/self._safe_id(kind)
        if not d.exists(): return []
        out=[]
        for path in sorted(d.glob("*.json"),key=lambda x:x.stat().st_mtime,reverse=True)[:self.retention]:
            out.append(self.get(kind,path.stem))
        return out

    @staticmethod
    def _is_protected(path:Path)->bool:
        # Mutation evidence (APPLY/ROLLBACK) is never pruned; only read-only records rotate.
        try: mode=json.loads(path.read_text(encoding="utf-8")).get("payload",{}).get("mode")
        except Exception: return True
        return mode in PROTECTED_MODES

    def _prune(self,d:Path)->None:
        rows=sorted(d.glob("*.json"),key=lambda x:x.stat().st_mtime,reverse=True)
        for path in rows[self.retention:]:
            if not self._is_protected(path): path.unlink(missing_ok=True)
