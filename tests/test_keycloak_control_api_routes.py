from __future__ import annotations
import http.client,json,sys,threading
from http.server import ThreadingHTTPServer
from pathlib import Path
import pytest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"scripts")); sys.path.insert(0,str(ROOT/"tests"))
from keycloak_control_api import Handler
from test_pas237_keycloak_control_plane import make_service

P="/platform/v1/keycloak"

@pytest.fixture
def server(tmp_path):
    class T(Handler): service=make_service(tmp_path,None)
    srv=ThreadingHTTPServer(("127.0.0.1",0),T); th=threading.Thread(target=srv.serve_forever,daemon=True); th.start()
    def call(method,path,body=None):
        conn=http.client.HTTPConnection("127.0.0.1",srv.server_port,timeout=5)
        data=None if body is None else json.dumps(body).encode()
        conn.request(method,path,body=data,headers={"Content-Type":"application/json"} if data else {})
        r=conn.getresponse(); raw=r.read(); conn.close()
        return r.status,r.getheader("Content-Type") or "",r.getheader("Allow"),json.loads(raw) if raw else None
    yield call
    srv.shutdown(); srv.server_close()

def test_promotion_plan_rejects_a_malformed_id_as_a_client_error(server):
    for pid in ("bad id","../x","..",".hidden","x"*129,7):
        status,_,_,body=server("POST",P+"/promotion/plan",{"promotionId":pid,"targetEnvironment":"staging"})
        assert (status,body["error"]["code"])==(400,"invalid_request"),pid

def test_promotion_plan_never_replaces_an_existing_plan(server):
    status,_,_,first=server("POST",P+"/promotion/plan",{"promotionId":"plan-1","targetEnvironment":"staging"})
    assert status==200
    status,_,_,body=server("POST",P+"/promotion/plan",{"promotionId":"plan-1","targetEnvironment":"production"})
    assert (status,body["error"]["code"])==(409,"promotion_exists")
    status,_,_,stored=server("GET",P+"/promotion/plans/plan-1")
    assert status==200 and stored["promotion"]==first["promotion"]

@pytest.mark.parametrize("path",[
    "/reconcile/executions/abc/other","/reconcile/executions/abc/evidence/more","/reconcile/executions/",
    "/reconcile/rollbacks/abc/more","/reconcile/rollbacks/","/promotion/plans/abc/more","/promotion/plans/",
])
def test_paths_deeper_than_a_record_route_are_not_routes(server,path):
    status,ctype,_,body=server("GET",P+path)
    assert (status,body["error"]["code"])==(404,"not_found") and "application/json" in ctype

def test_record_routes_still_resolve_one_id(server):
    assert server("GET",P+"/reconcile/executions/missing")[3]["error"]["code"]=="execution_not_found"
    assert server("GET",P+"/reconcile/executions/missing/evidence")[3]["error"]["code"]=="execution_not_found"
    assert server("GET",P+"/reconcile/rollbacks/missing")[3]["error"]["code"]=="rollback_not_found"
    assert server("GET",P+"/promotion/plans/missing")[3]["error"]["code"]=="promotion_not_found"

@pytest.mark.parametrize("method",["PUT","DELETE","PATCH","OPTIONS"])
def test_unsupported_methods_get_a_json_405(server,method):
    status,ctype,allow,body=server(method,P+"/reconcile/apply")
    assert (status,allow,body["error"]["code"])==(405,"GET, POST","method_not_allowed") and "application/json" in ctype
