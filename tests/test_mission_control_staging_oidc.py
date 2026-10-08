import json
from copy import deepcopy
from pathlib import Path

import pytest

from tools.generate_mission_control_staging_realm import build


ROOT = Path(__file__).resolve().parents[1]


def test_staging_pkce_audience_scope_and_no_apply():
    base=json.loads((ROOT/"config/realms/codestra.json").read_text())
    contract=json.loads((ROOT/"staging/mission-control-oidc.v1.json").read_text())
    assert contract["runtime_apply_authorized"] is False
    assert contract["environment"]=="staging"
    assert contract["issuer"]=="https://auth-staging.codestra.co/realms/codestra"
    client=contract["client"]
    assert client["publicClient"] is True
    assert client["standardFlowEnabled"] is True
    assert client["directAccessGrantsEnabled"] is False
    assert client["serviceAccountsEnabled"] is False
    assert client["implicitFlowEnabled"] is False
    assert client["fullScopeAllowed"] is False
    assert client["attributes"]["pkce.code.challenge.method"]=="S256"
    assert client["optionalClientScopes"]==["dashboard.read"]
    compiled=build(base,contract)
    assert build(compiled,contract)==compiled
    scope=contract["clientScope"]
    assert scope["protocolMappers"][0]["config"]["included.custom.audience"]=="mission-control-backend"
    assert "Viewer" not in contract["backend_requirements"]["authorized_realm_roles"]
    broken=deepcopy(contract);broken["client"]["attributes"]["pkce.code.challenge.method"]="plain"
    with pytest.raises(ValueError,match="pkce_s256_required"):
        build(base,broken)
    broken=deepcopy(contract);broken["client"]["webOrigins"]=["*"]
    bad_existing=deepcopy(base);bad_existing.setdefault("clients",[]).append(broken["client"])
    with pytest.raises(ValueError,match="conflicting_clients"):
        build(bad_existing,contract)
