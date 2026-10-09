"""Production OIDC client must match the live canonical Klyrow browser host."""
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def load(path):
    return json.loads((ROOT / path).read_text(encoding="utf-8"))


def test_klyrow_public_pkce_exact_redirect_origin():
    client = load("config/clients/klyrow-portal.json")
    assert client["clientId"] == "klyrow-portal"
    assert client["enabled"] and client["publicClient"] and client["standardFlowEnabled"]
    assert not client["implicitFlowEnabled"] and not client["directAccessGrantsEnabled"]
    assert not client["serviceAccountsEnabled"]
    assert client["rootUrl"] == "https://app.klyrow.com"
    assert client["baseUrl"] == "https://app.klyrow.com/login"
    assert client["redirectUris"] == ["https://app.klyrow.com/auth/callback"]
    assert client["webOrigins"] == ["https://app.klyrow.com"]
    assert client["attributes"]["pkce.code.challenge.method"] == "S256"
    assert client["attributes"]["post.logout.redirect.uris"] == "https://app.klyrow.com/login"
    for uri in client["redirectUris"] + client["webOrigins"]:
        assert "*" not in uri and "http://" not in uri


def test_registry_consistency_and_production_remains_fail_closed():
    registry = load("config/identity/application-domain-registry.json")
    client = load("config/clients/klyrow-portal.json")
    entries = [d for d in registry["domains"] if d["domain"] == "klyrow.com"]
    assert len(entries) == 1
    entry = entries[0]
    assert entry["humanClientId"] == client["clientId"]
    assert entry["redirectUris"] == client["redirectUris"]
    assert entry["webOrigins"] == client["webOrigins"]
    assert entry["localPasswordResetAllowed"] is False
    assert registry["policy"]["wildcardRedirectUrisAllowed"] is False
    assert registry["policy"]["clientCreationBeforeRuntimeVerification"] is False
    assert load("config/certification/service-identity-matrix.json")["productionMutationAllowed"] is False
