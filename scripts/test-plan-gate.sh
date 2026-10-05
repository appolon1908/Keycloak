#!/usr/bin/env bash
set -Eeuo pipefail
report_error() {
  local exit_status="$1"
  local line_number="$2"
  printf 'TEST_PLAN_GATE_ERROR=line:%s status:%s\n' "$line_number" "$exit_status" >&2
  exit "$exit_status"
}
trap 'report_error "$?" "$LINENO"' ERR
umask 077

ROOT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=scripts/lib/keycloak-admin.sh
source "$ROOT_DIR/scripts/lib/keycloak-admin.sh"
test_root="$(mktemp -d)"
export KEYCLOAK_CONTROL_EVIDENCE_DIR="$test_root/control-evidence"
mkdir -m 700 "$KEYCLOAK_CONTROL_EVIDENCE_DIR"
server_pid=""
cleanup() {
  if [[ -n "$server_pid" ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
  fi
  rm -rf "$test_root"
}
trap cleanup EXIT

state_file="$test_root/clients.json"
realm_state_file="$test_root/realm.json"
port_file="$test_root/port"
control_file="$test_root/control.json"
printf '{}\n' >"$control_file"

# Keep the plan gate test isolated from the real Docker daemon and runtime.
mkdir -p "$test_root/bin" "$test_root/runtime"
export RUNTIME_REPO_DIR="$test_root/runtime"
export RUNTIME_COMPOSE_FILE="$test_root/runtime/compose.yaml"
export RUNTIME_ENV_FILE="$test_root/runtime/runtime.env"
export RUNTIME_KEYCLOAK_SERVICE=keycloak
export MOCK_SMTP_CONTROL_FILE="$control_file"
printf 'services: {}\n' >"$RUNTIME_COMPOSE_FILE"
: >"$RUNTIME_ENV_FILE"
cat >"$test_root/bin/docker" <<'PYSMTP'
#!/usr/bin/env python3
import json
import os
import sys
from pathlib import Path

args = sys.argv[1:]
blocked = json.loads(Path(os.environ["MOCK_SMTP_CONTROL_FILE"]).read_text()).get("smtpRouteBlocked", False)
if args[0] == "compose" and args[-3:] == ["config", "--format", "json"]:
    print(json.dumps({
        "name": "smtp-regression",
        "services": {"keycloak": {"extra_hosts": {} if blocked else {"mail.klyrow.com": "10.40.0.4"}}},
    }))
elif args[0] == "compose" and args[-4:] == ["ps", "--all", "--quiet", "keycloak"]:
    print("a" * 64)
elif args == ["inspect", "a" * 64]:
    print(json.dumps([{
        "State": {"Running": True},
        "Config": {"Labels": {"com.docker.compose.project": "smtp-regression", "com.docker.compose.service": "keycloak"}},
        "HostConfig": {"ExtraHosts": ["mail.klyrow.com:10.40.0.4"], "NetworkMode": "default"},
    }]))
elif args == ["exec", "a" * 64, "getent", "ahosts", "mail.klyrow.com"]:
    print("10.40.0.4 STREAM mail.klyrow.com")
else:
    raise SystemExit("Unexpected Docker call in isolated SMTP regression fixture")
PYSMTP
chmod 700 "$test_root/bin/docker"
export PATH="$test_root/bin:$PATH"

jq -S '.rememberMe = true' "$ROOT_DIR/config/realms/codestra.json" >"$realm_state_file"

jq -S -n \
  --slurpfile klyrow "$ROOT_DIR/config/clients/klyrow-portal.json" '
    {
      "klyrow-portal": {
        id: "uuid-klyrow",
        representation: ($klyrow[0] | .redirectUris = ["https://wrong.example/callback"])
      }
    }
  ' >"$state_file"

cat >"$test_root/mock_keycloak.py" <<'PY'
#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

state_path = Path(os.environ["MOCK_STATE_FILE"])
realm_state_path = Path(os.environ["MOCK_REALM_STATE_FILE"])
port_path = Path(os.environ["MOCK_PORT_FILE"])
control_path = Path(os.environ["MOCK_CONTROL_FILE"])


def load_state() -> dict[str, dict]:
    return json.loads(state_path.read_text())


def save_state(value: dict[str, dict]) -> None:
    state_path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n")


def load_control() -> dict:
    return json.loads(control_path.read_text())


def save_control(value: dict) -> None:
    control_path.write_text(json.dumps(value, sort_keys=True) + "\n")


def realm_exists() -> bool:
    return not bool(load_control().get("realmMissing", False))


def apply_controlled_get_mutation(client_id: str, state: dict[str, dict]) -> dict[str, dict]:
    control = json.loads(control_path.read_text())
    if not control.get("armed") or control.get("clientId") != client_id:
        return state
    remaining = int(control.get("remainingGets", 0))
    if remaining > 0:
        control["remainingGets"] = remaining - 1
        control_path.write_text(json.dumps(control, sort_keys=True) + "\n")
        return state
    representation = state[client_id]["representation"]
    if control.get("kind") == "managed":
        representation["redirectUris"] = ["https://concurrent.example/callback"]
    elif control.get("kind") == "unmanaged":
        representation["unmanagedConcurrentMarker"] = "preserved"
    else:
        raise RuntimeError("unsupported controlled mutation")
    control["armed"] = False
    control["fired"] = True
    save_state(state)
    control_path.write_text(json.dumps(control, sort_keys=True) + "\n")
    return state


def live_representation(client_id: str, item: dict) -> dict:
    value = json.loads(json.dumps(item["representation"]))
    value["id"] = item["id"]
    mappers = value.get("protocolMappers")
    if isinstance(mappers, list):
        for index, mapper in enumerate(mappers):
            if isinstance(mapper, dict):
                mapper.setdefault("id", f"mapper-{client_id}-{index}")
    return value


class Handler(BaseHTTPRequestHandler):
    server_version = "MockKeycloak/2"

    def log_message(self, _format: str, *_args: object) -> None:
        return

    def send_json(self, status: int, payload: object) -> None:
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def read_json(self) -> dict:
        content_length = int(self.headers.get("Content-Length", "0"))
        return json.loads(self.rfile.read(content_length))

    def do_POST(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/realms/master/protocol/openid-connect/token":
            self.send_json(200, {"access_token": "test-token", "expires_in": 60})
            return
        if parsed.path == "/admin/realms":
            control = load_control()
            if not control.get("realmMissing", False):
                self.send_json(409, {"error": "realm_exists"})
                return
            realm_state_path.write_text(
                json.dumps(self.read_json(), indent=2, sort_keys=True) + "\n"
            )
            control["realmMissing"] = False
            save_control(control)
            self.send_response(201)
            self.end_headers()
            return
        if parsed.path == "/admin/realms/codestra/clients":
            if not realm_exists():
                self.send_json(404, {"error": "realm_not_found"})
                return
            payload = self.read_json()
            client_id = str(payload.get("clientId") or "")
            state = load_state()
            if not client_id or client_id in state:
                self.send_json(409, {"error": "client_exists_or_invalid"})
                return
            # Match the admin API representation returned by Keycloak when
            # authorization services are disabled.
            if payload.get("authorizationServicesEnabled") is False:
                payload.pop("authorizationServicesEnabled")
            state[client_id] = {
                "id": f"uuid-{client_id}",
                "representation": payload,
            }
            save_state(state)
            self.send_response(201)
            self.end_headers()
            return
        self.send_json(404, {"error": "not_found"})

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/admin/realms/codestra":
            if not realm_exists():
                self.send_json(404, {"error": "realm_not_found"})
            else:
                self.send_json(200, json.loads(realm_state_path.read_text()))
            return
        state = load_state()
        if parsed.path == "/admin/realms/codestra/clients":
            if not realm_exists():
                self.send_json(404, {"error": "realm_not_found"})
                return
            query = parse_qs(parsed.query)
            client_ids = query.get("clientId") or []
            client_id = client_ids[0] if client_ids else ""
            item = state.get(client_id)
            if item is None:
                self.send_json(200, [])
            else:
                self.send_json(200, [{"id": item["id"], "clientId": client_id}])
            return

        prefix = "/admin/realms/codestra/clients/"
        if parsed.path.startswith(prefix):
            client_uuid = parsed.path.removeprefix(prefix)
            for client_id, item in state.items():
                if item["id"] == client_uuid:
                    state = apply_controlled_get_mutation(client_id, state)
                    item = state[client_id]
                    self.send_json(200, live_representation(client_id, item))
                    return
            self.send_json(404, {"error": "not_found"})
            return
        self.send_json(404, {"error": "not_found"})

    def do_PUT(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/admin/realms/codestra":
            if not realm_exists():
                self.send_json(404, {"error": "realm_not_found"})
                return
            realm_state_path.write_text(
                json.dumps(self.read_json(), indent=2, sort_keys=True) + "\n"
            )
            self.send_response(204)
            self.end_headers()
            return
        prefix = "/admin/realms/codestra/clients/"
        if not parsed.path.startswith(prefix):
            self.send_json(404, {"error": "not_found"})
            return
        client_uuid = parsed.path.removeprefix(prefix)
        state = load_state()
        for client_id, item in state.items():
            if item["id"] == client_uuid:
                payload = self.read_json()
                payload.pop("id", None)
                # Keycloak omits this field when authorization services are
                # disabled, so its admin API returns null after a successful
                # create/update with an explicit false value.
                if payload.get("authorizationServicesEnabled") is False:
                    payload.pop("authorizationServicesEnabled")
                item["representation"] = payload
                state[client_id] = item
                save_state(state)
                self.send_response(204)
                self.end_headers()
                return
        self.send_json(404, {"error": "not_found"})


server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
port_path.write_text(str(server.server_port))
server.serve_forever()
PY

MOCK_STATE_FILE="$state_file" \
MOCK_REALM_STATE_FILE="$realm_state_file" \
MOCK_PORT_FILE="$port_file" \
MOCK_CONTROL_FILE="$control_file" \
python3 "$test_root/mock_keycloak.py" &
server_pid=$!

for _ in {1..50}; do
  [[ -s "$port_file" ]] && break
  sleep 0.1
done
[[ -s "$port_file" ]] || {
  echo 'TEST_ERROR=mock_keycloak_failed_to_start' >&2
  exit 1
}

port="$(cat "$port_file")"
export KC_BASE_URL="http://127.0.0.1:${port}"
export KC_PUBLIC_URL="https://auth-staging.codestra.co"
export KC_TARGET_REALM="codestra"
export KC_ADMIN_REALM="master"
export KC_ADMIN_CLIENT_ID="test-gitops-client"
# The mock accepts any non-empty credential marker; no real credential is used.
KC_ADMIN_CLIENT_SECRET=$(printf %s ci-only-placeholder)
export KC_ADMIN_CLIENT_SECRET
export ALLOW_INSECURE_KC_BASE_URL="true"
export ALLOW_NONCANONICAL_KC_BASE_URL_FOR_TESTS="true"
export DEPLOY_ENVIRONMENT="staging"
export KC_SMTP_CREDENTIAL_VERSION="ci-rotation-v1"
# Isolated fixture-only SMTP values. These never leave the mock test process
# and prove that plan/recovery artifacts do not serialize credential material.
export KC_SMTP_USERNAME="ci-smtp-user"
export KC_SMTP_PASSWORD="ci-smtp-pass"
expected_sha="1111111111111111111111111111111111111111"

[[ "$(keycloak_endpoint_file)" == "$ROOT_DIR/config/endpoints/codestra-staging.json" ]]
DEPLOY_ENVIRONMENT=production
[[ "$(keycloak_endpoint_file)" == "$ROOT_DIR/config/endpoints/codestra.json" ]]
DEPLOY_ENVIRONMENT=staging

plan_dir="$test_root/plan"
"$ROOT_DIR/scripts/plan.sh" \
  --output-dir "$plan_dir" \
  --expected-deploy-sha "$expected_sha" >/dev/null

[[ "$(jq -er '.api.adminApiBaseUrl' "$plan_dir/plan.json")" == "https://auth-staging.codestra.co" ]]
[[ "$(jq -er '.api.issuer' "$plan_dir/plan.json")" == "https://auth-staging.codestra.co/realms/codestra" ]]

# 37 managed clients: monitoring-readonly is not planned in staging (its staging writer is
# the Stage 6 reconciler), klyrow-portal pre-exists in the mock (update), the other 35 are
# created, and the realm policy drifts (update).
[[ "$(jq -er '.driftCount' "$plan_dir/plan.json")" -eq 37 ]]
[[ "$(jq -er '.blockedCount' "$plan_dir/plan.json")" -eq 0 ]]
[[ "$(jq -er '.createCount' "$plan_dir/plan.json")" -eq 35 ]]
[[ "$(jq -er '.updateCount' "$plan_dir/plan.json")" -eq 2 ]]
[[ "$(jq -er '.realmPolicy.action' "$plan_dir/plan.json")" == "update" ]]
[[ "$(jq -er '.clients[] | select(.clientId == "klyrow-portal") | .action' "$plan_dir/plan.json")" == "update" ]]
for client_id in codestra-provisioning-service odoo-web moneybee-admin moneybee-borrower moneybee-lender moneybee-backend breero-backend larim-a-backend transportation-backend beyvra-backend social-codestra codestra-agent-desktop klyrow-staging-portal odoo-email production-operator; do
  [[ "$(jq -er --arg client_id "$client_id" '.clients[] | select(.clientId == $client_id) | .action' "$plan_dir/plan.json")" == "create" ]]
  jq -e --arg client_id "$client_id" '
    .clients[]
    | select(.clientId == $client_id)
    | .before == {}
      and .rollback.kind == "disable_then_reviewed_delete"
      and .rollback.disableFirst == true
      and .rollback.deleteRequiresSeparateReviewedRollback == true
  ' "$plan_dir/plan.json" >/dev/null
done

[[ "$(jq -er '.excludedCount' "$plan_dir/plan.json")" -eq 1 ]]
jq -e '
  ([.clients[] | select(.clientId == "monitoring-readonly")] | length == 0)
  and .excludedClients == [{
    clientId: "monitoring-readonly",
    reason: "environment_scoped",
    allowedEnvironments: ["production", "test-syn"]
  }]
' "$plan_dir/plan.json" >/dev/null

# The staging-only Klyrow portal is excluded from a production plan instead of being
# created in the production realm with staging redirect URIs.
production_plan_dir="$test_root/plan-production"
DEPLOY_ENVIRONMENT=production KC_PUBLIC_URL="https://auth.codestra.co" "$ROOT_DIR/scripts/plan.sh" \
  --output-dir "$production_plan_dir" \
  --expected-deploy-sha "$expected_sha" >/dev/null
[[ "$(jq -er '.environment' "$production_plan_dir/plan.json")" == "production" ]]
[[ "$(jq -er '.api.adminApiBaseUrl' "$production_plan_dir/plan.json")" == "https://auth.codestra.co" ]]
[[ "$(jq -er '.driftCount' "$production_plan_dir/plan.json")" -eq 37 ]]
[[ "$(jq -er '.createCount' "$production_plan_dir/plan.json")" -eq 35 ]]
[[ "$(jq -er '.updateCount' "$production_plan_dir/plan.json")" -eq 2 ]]
[[ "$(jq -er '.excludedCount' "$production_plan_dir/plan.json")" -eq 1 ]]
jq -e '
  ([.clients[] | select(.clientId == "klyrow-staging-portal")] | length == 0)
  and .excludedClients == [{
    clientId: "klyrow-staging-portal",
    reason: "environment_scoped",
    allowedEnvironments: ["staging"]
  }]
' "$production_plan_dir/plan.json" >/dev/null
printf 'PLAN_ENVIRONMENT_SCOPE_EXCLUSION=PASS\n'

plan_sha256="$(awk 'NR == 1 {print $1}' "$plan_dir/plan.sha256")"
[[ "$plan_sha256" =~ ^[0-9a-f]{64}$ ]]
export KEYCLOAK_REVIEWER_ID="independent-reviewer"
export KEYCLOAK_CHANGE_AUTHOR_ID="change-author"
export KEYCLOAK_CHANGE_TICKET="TEST-PLAN-GATE"
review_file="$test_root/review.json"
"$ROOT_DIR/scripts/review-plan.sh" \
  --plan "$plan_dir/plan.json" \
  --expected-plan-sha "$plan_sha256" \
  --expected-deploy-sha "$expected_sha" \
  --output "$review_file" >/dev/null
review_sha256="$(awk 'NR == 1 {print $1}' "${review_file}.sha256")"

rollback_dir="$test_root/rollback"
mapfile -t managed_clients < <(jq -r '.clients[]' "$ROOT_DIR/config/policy/managed-clients.json")
"$ROOT_DIR/scripts/export-client.sh" \
  --output "$rollback_dir" \
  "${managed_clients[@]}" >/dev/null
[[ -f "$rollback_dir/config/clients/klyrow-portal.json" ]]
[[ "$(jq -er '.existingClientCount' "$rollback_dir/rollback-metadata.json")" -eq 1 ]]
[[ "$(jq -er '.absentCreatableClientCount' "$rollback_dir/rollback-metadata.json")" -eq 36 ]]

# Exercise the apply create path with a non-empty test credential for every
# managed machine identity. Production values remain supplied only by the
# protected apply workflow; these placeholders never leave the test process.
while IFS= read -r secret_name; do
  printf -v "$secret_name" 'ci-only-%s' "$secret_name"
  export "${secret_name?}"
done < <(jq -er '.clients[].applyEnvironment' \
  "$ROOT_DIR/config/contracts/machine-secret-destinations.json")

if "$ROOT_DIR/scripts/apply-plan.sh" \
  --plan "$plan_dir/plan.json" \
  --expected-plan-sha 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' \
  --review "$review_file" \
  --expected-review-sha "$review_sha256" \
  --expected-deploy-sha "$expected_sha" \
  --recovery-dir "$test_root/recovery-bad-hash" >/dev/null 2>&1; then
  echo 'TEST_ERROR=mismatched_plan_hash_was_accepted' >&2
  exit 1
fi

# A reviewed plan that excludes a client allowed in this environment is refused before
# authentication or any write; only the environment-scope policy may exclude a client.
tampered_dir="$test_root/tampered-exclusion"
mkdir -p "$tampered_dir"
jq -S '
  del(.clients[] | select(.clientId == "klyrow-staging-portal"))
  | .excludedClients = [{clientId: "klyrow-staging-portal", reason: "environment_scoped", allowedEnvironments: ["staging"]}]
  | .excludedCount = 1
  | .createCount -= 1
  | .driftCount -= 1
' "$plan_dir/plan.json" >"$tampered_dir/plan.json"
tampered_sha256="$(jq -S -c . "$tampered_dir/plan.json" | sha256sum | awk '{print $1}')"
"$ROOT_DIR/scripts/review-plan.sh" \
  --plan "$tampered_dir/plan.json" \
  --expected-plan-sha "$tampered_sha256" \
  --expected-deploy-sha "$expected_sha" \
  --output "$tampered_dir/review.json" >/dev/null
tampered_review_sha256="$(awk 'NR == 1 {print $1}' "$tampered_dir/review.json.sha256")"
if "$ROOT_DIR/scripts/apply-plan.sh" \
  --plan "$tampered_dir/plan.json" \
  --expected-plan-sha "$tampered_sha256" \
  --review "$tampered_dir/review.json" \
  --expected-review-sha "$tampered_review_sha256" \
  --expected-deploy-sha "$expected_sha" \
  --recovery-dir "$test_root/recovery-tampered-exclusion" >"$test_root/tampered-exclusion.log" 2>&1; then
  echo 'TEST_ERROR=plan_with_unauthorized_exclusion_was_accepted' >&2
  exit 1
fi
grep -Fq 'Plan client set does not match' "$test_root/tampered-exclusion.log"
[[ "$(jq -er 'length' "$state_file")" -eq 1 ]]
printf 'APPLY_UNAUTHORIZED_EXCLUSION_FAIL_CLOSED=PASS\n'

jq -S \
  --slurpfile admin "$ROOT_DIR/config/clients/moneybee-admin.json" '
    .["moneybee-admin"] = {
      id: "uuid-race-moneybee-admin",
      representation: $admin[0]
    }
  ' "$state_file" >"$state_file.tmp"
mv "$state_file.tmp" "$state_file"

if "$ROOT_DIR/scripts/apply-plan.sh" \
  --plan "$plan_dir/plan.json" \
  --expected-plan-sha "$plan_sha256" \
  --review "$review_file" \
  --expected-review-sha "$review_sha256" \
  --expected-deploy-sha "$expected_sha" \
  --recovery-dir "$test_root/recovery-create-race" >/dev/null 2>&1; then
  echo 'TEST_ERROR=create_race_was_not_rejected' >&2
  exit 1
fi

jq -e '
  .["klyrow-portal"].representation.redirectUris == ["https://wrong.example/callback"]
  and has("moneybee-admin")
  and (has("moneybee-borrower") | not)
  and (has("moneybee-lender") | not)
  and (has("moneybee-backend") | not)
  and (has("social-codestra") | not)
' "$state_file" >/dev/null

jq -S 'del(."moneybee-admin")' "$state_file" >"$state_file.tmp"
mv "$state_file.tmp" "$state_file"

smtp_before_sha="$(sha256sum "$state_file" "$realm_state_file")"
jq '.smtpRouteBlocked = true' "$control_file" >"$control_file.tmp"
mv "$control_file.tmp" "$control_file"
if "$ROOT_DIR/scripts/apply-plan.sh" \
  --plan "$plan_dir/plan.json" \
  --expected-plan-sha "$plan_sha256" \
  --review "$review_file" \
  --expected-review-sha "$review_sha256" \
  --expected-deploy-sha "$expected_sha" \
  --recovery-dir "$test_root/smtp-blocked-recovery" >"$test_root/smtp-blocked.log" 2>&1; then
  echo 'TEST_ERROR=apply_accepted_missing_runtime_smtp_route' >&2
  exit 1
fi
grep -Fq 'Rendered runtime Compose is missing the private SMTP mapping' "$test_root/smtp-blocked.log"
[[ "$(sha256sum "$state_file" "$realm_state_file")" == "$smtp_before_sha" ]] || {
  echo 'TEST_ERROR=blocked_smtp_route_mutated_keycloak' >&2
  exit 1
}
jq 'del(.smtpRouteBlocked)' "$control_file" >"$control_file.tmp"
mv "$control_file.tmp" "$control_file"
printf 'APPLY_PRIVATE_SMTP_ROUTE_FAIL_CLOSED=PASS\n'

"$ROOT_DIR/scripts/apply-plan.sh" \
  --plan "$plan_dir/plan.json" \
  --expected-plan-sha "$plan_sha256" \
  --review "$review_file" \
  --expected-review-sha "$review_sha256" \
  --expected-deploy-sha "$expected_sha" \
  --recovery-dir "$test_root/recovery-success" >/dev/null

expected_operation_count="$(jq -er '(.clients | length) + 1' "$plan_dir/plan.json")"
jq -e --argjson expected_operation_count "$expected_operation_count" '
  .partialApply == false
  and (.operations | length == $expected_operation_count)
  and all(.operations[]; (.state == "created" or .state == "updated" or .state == "unchanged"))
' "$test_root/recovery-success/recovery-manifest.json" >/dev/null

for client_id in klyrow-portal moneybee-admin moneybee-borrower moneybee-lender moneybee-backend breero-backend larim-a-backend transportation-backend beyvra-backend social-codestra sdk-intake alertmanager codestra-agent-desktop klyrow-staging-portal odoo-email production-operator; do
  jq -e --arg client_id "$client_id" 'has($client_id)' "$state_file" >/dev/null
done
jq -e --slurpfile desired "$ROOT_DIR/config/clients/klyrow-portal.json" '
  .["klyrow-portal"].representation == $desired[0]
' "$state_file" >/dev/null

converged_dir="$test_root/converged"
"$ROOT_DIR/scripts/plan.sh" \
  --output-dir "$converged_dir" \
  --expected-deploy-sha "$expected_sha" >/dev/null
[[ "$(jq -er '.driftCount' "$converged_dir/plan.json")" -eq 0 ]]
[[ "$(jq -er '.blockedCount' "$converged_dir/plan.json")" -eq 0 ]]
[[ "$(jq -er '.createCount' "$converged_dir/plan.json")" -eq 0 ]]
[[ "$(jq -er '.updateCount' "$converged_dir/plan.json")" -eq 0 ]]

# A non-secret credential-version change must produce reviewed realm drift even
# when every non-secret realm field is already converged. Secrets must never be
# serialized into the plan.
export KC_SMTP_CREDENTIAL_VERSION="ci-rotation-v2"
rotation_dir="$test_root/smtp-rotation"
"$ROOT_DIR/scripts/plan.sh" \
  --output-dir "$rotation_dir" \
  --expected-deploy-sha "$expected_sha" >/dev/null
[[ "$(jq -er '.realmPolicy.action' "$rotation_dir/plan.json")" == "update" ]]
[[ "$(jq -er '.realmPolicy.smtpCredentialVersion' "$rotation_dir/plan.json")" == "ci-rotation-v2" ]]
[[ "$(jq -er '.driftCount' "$rotation_dir/plan.json")" -eq 1 ]]
if rg -F "$KC_SMTP_USERNAME" "$rotation_dir" || rg -F "$KC_SMTP_PASSWORD" "$rotation_dir"; then
  echo 'TEST_ERROR=smtp_secret_was_serialized_in_plan' >&2
  exit 1
fi
export KC_SMTP_CREDENTIAL_VERSION="ci-rotation-v1"

for client_id in moneybee-admin moneybee-borrower moneybee-lender; do
  jq -e --arg client_id "$client_id" '
    .[$client_id].representation.protocolMappers[0].name == "moneybee-api-audience"
  ' "$state_file" >/dev/null
done
for client_id in moneybee-backend breero-backend larim-a-backend transportation-backend beyvra-backend social-codestra sdk-intake alertmanager; do
  jq -e --arg client_id "$client_id" '
    .[$client_id].representation.serviceAccountsEnabled == true
    and .[$client_id].representation.publicClient == false
    and .[$client_id].representation.attributes["access.token.lifespan"] == "300"
  ' "$state_file" >/dev/null
done

# Two reviewed updates are prepared. The first succeeds, then the second is
# changed concurrently immediately before its PUT. Apply must fail closed and
# leave exact durable partial-apply evidence.
jq -S '
  .["klyrow-portal"].representation.redirectUris = ["https://drift-one.example/callback"]
  | .["moneybee-admin"].representation.redirectUris = ["https://drift-two.example/callback"]
' "$state_file" >"$state_file.tmp"
mv "$state_file.tmp" "$state_file"
multi_update_plan="$test_root/multi-update-plan"
"$ROOT_DIR/scripts/plan.sh" \
  --output-dir "$multi_update_plan" \
  --expected-deploy-sha "$expected_sha" >/dev/null
[[ "$(jq -er '.updateCount' "$multi_update_plan/plan.json")" -eq 2 ]]
multi_update_hash="$(awk 'NR == 1 {print $1}' "$multi_update_plan/plan.sha256")"
multi_update_review="$test_root/multi-update-review.json"
"$ROOT_DIR/scripts/review-plan.sh" --plan "$multi_update_plan/plan.json" --expected-plan-sha "$multi_update_hash" --expected-deploy-sha "$expected_sha" --output "$multi_update_review" >/dev/null
multi_update_review_hash="$(awk 'NR == 1 {print $1}' "${multi_update_review}.sha256")"
jq -n '{armed: true, clientId: "moneybee-admin", remainingGets: 1, kind: "managed"}' >"$control_file"
if "$ROOT_DIR/scripts/apply-plan.sh" \
  --plan "$multi_update_plan/plan.json" \
  --expected-plan-sha "$multi_update_hash" \
  --review "$multi_update_review" \
  --expected-review-sha "$multi_update_review_hash" \
  --expected-deploy-sha "$expected_sha" \
  --recovery-dir "$test_root/recovery-update-race" \
  >"$test_root/update-race.stdout" 2>"$test_root/update-race.stderr"; then
  echo 'TEST_ERROR=update_race_was_not_rejected' >&2
  exit 1
fi
grep -q '^PARTIAL_APPLY=true$' "$test_root/update-race.stderr"
jq -e '
  .partialApply == true
  and ([.operations[] | select(.clientId == "klyrow-portal")][0].state == "rollback-required")
  and ([.operations[] | select(.clientId == "moneybee-admin")][0].state == "failed")
  and all(.operations[] | select(.clientId == "moneybee-borrower" or .clientId == "moneybee-lender"); .state == "pending")
' "$test_root/recovery-update-race/recovery-manifest.json" >/dev/null
jq -e --slurpfile desired "$ROOT_DIR/config/clients/klyrow-portal.json" '
  .["klyrow-portal"].representation == $desired[0]
  and .["moneybee-admin"].representation.redirectUris == ["https://concurrent.example/callback"]
' "$state_file" >/dev/null

# An unmanaged field may change concurrently: the immediate re-read must retain
# that field while still applying only the reviewed managed overlay.
jq -S --slurpfile admin "$ROOT_DIR/config/clients/moneybee-admin.json" '
  .["moneybee-admin"].representation = $admin[0]
  | .["klyrow-portal"].representation.redirectUris = ["https://unmanaged-race.example/callback"]
' "$state_file" >"$state_file.tmp"
mv "$state_file.tmp" "$state_file"
unmanaged_plan="$test_root/unmanaged-plan"
"$ROOT_DIR/scripts/plan.sh" \
  --output-dir "$unmanaged_plan" \
  --expected-deploy-sha "$expected_sha" >/dev/null
unmanaged_hash="$(awk 'NR == 1 {print $1}' "$unmanaged_plan/plan.sha256")"
unmanaged_review="$test_root/unmanaged-review.json"
"$ROOT_DIR/scripts/review-plan.sh" --plan "$unmanaged_plan/plan.json" --expected-plan-sha "$unmanaged_hash" --expected-deploy-sha "$expected_sha" --output "$unmanaged_review" >/dev/null
unmanaged_review_hash="$(awk 'NR == 1 {print $1}' "${unmanaged_review}.sha256")"
jq -n '{armed: true, clientId: "klyrow-portal", remainingGets: 1, kind: "unmanaged"}' >"$control_file"
"$ROOT_DIR/scripts/apply-plan.sh" \
  --plan "$unmanaged_plan/plan.json" \
  --expected-plan-sha "$unmanaged_hash" \
  --review "$unmanaged_review" \
  --expected-review-sha "$unmanaged_review_hash" \
  --expected-deploy-sha "$expected_sha" \
  --recovery-dir "$test_root/recovery-unmanaged-race" >/dev/null
jq -e '
  .["klyrow-portal"].representation.unmanagedConcurrentMarker == "preserved"
  and .["klyrow-portal"].representation.redirectUris == ["https://klyrow.com/"]
' "$state_file" >/dev/null

jq -S 'del(."klyrow-portal")' "$state_file" >"$state_file.tmp"
mv "$state_file.tmp" "$state_file"
missing_dir="$test_root/missing-creatable"
"$ROOT_DIR/scripts/plan.sh" \
  --output-dir "$missing_dir" \
  --expected-deploy-sha "$expected_sha" >/dev/null
[[ "$(jq -er '.blockedCount' "$missing_dir/plan.json")" -eq 0 ]]
[[ "$(jq -er '.clients[] | select(.clientId == "klyrow-portal") | .action' "$missing_dir/plan.json")" == "create" ]]
jq -e '
  .clients[]
  | select(.clientId == "klyrow-portal")
  | .before == {}
    and .rollback.kind == "disable_then_reviewed_delete"
    and .rollback.disableFirst == true
    and .rollback.deleteRequiresSeparateReviewedRollback == true
' "$missing_dir/plan.json" >/dev/null

# Bootstrap regression: an absent realm is a reviewed CREATE owned by the
# governed deploy pipeline. No client read occurs before the realm exists.
printf '{}\n' >"$state_file"
jq -n '{realmMissing: true}' >"$control_file"
export KC_SMTP_CREDENTIAL_VERSION="ci-bootstrap-v1"
bootstrap_plan="$test_root/bootstrap-plan"
"$ROOT_DIR/scripts/plan.sh" \
  --output-dir "$bootstrap_plan" \
  --expected-deploy-sha "$expected_sha" >/dev/null
[[ "$(jq -er '.realmPolicy.action' "$bootstrap_plan/plan.json")" == "create" ]]
[[ "$(jq -er '.realmPolicy.before == {}' "$bootstrap_plan/plan.json")" == "true" ]]
[[ "$(jq -er '.createCount' "$bootstrap_plan/plan.json")" -eq 37 ]]
[[ "$(jq -er '.updateCount' "$bootstrap_plan/plan.json")" -eq 0 ]]
[[ "$(jq -er '.driftCount' "$bootstrap_plan/plan.json")" -eq 37 ]]
jq -e '
  .realmPolicy.rollback.kind == "disable_then_separate_reviewed_realm_delete"
  and .realmPolicy.rollback.preApplyState == "absent"
  and .realmPolicy.rollback.deleteRequiresSeparateReviewedRollback == true
  and .realmPolicy.rollback.requiresReviewedPlan == true
' "$bootstrap_plan/plan.json" >/dev/null

bootstrap_hash="$(awk 'NR == 1 {print $1}' "$bootstrap_plan/plan.sha256")"
bootstrap_review="$test_root/bootstrap-review.json"
"$ROOT_DIR/scripts/review-plan.sh" \
  --plan "$bootstrap_plan/plan.json" \
  --expected-plan-sha "$bootstrap_hash" \
  --expected-deploy-sha "$expected_sha" \
  --output "$bootstrap_review" >/dev/null
bootstrap_review_hash="$(awk 'NR == 1 {print $1}' "${bootstrap_review}.sha256")"
"$ROOT_DIR/scripts/apply-plan.sh" \
  --plan "$bootstrap_plan/plan.json" \
  --expected-plan-sha "$bootstrap_hash" \
  --review "$bootstrap_review" \
  --expected-review-sha "$bootstrap_review_hash" \
  --expected-deploy-sha "$expected_sha" \
  --recovery-dir "$test_root/recovery-bootstrap" >/dev/null

jq -e '.realm == "codestra" and .enabled == true' "$realm_state_file" >/dev/null
[[ "$(jq -er 'length' "$state_file")" -eq 36 ]]
jq -e '
  .partialApply == false
  and .operations[0].resourceType == "realm"
  and .operations[0].action == "create"
  and .operations[0].state == "created"
  and ([.operations[] | select(.resourceType == "client")] | length == 36)
  and all(.operations[] | select(.resourceType == "client"); .state == "created")
' "$test_root/recovery-bootstrap/recovery-manifest.json" >/dev/null

bootstrap_converged="$test_root/bootstrap-converged"
"$ROOT_DIR/scripts/plan.sh" \
  --output-dir "$bootstrap_converged" \
  --expected-deploy-sha "$expected_sha" >/dev/null
[[ "$(jq -er '.driftCount' "$bootstrap_converged/plan.json")" -eq 0 ]]
[[ "$(jq -er '.blockedCount' "$bootstrap_converged/plan.json")" -eq 0 ]]
[[ "$(jq -er '.createCount' "$bootstrap_converged/plan.json")" -eq 0 ]]
[[ "$(jq -er '.updateCount' "$bootstrap_converged/plan.json")" -eq 0 ]]
printf 'REALM_BOOTSTRAP_CREATE_GATE=PASS\n'

printf 'PLAN_GATE_TESTS=PASS\n'
printf 'INDEPENDENT_DRIFT_REVIEW_GATE=PASS\n'
printf 'ADMIN_AUTH_REALM=master\n'
printf 'TARGET_REALM=codestra\n'
printf 'REVIEWED_CREATE_TESTS=PASS\n'
printf 'CREATE_PREWRITE_RACE_GUARD=PASS\n'
printf 'UPDATE_PREWRITE_RACE_GUARD=PASS\n'
printf 'UNMANAGED_CONCURRENT_STATE_PRESERVATION=PASS\n'
printf 'PARTIAL_APPLY_RECOVERY_MANIFEST=PASS\n'
printf 'ROLLBACK_EVIDENCE_TESTS=PASS\n'
printf 'MAPPER_NORMALIZATION_TESTS=PASS\n'
printf 'PRODUCT_MACHINE_CLIENT_CREATE_TESTS=PASS\n'
printf 'KLYROW_PORTAL_REVIEWED_CREATE=PASS\n'
printf 'SMTP_CREDENTIAL_ROTATION_PLAN=PASS\n'
