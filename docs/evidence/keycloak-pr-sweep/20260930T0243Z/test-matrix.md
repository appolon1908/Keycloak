# Requirement to code to test matrix

Status values: `VERIFIED` (code and a passing test on the exact commit), `REPAIRED`
(gap reproduced and fixed in this run, then verified), `EXTERNAL` (needs a live system or
another owner), `DECISION` (needs an owner decision), `UNRESOLVED`.

Certification of record for the candidate code commit `63f01a4`: Linux clone
(python:3.12-slim, jq, shellcheck, curl, ripgrep, PyYAML 6.0.3, pytest 9.1.1) running the same
commands as the protected `validate-source` and `validate-merge-result` jobs.

| Gate on `63f01a4` | Result |
|---|---|
| release-intent gate (`scripts/release`) | 9 tests OK |
| `./scripts/validate.sh` | `VALIDATION=PASS` |
| repository-name authority, Stage 6, governance | PASS |
| service, Kong, n8n, registry, Beyvra, MoneyBee, password-reset validators | PASS |
| `test-plan-gate.sh` (mock Keycloak) | PASS, including `PLAN_ENVIRONMENT_SCOPE_EXCLUSION` and `APPLY_UNAUTHORIZED_EXCLUSION_FAIL_CLOSED` |
| `validate-workflows.py` | `WORKFLOW_POLICY=PASS` |
| `pytest -q tests` | 438 passed, 684 subtests passed |
| `unittest discover -s tests` | OK |
| identity compiler `--check` | PASS |
| executable closure | 13 of 13 digests and the manifest digest match |
| `git diff --check`, private-key scan | PASS |
| image build (host Docker) | PASS |
| Postman control-API suite (Newman, loopback, mutation disabled) | 20 requests, 45 assertions, 0 failed |

## K4A environment-scoped clients

| Requirement | Code | Test | Status |
|---|---|---|---|
| Staging includes, production and TEST_SYN exclude `klyrow-staging-portal` | `config/policy/environment-scoped-clients.json`, `plan.sh`, `scoped_for_environment` | plan gate production plan; `test_apply_and_drift_exclude_environment_scoped_clients_outside_their_environments` | VERIFIED |
| Unknown environment carries no scoped client | `scoped_for_environment`, `plan.sh` environment gate | `test_scoped_for_environment_drops_scoped_client_roles_and_mappings_outside_its_environments`; `test_unknown_environment_exports_no_scoped_client` | VERIFIED |
| Wrong target realm or host refused | `keycloak_assert_canonical_configuration`, control-API issuer binding | plan gate endpoint checks; `test_apply_refuses_unknown_environment_and_foreign_issuer` | VERIFIED |
| Tampered client set, removed exclusion or stale review refused | `apply-plan.sh` policy-derived client and exclusion sets, plan and review hashes | plan gate tampered-exclusion and mismatched-hash cases; `validate.sh` pins the scope | VERIFIED |
| Same scoped state in rollback and drift | control API scoped rollback and drift; deploy rollback export | `test_environment_scoped_rollback_export.py`; scoped rollback tests | REPAIRED (G4) |
| Exclusion never deletes a real client | excluded client stays `KEEP` unmanaged | production drift test asserts no create, update or delete | VERIFIED |

## K4B client roles, scopes and claims

| Requirement | Code | Test | Status |
|---|---|---|---|
| Roles compile, plan and reconcile as real resources | `_client_roles`, `client_role` plan and apply | client-role apply and rollback tests | VERIFIED |
| `telephony.webphone.use` reaches the desktop token | scope mapping plus compiler token-scope check | end-to-end provision test; token-scope tests | REPAIRED (G1) |
| Undeclared, absent or foreign-client roles fail closed | contract cross-checks | `test_contract_roles_must_be_compiled_and_client_roles_need_a_compiled_client`; foreign-client test | VERIFIED |
| Duplicate declarations and conflicting mappers fail closed | `validate_mappers`, `_unique_by_path`, duplicate-role check | mapper and client-role declaration tests | REPAIRED (G2) |
| No broadened scopes, realm-admin or service privileges | scope-mapping rules; composite roles forbidden | `test_scope_mapping_cannot_broaden_privileges` (includes `realm-admin`) | REPAIRED (G2) |
| Wrong tenant or campaign | `tenant_ids` user-attribute mapper; enforcement is the consumer's | not testable here | DECISION (U3) |

## K4C PAS-237 control plane

| Requirement | Test | Status |
|---|---|---|
| Plan-only requests make no mutation | dry-run and drift tests; Newman suite | VERIFIED |
| Apply disabled by default; explicit enable plus idempotency key | `test_control_api_health_and_apply_denial`; replay tests | VERIFIED |
| Environment and realm binding | issuer-host binding tests | VERIFIED |
| Unexecutable or altered plan cannot apply; no silent expansion | `validate_plan`; `ERROR` tests; forged-plan test | REPAIRED (G3) |
| Partial failure and readback failure recorded durably | journal and readback-failure tests | VERIFIED |
| Rollback bounded by the apply's own evidence | rollback tests (created-only deletes, attribute removal, second rollback refused) | VERIFIED |
| Required actions in the canonical model | none | DECISION (U1) |
| Service-account mapping adapter | none | DECISION (U2) |

## K4D to K4H

| Area | Status | Evidence |
|---|---|---|
| K4D human accounts and service clients | VERIFIED statically; EXTERNAL live | realm security policy validator, password-reset contract and SMTP transport tests; live reset lifecycle not run (U8) |
| K4E token and browser contracts | VERIFIED statically; EXTERNAL live | V3, CIP and MCR token matrices; PKCE and redirect shape gates; JWKS rotation and revocation not run (U9) |
| K4F cross-system compatibility | VERIFIED as a read-only matrix | `identity-contract-matrix.md`; operational acceptance `NOT_VERIFIED_LIVE` |
| K4G build, closure and release trust | VERIFIED | closure digests from canonical Git blobs on Linux; Windows CRLF differences are checkout artifacts |
| K4H PowerShell handoff helper | VERIFIED | pre-repair copy reproduces `CallDepthOverflow` and fails 10 of 11 regression tests; installed repair passes 11 of 11; helper is read-only; tools directory is not a Git repository |
