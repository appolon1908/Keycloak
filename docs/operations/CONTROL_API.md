# Keycloak control API

`scripts/keycloak_control_api.py` is the PAS-237 identity control plane: a
loopback-only HTTP service that compiles the checked-in identity authority,
plans drift against the live realm, and, only when explicitly enabled, applies
and rolls back that plan with durable evidence. It never replaces the reviewed
GitHub `check`/`apply` workflow; it is the programmatic surface behind it.

## Fail-closed defaults

- The server refuses any bind other than `127.0.0.1`, `::1` or `localhost`.
- Live mutation is disabled unless `KEYCLOAK_MUTATION_ENABLED=true`; every
  apply or rollback is `403 apply_disabled` before any evidence lookup.
- Deletes stay disabled unless `KEYCLOAK_DELETE_ENABLED=true`, and even then
  only resources the original apply created may be deleted by a rollback.
- `KEYCLOAK_ENVIRONMENT` must name `production`, `staging` or `test-syn`
  (`TEST_SYN` is accepted). The admin host must match that environment's
  issuer; `test-syn` may never target the production or staging issuer.
- The admin adapter accepts HTTPS or loopback HTTP only and refuses redirects,
  so the bearer never leaves the configured host.
- Secret material is redacted before evidence is written and the store
  rejects any record that still carries a secret-bearing value.
- Environment scoping from `config/policy/environment-scoped-clients.json` is
  applied to every plan, drift, apply, rollback and observability read: a
  client scoped to other environments is excluded from the desired state, and
  a live copy of it is left unmanaged. An unknown environment excludes every
  scoped client.

## Environment

| Variable | Purpose |
|---|---|
| `KEYCLOAK_ADMIN_BASE_URL` | Admin API origin; must be HTTPS or loopback |
| `KEYCLOAK_ADMIN_BEARER` | Admin bearer token, never logged or stored |
| `KEYCLOAK_ENVIRONMENT` | `production`, `staging` or `test-syn` |
| `KEYCLOAK_MUTATION_ENABLED` | `true` enables apply and rollback |
| `KEYCLOAK_DELETE_ENABLED` | `true` lets an apply delete managed resources |
| `KEYCLOAK_CONTROL_EVIDENCE_DIR` | Evidence root, created `0700`, must be owned by the service user |
| `KEYCLOAK_BACKUP_DIR` | Encrypted PostgreSQL backups read by the recovery controller |
| `KEYCLOAK_RESTORE_EVIDENCE_DIR` | Restore rehearsal evidence read by the recovery controller |

## Routes

All routes live under `/platform/v1/keycloak`. Responses are JSON with
`ok`, echo `X-Correlation-ID`, and carry `Cache-Control: no-store`.

| Method | Route | Behaviour |
|---|---|---|
| GET | `/health` | Service status, `applyEnabled`, normalized environment |
| GET | `/desired-state` | Compiled identity authority, including `clientRoles` and `environmentScopes` |
| POST | `/compile` | Read-only compile; reports `generatedDrift` against `generated/` |
| POST | `/validate` | Compiles and counts clients, scopes, client roles and environment-scoped clients |
| GET | `/drift` | Reconciliation plan against the live realm |
| POST | `/reconcile/dry-run` | Persists a `DRY_RUN` execution with the plan |
| POST | `/reconcile/apply` | Requires `X-Idempotency-Key`; live apply with evidence |
| POST | `/reconcile/rollback` | Body `{"executionId": ...}`; restores an apply's pre-state |
| GET | `/reconcile/executions/{id}` | Execution payload |
| GET | `/reconcile/executions/{id}/evidence` | Execution evidence envelope with `sha256` |
| GET | `/reconcile/rollbacks/{id}` | Rollback evidence envelope with `sha256` |
| GET | `/recovery/status`, `/recovery/backups`, `/recovery/restores` | Backup and restore-rehearsal evidence, redacted |
| POST | `/recovery/validate` | Persists a recovery policy evaluation |
| GET | `/observability/status` | Managed drift, `pendingMutations`, `eventsEnabled` |
| GET | `/observability/events?limit=` | Redacted realm events, `1..500` |
| GET | `/observability/metrics?limit=` | Failure counters including `keycloak_readback_failures` |
| GET | `/promotion/policy` | Promotion policy constants |
| POST | `/promotion/plan` | Deterministic promotion packet; TEST_SYN can never reach production |
| GET | `/promotion/plans/{id}` | Stored promotion packet |

## Managed resources

A plan orders its actions by resource type: `realm`, `user_profile_attribute`,
`client_scope`, `realm_role`, `client`, `client_role`, `scope_mapping`,
`service_account_roles`, `required_action`.
Each action is `CREATE`, `UPDATE`, `DELETE`, `KEEP` or `ERROR`.

`ERROR` marks a managed resource the plan cannot reconcile. Its `reason`
names the cause: `missing_internal_id:<id>` for a live client or client scope
without a Keycloak id, `client_role_client_missing:<clientId>:<role>` for a
role whose client is neither desired nor live, and
`scope_mapping_role_missing:<roles>` for a scope mapping naming a realm role
that is neither desired nor live, `required_action_not_registered:<alias>` for a
declared required action the server does not list,
`service_account_role_missing:<roles>` for a service-account grant naming a realm
role that is neither desired nor live, and `service_account_client_missing:<clientId>`
for a grant whose client is neither desired nor live. Drift and dry-run show these actions; an
apply whose plan carries one is `REJECTED` with that reason before any write,
and readback and observability count it as unconverged.

Client roles are declared once per client under
`config/desired-state/<group>/client-roles/<clientId>.json` and compiled into
`clientRoles`; the client must be compiled in the same authority. A role's plan
id is `<clientId>:<roleName>`. Its client is resolved by `clientId` at apply
time, so a role can be created in the same plan as its client. Live roles that
desired state does not declare are unmanaged and kept. A rollback deletes only
roles the apply created, and never separately from a client that the same plan
deletes (`deleted_with_client`).

The compiler fails closed when a checked-in contract under `config/contracts/`
requires a realm role or client role that is not compiled
(`contract_realm_role_unprovisioned`, `contract_client_role_unprovisioned`).
A client with `fullScopeAllowed: false` only carries its own client roles and
the realm roles in its role scope mapping into a token, so a required realm
role outside that mapping fails with `contract_realm_role_not_in_token_scope`,
and another client's roles fail with `contract_client_role_not_in_token_scope`.
The agent desktop contract therefore provisions `telephony.webphone.use`,
`codestra-agent-desktop:realtime.agent.connect` and the desktop's scope mapping
for the realm role from `config/desired-state/agent-desktop-identity/`.

Role scope mappings under `config/desired-state/<group>/scope-mappings/` must
name a compiled client, keep `fullScopeAllowed` and `crossFamilyRolesAllowed`
false, and list distinct compiled realm roles from a single
`codestra.role.family`. Protocol mappers on a client or client scope need a
unique name, and no two of them may write the same `claim.name`.

Required actions are compiled from `config/security/required-actions.json`.
Every switch in the `requiredActions` section of
`config/security/realm-security-policy.json` is covered exactly once: either by
a required-action alias whose `enabled` equals the switch, or by a managed realm
setting with the same value (`verifyEmail` maps to the realm's `verifyEmail`,
because MoneyBee's email code replaces Keycloak's link verification). The
compiled row holds `alias`, `enabled` and `defaultAction`; an update sends the
live provider record with those fields replaced, so its name, priority and
configuration are kept. A provider the server ships but the realm has not
registered (Keycloak does not register custom providers such as
`moneybee-verify-email-otp` by itself) is planned as `CREATE`: the apply
registers it and then sets its declared flags. A provider the server does not
ship at all is an `ERROR`. A rollback unregisters only a provider its apply
registered.

Keycloak keeps names, descriptions and URLs of clients, client scopes and roles
in 255-character columns. The compiler rejects a longer declared value for any
protected client, staged client, client scope, realm role or client role
(`keycloak_column_too_long:<resource>:<field>:<length>`), and the plan also
marks one as `ERROR` before any write, so an apply never fails part-way with a
database error.

`postman/keycloak-control-api.postman_collection.json` covers the fail-closed
contract without a backend. `postman/keycloak-control-api.live-backend.postman_collection.json`
runs the full lifecycle against a control plane backed by a disposable, empty
TEST_SYN realm with mutation enabled: apply, convergence, idempotent repeat and
replay, hashed evidence, rollback and refusal of a second rollback. Never point
it at staging or production.

Live readback is compared the way Keycloak stores it: role lists are read with
full representations so attributes are compared, a declared `false` flag matches
an omitted one, the built-in `service_account` default scope Keycloak adds to
service clients is ignored unless declared, and mapper configuration is compared
on declared keys only, with a declared empty value matching an omitted one.

Service-account realm roles are declared under
`config/desired-state/<group>/service-account-roles/<clientId>.json` as
`{"clientId": ..., "realmRoles": [...]}`. The client must be a protected service
client, every role must be a compiled realm role with
`codestra.actor.kind: ["service"]` that is not `PREPARED_DISABLED`, the roles
must share one `codestra.role.family`, and each must also be in the client's role
scope mapping, because a service client never has full scope and a role outside
that mapping would never reach its token. Once declared, the service account's
realm roles are exactly the declared set; the realm's `default-roles-*`
composite is left alone. No grant is declared yet; the prepared CIP service
grants stay with their own staging reconciler.

User-profile attributes are declared in `config/security/user-profile.json`.
Each must give edit rights to administrators only, must not be a Keycloak
built-in attribute or an attribute a desired-state family declares under its own
`user-profile/`, and may carry only `name`, `displayName`, `multivalued`,
`permissions`, `validations` and `annotations`. Every user attribute that a
compiled client, staged client or client scope copies into a token with an
attribute mapper must be declared admin-edited here or by its family
(`token_claim_attribute_not_admin_only`), so a user can never choose a claim.
`tenant_id` and `tenant_ids` are declared this way. The plan appends missing
attributes, replaces a declared attribute whose declared fields drift, and keeps
every other attribute, the groups and the unmanaged-attribute policy. A rollback
deletes only attributes its apply created and restores replaced ones exactly.

## Integrity and ownership

- Every plan carries `desiredSha256`, `liveSha256` and `planSha256`. Apply recomputes all three and refuses, before any write, a plan whose contents no longer match its hash (`plan_integrity_mismatch`) or that was computed from a different desired or live state (`plan_stale_desired_state`, `plan_stale_live_state`).
- An idempotency key replays only the desired state it was first used for; reusing it for a different desired state is `409 idempotency_key_conflict`.
- The compiled authority carries an `ownership` registry: every client, client scope, realm role, client role, scope mapping, service-account grant, user-profile attribute and protocol mapper with its authority group and source file. A second declaration of any of them, identical or not and in any authority group, fails compilation (`identity_multiple_owners`, `duplicate_<type>`).
- `config/policy/identity-emitters.json` lists every script that can write to the Admin API. `keycloak_admin_api.py` is the only canonical adapter; the shell deploy path and the family staging reconcilers are recorded with their scope and retirement note, and a new writer fails CI until it is classified.
- The source digest is computed last, over the complete compiled model, and the committed authority must equal a fresh compilation byte for byte.

## Writer authority

`config/policy/reconciler-authority.json` gives every Keycloak object exactly one writer per
environment. In production and staging the governed deploy pipeline (`deploy.yml`, reviewed
plan and independent drift review) owns the realm and the protected clients, and in staging the
Stage 6 monitoring reconciler owns `health.read` and `metrics.read`. The control plane plans an
object owned by another writer as `HOLD` with reason `owned_by:<writer>`: it is never written,
never deleted, and never counted as drift or unconverged readback. TEST_SYN holds nothing, so
the disposable realm exercises every write path. `monitoring-readonly` is environment-scoped to
production and TEST_SYN, leaving the Stage 6 reconciler as its only staging writer.

## Service identities

The compiled authority carries `serviceIdentities`: one entry per protected service client,
built only from canonical sources. Owners come from the CODEOWNERS entry for `/config/`;
purpose from the service access matrix (kind and granted scopes), the product client contract,
or the client's own specific description; credentials from the machine secret destinations with
the rotation limit in `config/policy/service-identity-policy.json`; Keycloak admin access from
the matrix's administrative boundaries or a sourced policy override; risk from a fixed rule
(admin access, any non-read scope or a declared privilege is high; read-only scopes medium;
none low). A service client with no purpose source or no secret destination fails compilation.

## Apply evidence and statuses

An apply writes its execution record before the first mutation. The record
holds the plan, the desired and live digests, the redacted pre-state and the
paths that were redacted. If the record cannot be written nothing is applied.

| Status | Meaning |
|---|---|
| `IN_PROGRESS` | Evidence written, mutations not yet journaled; rollback is refused |
| `REJECTED` | Pre-flight validation failed; no mutation happened |
| `FAILED` | The apply raised before mutating (for example an environment mismatch) |
| `APPLIED_PENDING_READBACK` | Mutations journaled; readback not yet recorded |
| `COMPLETED` | Applied and the readback shows no pending managed mutation |
| `READBACK_MISMATCH` | Applied but the realm still needs managed mutations |
| `PARTIAL_FAILURE` | A mutation failed; the journal lists what completed |
| `READBACK_UNAVAILABLE` | Applied but the admin API could not be read back |

`mutationPerformed` reflects real CREATE, UPDATE or DELETE journal entries.
`attributeAdditions` records the client attributes the apply introduced so a
later rollback removes exactly those, regardless of how the desired state has
moved since. A second apply with the same idempotency key returns the stored
record without touching Keycloak; while a record is `IN_PROGRESS` or
`APPLIED_PENDING_READBACK` the replay is refused with `409 apply_in_progress`.

APPLY and ROLLBACK records are never pruned by the evidence store.

## Rollback rules

- Only an `APPLY` record with a pre-state can be rolled back, in the same
  environment the apply targeted.
- A rollback deletes only resources that the apply created and drops only the
  attributes that the apply added; anything that appeared since is preserved.
- The rollback plan is persisted before the first mutation and the journal is
  persisted before readback, with the same status vocabulary as an apply.
- The source execution is marked `ROLLED_BACK` only when the readback confirms
  the pre-state; otherwise it is `ROLLBACK_FAILED` and another attempt is
  allowed. A `ROLLED_BACK` execution refuses a second rollback with
  `409 rollback_already_applied`.

## Error codes

| HTTP | Code |
|---|---|
| 400 | `idempotency_key_required`, `invalid_request` (including a malformed `promotionId`), `invalid_json`, `invalid_query` |
| 403 | `apply_disabled` |
| 404 | `execution_not_found`, `rollback_not_found`, `promotion_not_found`, `not_found` (also for any path deeper than a record route) |
| 405 | `method_not_allowed` for PUT, DELETE, PATCH and OPTIONS, with `Allow: GET, POST` |
| 409 | `idempotency_key_conflict`, `apply_in_progress`, `environment_unknown`, `environment_issuer_mismatch`, `environment_mismatch`, `rollback_not_available`, `rollback_already_applied`, `promotion_exists` |
| 413 | `request_too_large` |
| 503 | `admin_not_configured`, `admin_transport_error`, upstream `admin_http_error` keeps its status |
| 500 | `internal_error`; the class and message are logged to stderr with the correlation id |

## Verification

```bash
python3 -m pytest -q tests/test_pas237_keycloak_control_plane.py tests/test_keycloak_core_build.py
```

`postman/keycloak-control-api.postman_collection.json` runs against a service
started with no admin backend and mutation disabled, and asserts every
fail-closed response above. The generated authority must match
`python3 scripts/keycloak_identity_compiler.py --check` before any apply.
