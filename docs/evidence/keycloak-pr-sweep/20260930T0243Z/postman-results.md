# Postman results

## Collection

| Field | Value |
|---|---|
| File | `postman/keycloak-control-api.postman_collection.json` (the repository's only Postman collection) |
| SHA-256 at `63f01a4` | `73bb6f092dbcafc4bb17d9243ae6748a774bf2ddd1000dfdc59d2cc69ad8e417` |
| Requests | 20 (13 GET, 7 POST), all to `{{baseUrl}}/platform/v1/keycloak/...` |
| Scripts | test assertions only; no `pm.sendRequest`, no pre-request scripts |
| Hosts in the file | `http://127.0.0.1:8785` (default `baseUrl`), the production issuer as request-body data only, and the Postman schema URL |

## Run of record

| Field | Value |
|---|---|
| Source | `63f01a46a68a6a3aab0ba06bae47fac34a12a891` (clean worktree) |
| Target | `scripts/keycloak_control_api.py --port 8785` on loopback, no admin backend configured, `KEYCLOAK_MUTATION_ENABLED` unset, evidence written to a private directory |
| Runner | `npx newman@6 run ... --env-var baseUrl=http://127.0.0.1:8785` |
| Result | 20 requests, 20 test scripts, 45 assertions, 0 failed; exit code 0 |
| Finished | 2026-09-30 04:55 UTC |

Coverage type: fail-closed control-API behavior without a Keycloak backend (health,
desired state including environment scopes and compiled agent-desktop roles, validation,
apply refused while disabled, backend-unavailable drift and observability, invalid limits,
missing executions and evidence, redacted recovery, promotion blocks, unknown route).

## Earlier runs (historical)

`f2bdb641ad33082b7a190de5ab91316f6dc7d9f3` on 2026-09-29: 20 requests, 45 assertions, 0 failed.

## Not run

Validation of the same collection against a control plane backed by a disposable Keycloak
realm is `NOT_RUN`: it depends on the Docker runtime in `docker-verification.md`. Postman Desktop
was not opened; Newman ran the repository's collection directly.

## Disposable realm, 2026-09-30

The same collection against the realm-backed control plane: 20 requests, 34 of 45 assertions
passed. The 11 failures are the collection's no-backend contract (`503` without an admin
backend, `403` while apply is disabled, `apply_disabled` before evidence lookup), which a
realm-backed, mutation-enabled service rightly does not return. The collection's apply found
nothing to change, and its rollback request named a missing id (`404`). The collection has no
backed-mode variant; the realm-backed API behaviour is evidenced by the apply, readback,
repeat-apply and rollback results in `docker-verification.md`.
