# Docker verification

## Result

`DOCKER_LOCAL_VALIDATION=BLOCKED`. Image builds of the candidate passed earlier in this run,
but the disposable Keycloak runtime check could not start: the shared Docker Desktop engine
stopped serving at about 05:08 UTC on 2026-09-30, and this mission may not restart it.

## Evidence that ran

| Check | Source | Result | When (UTC) |
|---|---|---|---|
| Image build (`docker build`, repository `Dockerfile`) | `63f01a46a68a6a3aab0ba06bae47fac34a12a891` | PASS, image `sha256:562e6d8fce0797ca5ca56a2f2a39f8f76cb62d203c1a9af126069c6115a8d68f` | 2026-09-30 04:47 |
| Image build | `f2bdb641ad33082b7a190de5ab91316f6dc7d9f3` | PASS, image `sha256:0507801ba137e2aa5df59bef602f0d16b635811d88b7a55671b442332ac07220` | 2026-09-28 16:30 (historical) |
| Compose render (`docker compose config --quiet`) with the CI placeholder values | `compose.yaml` unchanged since `ec74dc3` (2026-09-09) | PASS on 2026-09-28 for the same bytes (historical) | 2026-09-28 |
| Linux certification in a `python:3.12-slim` container | `63f01a4` and `ab5762e` | PASS (see `test-matrix.md`) | 2026-09-30 before 05:08 |

The build context is the exact commit's checkout; the Linux certification clones the commit
into the container, so file modes and Git-blob bytes are Linux-native there.

## What did not run

| Check | Status | Reason |
|---|---|---|
| Linux certification of the evidence head | NOT_RUN | the container never started (exit 127) once the engine stopped |
| Disposable Keycloak and PostgreSQL stack on loopback, readiness and management probes | NOT_RUN | engine unavailable |
| Control-plane apply and readback against a disposable realm | NOT_RUN | engine unavailable |

## Engine diagnosis (read-only)

- `docker version` and `docker info` time out after 20 seconds.
- The engine pipe `\\.\pipe\docker_engine` is absent, while the `docker-desktop` WSL
  distribution reports Running and the Docker Desktop backend processes, started 2026-09-28,
  are alive.
- Host resources were not the cause: 5.6 GB of 32 GB memory free and 362 GB of disk free.
- The only action taken was stopping this session's own two stuck `docker` client commands.
  No container, image, volume, network or engine setting was changed, and no other agent's
  workload was touched.

## To finish this check

After the workstation owner restarts Docker Desktop, run one disposable stack with a unique
project name, loopback-only ports and synthetic credentials, built from the exact candidate:
start Keycloak and PostgreSQL, wait for the management interface's readiness endpoint, import
the `codestra` realm, run the control plane against it (dry-run, apply, readback, rollback),
confirm through the Admin API that the agent desktop client, its client role and its
scope-mapped realm role exist, run the Postman collection against that control plane, then
remove only that project's containers, network and volumes.

## Disposable realm run, 2026-09-30 (branch `feat/keycloak-pas237-security-model-20260930`)

After the workstation owner restarted Docker Desktop, one disposable stack ran on loopback
with a unique project name (`kc-disp-c0d4c9b`) and throwaway credentials: Postgres
`17.6-alpine` and Keycloak `26.7.2` built from the exact bytes of `c0d4c9b` (image
`sha256:3c6d3a339d82eb0c8376cd0369f2787ecf3812dc001bd3adb19fc799115efdef`), ports bound to
`127.0.0.1` only, an empty `codestra` realm, and the control plane in `test-syn` mode.

| Step | Result |
|---|---|
| Readiness on the management interface | ready after 50 s |
| First full apply with the code as published | `PARTIAL_FAILURE`: HTTP 500, `value too long for type character varying(255)` |
| Same desired state after the fixes | `REJECTED` before any write: eight `keycloak_column_too_long` errors, all in the Kong-pinned CIP plan and the two platform-command scopes it reuses |
| Apply of everything else (harness leaving out only those eight) | all writes landed; readback first showed perpetual drift from five representation differences, fixed on the branch |
| Apply after the fixes, twice | `COMPLETED`, readback equal, no mutation on the repeat |
| Admin API readback | agent desktop client with `fullScopeAllowed: false`, client role `realtime.agent.connect`, scope-mapped `telephony.webphone.use`; `moneybee-verify-email-otp` registered and enabled; `tenant_id` and `tenant_ids` view and edit admin only; `klyrow-staging-portal` absent from `test-syn` |
| Rollback of the first apply | `COMPLETED`, readback equal: realm empty again, attributes removed, provider unregistered |
| Teardown | containers, network and volume removed; credentials deleted; the image kept as local build evidence |

Findings fixed on the branch: the MoneyBee provider is not registered by Keycloak itself;
over-length values; role lists omit attributes unless full representations are requested;
omitted `false` flags; the automatic `service_account` default scope; mapper config defaults
and dropped empty values. Still open: the eight over-length values (decision D3).

## Final disposable realm run on `59f06e37eeb65738a14bc71969b07d67f197b75f`

Same method as above, project `kc-disp-59f06e3`, image built from the exact commit
(`sha256:8f4801da3a34c585173026988f98f31d015598da3aa4256b906e5e4cebde0c05`), the real control API
with the complete desired state and nothing excluded.

| Step | Result |
|---|---|
| Readiness | ready after 40 s |
| Live-backend Postman lifecycle | 11 requests, 32 assertions, 0 failed: apply `COMPLETED` with readback equal, drift all `KEEP`, repeat apply without mutation, replay returns the same execution, hashed and redacted evidence, rollback `COMPLETED`, second rollback refused |
| Second apply and Admin API field checks | apply `COMPLETED`, readback equal; 973 checks, 0 failures: 17 roles with descriptions and 116 attributes, 36 clients with descriptions, 206 flags, 31 default-scope sets, 80 mappers with 397 config values, 14 scopes with descriptions, 4 required actions, 2 profile attributes, agent desktop role and scope mapping, staging portal absent |
| Rollback | `COMPLETED`, readback equal; realm back to Keycloak's six built-in clients and three built-in roles, default profile, MoneyBee provider unregistered |
| Teardown | containers, network and volume removed; throwaway credentials and local evidence directories deleted |
