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
