# Production deployment

The approved checkout is `/srv/keycloak`, cloned with a read-only deploy key from `git@github.com:appolon1908-hue/Keycloak.git`. Check out `main` at the exact approved 40-character SHA without local modifications. Keep environment files and SSH material outside the checkout. Run `runtime-preflight.sh --expected-deploy-sha SHA --require-approved FINGERPRINT`, then the protected CHECK workflow. APPLY requires the identical SHA, plan artifact and SHA-256, independent review and GitHub production-environment approval.

Never run `docker compose up`, APPLY, DNS changes, credential rotation or retirement as an incidental migration step. The repository prepares those operations; an approved cutover performs them.

Before any release, read back the GitHub environment configuration and prove required reviewers, self-review prevention, no administrator bypass, and protected-branch-only deployment. The current private-repository billing plan rejected these controls with HTTP 422 during the 2026-08-29 audit; production APPLY is blocked until the account plan or repository ownership supports them.

## PostgreSQL volume initialization

The pinned PostgreSQL 17.6 Alpine image uses UID/GID `70:70`. Compose first
runs `postgres-volume-init`, a one-shot container with no network, credentials
or published ports. It grants only `CHOWN` and `FOWNER` to set the data volume
root's owner and mode (`0700`). It does not recursively change existing data.

The PostgreSQL service waits for that step to succeed and runs as `70:70`,
with all capabilities dropped, a read-only root filesystem and an explicitly
owned `/run/postgresql` tmpfs. Both first startup and subsequent recreation
use the same persistent data volume. Do not delete that volume to fix a
startup failure. Data from a different image UID or major version requires a
separately reviewed migration; the initializer does not migrate its contents.

Run the disposable runtime regression checks before reviewing a deployment:

```bash
python3 -m pytest -q tests/integration/test_postgres_runtime.py
```

These checks require Docker Compose and exercise the production PostgreSQL
service with generated test credentials and a unique project name. They
verify empty-volume readiness, row persistence after runtime recreation and
non-root/capability/port isolation, then remove only their own containers and
volumes. They do not start Keycloak or connect to a production database.
