# Dependency map

## Within this repository

- Desired state (`config/clients`, `config/desired-state/**`, `config/policy/*`) feeds two paths:
  - the shell deploy path (`plan.sh`, `review-plan.sh`, `apply-plan.sh`, `deploy.yml`), which
    manages protected clients and the realm policy and now applies environment scoping to the
    plan, the review, the apply check and the rollback export;
  - the PAS-237 control plane (compiler, reconciliation, control API), which also manages
    client scopes, realm roles, client roles, role scope mappings and, when declared, required
    actions.
- Realm roles and role scope mappings reach Keycloak only through the control plane. The
  agent desktop contract therefore depends on a control-plane apply after the shell path has
  created `codestra-agent-desktop`.
- Contract cross-checks bind `config/contracts/*.json` to compiled roles and token scope, so a
  contract edit and its desired state must land together.
- The executable closure pins `validate.sh`, `validate.yml`, `validate-workflows.py` and ten
  other files; any change to them requires a reseal from canonical Git blobs.

## Between pull requests

| Change | Depends on | Conflicts with | Order |
|---|---|---|---|
| PR #136 (`63f01a4` and evidence) | `main` `45a487d` | trust prerequisite, in `config/bootstrap/executable-closure.json` only | independent |
| Trust prerequisite (`ab5762e`) | `main` `45a487d` | PR #136, same file | independent |

Whichever merges second must first merge `main`, reseal the closure and re-run its gates.

## Across systems (read-only, no edits made)

| Consumer | Dependency on this repository | Transfer impact |
|---|---|---|
| Middleware V3 | `middleware-api` audience and V3 route authority | none |
| Middleware realtime gateway | agent desktop realm and client roles, `tenant_ids` claim | role now in token scope; `tenant_ids` governance open (U3) |
| Kong | CIP gateway contract by SHA-256; `kong-gateway` client | none; the contract text keeps its historical repository name |
| Caddy | none (TLS edge) | none |
| Odoo, n8n, MoneyBee, Beyvra, Klyrow, MCR, Kyyow | their clients and contracts | Kyyow contract names the previous owner (U4) |
| Runtime server | git remote pinned to the previous owner | coordinated runtime change needed (U4) |
| GHCR images | namespace `ghcr.io/appolon1908-hue` | owner decision (U4) |
