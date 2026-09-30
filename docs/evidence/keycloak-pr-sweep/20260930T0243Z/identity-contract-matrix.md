# Identity contract matrix

Read-only matrix for the approved in-scope consumers, generated from
`generated/keycloak-identity-authority.v1.json` at the candidate code commit. Every client uses the
`codestra` realm; the production issuer is `https://auth.codestra.co/realms/codestra` and staging uses
`https://auth-staging.codestra.co/realms/codestra`. Client secrets are never in Git: machine clients take
them from the protected apply environment named in `config/contracts/machine-secret-destinations.json`.

Generated parity is not proof of a real login or deployed authorization flow. Operational acceptance
column values are `NOT_VERIFIED_LIVE` until the separately authorized staging mission runs them.

| Consumer | Client | Kind | Environments | Audiences emitted | Claims mapped | Roles | Operational acceptance | Owner |
|---|---|---|---|---|---|---|---|---|
| Middleware V3 API | `middleware-api` | service (client credentials) | production, staging, test-syn | kyqra-gateway, n8n-automation, odoo-integration, vicidial-adapter | scope | - | NOT_VERIFIED_LIVE | Middleware owner |
| Middleware V3 API | `middleware-worker` | service (client credentials) | production, staging, test-syn | ai-provider-adapter, klyrow-gateway, marketing-provider-adapter, middleware-api, postly-adapter, telnexa-gateway | scope | - | NOT_VERIFIED_LIVE | Middleware owner |
| Kong gateway | `kong-gateway` | service (client credentials) | production, staging, test-syn | middleware-api | scope | - | NOT_VERIFIED_LIVE | Kong owner |
| Odoo | `odoo-web` | public browser (code + PKCE) | production, staging, test-syn | - | - | - | NOT_VERIFIED_LIVE | Odoo owner |
| Odoo | `odoo-integration` | service (client credentials) | production, staging, test-syn | middleware-api | scope | - | NOT_VERIFIED_LIVE | Odoo owner |
| Odoo | `odoo-email` | service (client credentials) | production, staging, test-syn | middleware-api | scope, tenant_id | - | NOT_VERIFIED_LIVE | Odoo owner |
| n8n | `n8n-editor-gateway` | confidential browser (code) | production, staging, test-syn | - | - | - | NOT_VERIFIED_LIVE | n8n owner |
| n8n | `n8n-automation` | service (client credentials) | production, staging, test-syn | middleware-api | scope | - | NOT_VERIFIED_LIVE | n8n owner |
| Klyrow | `klyrow-portal` | public browser (code + PKCE) | production, staging, test-syn | - | - | - | NOT_VERIFIED_LIVE | Klyrow owner |
| Klyrow | `klyrow-gateway` | service (client credentials) | production, staging, test-syn | middleware-api | scope | - | NOT_VERIFIED_LIVE | Klyrow owner |
| Klyrow | `klyrow-staging-portal` | public browser (code + PKCE) | staging | klyrow-api | - | - | NOT_VERIFIED_LIVE | Klyrow owner |
| Agent desktop and webphone | `codestra-agent-desktop` | public browser (code + PKCE) | production, staging, test-syn | codestra-agent-desktop | tenant_ids | client: realtime.agent.connect; realm scope: telephony.webphone.use | NOT_VERIFIED_LIVE | Middleware realtime gateway owner |
| Beyvra | `beyvra-backend` | service (client credentials) | production, staging, test-syn | middleware-api | scope, tenant_id | - | NOT_VERIFIED_LIVE | Beyvra owner |
| MoneyBee | `moneybee-admin` | public browser (code + PKCE) | production, staging, test-syn | moneybee-api | - | - | NOT_VERIFIED_LIVE | MoneyBee owner |
| MoneyBee | `moneybee-borrower` | public browser (code + PKCE) | production, staging, test-syn | moneybee-api | - | - | NOT_VERIFIED_LIVE | MoneyBee owner |
| MoneyBee | `moneybee-lender` | public browser (code + PKCE) | production, staging, test-syn | moneybee-api | - | - | NOT_VERIFIED_LIVE | MoneyBee owner |
| MoneyBee | `moneybee-backend` | service (client credentials) | production, staging, test-syn | middleware-api | scope, tenant_id | - | NOT_VERIFIED_LIVE | MoneyBee owner |

## Other compiled clients

Listed for completeness; their consumers are outside this matrix's approved scope.

| Client | Kind | Audiences emitted |
|---|---|---|
| `ai-provider-adapter` | service (client credentials) | ai-provider-adapter |
| `alertmanager` | service (client credentials) | middleware-api |
| `breero-backend` | service (client credentials) | middleware-api |
| `codestra-ai` | service (client credentials) | middleware-api |
| `codestra-communication` | service (client credentials) | middleware-api |
| `codestra-marketing` | service (client credentials) | middleware-api |
| `codestra-provisioning-service` | service (client credentials) | codestra-provisioning-service |
| `codestra-social` | service (client credentials) | middleware-api |
| `kyqra-gateway` | service (client credentials) | middleware-api |
| `larim-a-backend` | service (client credentials) | middleware-api |
| `marketing-provider-adapter` | service (client credentials) | marketing-provider-adapter |
| `monitoring-readonly` | service (client credentials) | middleware-api |
| `postly-adapter` | service (client credentials) | middleware-api |
| `production-operator` | service (client credentials) | middleware-api |
| `provisioning-service` | service (client credentials) | middleware-api |
| `sdk-intake` | service (client credentials) | middleware-api |
| `social-codestra` | service (client credentials) | middleware-api |
| `telnexa-gateway` | service (client credentials) | middleware-api |
| `transportation-backend` | service (client credentials) | middleware-api |
| `vicidial-adapter` | service (client credentials) | middleware-api |

## Contracts consumed by digest or by name

- Kong consumes `release/cip-tenant-identity/keycloak-cip-gateway-identity-contract.v1.json` by SHA-256.
- MCR consumes `contracts/mcr-identity-v1.json`; Kyyow consumes `contracts/kyyow-saas-identity-v1.json`.
- The Middleware realtime gateway consumes `config/contracts/agent-desktop-realtime-client.json`: realm role
  `telephony.webphone.use` (now in the desktop's role scope mapping) and client role
  `codestra-agent-desktop:realtime.agent.connect`.
- Caddy owns public TLS only and issues no identity; Kong and Middleware revalidate tokens.

## Open owner decision

`codestra-agent-desktop` and `telnexa-gateway` map the `tenant_ids` user attribute into access tokens. No
document in this repository declares that attribute in the realm user profile or restricts who may edit
it. The owner must confirm, by live readback, that users cannot edit their own `tenant_ids`, or add a
reviewed user-profile declaration with administrator-only edit.
