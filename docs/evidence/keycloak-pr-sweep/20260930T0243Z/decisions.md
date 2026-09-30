# Decisions needed from owners

Each item is blocked on a decision or a live system, not on routine work. None is implemented
by guessing.

| Id | Decision | Why it matters | Owner | Suggested next step |
|---|---|---|---|---|
| U1 | Required-action desired state: aliases, `enabled`, `defaultAction` and priority for TOTP, update password, MoneyBee email OTP and privileged WebAuthn | PAS-237 section 1 lists required actions; today they exist only as booleans in `config/security/realm-security-policy.json`, so the reconciler never manages them | Identity owner | Approve a per-action table, then compile it; keep machine clients out of human required actions |
| U2 | Service-account role mappings in the Admin API adapter | PAS-237 section 4 lists them; no protected desired state consumes them yet | Identity owner | Implement together with the first consuming desired state, or record an approved deferral |
| U3 | Who may edit the `tenant_ids` user attribute | `codestra-agent-desktop` and `telnexa-gateway` map it into access tokens; user-editable tenancy would be an escalation path | Identity and security owners | Live readback of the realm user profile, or a reviewed administrator-only declaration |
| U4 | Remaining previous-owner references | Runtime sync remote, GHCR image namespace for `release-image.yml`, Kyyow, Orbit and monitoring contracts, proposal tooling (`identity-reference-matrix.md`) | Runtime, release and external owners | Coordinated changes; the release-intent contract itself allows zero images, so no image requirement was added |
| U5 | Operator verifier and rulesets | The verifier reads classic branch protection; `main` is protected by rulesets, so it rejects every candidate with `review-protection-missing` | Trust maintainer | Separately reviewed trust update to read effective rules |
| U6 | Protected-candidate policy refresh | `config/bootstrap/protected-candidate.json` binds the tree of `8258715`, not current `main` | Trust maintainer | Independently reviewed policy for a named reviewed commit |
| U7 | Staged client families | The PAS-237 plan reconciles protected clients; staged families keep their own staging reconcilers | Identity owner | Unify or keep, as a design decision |
| U8, U9 | Live password-reset lifecycle; JWKS rotation, sessions and revocation | Need staging credentials, a mailbox and a running realm | Identity owner | Separately authorized staging mission |
| D1 | Trust prerequisite acceptance | `ab5762e` changes trust-owned files, so only independent code-owner review and the required checks can accept it | Code owner (`appolon1908-hue` or `kazan555`) | Review the prerequisite PR once SentinelX or the owner opens it |
| D2 | Docker engine restart | The shared Docker Desktop engine stopped serving at about 05:08 UTC on 2026-09-30; this mission may not restart it | Workstation owner | Restart Docker Desktop when no other agent depends on it; then run the disposable runtime check in `docker-verification.md` |

Not a decision: the Keycloak realm, issuers, client ids, roles and redirect URIs stay as they are.
A repository transfer is not a realm migration.
