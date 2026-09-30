# Gap plan

Approved scope: the PAS-237 control-plane sections, the PR #136 convergence claims, the
sweep's K4 inspection list, and the transfer addendum's F1 to F3 bindings. Each gap below
was reproduced before it was repaired.

## Repaired in this run

| Gap | Evidence of the gap | Repair | Regression proof |
|---|---|---|---|
| G1 Agent desktop token cannot carry `telephony.webphone.use` | `codestra-agent-desktop` has `fullScopeAllowed: false` and no role scope mapping; Keycloak then puts only the client's own roles and scope-mapped realm roles into its tokens, so the realtime contract was unsatisfiable. The compiler now reports `contract_realm_role_not_in_token_scope` on the pre-repair state. | Scope mapping `config/desired-state/agent-desktop-identity/scope-mappings/codestra-agent-desktop.json`; compiler token-scope cross-check (`63f01a4`) | `test_agent_desktop_realm_role_reaches_its_token_scope`, `test_contract_role_outside_a_restricted_clients_token_scope_fails_closed`, end-to-end provision and rollback test |
| G2 Mapper and scope-mapping rules unenforced | Duplicate mapper names, two mappers writing one claim, and scope mappings with unknown roles, full scope or mixed role families all compiled | `validate_mappers`, `validate_scope_mappings` (`63f01a4`) | `test_conflicting_protocol_mappers_fail_closed`, `test_scope_mapping_cannot_broaden_privileges`, `test_client_role_declarations_fail_closed` |
| G3 PAS-237 `ERROR` classification missing | The plan had no `ERROR`; a scope mapping naming an unknown realm role failed after earlier writes (`PARTIAL_FAILURE`) | Plan emits `ERROR` for missing internal ids, clientless client roles and unknown mapped roles; apply refuses before any write; readback and observability count it (`63f01a4`) | `test_plan_reports_unreconcilable_resources_as_error_and_apply_refuses_them`, `test_control_api_surfaces_error_in_drift_and_rejects_apply_without_mutation` |
| G4 Rollback evidence not environment-scoped | The deploy workflow exported every managed client before a production apply, including the staging-only portal the plan excludes | Export selects the same scoped set as `apply-plan.sh` (`63f01a4`) | `tests/test_environment_scoped_rollback_export.py` executes the workflow's own selector |
| F1 to F3 Repository identity after transfer | Orchestrator contract, workflow validator pin and protected-candidate verifier named `appolon1908-hue/Keycloak` and resolved only by redirect | Trust prerequisite `ab5762e` on its own branch from `main`; stable id bound in the verifier | `scripts/release/test_release_contract_identity.py`, `RepositoryIdentityTests` and GraphQL id tests in `tests/test_verify_protected_candidate.py` |

## Remaining, with owner and next action

| Item | Status | Owner | Next action |
|---|---|---|---|
| U1 PAS-237 section 1 "required actions" | Not compiled. The policy lives as booleans in `config/security/realm-security-policy.json`; the reconciler can update required actions but receives none | Identity owner | Decide aliases, `enabled` and `defaultAction` per action, then compile them |
| U2 PAS-237 section 4 "service-account mappings" | No adapter endpoint for service-account user role mappings. No protected desired state requires one; the CIP contract's `serviceAccountRealmRoles` is prepared-only | Identity owner | Approve or defer; implement only with a consuming desired state |
| U3 `tenant_ids` edit rights | Mapped by `codestra-agent-desktop` and `telnexa-gateway`; no user-profile declaration restricts who can edit it | Identity and security owners | Live readback of the realm user profile, or a reviewed admin-only declaration |
| U4 Other old-owner references | Runtime sync remote, GHCR namespace, Kyyow, Orbit and monitoring contracts, bootstrap tooling; see `identity-reference-matrix.md` | Runtime, release and external owners | Coordinated changes; none may self-authorize |
| U5 Operator verifier reads classic protection | `main` is protected by rulesets, so the verifier rejects with `review-protection-missing` | Trust maintainer | Separately reviewed trust update to read effective rules |
| U6 Protected-candidate policy is stale | `config/bootstrap/protected-candidate.json` binds the tree of `8258715`, not current `main` | Trust maintainer | Independently reviewed policy refresh |
| U7 Staged client families | The PAS-237 plan reconciles protected clients; staged families use their own staging reconcilers | Identity owner | Design decision: unify or keep per-family reconcilers |
| U8 Password-reset lifecycle | `password-reset-e2e.py` needs staging credentials and a mail sink; not run | Identity owner | Staging mission |
| U9 JWKS rotation, session and revocation | Runtime-only behavior; not exercised | Identity owner | Staging mission |

Windows note: two HTTP tests in the control-plane suites intermittently raise
`ConnectionAbortedError` on Windows when the server answers 413 or 400 before reading the
body. Both pass on rerun and on Linux; the Linux run is the certification of record.
