# Release readiness and verdicts

Verdicts as of the evidence commit. Live CI, review and merge state after publication are
recorded on PR #136 and in the Linear checkpoint.

| Verdict | Value | Basis |
|---|---|---|
| SWEEP_AUDIT_COMPLETE | YES | All 130 PRs retrieved and classified; 21 local checkouts and 40 local commits classified; every audited contribution has a containment file |
| CODE_CONVERGENCE_COMPLETE | NO | Four gaps repaired and tested; PAS-237 required actions (U1) and service-account mappings (U2) await owner decisions |
| PUBLICATION_VERIFIED | PENDING | Requires readback of the new head on `appolon1908/Keycloak` after guarded publication |
| PR_DISPOSITION_COMPLETE | YES | 12 predecessors closed with preservation evidence; #136 is the only open PR; the trust prerequisite PR is to be opened by SentinelX or the owner |
| TRANSFER_IDENTITY_VERIFIED | YES | Repository metadata: `appolon1908/Keycloak`, stable id 1347523366, owner id 335843231 |
| ACTIVE_REFERENCES_RECONCILED | PARTIAL | F1 to F3 reconciled on the trust prerequisite branch; other active references await coordinated owners (U4) |
| TRUST_TRANSITION_ACCEPTED | NO | Independent review and merge of the trust prerequisite pending |
| REQUIRED_CI_PASS | NO | No required check has run on any head since the billing lock; post-transfer runs pending |
| REVIEW_ACCEPTED | NO | Publication dismisses the previous approval; a code owner must approve the new head |
| MERGE_READY | NO | Checks and review pending |
| MAIN_CONVERGED | NO | Not merged |
| STAGING_CERTIFIED | NO | No staging deployment or live login under this sweep |
| PRODUCTION_READY | NO | Release, recovery and live evidence absent |
| PRODUCTION_GO | NO | No production decision exists |

## Required before a release decision

- Signed artifacts and provenance under the decided image namespace (U4).
- Accepted desired state including the owner decisions U1 to U3.
- Realm and database compatibility, backup and restore rehearsal, and rollback rehearsal.
- An isolated staging rehearsal with real consumer logins for every row of
  `identity-contract-matrix.md`, the agent desktop roles in its access token, the staging-only
  portal excluded from production, and plan, apply, drift and rollback evidence.
- Operational monitoring of authentication failures and readback drift.
- An explicit, recorded production approval.

A JSON client declaration does not prove the client exists in a running realm, and a mock
login does not certify a deployed application.
