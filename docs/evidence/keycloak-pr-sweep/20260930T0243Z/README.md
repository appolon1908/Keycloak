# Keycloak PR sweep 20260930T0243Z

Evidence for missions `KEYCLOAK_FULL_SWEEP_CLAUDE_20260929` and
`KC-COMPLETE-RECOVERY-CONVERGENCE-20260930`, and for the transfer addendum
`KEYCLOAK_TRANSFER_AUTHORITY_RECONCILIATION_APPOLON1908`, produced by the existing
`Keycloak-PR-Convergence` writer. It audits every pull request and local contribution,
repairs the gaps it found in the PR #136 candidate, and records the repository transfer to
`appolon1908/Keycloak`.

## Outcome

- Every PR (130) and every Keycloak checkout on the writer's host (21) is accounted for. No
  unique required work was stranded; the three commits found outside the candidate's ancestry
  are bundled privately and restore in a fresh clone of the canonical repository.
- The twelve 2026-09-28 closures were re-verified; each names its successor and evidence.
- Four gaps were repaired in `63f01a4`: the agent desktop's realm role now reaches its token,
  mapper and scope-mapping rules fail closed, the PAS-237 plan classifies unreconcilable
  resources as `ERROR` before any write, and rollback evidence follows environment scoping.
- The transfer's active identity bindings (F1 to F3) are rebound, with the stable repository
  id, on a separate trust prerequisite branch (`ab5762e`), because trust-owned files cannot
  change inside a candidate.
- The disposable Keycloak runtime check is blocked: the shared Docker engine stopped serving
  and this mission may not restart it.
- Nothing was merged, deployed or applied to a live realm. `PRODUCTION_GO=NO`.

## Files

| File | Content |
|---|---|
| `FINAL-REPORT.md` | Verdicts for mission `KC-COMPLETE-RECOVERY-CONVERGENCE-20260930` |
| `baseline.json`, `ownership.md` | Host, writer, repository ids, Git identities, rules; writer exclusivity |
| `local-work-ledger.jsonl`, `preservation-manifest.json`, `RECOVERY.md` | Local contributions, bundles and verified restore |
| `pr-ledger.md`, `pr-ledger.jsonl` | Every PR with classification and disposition |
| `historical-closure-audit.md` | Re-verification of the twelve superseded closures |
| `containment/PR-<number>.md` | Per-PR requirement, mapping, behavior evidence and disposition |
| `gap-plan.md`, `decisions.md` | Gaps repaired; remaining items and the owner decisions they need |
| `test-matrix.md` | Requirement to code to test, with the certification of record |
| `dependency-map.md` | Ordering between paths, PRs and consuming systems |
| `identity-contract-matrix.md` | Consumer clients, audiences, claims and roles (generated) |
| `identity-reference-matrix.md` | Every previous-owner reference, classified, with its decision |
| `trust-transition-record.md` | How the identity bindings change without self-authorization |
| `docker-verification.md`, `postman-results.md` | Build, runtime and API evidence, and what did not run |
| `ci-blockers.md` | CI and review matrix before and after the transfer |
| `cleanup-record.md` | Resources this writer stopped or removed, and what it kept |
| `actions.jsonl` | Ordered actions taken in this run |
| `release-readiness.md` | Separate verdicts and what a release decision still needs |
| `HANDOFF.md` | Where the work is, next permitted actions and stop conditions |

Names requested by mission `KC-COMPLETE-RECOVERY-CONVERGENCE-20260930` map to these files:
`transfer-reference-inventory.md` is `identity-reference-matrix.md`, `trust-transition.md` is
`trust-transition-record.md`, and `requirements-to-tests.md` is `test-matrix.md`.
