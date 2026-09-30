# Keycloak PR sweep 20260930T0243Z

Evidence for mission `KEYCLOAK_FULL_SWEEP_CLAUDE_20260929` and addendum
`KEYCLOAK_TRANSFER_AUTHORITY_RECONCILIATION_APPOLON1908`, produced by the existing
`Keycloak-PR-Convergence` writer. It audits every pull request and local contribution,
repairs the gaps it found in the PR #136 candidate, and records the repository transfer to
`appolon1908/Keycloak`.

## Outcome

- Every PR (130) and every Keycloak checkout on the writer's host (21) is accounted for. No
  unique required work was stranded; two local-only branches were bundled privately.
- The twelve 2026-09-28 closures were re-verified; each names its successor and evidence.
- Four gaps were repaired in `63f01a4`: the agent desktop's realm role now reaches its token,
  mapper and scope-mapping rules fail closed, the PAS-237 plan classifies unreconcilable
  resources as `ERROR` before any write, and rollback evidence follows environment scoping.
- The transfer's active identity bindings (F1 to F3) are rebound, with the stable repository
  id, on a separate trust prerequisite branch (`ab5762e`), because trust-owned files cannot
  change inside a candidate.
- Nothing was merged, deployed or applied to a live realm. `PRODUCTION_GO=NO`.

## Files

| File | Content |
|---|---|
| `baseline.json` | Host, writer, repository ids, Git identities, rules and preservation |
| `pr-ledger.md`, `pr-ledger.jsonl` | Every PR with classification and disposition |
| `historical-closure-audit.md` | Re-verification of the twelve superseded closures |
| `containment/PR-<number>.md` | Per-PR requirement, mapping, behavior evidence and disposition |
| `local-work-ledger.jsonl` | Local checkouts, commits, containment and preservation bundles |
| `gap-plan.md` | Gaps repaired, and remaining items with owner and next action |
| `test-matrix.md` | Requirement to code to test, with the certification of record |
| `dependency-map.md` | Ordering between paths, PRs and consuming systems |
| `identity-contract-matrix.md` | Consumer clients, audiences, claims and roles (generated) |
| `identity-reference-matrix.md` | Every old-owner reference, classified, with its decision |
| `trust-transition-record.md` | How the identity bindings change without self-authorization |
| `ci-blockers.md` | CI and review matrix before and after the transfer |
| `actions.jsonl` | Ordered actions taken in this run |
| `release-readiness.md` | Separate verdicts and what a release decision still needs |
| `HANDOFF.md` | Where the work is, next permitted actions and stop conditions |
