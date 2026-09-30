# Handoff

## Where the work is

| Item | Value |
|---|---|
| Repository | `appolon1908/Keycloak`, stable id 1347523366 |
| Writer | Claude Code session `Keycloak-PR-Convergence` on host `APPOLON`, user `Usuario` |
| Candidate worktree | `C:/Users/Usuario/Desktop/Keycloak-Conflict-Convergence-Work` |
| Candidate branch | `integration/keycloak-conflict-convergence-20260927` (PR #136) |
| Candidate code commit | `63f01a46a68a6a3aab0ba06bae47fac34a12a891` (the evidence commit that carries this file sits on top of it) |
| Trust worktree | `C:/Users/Usuario/Desktop/Keycloak-Trust-Identity-20260930` |
| Trust branch | `trust/keycloak-repository-identity-appolon1908-20260930`, head `ab5762e923cd854aaa21db3886a6f449591ec5c2`, base `main` |
| Protected main | `45a487d71a516ae3039b00c250752897469ffe7a` |
| Durable evidence | this directory; private raw evidence in `C:/Users/Usuario/Documents/Codestra-Agent-Control/Keycloak-PR-Sweep-20260930T0243Z` |

Both worktrees were clean when their commits were made. Publication results, CI outcomes
and review state after publication are recorded on PR #136 and in Linear PAS-8, so that
recording them does not move the head under review.

## Next permitted actions, in order

1. Point the candidate worktree at the transferred repository after checking there is no
   separate push URL or URL rewrite, then publish through the guarded publisher:

   ```powershell
   git -C "C:\Users\Usuario\Desktop\Keycloak-Conflict-Convergence-Work" remote set-url origin https://github.com/appolon1908/Keycloak.git
   & "C:\Users\Usuario\Documents\GitHub\tools\codestra-publish.ps1" -RepoPath "C:\Users\Usuario\Desktop\Keycloak-Conflict-Convergence-Work" -Remote origin
   ```

2. Read back the remote branch and the PR #136 head; they must equal the local head.
3. Observe the first post-transfer runs once and classify each check (`ci-blockers.md`).
4. Request review of the exact new head from a code owner (`appolon1908-hue` or `kazan555`).
5. Publish the trust prerequisite the same way (`-RepoPath` the trust worktree), after the same
   remote check. Opening its pull request is reserved for SentinelX or the owner:
   base `main`, head `trust/keycloak-repository-identity-appolon1908-20260930`, title
   `chore(trust): bind repository identity to appolon1908/Keycloak and its stable id`, body
   from `trust-transition-record.md`. It needs independent code-owner review.
6. Whichever of the two PRs merges second first merges `main`, reseals the executable
   closure from canonical Git blobs, and re-runs its gates.
7. Merge only when both required checks pass on the exact head, a code owner who is not the
   last pusher approved that head, and every thread is resolved. Never use an admin merge.

## Stop conditions

- The remote branch or PR head moved to a commit that is not an ancestor of the local head.
- Either worktree is dirty, detached or on `main`, `staging` or `production`.
- A check fails with a billing or runner annotation again: record it and stop retrying.
- A check fails on code: repair on the candidate branch, re-certify, then publish.
- A proposed change would edit a trust-owned file inside PR #136, weaken a required check, or
  move protected jobs to self-hosted runners.
- Any step would change a live realm, send email, rotate a credential or deploy.

## Owner decisions carried forward

U1 required actions, U2 service-account mappings, U3 `tenant_ids` edit rights, U4 remaining
old-owner references, U5 verifier reading rulesets, U6 protected-candidate policy refresh,
U7 staged-family reconciliation, U8 and U9 live staging checks. See `gap-plan.md`.

`PRODUCTION_GO=NO`.
