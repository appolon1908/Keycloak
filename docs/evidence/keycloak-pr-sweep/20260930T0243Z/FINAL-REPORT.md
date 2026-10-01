# Final report

Verdicts for mission `KC-COMPLETE-RECOVERY-CONVERGENCE-20260930` as of the evidence commit that
carries this file. States that change after publication (publication readback, CI, review,
merge) are recorded on PR #136 and in Linear PAS-8, so recording them does not move the head
under review.

```text
MISSION = KC-COMPLETE-RECOVERY-CONVERGENCE-20260930
REPOSITORY = appolon1908/Keycloak
REPOSITORY_ID = 1347523366
LOCAL_SHA = the evidence commit that carries this file on integration/keycloak-conflict-convergence-20260927; code commit 63f01a46a68a6a3aab0ba06bae47fac34a12a891
PUBLISHED_SHA = f2bdb641ad33082b7a190de5ab91316f6dc7d9f3 when this commit was made; it is an ancestor of the local head
MAIN_SHA = 45a487d71a516ae3039b00c250752897469ffe7a

SESSION_AND_WRITER = PASS: sole Keycloak writer on this host (ownership.md)
ACCESS_AND_REMOTES = PASS: push access without admin on appolon1908/Keycloak; origin rebound to https://github.com/appolon1908/Keycloak.git with the prior configuration saved privately; a fetch without pruning changed no refs
LOCAL_PRESERVATION = PASS: three commits outside the candidate's ancestry are bundled (preservation-manifest.json)
RECIPIENT_RECOVERY = PASS: both bundles restore into a fresh clone of the canonical repository (RECOVERY.md)
CROSS_HOST_PRESERVATION = BLOCKED: the Ubuntu host is not reachable from this session; this host is covered by LOCAL_PRESERVATION
PR_AUDIT_AND_CONTAINMENT = PASS: all 130 PRs classified; every audited contribution has a containment file
TRANSFER_AND_TRUST = BLOCKED: trust prerequisite ab5762e is prepared and Linux-tested and needs independent code-owner review
SCOPED_CODE_CONVERGENCE = BLOCKED: the four proven gaps are repaired and tested; U1 and U2 need owner decisions
DOCKER_LOCAL_VALIDATION = BLOCKED: the image build passed; the shared engine stopped serving and may not be restarted here (D2)
POSTMAN_API_VALIDATION = PASS: the repository collection passed against the loopback control API without a backend; the disposable-realm run is NOT_RUN
EXACT_SHA_TESTS = PASS: Linux certification of 63f01a4 and ab5762e; the evidence commits add documentation only and passed the whole-tree scans, their container run is NOT_RUN
REQUIRED_GITHUB_CI = NOT_RUN: no required check has run on any head since the 2026-09-22 billing lock
INDEPENDENT_REVIEW = BLOCKED: publication dismisses the earlier approval; a code owner must approve the new head
PUBLICATION = NOT_RUN when this commit was made; the readback is recorded on PR #136
PR_DISPOSITION = PASS: #136 is the only open PR; twelve predecessors were closed with preservation evidence
MAIN_CONVERGED = BLOCKED: merging needs the required checks and a code-owner approval on the exact head
STAGING_CERTIFIED = NOT_RUN: needs a separately authorized staging mission
PRODUCTION_READY = BLOCKED: needs staging certification, release evidence and rehearsed recovery
PRODUCTION_GO = NO
LIVE_EFFECTS = DISABLED
NEXT_PERMITTED_ACTION = publish with codestra-publish.ps1 -Remote origin, read back the PR head, observe the first post-transfer runs once
```

## Answers

- **What was preserved.** Three commits outside the candidate's ancestry, in two verified
  bundles that restore into a fresh clone of the canonical repository; the handoff helper as
  found and as it was before its repair.
- **What reached the new remote.** Nothing yet at this commit; see PR #136 for the readback.
- **What code changed.** `63f01a4`: agent-desktop token scope, mapper and scope-mapping rules,
  PAS-237 `ERROR` classification, environment-scoped rollback evidence. `ab5762e` (separate
  trust branch): repository identity bound to `appolon1908/Keycloak` and stable id 1347523366.
- **Which closures remain valid.** All twelve (`historical-closure-audit.md`).
- **Which tests ran on which SHA.** `test-matrix.md`, `postman-results.md`,
  `docker-verification.md`, and `trust-transition-record.md` for `ab5762e`.
- **What was cleaned.** Only this writer's own processes and generated caches
  (`cleanup-record.md`).
- **What remains.** Publication, post-transfer CI, independent reviews of both PRs, the owner
  decisions in `decisions.md`, the Docker runtime check, and every staging and production step.
