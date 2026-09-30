# CI and review matrix

## Before the transfer (published head `f2bdb64`, owner `ingtrader21-spec`)

Every check on `f2bdb641ad33082b7a190de5ab91316f6dc7d9f3` ended without a runner being
assigned, with the annotation "The job was not started because your account is locked due
to a billing issue." These jobs are untested, not failed tests.

| Check | Workflow run and latest attempt | Required | Runner assigned | Class |
|---|---|---|---|---|
| `validate` | 36454552023, attempt 2 (2026-09-29 19:48 UTC) | yes | no | INFRA_BILLING |
| `validate-merge-result` | 36454552023, attempt 2 | yes | no | INFRA_BILLING |
| `validate-source` | 36454552023, attempt 2 | no | no | INFRA_BILLING |
| `orchestrator-contract` | 36454552023, attempt 2 | no | no | INFRA_BILLING |
| `bootstrap` | 36454552256, attempt 1 (2026-09-28 16:55 UTC) | no | no | INFRA_BILLING |
| `repository-name-authority` | 36454552265, attempt 1 | no | no | INFRA_BILLING |
| `validate-source-e2e` | 36454552283, attempt 1 | no | no | INFRA_BILLING |
| `validate-merge-result-e2e` | 36454552283, attempt 1 | no | no | INFRA_BILLING |

Self-hosted runners on the same account: the latest recorded self-hosted jobs (Kong,
2026-09-28 03:18 UTC on `codestra-ubuntu-kong`) completed while the hosted job in the same
batch was refused. No self-hosted job was attempted after that, so run data neither confirms
nor rules out a later lock on self-hosted jobs. Keycloak's required jobs are hosted-only by
policy (`validate-workflows-core.py` refuses self-hosted runners for source validation), so
moving them was not an option and was not attempted.

## After the transfer

The repository moved to `appolon1908/Keycloak` on 2026-09-30. No workflow had run under the
new owner when this file was written. The first runs are triggered by publishing the new
candidate head; their results, classified with the same vocabulary, are recorded on PR #136
and in the Linear checkpoint rather than in this file, so that recording them does not
change the head under review.

## Review requirements (effective rules for `main`)

| Rule | Requirement | State to satisfy |
|---|---|---|
| Ruleset 21608098 | 1 approval, code-owner review, last-push approval, stale dismissal, resolved threads, squash only; strict `validate` and `validate-merge-result` | A code owner who is not the last pusher approves the exact new head; both checks succeed on it |
| Ruleset 22197063 | 1 approval, stale dismissal, resolved threads, squash only, linear history | Satisfied by the same approval and a squash merge |
| Ruleset 22208412 | Applies to `refs/heads/production` only | Not applicable to this merge |

Code owners after the transfer: `appolon1908-hue` (write) and `kazan555` (write). The last
pusher is `ingtrader21-spec`. Approvals on `f2bdb64` are dismissed by publication of a new
head, as intended by the stale-review rule.

## Next allowed actions

1. Publish the new head through the guarded publisher, then read back the branch and PR head.
2. Observe the first post-transfer runs once; classify each result.
3. If a check fails on code, repair and re-certify; if execution is refused again, record
   the exact annotation and stop retrying.
4. Request review from a code owner for the exact new head.
