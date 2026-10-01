# Trust-transition record

## Governing rule

`config/bootstrap/OPERATOR-VERIFICATION.md` (protected `main`) makes four paths
trust-owned: `scripts/verify_protected_candidate.py`, its test, its policy
`config/bootstrap/protected-candidate.json`, and the operator document. They must equal
protected `main` exactly, so a candidate cannot change them to authorize itself.

## Transition order

1. Trust prerequisite branch `trust/keycloak-repository-identity-appolon1908-20260930`,
   commit `ab5762e923cd854aaa21db3886a6f449591ec5c2`, parent `main`
   `45a487d71a516ae3039b00c250752897469ffe7a`. It changes only:
   - `.codestra/production-orchestrator-contract.v1.json`: repository name to `appolon1908/Keycloak`; `repository_id` 1347523366 unchanged
   - `scripts/validate-workflows.py`: the contract pin, same name and id
   - `scripts/verify_protected_candidate.py`: `REPOSITORY`, new `REPOSITORY_ID`, identity check before any other lookup, GraphQL owner and name as variables, `databaseId` required on both queries
   - `tests/test_verify_protected_candidate.py` and new `scripts/release/test_release_contract_identity.py`
   - `config/bootstrap/OPERATOR-VERIFICATION.md`: the binding and the classic-protection gap
   - `config/bootstrap/executable-closure.json`: resealed for `validate-workflows.py`, manifest `5bd356842979abae...`
2. Independent review of that PR by a code owner (`appolon1908-hue` or `kazan555`, both with
   write access after the transfer), then the required checks, then a squash merge.
3. PR #136 then merges `main`, reseals the executable closure (both branches touch it), and is
   re-certified and re-reviewed on its new head.

PR #136 does not modify any of the four trust-owned files; its diff against `main` touches
neither the verifier, its test, its policy nor the operator document.

## Checks kept, not removed

- `manual-release-intent.yml` still requires the contract name to equal `GITHUB_REPOSITORY`
  and the live repository id to equal the contract's `repository_id`.
- The workflow validator still pins both the name and the id.
- The verifier still requires native exact-head approval, last-push approval, stale-review
  dismissal, resolved threads and successful checks.

## Negative tests (trust prerequisite, Linux)

| Case | Result |
|---|---|
| Same name, different stable id (REST) | rejected, `repository-identity-mismatch` |
| Moved or redirected name with the right id | rejected |
| GraphQL returns another `databaseId` or none | rejected, both queries |
| Previous owner names, a fork name, another id or a string id in the release contract | rejected by the workflow validator |
| Review against a base other than `main` | rejected, `native-review-head-mismatch` |
| Stale approval, candidate trust-file change, missing trust file | rejected (existing tests) |
| Bound name and id | accepted |

Linux results for `ab5762e`: `validate.sh` PASS, governance and workflow policy PASS, plan
gate PASS, 253 pytest tests and 44 verifier and release tests passed, closure digests and
`git diff --check` PASS. The identity compiler check does not apply to a `main`-based tree.

## Not self-authorizing

The trust prerequisite is based on `main`, touches no candidate code, and cannot be accepted
by the verifier it changes; its acceptance is the independent code-owner review and the
required checks. Historical proposals and certification records keep their original
repository names (`identity-reference-matrix.md`, class 2).

## Status

`TRUST_TRANSITION_ACCEPTED=NO` until the prerequisite is independently reviewed and merged.
Opening its pull request is reserved for SentinelX or the owner; this agent session does not
run `gh pr create`.
