# Identity-reference matrix

Old-owner references at the candidate after the 2026-09-30 transfer to `appolon1908/Keycloak`
(stable repository id 1347523366). Classes follow the transfer addendum: 1 active identity,
2 historical evidence, 3 external dependency, 4 workload identity or signing, 5 application
authentication configuration. Class 5 has no entries: no client, realm, scope or role document
names a GitHub repository, and the transfer changes no issuer, redirect URI, audience or role.

| Class | References |
|---|---|
| 1 active repository identity | 3 |
| 1 active repository identity (tooling) | 2 |
| 1 runtime sync identity | 9 |
| 1/4 image publication identity | 15 |
| 2 historical evidence | 43 |
| 3 external contract (Kong, by digest) | 2 |
| 3 external contract (Kyyow) | 2 |
| 3 external contract (Orbit adoption) | 2 |
| 3 external contract (monitoring) | 4 |
| 3 external dependency (protocol repository) | 4 |

| Class | File | Line | Reference | Decision |
|---|---|---|---|---|
| 1 active repository identity | `.codestra/production-orchestrator-contract.v1.json` | 3 | `"repository": "appolon1908-hue/Keycloak",` | Reconciled in trust prerequisite `ab5762e` (name plus stable id 1347523366) |
| 1 active repository identity | `scripts/validate-workflows.py` | 400 | `"repository": "appolon1908-hue/Keycloak",` | Reconciled in trust prerequisite `ab5762e` (name plus stable id 1347523366) |
| 1 active repository identity | `scripts/verify_protected_candidate.py` | 18 | `REPOSITORY = "appolon1908-hue/Keycloak"` | Reconciled in trust prerequisite `ab5762e` (name plus stable id 1347523366) |
| 1 active repository identity (tooling) | `scripts/bootstrap_manifest.py` | 15 | `REPOSITORY = "appolon1908-hue/Keycloak"` | Defer to trust maintenance: proposal generator and local audit default; CI passes GITHUB_REPOSITORY |
| 1 active repository identity (tooling) | `scripts/ci/audit_keycloak_pull_requests.py` | 328 | `value.add_argument("--repository", default=os.environ.get("GITHUB_REPOSITORY", "appolon...` | Defer to trust maintenance: proposal generator and local audit default; CI passes GITHUB_REPOSITORY |
| 1 runtime sync identity | `.github/workflows/runtime-preflight.yml` | 125 | `MIDDLEWARE_IMAGE_REFERENCE: ghcr.io/appolon1908-hue/codestra-middleware@sha256:695fa3ce...` | Defer: the runtime server's git remote and deploy key must change in lockstep with the runtime owner |
| 1 runtime sync identity | `deploy/runtime-paths.env.example` | 15 | `RUNTIME_GIT_REMOTE=git@github.com:appolon1908-hue/Keycloak.git` | Defer: the runtime server's git remote and deploy key must change in lockstep with the runtime owner |
| 1 runtime sync identity | `docs/SERVER_GIT_SSH.md` | 6 | ``appolon1908-hue/Keycloak`. GitHub write access must remain disabled. The server` | Defer: the runtime server's git remote and deploy key must change in lockstep with the runtime owner |
| 1 runtime sync identity | `scripts/runtime-preflight.sh` | 117 | `RUNTIME_GIT_REMOTE="${RUNTIME_GIT_REMOTE:-git@github.com:appolon1908-hue/Keycloak.git}"` | Defer: the runtime server's git remote and deploy key must change in lockstep with the runtime owner |
| 1 runtime sync identity | `scripts/runtime-preflight.sh` | 119 | `readonly EXPECTED_REMOTE='git@github.com:appolon1908-hue/Keycloak.git'` | Defer: the runtime server's git remote and deploy key must change in lockstep with the runtime owner |
| 1 runtime sync identity | `scripts/sync-runtime-repository.sh` | 25 | `RUNTIME_GIT_REMOTE="${RUNTIME_GIT_REMOTE:-git@github.com:appolon1908-hue/Keycloak.git}"` | Defer: the runtime server's git remote and deploy key must change in lockstep with the runtime owner |
| 1 runtime sync identity | `scripts/sync-runtime-repository.sh` | 27 | `[[ "$RUNTIME_GIT_REMOTE" == 'git@github.com:appolon1908-hue/Keycloak.git' ]] \|\|` | Defer: the runtime server's git remote and deploy key must change in lockstep with the runtime owner |
| 1 runtime sync identity | `scripts/test-runtime-preflight.sh` | 49 | `git -C "$test_root/repository" remote add origin git@github.com:appolon1908-hue/Keycloa...` | Defer: the runtime server's git remote and deploy key must change in lockstep with the runtime owner |
| 1 runtime sync identity | `scripts/test-runtime-preflight.sh` | 68 | `export RUNTIME_GIT_REMOTE='git@github.com:appolon1908-hue/Keycloak.git'` | Defer: the runtime server's git remote and deploy key must change in lockstep with the runtime owner |
| 1/4 image publication identity | `.env.example` | 2 | `KEYCLOAK_IMAGE=ghcr.io/appolon1908-hue/codestra-keycloak:REPLACE_WITH_40_HEX_SOURCE_SHA...` | Owner decision: the GHCR namespace stays with the account that owns the package; attestation subjects are derived from GITHUB_REPOSITORY at run time |
| 1/4 image publication identity | `.github/workflows/release-image.yml` | 168 | `RELEASE_IMAGE: ghcr.io/appolon1908-hue/codestra-keycloak@${{ steps.digest.outputs.diges...` | Owner decision: the GHCR namespace stays with the account that owns the package; attestation subjects are derived from GITHUB_REPOSITORY at run time |
| 1/4 image publication identity | `.github/workflows/release-image.yml` | 192 | `subject-name: ghcr.io/appolon1908-hue/codestra-keycloak` | Owner decision: the GHCR namespace stays with the account that owns the package; attestation subjects are derived from GITHUB_REPOSITORY at run time |
| 1/4 image publication identity | `.github/workflows/release-image.yml` | 199 | `subject-name: ghcr.io/appolon1908-hue/codestra-keycloak` | Owner decision: the GHCR namespace stays with the account that owns the package; attestation subjects are derived from GITHUB_REPOSITORY at run time |
| 1/4 image publication identity | `.github/workflows/release-image.yml` | 40 | `IMAGE_REPOSITORY: ghcr.io/appolon1908-hue/codestra-keycloak` | Owner decision: the GHCR namespace stays with the account that owns the package; attestation subjects are derived from GITHUB_REPOSITORY at run time |
| 1/4 image publication identity | `.github/workflows/validate.yml` | 111 | `KEYCLOAK_IMAGE: ghcr.io/appolon1908-hue/codestra-keycloak:26.7.2-ci@sha256:aaaaaaaaaaaa...` | Owner decision: the GHCR namespace stays with the account that owns the package; attestation subjects are derived from GITHUB_REPOSITORY at run time |
| 1/4 image publication identity | `.github/workflows/validate.yml` | 216 | `KEYCLOAK_IMAGE: ghcr.io/appolon1908-hue/codestra-keycloak:26.7.2-ci@sha256:aaaaaaaaaaaa...` | Owner decision: the GHCR namespace stays with the account that owns the package; attestation subjects are derived from GITHUB_REPOSITORY at run time |
| 1/4 image publication identity | `compose.yaml` | 47 | `ghcr.io/appolon1908-hue/codestra-keycloak:[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a...` | Owner decision: the GHCR namespace stays with the account that owns the package; attestation subjects are derived from GITHUB_REPOSITORY at run time |
| 1/4 image publication identity | `scripts/rehearse-release-pg17.py` | 25 | `if not re.fullmatch(r"ghcr.io/appolon1908-hue/codestra-keycloak@sha256:[0-9a-f]{64}", i...` | Owner decision: the GHCR namespace stays with the account that owns the package; attestation subjects are derived from GITHUB_REPOSITORY at run time |
| 1/4 image publication identity | `scripts/release/test_verify_intent.py` | 12 | `validate_plan(plan,"appolon1908-hue/Keycloak","a"*40,digest)` | Owner decision: the GHCR namespace stays with the account that owns the package; attestation subjects are derived from GITHUB_REPOSITORY at run time |
| 1/4 image publication identity | `scripts/release/test_verify_intent.py` | 9 | `self.plan = dict(schema="reviewed-image-publication/v1", repository="appolon1908-hue/Ke...` | Owner decision: the GHCR namespace stays with the account that owns the package; attestation subjects are derived from GITHUB_REPOSITORY at run time |
| 1/4 image publication identity | `scripts/release/verify_intent.py` | 47 | `expected_image = {'appolon1908-hue/Keycloak': 'ghcr.io/appolon1908-hue/codestra-keycloak',` | Owner decision: the GHCR namespace stays with the account that owns the package; attestation subjects are derived from GITHUB_REPOSITORY at run time |
| 1/4 image publication identity | `scripts/release/verify_intent.py` | 48 | `'appolon1908-hue/codestra-server-c': 'ghcr.io/appolon1908-hue/codestra-server-c'}` | Owner decision: the GHCR namespace stays with the account that owns the package; attestation subjects are derived from GITHUB_REPOSITORY at run time |
| 1/4 image publication identity | `scripts/validate-runtime-security.py` | 190 | `if "ghcr.io/appolon1908-hue/codestra-keycloak:" not in policy_command[0] or "@sha256:" ...` | Owner decision: the GHCR namespace stays with the account that owns the package; attestation subjects are derived from GITHUB_REPOSITORY at run time |
| 1/4 image publication identity | `scripts/validate-runtime-security.py` | 192 | `if "ghcr.io/appolon1908-hue/*:" in policy_command[0]:` | Owner decision: the GHCR namespace stays with the account that owns the package; attestation subjects are derived from GITHUB_REPOSITORY at run time |
| 2 historical evidence | `KEYCLOAK_PRODUCTION_AUTHORITY_COMPLETION_REPORT.md` | 5 | `- Repository: `appolon1908-hue/Keycloak`` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `config/bootstrap/proposals/email-production-identities-20260912.json` | 63 | `"repository": "appolon1908-hue/Keycloak",` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `config/bootstrap/proposals/pas155-trust-root-20260920.json` | 58 | `"repository": "appolon1908-hue/Keycloak",` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `config/bootstrap/proposals/pr106-reconciled-faa840a9.json` | 58 | `"repository": "appolon1908-hue/Keycloak",` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `config/bootstrap/proposals/pr106-webphone-production-client.json` | 58 | `"repository": "appolon1908-hue/Keycloak",` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `config/bootstrap/proposals/pr108-4b0d976.json` | 63 | `"repository": "appolon1908-hue/Keycloak",` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `config/bootstrap/proposals/pr108-ca901237.json` | 63 | `"repository": "appolon1908-hue/Keycloak",` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `config/bootstrap/proposals/pr113-c6abb828.json` | 58 | `"repository": "appolon1908-hue/Keycloak",` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `config/bootstrap/proposals/pr118-main-reconcile-20260920.json` | 70 | `"repository": "appolon1908-hue/Keycloak",` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `config/bootstrap/proposals/pr96-93e6e7f.json` | 83 | `"repository": "appolon1908-hue/Keycloak",` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `config/certification/cip-f3-cross-repo-parity-recertification.v1.json` | 7 | `"repository": "ingtrader21-spec/Keycloak",` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/CODESTRA_MISSION_PLAN.md` | 55 | `### Tasks — owner: `appolon1908-hue/Keycloak`` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/COMMUNICATIONS_PLATFORM_AUTHORITY.md` | 5 | `This document defines `appolon1908-hue/Keycloak` as the principal identity authority fo...` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/GITHUB_SECURITY.md` | 78 | `RUNTIME_GIT_REMOTE=git@github.com:appolon1908-hue/Keycloak.git` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/KEYCLOAK_REPOSITORY_AUTHORITY.md` | 159 | ``appolon1908-hue/Keycloak` is the authoritative independent repository for Codestra Key...` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/WEBPHONE_PRODUCTION_CLIENT.md` | 74 | `[platform PR #336](https://github.com/appolon1908-hue/codestra-production-platform/pull...` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/architecture/KEYCLOAK_AUTHORITY_ARCHITECTURE.md` | 3 | `The sole desired-state authority is `github.com/appolon1908-hue/Keycloak`. Production i...` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_BASELINE_AUDIT.md` | 4 | `Repository: `https://github.com/appolon1908-hue/Keycloak`` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 1045 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/12"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 1104 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/10"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 1156 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/9"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 117 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/62"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 1260 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/8"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 1339 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/6"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 1342 | `"repository": "appolon1908-hue/Keycloak",` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 195 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/59"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 245 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/44"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 379 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/37"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 504 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/32"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 554 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/28"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 59 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/68"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 652 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/27"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 718 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/19"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 791 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/18"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 869 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/17"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 930 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/16"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.json` | 989 | `"url": "https://github.com/appolon1908-hue/Keycloak/pull/14"` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/audits/KEYCLOAK_OPEN_PR_RECONCILIATION_2026-09-03.md` | 3 | `Repository: `appolon1908-hue/Keycloak`` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/governance/KEYCLOAK_BRANCH_TOPOLOGY_2026-09-03.md` | 4 | `Repository: `appolon1908-hue/Keycloak`` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/operations/PRODUCTION_DEPLOYMENT.md` | 3 | `The approved checkout is `/srv/keycloak`, cloned with a read-only deploy key from `git@...` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `docs/review-proposals/n8n-editor-login-bootstrap-20260910.json` | 58 | `"repository": "appolon1908-hue/Keycloak",` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `release/intents/keycloak-20260909.json` | 3 | `"repository": "appolon1908-hue/Keycloak",` | Keep unchanged: records what was true when produced |
| 2 historical evidence | `release/intents/keycloak-20260909.json` | 6 | `"image_repository": "ghcr.io/appolon1908-hue/codestra-keycloak",` | Keep unchanged: records what was true when produced |
| 3 external contract (Kong, by digest) | `release/cip-tenant-identity/keycloak-cip-gateway-identity-contract.v1.json` | 21 | `"repository": "ingtrader21-spec/Keycloak",` | Resolved 2026-09-30: regenerated as `appolon1908/Keycloak`; no consumer pins it yet (see below) |
| 3 external contract (Kong, by digest) | `scripts/cip_tenant_identity.py` | 1006 | `"repository": "ingtrader21-spec/Keycloak",` | Resolved 2026-09-30: the generator names `appolon1908/Keycloak` |
| 3 external contract (Kyyow) | `contracts/kyyow-saas-identity-v1.json` | 6 | `"identity_owner": "appolon1908-hue/Keycloak",` | Defer: coordinated identity-owner update with the Kyyow owner |
| 3 external contract (Kyyow) | `scripts/validate-kyyow-identity.py` | 15 | `'identity_owner': 'appolon1908-hue/Keycloak',` | Defer: coordinated identity-owner update with the Kyyow owner |
| 3 external contract (Orbit adoption) | `orbit/adoption-manifest.json` | 3 | `"repository": "appolon1908-hue/Keycloak",` | Defer: coordinated with the Orbit owner |
| 3 external contract (Orbit adoption) | `scripts/validate-orbit-theme.py` | 13 | `assert manifest["repository"] == "appolon1908-hue/Keycloak"` | Defer: coordinated with the Orbit owner |
| 3 external contract (monitoring) | `MONITORING-INTEGRATION.md` | 5 | `- [Complete architecture and rollout design](https://github.com/appolon1908-hue/Infustr...` | Defer: coordinated with the monitoring repositories |
| 3 external contract (monitoring) | `MONITORING-INTEGRATION.md` | 6 | `- [36-operation Middleware implementation](https://github.com/appolon1908-hue/Middlewar...` | Defer: coordinated with the monitoring repositories |
| 3 external contract (monitoring) | `monitoring-integration.v1.json` | 3 | `"repository": "appolon1908-hue/Keycloak",` | Defer: coordinated with the monitoring repositories |
| 3 external contract (monitoring) | `monitoring-integration.v1.json` | 7 | `"design_url": "https://github.com/appolon1908-hue/Infustruction-repo/blob/afeea11b86d29...` | Defer: coordinated with the monitoring repositories |
| 3 external dependency (protocol repository) | `.github/copilot-instructions.md` | 5 | `https://github.com/ingtrader21-spec/codestra/blob/main/docs/AGENT-CONTINUATION-PROTOCOL.md` | Keep: points at the separate codestra protocol repository, which was not transferred |
| 3 external dependency (protocol repository) | `AGENTS.md` | 5 | `https://github.com/ingtrader21-spec/codestra/blob/main/docs/AGENT-CONTINUATION-PROTOCOL.md` | Keep: points at the separate codestra protocol repository, which was not transferred |
| 3 external dependency (protocol repository) | `AGENTS.md` | 8 | `https://github.com/ingtrader21-spec/codestra/blob/main/docs/AGENT-QUICKSTART.md` | Keep: points at the separate codestra protocol repository, which was not transferred |
| 3 external dependency (protocol repository) | `CLAUDE.md` | 5 | `https://github.com/ingtrader21-spec/codestra/blob/main/docs/AGENT-CONTINUATION-PROTOCOL.md` | Keep: points at the separate codestra protocol repository, which was not transferred |

The desired-state contracts that mention a repository (CIP, edge certification, OpenBao
workload identity) name other repositories or record provenance; none names this repository's
owner. No workflow configures an OIDC subject or signing identity by repository name; the release
workflow's provenance attestations take their subject from the run.

Correction, 2026-09-30: the CIP gateway contract says Kong pins it by digest, but that is an
activation precondition, not current state. Read-only inspection of `appolon1908/Kong` found no
reference to the contract or its digest on `main` or on its CIP branch
(`product/cip-gateway-tenant-policy-20260924`). The contract was therefore regenerated here with
its canonical generator. When Kong adopts it, Kong pins the digest in
`release/cip-tenant-identity/keycloak-cip-gateway-identity-contract.v1.sha256` at the merged
commit. The bootstrap proposal generator and the pull-request audit default now name
`appolon1908/Keycloak`; historical proposals, audits and intents keep the names they were made with.
