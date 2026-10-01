# Recovery

Two bundles preserve every Keycloak commit found on the writer's host that is not already an
ancestor of the published candidate or of `main`. Both are incremental: they need a recipient
that already holds their prerequisite commit, which any clone of the canonical repository does.
The bundles live privately under
`C:/Users/Usuario/Documents/Codestra-Agent-Control/Keycloak-PR-Sweep-20260930T0243Z/preservation/`;
they contain Git objects only, no credentials.

| Bundle | SHA-256 | Prerequisite | Restores |
|---|---|---|---|
| `klyrow-staging-first-cut.v2.bundle` | `7214B01704ADFE5F656E0D94DDBDAD2FB34EDC4A26383C2C58014BEB7631160D` | `45a487d` | `4e76fa4` on `mission/klyrow-staging-identity-20260921` |
| `keycloak-lf-pr56.v2.bundle` | `9370468EFC1EAAB0C572FEE1E379186370D137A23B5D1560A31D90A72F53381E` | `c50a542` | `f387ed6` and `4621901` on `pr56` |

## Restore

```sh
git clone https://github.com/appolon1908/Keycloak.git recipient
cd recipient
git bundle verify /path/to/klyrow-staging-first-cut.v2.bundle
git fetch /path/to/klyrow-staging-first-cut.v2.bundle \
  refs/heads/mission/klyrow-staging-identity-20260921:refs/preserved/klyrow-staging-first-cut
git bundle verify /path/to/keycloak-lf-pr56.v2.bundle
git fetch /path/to/keycloak-lf-pr56.v2.bundle refs/heads/pr56:refs/preserved/keycloak-lf-pr56
```

## Verification performed

In a fresh clone of `appolon1908/Keycloak` at `main` `45a487d`, both bundles verified, all three
commits were restored as commits, each commit's tree matched the source repository's tree, and
`git fsck` reported no problems.

## What went wrong first

The first two bundles were defective and are kept only as superseded artifacts. One was made
from a shallow repository and could not be fetched by an empty recipient; its earlier "okay"
came from verifying it inside a repository that already had the missing history. The other
captured branch `main` instead of branch `pr56`, so it did not contain the two local-only
commits. Recipient-side verification found both defects.
