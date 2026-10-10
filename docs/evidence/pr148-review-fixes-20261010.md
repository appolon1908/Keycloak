# PR #148 review fixes

The staging realm compiler rejects duplicate mission-control-ui clients and
dashboard.read scopes instead of accepting the first matching entry. A single
matching entry remains idempotent; a conflicting entry remains rejected.

Two duplicate-entry regressions failed before the fix and pass afterward.
Full tests: 61 passed. make validate, workflow policy validation, and
git diff --check pass. Source and merge-result CI now run the compiler suite.

This generates only a separate candidate file. Live provisioning and staging
browser acceptance remain unverified and require the existing approval path.
Production effects remain disabled.
