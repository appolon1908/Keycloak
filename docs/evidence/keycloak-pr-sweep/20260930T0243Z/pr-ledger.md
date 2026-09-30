# PR ledger

Retrieved every pull request of `appolon1908/Keycloak` (2 pages, 130 PRs, no forks, no open drafts).
The machine-readable rows are in `pr-ledger.jsonl`.

| Disposition | PRs |
|---|---|
| `CLOSED_BEFORE_SWEEP_NOT_REAUDITED` | 38 |
| `CLOSE_SUPERSEDED` | 12 |
| `IN_CANDIDATE_ANCESTRY` | 5 |
| `KEEP_CANONICAL` | 1 |
| `MERGED_INTO_PREDECESSOR` | 2 |
| `MERGED_TO_BRANCH_NOT_REAUDITED` | 17 |
| `MERGED_TO_MAIN` | 55 |

## PRs audited in depth

| PR | Classification | Disposition | Evidence |
|---|---|---|---|
| #115 | `CONTAINED` | `CLOSE_SUPERSEDED` | containment/PR-115.md |
| #123 | `SUPERSEDED` | `CLOSE_SUPERSEDED` | containment/PR-123.md |
| #124 | `CONTAINED` | `CLOSE_SUPERSEDED` | containment/PR-124.md |
| #125 | `CONTAINED` | `CLOSE_SUPERSEDED` | containment/PR-125.md |
| #126 | `SUPERSEDED` | `CLOSE_SUPERSEDED` | containment/PR-126.md |
| #127 | `CONTAINED` | `CLOSE_SUPERSEDED` | containment/PR-127.md |
| #128 | `CONTAINED` | `CLOSE_SUPERSEDED` | containment/PR-128.md |
| #129 | `CONTAINED` | `CLOSE_SUPERSEDED` | containment/PR-129.md |
| #130 | `CONTAINED` | `MERGED_INTO_PREDECESSOR` | containment/PR-130.md |
| #131 | `CONTAINED` | `CLOSE_SUPERSEDED` | containment/PR-131.md |
| #132 | `CONTAINED` | `CLOSE_SUPERSEDED` | containment/PR-132.md |
| #133 | `CONTAINED` | `CLOSE_SUPERSEDED` | containment/PR-133.md |
| #134 | `CONTAINED` | `CLOSE_SUPERSEDED` | containment/PR-134.md |
| #135 | `CONTAINED` | `MERGED_INTO_PREDECESSOR` | containment/PR-135.md |
| #136 | `CANONICAL` | `KEEP_CANONICAL` | published head f2bdb641ad33082b7a190de5ab91316f6dc7d9f3; candidate code commit 63f01a46a68a6a3aab0ba06bae47fac34a12a891 certified in this run |

PRs marked `NOT_REAUDITED` predate the sweep baseline and were not semantically re-audited in this run.
