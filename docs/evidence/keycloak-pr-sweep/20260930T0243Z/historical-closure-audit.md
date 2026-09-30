# Historical closure audit

The twelve PRs closed as superseded by #136 on 2026-09-28 were re-read on 2026-09-30
through the new namespace `appolon1908/Keycloak`. Each closure carries a comment that
names the successor and its preservation evidence. None was reopened.

| PR | Original head | Closed (UTC) | Closed by | Evidence comment | Content at successor | Verdict |
|---|---|---|---|---|---|---|
| #115 | `7e98947` | 2026-09-28 16:20:48 | ingtrader21-spec | yes | 14 of 18 files identical; rest are supersets | Closure valid |
| #132 | `7e98947` | 2026-09-28 16:20:50 | ingtrader21-spec | yes | same head as #115 | Closure valid |
| #124 | `a49390e` | 2026-09-28 16:20:53 | ingtrader21-spec | yes | client and allowlist identical; policy and gate supersets | Closure valid |
| #125 | `aa8acf3` | 2026-09-28 16:20:56 | ingtrader21-spec | yes | 3 of 3 identical | Closure valid |
| #126 | `03bc7a6` | 2026-09-28 16:20:59 | ingtrader21-spec | yes | superseded by #134's strict superset; both threads resolved | Closure valid |
| #128 | `377b8b9` | 2026-09-28 16:21:02 | ingtrader21-spec | yes | 6 of 8 identical; README and gate supersets | Closure valid |
| #129 | `132e349` | 2026-09-28 16:21:04 | ingtrader21-spec | yes | identical; review finding fixed in `f2bdb64` | Closure valid |
| #131 | `bb08b08` | 2026-09-28 16:21:07 | ingtrader21-spec | yes | 13 of 13 identical | Closure valid |
| #133 | `5f9a9a7` | 2026-09-28 16:21:09 | ingtrader21-spec | yes | 12 of 15 identical; independent audit found nothing dropped | Closure valid |
| #134 | `ecfb578` | 2026-09-28 16:21:12 | ingtrader21-spec | yes | 5 of 9 identical; rest supersets | Closure valid |
| #127 | `9bf6cb2` | 2026-09-28 16:56:12 | ingtrader21-spec | yes | 47 of 50 identical at `f2bdb64`; 3 in the stricter #131 version | Closure valid |
| #123 | `9b92388` | 2026-09-28 16:56:15 | ingtrader21-spec | yes | evidence document verbatim under a banner; pinned certifier replaced | Closure valid |

Notes:

- Closures of #127 and #123 came after `f2bdb64` was published, as the earlier status
  comments required. They were performed through the shared `ingtrader21-spec` account
  seconds after publication; this session's own close command then found them already
  closed and added the preservation comments.
- "Identical" means byte-identical after CRLF normalization, compared against the named
  successor head. Byte-identical files prove the file survived; behavior is proven by the
  tests listed in each `containment/PR-<number>.md`.
- Two stacked PRs were merged into predecessor branches rather than closed: #130 into
  #127's branch and #135 into #133's branch. Both are contained; see their containment files.
- Closed PR branches remain on GitHub. No branch or tag was deleted and nothing was force-pushed.

Correction to an earlier in-session statement: PR #56, whose two pre-squash commits sit
in `Documents/CODESTRA/Keycloak-lf`, was squash-merged into `main` on 2026-08-31, not
closed unmerged. Its Python 3.10 pin was later replaced on `main` by the Python 3.12
validation baseline.
