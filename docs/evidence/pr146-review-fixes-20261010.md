# PR #146 review fixes

The hierarchy workflow now passes refs through quoted environment variables,
runs the promotion validator and its policy/map from the exact target-base SHA,
and covers section targets. Its existing, named governance bootstrap exception
is handled before fetching the not-yet-installed validator. Fork heads do not
run on the self-hosted control-plane runner.

The guard requires a registered section/subsection pair from product-map.json;
unassigned sections and tasks fail closed. The script already supported refs
from the environment, so the earlier missing-arguments review finding did not
require another parser change. The removed governed-promotion workflow is no
longer an active finding.

Validation: six promotion regression tests pass, including all 24 mapped
subsections. Full tests: 585 passed, 720 subtests passed. make validate,
workflow policy validation, bootstrap closure tests, and git diff --check pass.
The new tests failed on the preceding implementation before the fixes.

The candidate executable-closure hashes track the changed guard/tests. This
does not grant independent approval or establish protected-main trust authority.
Exact-head CI, independent review, resolved review threads, and protected
promotion remain required. Production effects remain disabled.
