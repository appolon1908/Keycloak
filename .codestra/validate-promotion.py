#!/usr/bin/env python3
"""Validate the Keycloak promotion chain without altering Git or deployments."""
from __future__ import annotations

import os
import re
import sys

REPOSITORY_RULES = {
    "Middleware-": ("mw", "testing", "staging", "production/environment"),
    "Kong": ("kg", "testing", "staging", "production"),
    "Caddy": ("cd", "testing", "staging", "production"),
    "Keycloak": ("kc", "testing", "staging", "production"),
    "Codestra-OpenBao": ("ob", "testing", "staging", "production"),
    "N8N": ("n8", "testing/environment", "staging", "production/environment"),
}


def validate(repository: str, head: str, base: str) -> tuple[bool, str]:
    name = repository.split("/")[-1]
    if name not in REPOSITORY_RULES:
        return False, "unknown_repository"
    prefix, testing, staging, production = REPOSITORY_RULES[name]
    section_re = re.compile(rf"{re.escape(prefix)}-[0-9]{{2}}-[a-z0-9][a-z0-9-]*\Z")
    task_re = re.compile(r"[a-z0-9][a-z0-9-]*\Z")

    if (head, base) == ("governance/agent-hierarchy-main-v1", "main"):
        return True, "governance_main_bootstrap"
    if (head, base) == ("governance/agent-hierarchy-v1", "development"):
        return True, "governance_development_bootstrap"
    if name == "Keycloak" and (head, base) == ("governance/development-control-plane-v1", "main"):
        return True, "control_plane_bootstrap"

    if head.startswith("subsection/"):
        section, sep, task = head[len("subsection/"):].partition("--")
        permitted = bool(sep and section_re.fullmatch(section) and task_re.fullmatch(task)
                         and base == "section/" + section)
        return permitted, "subsection_to_matching_section"
    if head.startswith("section/"):
        section = head[len("section/"):]
        permitted = bool(section_re.fullmatch(section) and base == "development")
        return permitted, "section_to_development"
    if head == "development":
        return base == testing, "development_to_testing"
    if head == testing:
        return base == staging, "testing_to_staging"
    if head == staging:
        return base == production, "staging_to_production"
    if head == production:
        return base == "main", "production_to_main"
    return False, "not_a_promotion_ref"


def main() -> int:
    if len(sys.argv) != 3:
        print("PROMOTION_ALLOWED=NO wrong_arguments")
        return 2
    allowed, reason = validate(os.environ.get("GITHUB_REPOSITORY", ""), sys.argv[1], sys.argv[2])
    print("PROMOTION_ALLOWED=" + ("YES " if allowed else "NO ") + reason)
    return 0 if allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())
