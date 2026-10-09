#!/usr/bin/env python3
"""Reject all non-canonical Keycloak promotion paths; never mutate Git."""
import argparse
import fnmatch
import json
import os
from pathlib import Path
import re

arg_parser = argparse.ArgumentParser()
arg_parser.add_argument("--head")
arg_parser.add_argument("--base")
args = arg_parser.parse_args()
head = args.head or os.environ.get("GITHUB_HEAD_REF", "")
base = args.base or os.environ.get("GITHUB_BASE_REF", "")
policy = json.loads(Path("governance/promotion-policy.json").read_text())

bootstrap = policy["bootstrap_exception"]
if (head, base) == (bootstrap["head"], bootstrap["base"]):
    print("PROMOTION_GUARD=PASS bootstrap")
    raise SystemExit(0)

section_re = re.compile(r"kc-[0-9]{2}-[a-z0-9][a-z0-9-]*\Z")
task_re = re.compile(r"[a-z0-9][a-z0-9-]*\Z")
accepted = False
for rule in policy["accepted_promotions"]:
    if not (fnmatch.fnmatchcase(head, rule["head"])
            and fnmatch.fnmatchcase(base, rule["base"])):
        continue
    if rule.get("relation") == "matching-section-required":
        section, marker, task = head[len("subsection/"):].partition("--")
        accepted = bool(
            marker and section_re.fullmatch(section)
            and task_re.fullmatch(task)
            and base == "section/" + section
        )
    elif rule["head"] == "section/*":
        accepted = bool(section_re.fullmatch(head[len("section/"):]) and base == "development")
    elif "relation" in rule:
        accepted = False
    else:
        accepted = True
    if accepted:
        break

if not accepted:
    print(f"PROMOTION_GUARD=BLOCK head={head} base={base}")
    raise SystemExit(1)
print(f"PROMOTION_GUARD=PASS head={head} base={base}")
