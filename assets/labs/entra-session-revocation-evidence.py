#!/usr/bin/env python3
"""Classify fictional Entra revocation observations without contacting a tenant."""

import argparse
from datetime import datetime, timedelta
import json
from pathlib import Path

DECISIONS = {
    ("refresh", "denied", "revoked"): "refresh-revoked",
    ("resource", "allowed", None): "old-resource-access-observed",
    ("app-session", "allowed", None): "app-session-access-observed",
    ("resource", "challenged", "insufficient-claims"): "challenge-only",
    ("resource", "denied", "revoked"): "resource-denial-linked",
    ("app-session", "denied", "app-session-terminated"): "app-session-denial-linked",
}


def utc_timestamp(value):
    timestamp = datetime.fromisoformat(value[:-1] + "+00:00"
                                       if value.endswith("Z") else value)
    if timestamp.utcoffset() != timedelta(0):
        raise ValueError("expected an explicit UTC timestamp")
    return timestamp


def classify(case):
    action, scope, observation = case["action"], case["scope"], case["observation"]
    if action["result"] != "success":
        return "action-failed"
    if scope["external_user"] and action["tenant"] != scope["tenant"]:
        return "home-tenant-outside-scope"
    if action["tenant"] != scope["tenant"] or action["user"] != scope["user"]:
        return "action-scope-mismatch"
    if observation is None:
        return "downstream-unobserved"
    if any(observation[key] != scope[key] for key in ("tenant", "user", "surface")):
        return "observation-scope-mismatch"
    if utc_timestamp(observation["time"]) <= utc_timestamp(action["time"]):
        return "observation-not-after-action"
    if observation["session"] != scope["session"]:
        return "different-session"

    outcome = observation["outcome"]
    reason = observation["reason"]
    return DECISIONS.get((scope["surface"], outcome, reason),
                         "denial-reason-unconfirmed" if outcome == "denied"
                         else "result-unconfirmed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=Path,
                        default=Path(__file__).with_suffix(".json"))
    args = parser.parse_args()
    try:
        cases = json.loads(args.fixture.read_text(encoding="utf-8"))["cases"]
        if not cases:
            raise ValueError("fixture contains no cases")
        results = [(case["id"], classify(case), case["expected"]) for case in cases]
    except (OSError, ValueError, AttributeError, TypeError, KeyError) as error:
        parser.exit(2, f"{args.fixture}: {error}\n")

    matches = 0
    for case_id, observed, expected in results:
        passed = observed == expected
        matches += passed
        status = "OK" if passed else "FAIL"
        print(f"{case_id} {status} {observed}")
    print(f"{matches}/{len(results)} cases matched.")
    return 0 if matches == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
