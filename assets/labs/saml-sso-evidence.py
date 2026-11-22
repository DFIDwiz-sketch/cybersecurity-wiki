#!/usr/bin/env python3
"""Summarize the evidence stages in the fictional SAML investigation cases."""

import argparse
import json
from pathlib import Path


def matching_event(events, scope, kind, reference_key, reference, earliest):
    matches = (
        event for event in events
        if (event["tenant"], event["connection"]) == scope
        and event["kind"] == kind
        and event.get(reference_key) == reference
        and event["second"] >= earliest
    )
    return min(matches, default=None, key=lambda event: event["second"])


def investigate(events):
    # Every supplied case starts with a successful IdP observation.
    idp = events[0]
    scope = (idp["tenant"], idp["connection"])
    acs = matching_event(
        events, scope, "acs", "request", idp["request"], idp["second"]
    )
    if acs is None:
        return "acs_unobserved"
    if acs["outcome"] == "rejected":
        return f"acs_rejected:{acs['reason']}"

    session = matching_event(
        events, scope, "session", "transaction", acs["transaction"], acs["second"]
    )
    if session is None:
        return "session_unobserved"
    if session["outcome"] == "denied":
        return "session_denied"

    action = matching_event(
        events, scope, "action", "session", session["session"], session["second"]
    )
    if action is None:
        return "action_unobserved"
    return f"action_{action['outcome']}"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path, help="Fictional JSON cases")
    args = parser.parse_args()
    try:
        cases = json.loads(args.cases.read_text(encoding="utf-8"))
        for case in cases:
            print(f"{case['case']}: {investigate(case['events'])}")
    except (OSError, ValueError, KeyError, TypeError, IndexError) as error:
        parser.exit(1, f"Could not read or analyze the fixture: {error}\n")


if __name__ == "__main__":
    main()
