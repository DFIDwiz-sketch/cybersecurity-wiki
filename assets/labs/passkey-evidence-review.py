#!/usr/bin/env python3
"""Review synthetic passkey audit results. This is not a WebAuthn validator."""

import argparse
import json
from pathlib import Path


def scope_key(record):
    return record["scope"], record["id"]


def review(attempt, sessions):
    if attempt["method"] != "webauthn":
        return "alternate_method", attempt["method"]

    status, reason = attempt["verifier"], attempt["reason"]
    if status == "not_observed":
        return "verification_unconfirmed", reason
    if status == "denied":
        return "verifier_denied", reason
    if status != "accepted":
        raise ValueError(f"unexpected verifier state: {status}")

    session = sessions.get(scope_key(attempt))
    if not session:
        return "session_unconfirmed", "no scoped session record"
    if session == "policy_denied":
        return "session_denied", "access policy"
    if session != "created":
        raise ValueError(f"unexpected session state: {session}")
    if reason == "counter_signal":
        return "session_created_review_signal", reason
    return "session_created", "verified assertion and scoped session record"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=Path,
                        default=Path(__file__).with_name("passkey-evidence-cases.json"))
    args = parser.parse_args()
    try:
        fixture = json.loads(args.fixture.read_text(encoding="utf-8"))
        sessions = {}
        for event in fixture["sessions"]:
            key = scope_key(event)
            if key in sessions:
                raise ValueError(f"duplicate session outcome for {key}")
            sessions[key] = event["outcome"]

        for attempt in fixture["attempts"]:
            verdict, detail = review(attempt, sessions)
            print(f"{attempt['id']}: {verdict} | {detail}")
        print(f"Reviewed: {len(fixture['attempts'])}")
    except (OSError, KeyError, TypeError, ValueError) as error:
        parser.exit(2, f"{args.fixture}: {error}\n")


if __name__ == "__main__":
    main()
