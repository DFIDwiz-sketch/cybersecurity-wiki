#!/usr/bin/env python3
"""Classify normalized, fictional Azure Key Vault audit observations offline."""

import argparse
import json
from pathlib import Path
import sys


def review(row, vault):
    if row is None:
        return ["coverage-unknown", "no-version-established", "no-token-identity"]
    if row["vault"].lower() != vault.lower():
        return ["different-vault", "no-version-established", "no-token-identity"]
    if row["source"] == "activity":
        return ["management-operation", "no-version-established", "no-token-identity"]

    identity = "token-identity-observed" if row.get("token_id") else "token-identity-unresolved"
    result = row.get("http_status")
    if result is None:
        return ["http-status-unavailable", "no-version-established", identity]

    failures = {
        401: "authentication-response",
        403: "access-denied-response",
        404: "not-found-response",
        429: "throttled-response",
    }
    if result != 200:
        return [failures.get(result, "other-response"), "no-version-established", identity]

    operation = row["operation"]
    if operation == "SecretGet":
        version = row.get("requested_version")
        version_state = "explicit-version" if version else "latest-request-exact-version-unknown"
        return ["get-secret-value-response", version_state, identity]
    if operation in ("SecretList", "SecretListVersions"):
        return ["metadata-list-response", "no-version-established", identity]
    return ["other-successful-operation", "no-version-established", identity]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=Path, default=Path(__file__).with_name(
        "azure-key-vault-read-evidence-cases.json"
    ))
    args = parser.parse_args()
    try:
        document = json.loads(args.fixture.read_text(encoding="utf-8"))
        cases = document["cases"]
        if not cases:
            raise ValueError("no evidence cases")
        matches = 0
        for case in cases:
            outcome = review(case["row"], document["vault"])
            print(f"{case['id']}: {' / '.join(outcome)}")
            if outcome == case["expected"]:
                matches += 1
            else:
                print(f"  Expected {' / '.join(case['expected'])}", file=sys.stderr)
        print(f"{matches}/{len(cases)} Key Vault evidence cases matched.")
        return 0 if matches == len(cases) else 1
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f"Cannot read training fixture: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
