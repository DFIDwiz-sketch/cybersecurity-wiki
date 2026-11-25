#!/usr/bin/env python3
"""Review fictional verifier evidence. This tool consumes no tokens or keys."""

import json
from pathlib import Path
import sys


def review(config, record):
    if record["candidate_issuer"] != config["issuer"]:
        return "issuer-out-of-policy"
    if record["alg"] not in config["algorithms"]:
        return "algorithm-out-of-policy"
    if record["typ"] not in config["types"]:
        return "wrong-token-profile"

    kid = record["kid"]
    matches = record["cached_kids"].count(kid)
    after_refresh = False
    if matches == 0:
        refresh = record["refresh"]
        if refresh["status"] == "failed":
            return "trusted-refresh-failed"
        if refresh["status"] != "completed":
            return "cache-miss-without-refresh"
        if refresh["source"] != config["jwks_uri"]:
            return "untrusted-refresh-source"
        matches = refresh["kids"].count(kid)
        after_refresh = True

    if matches == 0:
        return "key-absent-after-refresh"
    if matches != 1:
        return "ambiguous-key-selection"

    if record["signature"] != "valid":
        return "signature-invalid-or-unconfirmed"
    if config["audience"] not in record["aud"]:
        return "wrong-audience"
    if record["now"] >= record["exp"]:
        return "expired"
    return "accepted-after-refresh" if after_refresh else "accepted-from-cache"


def main():
    if len(sys.argv) > 2:
        print("Usage: python3 jwt-key-rotation-evidence.py [cases.json]", file=sys.stderr)
        return 2
    fixture = Path(__file__).with_name("jwt-key-rotation-evidence-cases.json")
    if len(sys.argv) == 2:
        fixture = Path(sys.argv[1])

    try:
        data = json.loads(fixture.read_text(encoding="utf-8"))
        config, cases = data["verifier"], data["cases"]
        if not cases:
            raise ValueError("no cases")
        matches = 0
        for record in cases:
            outcome = review(config, record)
            print(f"{record['id']}: {outcome}")
            if outcome == record["expected"]:
                matches += 1
            else:
                print(f"  Expected {record['expected']}", file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f"Cannot read training cases: {error}", file=sys.stderr)
        return 2

    print(f"{matches}/{len(cases)} JWT evidence cases matched.")
    return 0 if matches == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main())
