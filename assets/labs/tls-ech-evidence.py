"""Interpret simplified, already-correlated fictional ECH observations."""

import argparse
import json
from pathlib import Path


def classify(case):
    result = case.get("client_ech_result")
    if result == "accepted":
        if case.get("origin_authenticated") and case.get("matching_http_request"):
            return "accepted_http_observed"
        return "accepted_check_http"
    if result == "rejected":
        if (
            case.get("public_name_authenticated")
            and case.get("recovery_handshake_complete")
            and case.get("replacement_supported")
        ):
            return "rejected_retry_available"
        return "rejected_no_trusted_retry"
    if result == "grease":
        return "grease_confirmed"
    if case.get("wire_ech_extension"):
        return "offer_or_grease"
    if case.get("https_ech_advertised"):
        return "configuration_advertised"
    return "insufficient_evidence"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path, help="path to the fictional JSON cases")
    args = parser.parse_args()
    try:
        cases = json.loads(args.cases.read_text(encoding="utf-8"))
        results = [(case["name"], classify(case)) for case in cases]
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"Could not read the exercise cases: {error}\n")
    for name, result in results:
        print(f"{name}: {result}")


if __name__ == "__main__":
    main()
