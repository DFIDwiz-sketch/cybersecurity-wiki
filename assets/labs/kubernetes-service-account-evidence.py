"""Interpret evidence in the supplied synthetic Kubernetes fixtures."""
import argparse
import json
from pathlib import Path


def explain(record):
    checks = {
        "issuer_or_signature_rejected": record["issuer_and_signature_valid"],
        "wrong_audience": record["audience_matches"],
        "outside_validity": record["within_validity"],
    }
    if record["verifier"] == "api":
        checks["account_binding_rejected"] = record["account_uid_matches"]
        checks["pod_binding_rejected"] = record["pod_uid_matches"]

    failed = [reason for reason, passed in checks.items() if passed is False]
    if failed:
        return ",".join(failed)
    if any(passed is not True for passed in checks.values()):
        return "insufficient_evidence"
    if record["verifier"] == "offline":
        return "jwt_checks_only"

    code = record["response_code"]
    decision = record["authorization_decision"]
    if decision == "allow" and code == 200:
        return "read_observed"
    if decision == "deny" and code == 403:
        return "authorization_denied"
    if decision == "allow" and code == 403:
        return "inspect_after_allow"
    return "inspect_api_outcome"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path)
    args = parser.parse_args()
    with args.cases.open(encoding="utf-8") as source:
        for line in source:
            record = json.loads(line)
            print(f'{record["case"]}: {explain(record)}')


if __name__ == "__main__":
    main()
