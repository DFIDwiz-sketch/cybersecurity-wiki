"""Review fictional normalized evidence without network access."""

import json
from pathlib import Path

ACCEPTED_ISSUER = "release-security.example.test"


def review(case):
    if case["deployment"] != case["inventory"]["artifact"]:
        return "inventory_scope_mismatch"
    if case["component"] not in case["inventory"]["packages"]:
        return "component_unconfirmed"

    statements = [
        entry for entry in case["statements"]
        if entry["artifact"] == case["deployment"]
        and entry["component"] == case["component"]
        and entry["finding"] == case["finding"]
    ]
    if not statements:
        return "no_applicable_statement"

    verified = [
        row for row in statements
        if row["issuer"] == ACCEPTED_ISSUER and row["source_verified"]
    ]
    if not verified:
        return "provenance_unverified"

    statuses = {row["status"] for row in verified}
    if len(statuses) != 1:
        return "conflicting_statements"
    status, = statuses
    if status == "not_affected":
        if any(row.get("justification") for row in verified):
            return "review_scoped_not_affected"
        return "justification_missing"
    if status == "affected":
        return "prioritize_remediation"
    if status == "fixed":
        return "verify_fixed_deployment"
    return "investigation_open"


def main():
    dataset = Path(__file__).with_name("sbom-vex-cases.json")
    cases = json.loads(dataset.read_text(encoding="utf-8"))
    for case in cases:
        print(f'{case["id"]}: {review(case)}')
    print(f"Reviewed: {len(cases)} synthetic cases")


if __name__ == "__main__":
    main()
