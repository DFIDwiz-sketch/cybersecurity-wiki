"""Classify the normalized fictional observations supplied with this lesson."""

import argparse
import json
from pathlib import Path


PSA_ANNOTATION = "pod-security.kubernetes.io/"


def classify(case):
    code = case.get("responseStatus", {}).get("code")
    if case["stage"] != "ResponseComplete" or not isinstance(code, int):
        return "outcome_unobserved"

    resource = case["resource"]
    annotations = case.get("annotations", {})
    if code >= 400:
        if code == 403 and resource == "pods" and case.get("denialSource") == "pod-security":
            return "psa_denied"
        return "rejection_source_unconfirmed"
    if not 200 <= code < 300:
        return "outcome_unobserved"

    if case.get("dryRun"):
        return "dry_run_no_persistence"
    if annotations.get(PSA_ANNOTATION + "exempt"):
        return "exempt_request"
    if resource == "deployments":
        return "template_accepted_check_pod"
    if resource == "pods" and case.get("storedPodUid"):
        if annotations.get(PSA_ANNOTATION + "audit-violations"):
            return "pod_stored_audit_violation"
        return "pod_stored_check_runtime"
    return "pod_persistence_unconfirmed"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path, help="path to the lesson's JSON fixture")
    args = parser.parse_args()
    try:
        cases = json.loads(args.cases.read_text(encoding="utf-8"))
        results = [(case["name"], classify(case)) for case in cases]
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        parser.exit(2, f"Could not read the lesson fixture: {exc}\n")
    for name, result in results:
        print(f"{name}: {result}")


if __name__ == "__main__":
    main()
