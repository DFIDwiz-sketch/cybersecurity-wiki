#!/usr/bin/env python3
"""Classify fictional, normalized Kubernetes observations without an API client."""

import json
from pathlib import Path
import sys


def classify(case):
    code = case.get("pod_create_code")
    reason = case.get("refusal")
    if code == 403:
        if reason != "quota-exceeded":
            return {
                "quota-missing-request": "missing-resource-request",
                "limit-range": "per-object-limit",
            }.get(reason, "forbidden-cause-unresolved")

        usage = case["accounting"]
        if usage["unit"] not in {"millicores", "objects"}:
            raise ValueError("accounting unit must be millicores or objects")
        used, requested, hard = (usage[key] for key in ("used", "requested", "hard"))
        if any(type(value) is not int or value < 0 for value in (used, requested, hard)):
            raise ValueError("accounting values must be nonnegative integers")
        if used + requested <= hard:
            return "quota-refusal-numbers-conflict"
        return "quota-exceeded"

    if code == 201 and case.get("dry_run"):
        return "dry-run-not-persisted"
    if case.get("pod_uid"):
        if case.get("pod_scheduled") is False and case.get("event") == "FailedScheduling":
            return "scheduling-failure"
        if case.get("pod_scheduled") is True and case.get("container_reason") == "OOMKilled":
            return "runtime-oom-observed"
        return "pod-exists-outcome-unresolved"
    if case.get("deployment_create_code") == 201:
        return "deployment-only"
    return "insufficient-evidence"


def main():
    fixture = Path(__file__).with_name("kubernetes-quota-evidence-cases.json")
    cases = json.loads(fixture.read_text(encoding="utf-8"))
    if not cases:
        raise ValueError("expected at least one case")
    passed = 0
    for case in cases:
        result = classify(case)
        matched = result == case["expected"]
        passed += matched
        detail = "" if matched else f" (expected {case['expected']})"
        print(f"{case['id']}: {result}{detail}")
    print(f"{passed}/{len(cases)} evidence cases matched.")
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, KeyError, TypeError, ValueError) as error:
        sys.exit(f"Unable to read exercise: {error}")
