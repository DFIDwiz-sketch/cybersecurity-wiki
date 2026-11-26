#!/usr/bin/env python3
"""Check fictional evidence for a direct general purpose S3 bucket."""

import json
from pathlib import Path
import sys


BLOCK_FLAGS = (
    "BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"
)


def effective_flags(case):
    bucket = case["bucket"]
    account = case["effective_account"]
    for layer in (bucket, account):
        if set(layer) != set(BLOCK_FLAGS) or any(type(value) is not bool for value in layer.values()):
            raise ValueError("each scope must state all four Boolean flags")
    return {flag: bucket[flag] or account[flag] for flag in BLOCK_FLAGS}


def observed_read(case):
    if case["status"] == 403:
        return "request-denied"
    if case["operation"] == "REST.HEAD.OBJECT" and case["status"] == 200:
        return "metadata-response"
    if case["operation"] != "REST.GET.OBJECT" or case["status"] not in (200, 206):
        return "no-matching-body-observation"
    count = case.get("bytes_sent")
    if type(count) is not int or count <= 0:
        return "positive-body-bytes-unconfirmed"
    return {
        "-": "unauthenticated-body-response",
        "QueryString": "query-signed-body-response",
        "AuthHeader": "header-signed-body-response",
    }.get(case["auth_type"], "body-response-auth-unknown")


def classify(case):
    kind = case["kind"]
    if kind == "observed-read":
        return observed_read(case)

    active = effective_flags(case)
    if kind in ("public-acl-write", "public-acl-read") and case["acl_disabled"]:
        return "acl-path-disabled"
    if kind == "public-acl-write" and active["BlockPublicAcls"]:
        return "public-acl-write-blocked"
    if kind == "public-acl-read" and active["IgnorePublicAcls"]:
        return "public-acl-grant-ignored"
    if kind == "public-policy-write" and active["BlockPublicPolicy"]:
        return "public-policy-write-blocked"
    if (kind == "policy-read" and active["RestrictPublicBuckets"]
            and case["policy_public"] and case["requester"] in ("external-account", "unauthenticated")):
        return "public-policy-access-restricted"
    if kind not in ("public-acl-write", "public-acl-read", "public-policy-write", "policy-read"):
        raise ValueError(f"unsupported case kind: {kind}")
    return "no-block-from-modeled-controls"


def main():
    cases_path = Path(__file__).with_name("s3-block-public-access-cases.json")
    cases = json.loads(cases_path.read_text(encoding="utf-8"))
    if not cases:
        raise ValueError("expected at least one case")
    passed = 0
    for case in cases:
        result = classify(case)
        expected = case["expected"]
        if result == expected:
            passed += 1
            print(f"{case['id']}: {result}")
        else:
            print(f"{case['id']}: {result} (expected {expected})")
    print(f"{passed}/{len(cases)} evidence cases matched.")
    return 0 if passed == len(cases) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (KeyError, OSError, TypeError, ValueError) as error:
        sys.exit(f"Unable to read exercise: {error}")
