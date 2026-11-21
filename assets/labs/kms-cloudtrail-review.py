#!/usr/bin/env python3
"""Review the bundled synthetic KMS and S3 CloudTrail projections offline."""
import argparse
from collections import defaultdict
import json
from pathlib import Path

EXPECTED = {
    "K01": ("kms-decrypt-succeeded", 1),
    "K02": ("kms-incorrect-key", 1),
    "K03": ("cross-account-decrypt-succeeded", 1),
    "K04": ("cross-account-denied-caller-copy", 1),
    "K05": ("s3-read-no-per-call-kms-required", 0),
    "K06": ("kms-read-coverage-gap", 0),
    "K07": ("key-policy-changed", 0),
    "K08": ("s3-read-and-bucket-level-kms-object-link-unproven", 1),
}


def summarize(case):
    events = case["events"]
    kms = [event for event in events if event["eventSource"] == "kms.amazonaws.com"]
    decrypts = [event for event in kms if event["eventName"] == "Decrypt"]
    groups = defaultdict(list)
    for event in decrypts:
        identifier = event.get("sharedEventID") or event["eventID"]
        groups[identifier].append(event)
    count = len(groups)
    s3_read = any(event["eventSource"] == "s3.amazonaws.com"
                  and event["eventName"] == "GetObject" and not event.get("errorCode")
                  for event in events)

    if not decrypts:
        if s3_read and case.get("bucket_key_for_object"):
            return "s3-read-no-per-call-kms-required", count
        if not case["kms_read_covered"]:
            return "kms-read-coverage-gap", count
        if any(event["eventName"] == "PutKeyPolicy" and not event.get("errorCode")
               for event in kms):
            return "key-policy-changed", count
        return "review-missing-decrypt", count

    if count != 1:
        return "review-multiple-decrypts", count
    if any(event.get("errorCode") == "IncorrectKeyException" for event in decrypts):
        return "kms-incorrect-key", count
    if any(event.get("errorCode") in {"AccessDenied", "AccessDeniedException"} for event in decrypts):
        recipients = {event["recipientAccountId"] for event in decrypts}
        if (case["caller_account"] != case["key_account"]
                and recipients == {case["caller_account"]}):
            return "cross-account-denied-caller-copy", count
        return "review-denied", count
    if any(event.get("errorCode") for event in decrypts):
        return "review-kms-error", count
    if s3_read and case.get("bucket_key_for_object"):
        return "s3-read-and-bucket-level-kms-object-link-unproven", count

    recipients = {event["recipientAccountId"] for event in decrypts}
    if (case["caller_account"] != case["key_account"]
            and recipients == {case["caller_account"], case["key_account"]}
            and len({event["eventID"] for event in decrypts}) >= 2
            and all(event.get("sharedEventID") for event in decrypts)):
        return "cross-account-decrypt-succeeded", count
    return "kms-decrypt-succeeded", count


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--check", action="store_true", help="verify the eight bundled cases")
    args = parser.parse_args()

    outcomes = {}
    for case in json.loads(args.fixture.read_text(encoding="utf-8"))["cases"]:
        evidence, calls = summarize(case)
        outcomes[case["case"]] = (evidence, calls)
        print(f"{case['case']} {evidence}; observed decrypt actions={calls}")
    if args.check:
        if outcomes != EXPECTED:
            raise SystemExit("Results differ from the eight bundled cases.")
        print(f"{len(outcomes)}/{len(EXPECTED)} synthetic cases matched.")


if __name__ == "__main__":
    main()
