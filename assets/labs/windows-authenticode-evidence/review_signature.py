"""Hash a text fixture and compare fictional Windows signature and policy evidence."""

import argparse
import hashlib
import json
from pathlib import Path

PROVIDER = "Microsoft-Windows-CodeIntegrity"
CHANNEL = "Microsoft-Windows-CodeIntegrity/Operational"


def sha256_file(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def related_policy_events(case):
    attempt = case["policy_attempt"]
    return [
        event for event in case["events"]
        if event["computer"] == attempt["computer"]
        and event.get("activity_id") == attempt["activity_id"]
        and event["provider"] == PROVIDER and event["channel"] == CHANNEL
    ]


def assess(case):
    verification = case["verification"]
    related = related_policy_events(case)
    ids = {event["event_id"] for event in related}
    if 3077 in ids:
        policy = "enforced-block-observed"
    elif 3076 in ids:
        policy = "audit-would-block-observed"
    else:
        policy = "no-matching-decision"
    return {
        "release_hash_matches": case["collected_sha256"] == case["release_sha256"],
        "verification_path": verification["path"],
        "verifier_status": verification["status"],
        "embedded_check": verification.get("embedded_check"),
        "timestamp_evidence": verification["timestamp"],
        "policy_evidence": policy,
        "related_signature_details": sum(event["event_id"] == 3089 for event in related),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("sample", type=Path)
    args = parser.parse_args()
    try:
        data = json.loads(args.fixture.read_text(encoding="utf-8"))
        actual_digest = sha256_file(args.sample)
        digest_match = actual_digest == data["sample_sha256"]
        print(f"{'PASS' if digest_match else 'FAIL'} sample SHA-256 {actual_digest}")
        failed = int(not digest_match)
        for case in data["cases"]:
            result = assess(case)
            matches = result == case["expected"]
            failed += int(not matches)
            print(f"{'PASS' if matches else 'FAIL'} {case['id']}: {json.dumps(result)}")
            if not matches:
                print(f"  Expected: {json.dumps(case['expected'])}")
        return int(failed != 0)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Invalid fixture or sample: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
