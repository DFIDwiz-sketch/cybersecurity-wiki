"""Compare normalized fictional managed identity evidence without network access."""

import argparse
import json
from pathlib import Path


def compare(case):
    scope = case["scope"]
    tenant = scope["tenant"]
    principal = scope["principal"]

    def same_identity(event):
        return event["tenant"] == tenant and event["principal"] == principal

    signins = [
        event for event in case["signins"]
        if same_identity(event) and event["api"] == scope["api"]
    ]
    operations = [
        event for event in case["operations"]
        if same_identity(event) and event["target"] == scope["target"]
        and event["operation"] == scope["operation"]
    ]
    attached = {
        entry["workload"] for entry in case["attachments"] if same_identity(entry)
    }
    request_ids = {event["request_id"] for event in operations if event["request_id"]}
    workload_traces = {
        trace["workload"] for trace in case["traces"]
        if trace["workload"] in attached and trace["target"] == scope["target"]
        and trace["request_id"] in request_ids
    }

    return {
        "successful_signins": sum(event["outcome"] == "success" for event in signins),
        "failed_signins": sum(event["outcome"] == "failure" for event in signins),
        "successful_operations": sum(event["outcome"] == "success" for event in operations),
        "denied_operations": sum(event["outcome"] == "denied" for event in operations),
        "attached_workloads": sorted(attached),
        "workloads_with_matching_trace": sorted(workload_traces),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    path = parser.parse_args().fixture
    try:
        cases = json.loads(path.read_text(encoding="utf-8"))["cases"]
        if not cases:
            raise ValueError("the fixture has no cases")
        results = [(case["id"], compare(case), case["expected"]) for case in cases]
    except (OSError, ValueError, KeyError, TypeError) as exc:
        parser.error(str(exc))

    passed = 0
    for case_id, actual, expected in results:
        match = actual == expected
        passed += match
        print(f"{'PASS' if match else 'FAIL'} {case_id}: {json.dumps(actual, sort_keys=True)}")
        if not match:
            print(f"  expected: {json.dumps(expected, sort_keys=True)}")
    print(f"{passed}/{len(results)} cases match")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
