"""Compare fictional Kubernetes admission evidence without contacting a cluster."""

import argparse
import json
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

MUTATION = "mutation.webhook.admission.k8s.io/"
PATCH = "patch.webhook.admission.k8s.io/"
FAIL_OPEN = (
    "failed-open.mutation.webhook.admission.k8s.io/",
    "failed-open.validating.webhook.admission.k8s.io/",
)


def linked_outcome(case, event, final_status):
    evidence = case.get("diagnostic") or {}
    if evidence.get("cluster") != case["cluster"] or evidence.get("audit_id") != event["auditID"]:
        return "unknown"
    review_uid = evidence.get("review_uid")
    response = evidence.get("response") or {}
    if (
        evidence.get("webhook_http") == 200
        and isinstance(review_uid, str) and review_uid
        and response.get("uid") == review_uid
        and isinstance(response.get("allowed"), bool)
    ):
        return "allowed" if response["allowed"] else "explicit-denial"
    if (
        evidence.get("call_error") and evidence.get("effective_failure_policy") == "Fail"
        and final_status >= 400
    ):
        return "call-error-rejected"
    return "unknown"


def assess(case):
    event = case["audit_event"]
    if event["stage"] != "ResponseComplete":
        raise ValueError("The exercise requires a final audit stage")
    status = event["responseStatus"]["code"]
    annotations = event.get("annotations", {})
    mutations = [
        json.loads(value) for key, value in annotations.items() if key.startswith(MUTATION)
    ]
    patches = [
        json.loads(value) for key, value in annotations.items() if key.startswith(PATCH)
    ]
    failed_open = sorted({value for key, value in annotations.items() if key.startswith(FAIL_OPEN)})
    outcome = linked_outcome(case, event, status)
    if failed_open and outcome == "unknown":
        outcome = "fail-open-observed"
    dry_run = "All" in parse_qs(urlsplit(event["requestURI"]).query).get("dryRun", [])
    return {
        "api_status": status,
        "diagnostic_outcome": outcome,
        "failed_open_webhooks": failed_open,
        "mutating_invocations": len(mutations),
        "mutations_observed": sum(item["mutated"] is True for item in mutations),
        "patches_observed": len(patches),
        "dry_run": dry_run,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    opts = parser.parse_args()
    try:
        cases = json.loads(opts.fixture.read_text(encoding="utf-8"))["cases"]
        failed = 0
        for case in cases:
            actual = assess(case)
            matches = actual == case["expected"]
            failed += int(not matches)
            print(f"{'PASS' if matches else 'FAIL'} {case['id']}: {json.dumps(actual)}")
            if not matches:
                print(f"  Expected: {json.dumps(case['expected'])}")
        return int(failed != 0)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Invalid fixture: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
