"""Check fictional S3 presigned GET evidence. This program makes no network calls."""

import argparse
import json
from datetime import datetime
from pathlib import Path


def timestamp(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError(f"Time zone required: {value}")
    return parsed


def assess(case):
    event = case["event"]
    params = event["requestParameters"]
    method = event.get("additionalEventData", {}).get("AuthenticationMethod")
    is_s3_data_get = (
        event["eventSource"] == "s3.amazonaws.com"
        and event["eventCategory"] == "Data"
        and event["eventName"] == "GetObject"
    )
    result = {"kind": "outside-scope", "issuance_matches": None,
              "response": None, "object_bytes": None}
    if not is_s3_data_get or method != "QueryString":
        return result
    if "X-Amz-Expires" not in params:
        result["kind"] = "query-signed-uncertain"
        return result

    result["kind"] = "presigned-get-candidate"
    scope = {"account": event["recipientAccountId"], "bucket": params["bucketName"],
             "key": params["key"], "operation": event["eventName"]}
    observed_at = timestamp(event["eventTime"])
    signer = event["userIdentity"]["arn"]
    result["issuance_matches"] = sum(
        1 for record in case["issuances"]
        if all(record[k] == value for k, value in scope.items())
        and record["signer"] == signer
        and timestamp(record["issued_at"]) <= observed_at
        < min(timestamp(record["url_expires_at"]),
              timestamp(record["credential_expires_at"]))
    )

    access = case.get("access")
    if (
        access and access["request_id"] == event["requestID"]
        and all(access[k] == value for k, value in scope.items())
    ):
        result["response"] = access["status"]
        if not event.get("errorCode") and access["status"] in (200, 206):
            result["object_bytes"] = access["bytes_sent"]
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    cases = json.loads(args.fixture.read_text(encoding="utf-8"))["cases"]
    failures = 0
    for case in cases:
        actual = assess(case)
        matches = actual == case["expected"]
        print(f"{'PASS' if matches else 'FAIL'} {case['id']}: {json.dumps(actual)}")
        if not matches:
            print(f"  Expected: {json.dumps(case['expected'])}")
            failures += 1
    return int(failures > 0)


if __name__ == "__main__":
    raise SystemExit(main())
