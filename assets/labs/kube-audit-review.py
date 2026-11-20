"""Review synthetic Kubernetes audit events. Uses local data only."""

import json
import sys
from collections import defaultdict
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

WRITES = {"create", "update", "patch", "delete", "deletecollection"}


def summarize(stages):
    complete = stages.get("ResponseComplete")
    if complete is None:
        if "Panic" in stages:
            return "panic_observed"
        if "ResponseStarted" in stages:
            return "response_started"
        return "completion_unobserved"

    code = complete.get("responseStatus", {}).get("code")
    decision = complete.get("annotations", {}).get("authorization.k8s.io/decision")
    if type(code) is not int:
        return "status_missing"
    if code == 403 and decision == "forbid":
        return "authorization_forbid"
    if code == 403 and decision == "allow":
        return "allowed_then_403"
    if not 200 <= code < 300:
        return f"non_success_{code}"
    if complete["verb"] not in WRITES:
        return "successful_read" if complete["verb"] in {"get", "list"} else "successful_response"
    params = parse_qs(urlsplit(complete["requestURI"]).query)
    if "All" in params.get("dryRun", []):
        return "successful_dry_run"
    return "write_response_verify_state"


def collect(source):
    requests = defaultdict(dict)
    duplicates = 0
    with source.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            row = json.loads(line)
            event = row["event"]
            if (event["apiVersion"], event["kind"]) != ("audit.k8s.io/v1", "Event"):
                raise ValueError(f"unexpected record type at line {number}")
            key = (row["cluster"], event["auditID"])
            stages = requests[key]
            stage = event["stage"]
            if stage in stages:
                if stages[stage] != event:
                    raise ValueError(f"conflicting {stage} records for {key}")
                duplicates += 1
            else:
                stages[stage] = event
    return requests, duplicates


def main():
    requests, duplicates = collect(Path(__file__).with_name("kube-audit-samples.jsonl"))
    for (cluster, request_id), stages in sorted(requests.items()):
        event = max(stages.values(), key=lambda stage: stage["stageTimestamp"])
        actor = event["user"]["username"]
        effective = event.get("impersonatedUser", {}).get("username", actor)
        suffix = f"; authenticated={actor}; effective={effective}" if actor != effective else ""
        print(f"{cluster}/{request_id[-12:]}: {summarize(stages)}{suffix}")
    print(f"Requests: {len(requests)}; duplicate stage records: {duplicates}")


if __name__ == "__main__":
    try:
        main()
    except (OSError, KeyError, TypeError, ValueError) as error:
        sys.exit(f"Audit worksheet error: {error}")
