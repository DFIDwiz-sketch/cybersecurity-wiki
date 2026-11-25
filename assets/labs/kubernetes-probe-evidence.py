#!/usr/bin/env python3
"""Compare normalized Kubernetes training snapshots. Reads local JSON only."""

import json
from pathlib import Path
import sys


def review(case):
    before = case["before"]
    after = case["after"]
    uid = after["uid"]
    target = after["container"]
    restart = "same-instance"
    cause = "none-observed"

    if before["uid"] != uid:
        restart = "replacement-pod"
        cause = "different-pod-uid"
    elif before["container"] != target:
        restart = "not-comparable"
        cause = "different-container-name"
    elif (
        after["restart_count"] > before["restart_count"]
        and after["container_id"] != before["container_id"]
    ):
        restart = "new-container-instance"
        previous = after["previous"]
        cause = "restart-cause-open"
        if previous and previous["container_id"] == before["container_id"]:
            if previous["reason"] == "OOMKilled":
                cause = "oom-reported"
            else:
                for event in case["probe_events"]:
                    if (
                        event["pod_uid"] == uid
                        and event["container"] == target
                        and event["instance_id"] == previous["container_id"]
                        and before["time"] <= event["time"] <= previous["finished_at"]
                        and event["probe"] in ("liveness", "startup")
                        and event["action"] == "kubelet-probe-stop"
                    ):
                        cause = event["probe"] + "-stop-correlated"
                        break
    elif (
        before["restart_count"] != after["restart_count"]
        or before["container_id"] != after["container_id"]
    ):
        restart = "not-comparable"
        cause = "incomplete-instance-evidence"

    endpoint = case["endpoint"]
    if endpoint is None or endpoint["target_uid"] != uid:
        route = "no-matching-endpoint-evidence"
    elif endpoint["terminating"] is True:
        route = "terminating-endpoint"
    elif endpoint["ready"] is True:
        route = "published-unready" if (
            case["publish_not_ready"] and not after["pod_ready"]
        ) else "ready-endpoint"
    elif endpoint["ready"] is False:
        route = "unready-endpoint"
    else:
        route = "endpoint-readiness-unspecified"
    return restart, cause, route


def main():
    path = Path(sys.argv[1]) if len(sys.argv) == 2 else Path(__file__).with_name(
        "kubernetes-probe-evidence-cases.json"
    )
    if len(sys.argv) > 2:
        print("Usage: python3 kubernetes-probe-evidence.py [cases.json]", file=sys.stderr)
        return 2

    try:
        cases = json.loads(path.read_text(encoding="utf-8"))["cases"]
        if not cases:
            raise ValueError("the fixture contains no cases")
        matches = 0
        for case in cases:
            observed = review(case)
            expected = tuple(case["expected"])
            passed = observed == expected
            matches += passed
            print(f"{case['id']}: {' | '.join(observed)}")
            if not passed:
                print(f"  Expected {' | '.join(expected)}", file=sys.stderr)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Cannot read training fixture: {error}", file=sys.stderr)
        return 2

    print(f"{matches}/{len(cases)} probe evidence cases matched.")
    return 0 if matches == len(cases) else 1


if __name__ == "__main__":
    sys.exit(main())
