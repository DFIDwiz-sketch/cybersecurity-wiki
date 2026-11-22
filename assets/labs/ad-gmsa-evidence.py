"""Classify normalized fictional gMSA observations."""

import argparse
import json
from pathlib import Path


def classify(case):
    sid = case["audit_sid"]
    logon = case.get("logon", {})
    if logon.get("type") == 5 and logon.get("sid") == sid:
        host = logon["host"]
        if host not in case["approved_hosts"]:
            return "unexpected_host_logon"
        process = case.get("service_process", {})
        health = case.get("health", {})
        if (
            process.get("host") == health.get("host") == host
            and process.get("sid") == health.get("sid") == sid
            and process.get("instance")
            and process["instance"] == health.get("instance")
            and health.get("result") == "ok"
        ):
            return "service_outcome_confirmed"
        return "service_logon_only"
    if case.get("eligibility_change") in ("direct", "group"):
        return "eligibility_changed_usage_unproven"
    if case.get("readiness", {}).get("result") == "ok":
        return "readiness_only"
    if case.get("ticket", {}).get("target_sid") == sid:
        return "ticket_activity_only"
    return "insufficient_evidence"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path, help="path to the fictional JSON cases")
    args = parser.parse_args()
    try:
        cases = json.loads(args.cases.read_text(encoding="utf-8"))
        results = [(case["id"], classify(case)) for case in cases]
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        parser.exit(2, f"Could not read the exercise cases: {error}\n")
    for name, result in results:
        print(f"{name}: {result}")


if __name__ == "__main__":
    main()
