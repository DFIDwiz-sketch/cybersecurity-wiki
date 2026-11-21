#!/usr/bin/env python3
"""Assess the bundled synthetic Windows log continuity cases."""
import argparse
import json
from pathlib import Path

EVENTLOG = "Microsoft-Windows-Eventlog"
AUDITING = "Microsoft-Windows-Security-Auditing"
EXPECTED = {
    "W01": "security-clear-corroborated-maintenance",
    "W02": "security-clear-unexplained",
    "W03": "source-overwrite-supported",
    "W04": "delivery-leg-needs-review",
    "W05": "security-full-retain",
    "W06": "policy-change-no-clear-evidence",
    "W07": "other-channel-clear-only",
    "W08": "backup-check-archive",
    "W09": "shutdown-explained-by-reboot",
}


def assess(case):
    source = case["source"]
    signatures = {(event["channel"], event["provider"], event["id"])
                  for event in case["events"] if event["computer"] == source}
    if ("Security", EVENTLOG, 1102) in signatures:
        return ("security-clear-corroborated-maintenance" if case.get("approved_clear_match")
                else "security-clear-unexplained")
    if ("Security", EVENTLOG, 1104) in signatures and case.get("mode") == "Retain":
        return "security-full-retain"
    if ("Security", EVENTLOG, 1105) in signatures:
        return "backup-check-archive"
    if ("Security", EVENTLOG, 1100) in signatures and case.get("approved_reboot_match"):
        return "shutdown-explained-by-reboot"
    if ("System", EVENTLOG, 104) in signatures and case.get("clear_target") == "Application":
        return "other-channel-clear-only"
    if ("Security", AUDITING, 4719) in signatures:
        return "policy-change-no-clear-evidence"

    marker = case.get("marker", {})
    if (marker.get("local") and marker.get("selected")
            and not marker.get("collector") and marker.get("past_latency_window")):
        return "delivery-leg-needs-review"
    if (case.get("mode") == "Circular" and case.get("same_active_log")
            and case.get("previously_seen_record", 0) < case.get("oldest_record", 0)
            and "previously_seen_record" in case):
        return "source-overwrite-supported"
    return "uncertain"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    fixture = json.loads(args.fixture.read_text(encoding="utf-8"))
    results = {}
    for case in fixture["cases"]:
        label = assess(case)
        results[case["id"]] = label
        print(f"{case['id']} {case['source']}: {label}")

    if args.check:
        if results != EXPECTED:
            raise SystemExit("Outcomes differ from the nine bundled cases.")
        print(f"{len(results)}/{len(EXPECTED)} synthetic cases matched.")


if __name__ == "__main__":
    main()
