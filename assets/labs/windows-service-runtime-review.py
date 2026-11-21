"""Read normalized fictional service evidence from a JSONL file."""
import json
import sys
from pathlib import Path


def summarize(case):
    events = sorted(
        row for row in case["observations"]
        if row[1:3] == [case["host"], case["boot"]]
    )
    service = case["service"]
    snapshots = [
        row for row in events
        if row[3] in {"running", "pending", "start_failure"}
        and row[4] == service and row[0] <= case["at"]
    ]
    if not snapshots:
        return "registration_only" if any(
            row[3:] == ["install", service] and row[0] <= case["at"]
            for row in events
        ) else "state_unknown"

    time, _, _, state, _ = snapshots[-1]
    if state != "running":
        return state

    starts = [
        row for row in events
        if row[3] == "process" and row[4] == case["pid"] and row[0] <= time
    ]
    if not starts:
        return "running_report_only"

    started, _, _, _, _, identity, image = starts[-1]
    if any(
        row[3:] == ["process_end", identity] and started <= row[0] <= time
        for row in events
    ):
        return "running_report_only"

    if case["shared"]:
        loaded = any(
            row[3:] == ["image_load", identity, case["expected_image"]]
            and started <= row[0] <= time
            for row in events
        )
        return "shared_module_observed" if loaded else "shared_host_only"

    if image != case["expected_image"]:
        return "running_report_only"

    healthy = any(
        row[3:] == ["health", service] and time <= row[0] <= time + 2
        for row in events
    )
    return "dedicated_process_and_health" if healthy else "dedicated_process"


if __name__ == "__main__":
    for line in Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
        case = json.loads(line)
        print(f'{case["case"]}: {summarize(case)}')
