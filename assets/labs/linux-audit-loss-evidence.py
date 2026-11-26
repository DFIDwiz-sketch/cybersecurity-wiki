#!/usr/bin/env python3
"""Compare synthetic Linux Audit counters and an expected event's delivery."""

import argparse
import json
from pathlib import Path


def compare_counter(before, after):
    if before is None or after is None:
        return {"state": "unavailable"}
    if any(type(value) is not int or value < 0 for value in (before, after)):
        raise ValueError("counter must be a nonnegative integer or null")
    if after < before:
        return {"state": "counter-decreased"}
    return {"state": "increased" if after > before else "unchanged",
            "delta": after - before}


def compare_checkpoints(delivery):
    local = delivery["local"]
    central = delivery["collector"]
    if central == "complete":
        return "collector-confirmed"
    if local == "partial":
        return "local-incomplete"
    if local != "complete":
        return "local-unconfirmed"
    if not delivery["window_elapsed"]:
        return "pending-window"
    return "collector-incomplete" if central == "partial" else "missing-at-collector"


def inspect(case):
    before, after = case["before"], case["after"]
    if (before["host"], before["boot"]) != (after["host"], after["boot"]):
        kernel = plugin = {"state": "host-or-boot-boundary"}
    else:
        if after["known_kernel_reset"]:
            kernel = {"state": "known-reset"}
        else:
            kernel = compare_counter(before["kernel_lost"], after["kernel_lost"])

        if not before["daemon"] or not after["daemon"]:
            plugin = {"state": "unavailable"}
        elif before["daemon"] != after["daemon"]:
            plugin = {"state": "daemon-boundary"}
        else:
            plugin = compare_counter(before["plugin_dropped"], after["plugin_dropped"])

    return {"kernel": kernel, "plugin": plugin,
            "delivery": compare_checkpoints(case["delivery"])}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=Path,
                        default=Path(__file__).with_suffix(".json"))
    args = parser.parse_args()
    try:
        cases = json.loads(args.fixture.read_text(encoding="utf-8"))["cases"]
        if not cases:
            raise ValueError("fixture contains no cases")
        checks = [(case["id"], inspect(case), case["expected"]) for case in cases]
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"{args.fixture}: {error}\n")

    matched = 0
    for case_id, result, expected in checks:
        passed = result == expected
        matched += passed
        status = "OK" if passed else "FAIL"
        print(f"{case_id} {status} {json.dumps(result)}")
    print(f"{matched}/{len(checks)} cases matched.")
    return 0 if matched == len(checks) else 1


if __name__ == "__main__":
    raise SystemExit(main())
