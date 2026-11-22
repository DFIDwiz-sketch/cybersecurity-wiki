#!/usr/bin/env python3
"""Compare scoped evidence in the fictional scheduled task exercise."""

import argparse
import json
from pathlib import Path


def summarize(case):
    target = case["target"]
    runtime = [
        event for event in case["events"]
        if all(event.get(key) == target[key] for key in ("host", "task", "instance"))
    ]
    starts = [event for event in runtime if event["kind"] == "instance_start"]
    if not starts:
        return "run_unobserved"
    if len(starts) != 1:
        return "ambiguous_instance_start"

    actions = [
        event for event in runtime
        if event.get("action") == target["action"]
        and event["second"] >= starts[0]["second"]
    ]
    launches = [event for event in actions if event["kind"] == "action_start"]
    if not launches:
        return "action_unobserved"
    if len(launches) != 1:
        return "ambiguous_launch"

    after_launch = [
        event for event in actions if event["second"] >= launches[0]["second"]
    ]
    completions = [event for event in after_launch if event["kind"] == "action_end"]
    if not completions:
        return "completion_unobserved"
    if len(completions) != 1:
        return "ambiguous_completion"
    result = completions[0].get("result")
    if result is None:
        return "result_unobserved"
    if result != 0:
        return "nonzero_result"
    if any(event["kind"] == "effect" for event in after_launch):
        return "effect_observed"
    return "zero_effect_unobserved"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path, help="Fictional JSON cases")
    args = parser.parse_args()
    try:
        cases = json.loads(args.cases.read_text(encoding="utf-8"))
        for case in cases:
            print(f"{case['case']}: {summarize(case)}")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        parser.exit(1, f"Could not analyze the exercise file: {error}\n")


if __name__ == "__main__":
    main()
