"""Evaluate the offline benign validation worksheet, not a SIEM search."""
import json
from pathlib import Path

WINDOW_START = 5
WINDOW_END = 10
RUN_AT = 10

def evaluate(case):
    if not case["source"]:
        return "source missing"
    if not case["indexed"]:
        return "ingest missing"
    if case["arrived_min"] > RUN_AT:
        return "late arrival"
    if not WINDOW_START <= case["event_min"] < WINDOW_END:
        return "outside event window"
    if "marker" not in case:
        return "field missing"
    if case["marker"] != "wiki-canary":
        return "no match"
    if case["suppressed"]:
        return "suppressed"
    if not case["notification"]:
        return "delivery missing"
    return "delivered"

with Path(__file__).with_suffix(".json").open(encoding="utf-8") as source:
    cases = json.load(source)["cases"]

if len(cases) != 9 or len({case["id"] for case in cases}) != 9:
    raise SystemExit("Expected nine uniquely identified fixture cases")
for case in cases:
    result = evaluate(case)
    print(case["id"], result)
    if result != case["expected"]:
        raise SystemExit(f'{case["id"]}: expected {case["expected"]}')
print("PASS: nine detection pipeline cases")
