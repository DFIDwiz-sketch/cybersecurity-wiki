"""Compare fictional, pre-correlated observations against the exercise key."""

import argparse
import json
from pathlib import Path


def assess(case, budget_ms):
    expected = case["expected_source"]
    selected = case["selected_source"]
    source = case["sources"].get(expected, {})
    selected_mode = case["sources"].get(selected, {}).get("mode")
    before, after = source.get("good_before"), source.get("good_after")

    flags = []
    if selected is None:
        flags.append("no-source-selected")
    elif selected != expected:
        flags.append("different-source-selected")

    if selected_mode == "plain":
        flags.append("selected-source-unauthenticated")
    elif selected is not None and selected_mode is None:
        flags.append("selected-auth-missing")

    if before is None or after is None:
        flags.append("measurement-evidence-missing")
    elif after < before:
        flags.append("counter-discontinuity")
    elif after == before:
        flags.append("no-new-accepted-sample")
    elif source.get("mode") == "NTS" and source.get("last_auth") is True:
        flags.append("fresh-nts-evidence")
    else:
        flags.append("fresh-sample-without-nts-evidence")

    if source.get("ke_observed") is True:
        flags.append("key-establishment-observed")

    error_ms = case["estimated_error_ms"]
    if error_ms is None:
        flags.append("clock-estimate-missing")
    elif error_ms > budget_ms:
        flags.append("clock-estimate-over-budget")
    else:
        flags.append("clock-estimate-within-budget")

    return flags


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    path = parser.parse_args().fixture
    try:
        fixture = json.loads(path.read_text(encoding="utf-8"))
        cases = fixture["cases"]
        budget_ms = fixture["budget_ms"]
        if not cases:
            raise ValueError("the fixture contains no cases")
        results = [
            (case["id"], assess(case, budget_ms), case["expected_flags"])
            for case in cases
        ]
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        parser.error(str(exc))

    passed = 0
    for case_id, actual, expected in results:
        match = sorted(actual) == sorted(expected)
        passed += match
        print(f"{'PASS' if match else 'FAIL'} {case_id}: {', '.join(actual)}")
        if not match:
            print(f"  expected: {', '.join(expected)}")
    print(f"{passed}/{len(results)} cases match")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
