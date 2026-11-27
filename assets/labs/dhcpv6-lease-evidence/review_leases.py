"""Compare fictional DHCPv6 assignment history with scoped IPv6 observations."""

import argparse
from datetime import datetime
import ipaddress
import json
from pathlib import Path


def timestamp(text):
    parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if parsed.utcoffset() is None:
        raise ValueError("A time zone is required in the fixture")
    return parsed


def assess(case):
    observation = case["observation"]
    when = timestamp(observation["timestamp"])
    address = ipaddress.IPv6Address(observation["source"])
    exact = []
    prefixes = []
    for lease in case["bindings"]:
        if (
            lease["state"] != "committed" or lease["site"] != observation["site"]
            or lease["link"] != observation["binding_link"]
        ):
            continue
        start = timestamp(lease["valid_from"])
        preferred_end = timestamp(lease["preferred_until"])
        valid_end = timestamp(lease["valid_until"])
        if not start <= preferred_end <= valid_end or start == valid_end:
            raise ValueError(f"Invalid finite interval for {lease['id']}")
        if not start <= when < valid_end:
            continue

        if lease["ia_type"] == "IA_NA":
            if address == ipaddress.IPv6Address(lease["resource"]):
                exact.append({
                    "binding": lease["id"],
                    "address_lifetime": "preferred" if when < preferred_end else "deprecated",
                })
        elif lease["ia_type"] == "IA_PD":
            if address in ipaddress.IPv6Network(lease["resource"]):
                prefixes.append(lease["id"])
        else:
            raise ValueError(f"IA type outside this exercise: {lease['ia_type']}")
    return {"exact": exact, "delegations": prefixes}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    try:
        data = json.loads(args.fixture.read_text(encoding="utf-8"))
        failed = 0
        for case in data["cases"]:
            actual = assess(case)
            matches = actual == case["expected"]
            failed += int(not matches)
            print(f"{'PASS' if matches else 'FAIL'} {case['id']}: {json.dumps(actual)}")
            if not matches:
                print(f"  Expected: {json.dumps(case['expected'])}")
        return int(failed != 0)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Invalid fixture: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
