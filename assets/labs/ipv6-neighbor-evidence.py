"""Classify pre-decoded, fictional IPv6 neighbor evidence without network access."""

import ipaddress
import json
import sys
from pathlib import Path


def solicited_node(target):
    base = ipaddress.IPv6Address("ff02::1:ff00:0")
    return ipaddress.IPv6Address(int(base) | (int(target) & 0xFFFFFF))


def packet_evidence(packet, link, target):
    packet_target = ipaddress.IPv6Address(packet["target"])
    if packet["link"] != link or packet_target != target:
        return "outside_scope"
    if packet["hop_limit"] != 255 or packet["code"] != 0 or packet["fragment_header"]:
        return "header_check_failed"

    destination = ipaddress.IPv6Address(packet["destination"])
    if packet["kind"] == "NS":
        source = ipaddress.IPv6Address(packet["source"])
        if not source.is_unspecified:
            return "solicitation_observed"
        if destination != solicited_node(target) or packet.get("source_lladdr"):
            return "dad_shape_failed"
        return "dad_probe_observed"

    if packet["kind"] == "NA":
        if destination.is_multicast and packet["solicited"]:
            return "multicast_solicited_invalid"
        return "advertisement_observed"

    raise ValueError(f"unexpected packet kind: {packet['kind']}")


def endpoint_evidence(before, after):
    if after is None:
        neighbor = "unknown"
    elif after["state"] == "FAILED":
        neighbor = "failed"
    elif before and before.get("mac") and after.get("mac"):
        neighbor = "unchanged" if before["mac"].lower() == after["mac"].lower() else "changed"
    elif after.get("mac"):
        neighbor = "mapping_observed"
    else:
        neighbor = "no_mapping_in_snapshot"
    return {
        "neighbor": neighbor,
        "neighbor_state": after["state"] if after else None,
    }


def summarize(case):
    target = ipaddress.IPv6Address(case["target"])
    return {
        "packets": [packet_evidence(packet, case["link"], target) for packet in case["packets"]],
        "endpoint": endpoint_evidence(case["before"], case["after"]),
        "address_state": case["address_state"],
    }


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 ipv6-neighbor-evidence.py CASES.json", file=sys.stderr)
        return 2
    try:
        cases = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        if not isinstance(cases, list) or not cases:
            raise ValueError("expected a non-empty list of cases")
        results = [(case["id"], summarize(case), case["expected"]) for case in cases]
    except (OSError, KeyError, TypeError, ValueError) as error:
        print(f"Unable to read cases: {error}", file=sys.stderr)
        return 2

    failures = 0
    for case_id, actual, expected in results:
        matched = actual == expected
        failures += int(not matched)
        print(f"{'PASS' if matched else 'FAIL'} {case_id} {json.dumps(actual)}")
        if not matched:
            print(f"  expected {json.dumps(expected)}")
    return int(failures > 0)


if __name__ == "__main__":
    sys.exit(main())
