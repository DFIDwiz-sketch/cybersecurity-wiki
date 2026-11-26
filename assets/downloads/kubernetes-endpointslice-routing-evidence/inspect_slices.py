"""Check fictional IPv4 Service and EndpointSlice snapshots without network access."""

import argparse
import json
from pathlib import Path


def backend_state(endpoint):
    state = endpoint.get("conditions", {})
    if state.get("terminating") is True:
        return "terminating-serving" if state.get("serving") is not False else "skip"
    return "candidate" if state.get("ready") is not False else "skip"


def candidates_for(case):
    service = case["service"]
    meta, spec = service["metadata"], service["spec"]
    service_port = spec["ports"][0]
    port_key = service_port["name"], service_port.get("protocol", "TCP")
    candidates, findings = set(), set()

    for item in case["slices"]:
        labels = item["metadata"].get("labels", {})
        if item["metadata"]["namespace"] != meta["namespace"] or (
            labels.get("kubernetes.io/service-name") != meta["name"]
        ) or item["addressType"] != "IPv4":
            continue

        owners = item["metadata"].get("ownerReferences", [])
        if any(owner["kind"] == "Service" and owner["uid"] != meta["uid"] for owner in owners):
            findings.add("service-owner-uid-mismatch")
        if not spec.get("selector"):
            findings.add("selectorless-service")

        for port in item["ports"]:
            if (port.get("name"), port.get("protocol", "TCP")) != port_key:
                continue
            if not isinstance(port.get("port"), int):
                findings.add("numeric-port-missing")
                continue
            for endpoint in item["endpoints"]:
                if spec.get("internalTrafficPolicy") == "Local":
                    if endpoint.get("nodeName") != case["client_node"]:
                        findings.add("node-local-filter")
                        continue
                state = backend_state(endpoint)
                if state == "terminating-serving":
                    findings.add(state)
                if state != "candidate":
                    continue
                for address in endpoint["addresses"]:
                    key = f"{address}:{port['port']}/{port_key[1]}"
                    if key in candidates:
                        findings.add("duplicate-address-port")
                    candidates.add(key)

    return {"candidates": sorted(candidates), "findings": sorted(findings)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    path = parser.parse_args().fixture
    try:
        records = json.loads(path.read_text(encoding="utf-8"))["cases"]
        if not records:
            raise ValueError("the fixture has no cases")
        comparisons = [(case["id"], candidates_for(case), case["expected"]) for case in records]
    except (OSError, ValueError, TypeError, KeyError, AttributeError, IndexError) as exc:
        parser.error(str(exc))

    passed = 0
    for name, actual, expected in comparisons:
        match = actual == expected
        passed += match
        print(f"{'PASS' if match else 'FAIL'} {name}: {json.dumps(actual, sort_keys=True)}")
        if not match:
            print(f"  expected: {json.dumps(expected, sort_keys=True)}")
    print(f"{passed}/{len(comparisons)} cases match")
    return 0 if passed == len(comparisons) else 1


if __name__ == "__main__":
    raise SystemExit(main())
