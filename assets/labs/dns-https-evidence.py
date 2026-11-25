"""Read normalized fictional DNS and client observations without networking."""

import json
import sys
from pathlib import Path


def compatible_protocols(params, client):
    listed = set(params.get("mandatory", []))
    if "mandatory" in listed or not listed.issubset(params):
        return []
    required = listed | ({"port", "no-default-alpn"} & params.keys())
    if not required.issubset(client["keys"]):
        return []

    advertised = set(params.get("alpn", []))
    if "no-default-alpn" in params:
        if not advertised:
            return []
    else:
        advertised.add("http/1.1")
    return sorted(advertised.intersection(client["alpns"]))


def evaluate_offer(case):
    answers = case["answers"]
    owner = case["question"]
    visited = []
    while owner not in visited:
        visited.append(owner)
        if owner not in answers:
            return visited, "missing_answer", []
        rrset = answers[owner]
        if rrset["rcode"] != "NOERROR":
            return visited, rrset["rcode"], []
        records = rrset["records"]
        if not records:
            return visited, "nodata", []

        alias = next((record for record in records if record["priority"] == 0), None)
        if alias is not None:
            owner = alias["target"]
            if owner == ".":
                return visited, "advisory_unavailable", []
            continue

        client = case["client"]
        eligible = []
        for record in sorted(records, key=lambda item: item["priority"]):
            params = record["params"]
            protocols = compatible_protocols(params, client)
            if not protocols:
                continue
            target = owner if record["target"] == "." else record["target"]
            resolved = case["addresses"].get(target, [])
            hints = params.get("ipv4hint", []) + params.get("ipv6hint", [])
            eligible.append({
                "priority": record["priority"],
                "target": target,
                "port": params.get("port", case["origin_port"]),
                "alpns": protocols,
                "resolved": resolved,
                "hints": hints,
            })
        return visited, "service_mode" if eligible else "no_compatible_record", eligible

    return visited, "alias_loop", []


def evaluate_connection(case):
    observation = case.get("client_observation")
    if observation is None:
        return "not_observed"
    if not observation["connected"]:
        return "attempt_observed"
    if (observation.get("tls_origin_verified") is True
            and observation.get("http_authority") == case["origin_authority"]
            and observation.get("alpn")):
        return f"request_{observation['alpn']}"
    return "connection_observed"


def evaluate(case):
    names, answer, candidate_list = evaluate_offer(case)
    observation = case.get("client_observation")
    endpoint = ({key: observation[key] for key in ("destination", "port")}
                if observation is not None else None)
    return {
        "names": names,
        "answer": answer,
        "candidates": candidate_list,
        "use": evaluate_connection(case),
        "observed_endpoint": endpoint,
    }


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 dns-https-evidence.py CASES.json", file=sys.stderr)
        return 2
    try:
        cases = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
        if not isinstance(cases, list) or not cases:
            raise ValueError("expected a non-empty list of cases")
        results = [(case["id"], evaluate(case), case["expected"]) for case in cases]
    except (OSError, AttributeError, KeyError, TypeError, ValueError) as error:
        print(f"Unable to read cases: {error}", file=sys.stderr)
        return 2

    failures = 0
    for name, actual, expected in results:
        matches = actual == expected
        failures += int(not matches)
        print(f"{'PASS' if matches else 'FAIL'} {name} {json.dumps(actual)}")
        if not matches:
            print(f"  expected {json.dumps(expected)}")
    return int(failures > 0)


if __name__ == "__main__":
    sys.exit(main())
