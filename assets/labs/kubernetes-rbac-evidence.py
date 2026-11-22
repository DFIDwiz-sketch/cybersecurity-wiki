#!/usr/bin/env python3
"""Trace exact RBAC grants in a small fictional Kubernetes snapshot."""

import argparse
import json
from pathlib import Path


def subject_matches(subject, request):
    kind, name = subject["kind"], subject["name"]
    if kind == "Group":
        return name in request["groups"]
    if kind == "ServiceAccount":
        return request["username"] == f"system:serviceaccount:{subject['namespace']}:{name}"
    return kind == "User" and name == request["username"]


def matching_grants(snapshot, request):
    """Return matching binding identifiers, without assuming the live decision."""
    namespace = request["namespace"]
    for binding in snapshot["bindings"]:
        binding_namespace = binding["namespace"]
        if binding_namespace is not None and binding_namespace != namespace:
            continue
        if not any(subject_matches(subject, request) for subject in binding["subjects"]):
            continue
        for rule in snapshot["rules"][binding["role"]]:
            if (request["api_group"] == rule["api_group"]
                    and request["resource"] in rule["resources"]
                    and request["verb"] in rule["verbs"]
                    and (not rule["names"] or request["name"] in rule["names"])):
                yield binding["id"]
                break


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    snapshot = json.loads(args.fixture.read_text(encoding="utf-8"))
    for case, request in snapshot["requests"].items():
        matches = sorted(matching_grants(snapshot, request))
        print(f"{case}: {', '.join(matches) if matches else 'no_grant_found'}")


if __name__ == "__main__":
    main()
