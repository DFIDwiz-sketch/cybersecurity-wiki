"""Compare a fictional grant and a normalized request without calling a tenant."""
import argparse
import json
from pathlib import Path


def explain(row):
    grant = row["grant"]
    call = row["call"]
    if call is None:
        return "grant_only"
    identity = ("tenant", "client_sp", "resource_sp")
    if not all(call.get(field) for field in identity) or call["kind"] is None:
        return "request_context_missing"
    if any(call[field] != grant[field] for field in identity):
        return "different_identity_or_resource"
    if call["kind"] != grant["kind"]:
        return "different_permission_mode"
    if grant["kind"] == "delegated":
        if call["user"] is None:
            return "request_context_missing"
        if grant["consent"] == "Principal" and call["user"] != grant["user"]:
            return "different_delegated_user"
    if call["permission"] != grant["permission"]:
        return "different_token_permission"
    if call["at"] < grant["from"] or (
        grant["until"] is not None and call["at"] >= grant["until"]
    ):
        return "outside_grant_window"
    if call["status"] == 200:
        return "matching_success_response"
    if call["status"] == 403:
        return "matching_denied_response"
    return "inspect_response_semantics"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path)
    args = parser.parse_args()
    with args.cases.open(encoding="utf-8") as source:
        for line in source:
            row = json.loads(line)
            print(f'{row["case"]}: {explain(row)}')


if __name__ == "__main__":
    main()
