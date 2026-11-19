#!/usr/bin/env python3
"""Relate synthetic API decisions to app audit records. No tokens are processed."""

import argparse
import json
from collections import defaultdict
from pathlib import Path


def load_events(path):
    decisions = {}
    audits = defaultdict(list)
    with path.open(encoding="utf-8") as source:
        for line_number, line in enumerate(source, 1):
            try:
                event = json.loads(line)
                if not isinstance(event, dict):
                    raise ValueError("expected a JSON object")
                key = tuple(event[field] for field in ("environment", "service", "request_id"))
                if any(not isinstance(value, str) or not value for value in key):
                    raise ValueError("scope and request ID must be nonempty strings")
                kind = event["kind"]
                if kind == "api":
                    if key in decisions:
                        raise ValueError("duplicate API decision for the scoped request")
                    status = event["status"]
                    if type(status) is not int or not 100 <= status <= 599:
                        raise ValueError("expected an HTTP status integer from 100 to 599")
                    decisions[key] = (event["stage"], event["reason"], status)
                elif kind == "app_audit":
                    audits[key].append((event["action"], event["result"]))
                else:
                    raise ValueError(f"unknown event kind: {kind}")
            except (KeyError, ValueError) as error:
                raise ValueError(f"{path}:{line_number}: {error}") from error
    return decisions, audits


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "events",
        nargs="?",
        type=Path,
        default=Path(__file__).with_name("oauth-oidc-events.jsonl"),
    )
    args = parser.parse_args()
    try:
        decisions, audits = load_events(args.events)
    except (OSError, UnicodeError, ValueError) as error:
        parser.exit(2, f"{error}\n")

    matching = 0
    for key, (stage, reason, status) in decisions.items():
        entries = audits.get(key, [])
        matching += len(entries)
        evidence = ", ".join(f"{action}={result}" for action, result in entries)
        print(f"{'/'.join(key)} | HTTP {status} | {stage}: {reason} | audit: {evidence or 'unconfirmed'}")

    orphaned = sum(len(entries) for key, entries in audits.items() if key not in decisions)
    print(f"API decisions: {len(decisions)} | matching audits: {matching} | unmatched audits: {orphaned}")


if __name__ == "__main__":
    main()
