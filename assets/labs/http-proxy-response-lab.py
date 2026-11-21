#!/usr/bin/env python3
"""Correlate fictional proxy and application observations without network access."""

# Scope, request ID, final status, explicit response decision, attempt IDs.
PROXY = [
    ("shop", "r1", 200, "relayed", ("a1",)),
    ("shop", "r2", 403, "local_denial", ()),
    ("shop", "r3", 503, "relayed", ("a1",)),
    ("shop", "r4", 200, "relayed", ("a1", "a2")),
    ("shop", "r5", 504, "upstream_timeout", ("a1",)),
    ("shop", "r6", 502, "unknown", ("a1",)),
    ("shop", "r7", 504, "relayed", ("a1",)),
]

# Scope, request ID, attempt ID, application response, application outcome.
# In this synthetic log contract a null response has not been recorded.
BACKEND = [
    ("shop", "r1", "a1", 200, "served"),
    ("shop", "r3", "a1", 503, "maintenance"),
    ("shop", "r4", "a2", 200, "served"),
    ("shop", "r5", "a1", None, "committed"),
    ("other", "r6", "a1", 502, "unrelated scope"),
    ("shop", "r7", "a1", 504, "dependency timeout"),
]


def classify(proxy_row, backend_by_key):
    scope, request_id, status, decision, attempts = proxy_row
    matched = [backend_by_key.get((scope, request_id, attempt)) for attempt in attempts]
    if decision == "local_denial":
        return "local denial, no upstream attempt"
    if decision == "upstream_timeout" and any(row and row[1] == "committed" for row in matched):
        return "gateway timeout, application commit recorded"
    if decision == "relayed" and matched and matched[-1] and matched[-1][0] == status:
        if len(attempts) > 1:
            return "final upstream response after multiple attempts"
        return "relayed upstream response"
    return "response origin unresolved"


def main():
    backend_by_key = {
        (scope, request_id, attempt): (status, outcome)
        for scope, request_id, attempt, status, outcome in BACKEND
    }
    expected = [
        "relayed upstream response",
        "local denial, no upstream attempt",
        "relayed upstream response",
        "final upstream response after multiple attempts",
        "gateway timeout, application commit recorded",
        "response origin unresolved",
        "relayed upstream response",
    ]
    for proxy_row, answer in zip(PROXY, expected):
        result = classify(proxy_row, backend_by_key)
        if result != answer:
            raise SystemExit(f"FAIL {proxy_row[1]}: expected {answer}, got {result}")
        print(f"PASS {proxy_row[1]}: {result}")
    print(f"{len(expected)}/{len(expected)} evidence controls matched.")


if __name__ == "__main__":
    main()
