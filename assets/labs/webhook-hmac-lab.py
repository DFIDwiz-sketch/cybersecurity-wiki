#!/usr/bin/env python3
"""Offline teaching protocol. No sockets, vendor credentials or external writes."""

import hmac
import json
import secrets
import sqlite3


def tag(key, timestamp, raw_body):
    envelope = b"wiki-lab-v1:" + str(timestamp).encode("ascii") + b":" + raw_body
    return hmac.digest(key, envelope, "sha256")


def receive(db, key, now, timestamp, raw_body, supplied_tag, fail=False):
    if not isinstance(supplied_tag, bytes) or len(supplied_tag) != 32:
        return "invalid tag"
    if not hmac.compare_digest(tag(key, timestamp, raw_body), supplied_tag):
        return "invalid tag"
    if not now - 300 <= timestamp <= now + 30:
        return "outside lab time window"

    event = json.loads(raw_body)
    if event["type"] != "lesson.completed":
        return "unsupported event"
    # Both the claim and the fictional effect must commit, or neither does.
    try:
        with db:
            claimed = db.execute(
                "INSERT INTO processed VALUES (?, ?, ?) "
                "ON CONFLICT(provider, endpoint, event_id) DO NOTHING",
                ("fixture", "lessons", event["id"]),
            )
            if not claimed.rowcount:
                return "duplicate"
            db.execute("UPDATE effects SET count = count + 1")
            if fail:
                raise RuntimeError("simulated rollback")
    except RuntimeError:
        return "rolled back"
    return "processed"


def main():
    clock = 1_800_000_000
    key = secrets.token_bytes(32)
    original = b'{"id":"evt-a", "type":"lesson.completed"}'
    compact = b'{"id":"evt-a","type":"lesson.completed"}'
    other_type = b'{"id":"evt-b","type":"lesson.deleted"}'
    retry = b'{"id":"evt-c","type":"lesson.completed"}'
    valid = tag(key, clock, original)
    wrong = tag(secrets.token_bytes(32), clock, original)

    with sqlite3.connect(":memory:") as db:
        db.executescript("""
            CREATE TABLE processed(
              provider TEXT NOT NULL, endpoint TEXT NOT NULL, event_id TEXT NOT NULL,
              PRIMARY KEY(provider, endpoint, event_id)
            );
            CREATE TABLE effects(count INTEGER NOT NULL);
            INSERT INTO effects VALUES (0);
        """)
        cases = [
            ("A", clock, original, valid, False, "processed", 1),
            ("B", clock, compact, valid, False, "invalid tag", 1),
            ("C", clock, original, wrong, False, "invalid tag", 1),
            ("D", clock - 301, original, tag(key, clock - 301, original), False, "outside lab time window", 1),
            ("E", clock + 31, original, tag(key, clock + 31, original), False, "outside lab time window", 1),
            ("F", clock + 1, original, tag(key, clock + 1, original), False, "duplicate", 1),
            ("G", clock, other_type, tag(key, clock, other_type), False, "unsupported event", 1),
            ("H", clock, retry, tag(key, clock, retry), True, "rolled back", 1),
            ("I", clock, retry, tag(key, clock, retry), False, "processed", 2),
            ("J", clock, original, None, False, "invalid tag", 2),
        ]
        for label, timestamp, body, supplied_tag, fail, expected, expected_count in cases:
            result = receive(db, key, clock, timestamp, body, supplied_tag, fail)
            count = db.execute("SELECT count FROM effects").fetchone()[0]
            if (result, count) != (expected, expected_count):
                raise SystemExit(f"FAIL {label}: result={result}, effects={count}")
            print(f"PASS {label}: {result}, effects={count}")
        print(f"{len(cases)}/{len(cases)} webhook controls matched.")


if __name__ == "__main__":
    main()
