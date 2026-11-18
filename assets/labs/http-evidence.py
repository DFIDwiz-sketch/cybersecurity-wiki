#!/usr/bin/env python3
"""Correlate the supplied offline synthetic HTTP worksheet."""
import csv
from pathlib import Path

with Path(__file__).with_suffix(".csv").open(encoding="utf-8", newline="") as source:
    rows = list(csv.DictReader(source))

def index(plane, key):
    records = {}
    for row in rows:
        if row["plane"] == plane:
            identifier = row[key]
            if not identifier or identifier in records:
                raise ValueError(f"Missing or duplicate {key} for {plane}: {identifier!r}")
            records[identifier] = row
    return records

edges = index("edge", "request_id")
apps = index("app", "request_id")
jobs = index("worker", "work_id")
for identifier, edge in edges.items():
    app = apps.get(identifier)
    job = jobs.get(app["work_id"]) if app else None
    print(f'{identifier}: edge={edge["status"]} ({edge["decision"]}) '
          f'app={app["status"] if app else "unobserved"} '
          f'job={job["decision"] if job else "unobserved"}')

assert len(rows) == 12 and len(edges) == 7
assert edges["r-101"]["status"] == apps["r-101"]["status"] == "200"
assert apps["r-102"]["status"] == "202" and jobs[apps["r-102"]["work_id"]]["decision"] == "fail"
assert edges["r-103"]["decision"] == "deny" and "r-103" not in apps
assert (edges["r-104"]["status"], apps["r-104"]["status"]) == ("504", "200")
assert edges["r-105"]["decision"] == "cache_hit" and "r-105" not in apps
assert edges["r-106"]["status"] == apps["r-106"]["status"] == "404"
assert edges["r-107"]["status"] == "502" and "r-107" not in apps
print("PASS: seven request evidence cases")
