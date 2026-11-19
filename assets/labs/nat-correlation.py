"""Compare the provided fictional flow records. No network requests."""
import csv
from datetime import datetime
from pathlib import Path

with Path(__file__).with_suffix(".csv").open(encoding="utf-8", newline="") as source:
    rows = list(csv.DictReader(source))

def flow_key(row, translated=False):
    prefix = "nat_" if translated else ""
    fields = ("src_ip", "src_port", "dst_ip", "dst_port")
    return (row["boundary"], row["protocol"], *(row[prefix + field] for field in fields))

def interval(row):
    return tuple(datetime.fromisoformat(row[field].replace("Z", "+00:00"))
                 for field in ("start_utc", "end_utc"))

allowed = [row for row in rows if row["source"] == "firewall" and row["outcome"] == "allow"]
matches = {}
for observation in (row for row in rows if row["source"] != "firewall"):
    first, last = interval(observation)
    candidates = []
    for record in allowed:
        start, end = interval(record)
        if flow_key(observation) == flow_key(record, translated=True) and first <= end and start <= last:
            candidates.append(record["id"])
    matches[observation["id"]] = candidates
    label = "unlinked" if not candidates else ", ".join(candidates)
    if len(candidates) > 1:
        label = "ambiguous: " + label
    print(f'{observation["id"]} -> {label} | sensor state={observation["outcome"]}')

expected = {
    "obs-01": ["fw-01"], "obs-02": ["fw-02"], "obs-03": ["fw-04"], "obs-04": ["fw-05"],
    "obs-05": [], "obs-06": [], "obs-07": [],
}
denied = [row["id"] for row in rows if row["source"] == "firewall" and row["outcome"] == "deny"]
if len(rows) != 12 or matches != expected or denied != ["fw-03"]:
    raise SystemExit("Unexpected worksheet results")
print("PASS: four correlations, three unlinked observations, one firewall deny")
