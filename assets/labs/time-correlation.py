"""Normalize the bundled synthetic timeline without reading live logs."""
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

def utc(value):
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value, timezone.utc)
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if dt.tzinfo is None:
        return None
    return dt.astimezone(timezone.utc)

def key(row):
    return row["source"], row["host"], row["id"]

def fingerprint(row):
    # Only ingestion time may differ for a duplicate in this fixture.
    return {name: value for name, value in row.items() if name != "indexed"}

with Path(__file__).with_suffix(".json").open(encoding="utf-8") as source:
    rows = json.load(source)

unique, duplicates = {}, []
for row in rows:
    identity = key(row)
    kept = unique.get(identity)
    if kept is None:
        unique[identity] = row
    elif fingerprint(kept) != fingerprint(row):
        raise SystemExit(f"Conflicting observations for {identity}")
    else:
        duplicates.append(identity)
        if utc(row["indexed"]) < utc(kept["indexed"]):
            unique[identity] = row

bounds, unplaced = {}, {}
for identity, row in unique.items():
    observed = utc(row["raw"])
    correction = row["clock_ahead_s"]
    if observed is None or correction is None:
        unplaced[identity] = "timezone unknown" if observed is None else "clock correction unknown"
        continue
    corrected = observed - timedelta(seconds=correction)
    radius = timedelta(seconds=row["uncertainty_s"])
    bounds[identity] = (corrected - radius, corrected + radius)
    print(row["id"], "estimated UTC", corrected.isoformat(),
          "| indexed", row["indexed"])

for identity, reason in unplaced.items():
    print(identity[2], "unplaced:", reason)

def compare(left, right):
    a, b = bounds[left], bounds[right]
    if a[1] < b[0]:
        return "before"
    if b[1] < a[0]:
        return "after"
    return "order unresolved"

firewall = ("firewall", "edge-a", "f-01")
proxy = ("proxy", "proxy-a", "p-01")
host = ("host", "app-a", "h-01")
later = ("host", "app-a", "h-02")
results = (compare(firewall, host), compare(host, proxy), compare(proxy, later))
print("firewall / host:", results[0])
print("host / proxy:", results[1])
print("proxy / later host:", results[2])
if (len(rows) != 8 or duplicates != [proxy] or len(bounds) != 5
        or set(unplaced) != {("syslog", "old-a", "u-01"), ("host", "app-b", "h-03")}
        or results != ("before", "order unresolved", "before")):
    raise SystemExit("Unexpected worksheet results")
print("PASS: 8 records, 1 duplicate, 2 unplaced, 3 ordering checks")
