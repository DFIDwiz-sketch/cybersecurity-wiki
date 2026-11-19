"""Correlate the bundled synthetic CloudTrail events offline."""
import json
from datetime import datetime
from pathlib import Path

def utc(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))

with Path(__file__).with_name("aws-role-events.json").open(encoding="utf-8") as source:
    rows = json.load(source)["Records"]

issued = {}
denied_requests = []
actions = {}
for row in sorted(rows, key=lambda r: utc(r["eventTime"])):
    identity = row["userIdentity"]
    event_id = row["eventID"]
    at = utc(row["eventTime"])
    if row["eventSource"] == "sts.amazonaws.com" and row["eventName"] == "AssumeRole":
        if row.get("errorCode"):
            denied_requests.append(event_id)
            continue
        response = row.get("responseElements") or {}
        cred = response.get("credentials") or {}
        arn = (response.get("assumedRoleUser") or {}).get("arn")
        key = cred.get("accessKeyId")
        if arn and key and cred.get("expiration"):
            issued[(arn, key)] = (event_id, at, utc(cred["expiration"]))
        continue
    if identity.get("type") != "AssumedRole":
        continue
    entry = issued.get((identity.get("arn"), identity.get("accessKeyId")))
    source_id = entry[0] if entry and entry[1] <= at < entry[2] else None
    outcome = row.get("errorCode") or "no error recorded"
    actions[event_id] = (source_id, outcome)
    print(f'{event_id} {row["eventName"]}: {source_id or "unlinked"} | {outcome}')

expected = {
    "lab-04": ("lab-01", "no error recorded"),
    "lab-05": ("lab-01", "AccessDenied"),
    "lab-06": ("lab-02", "no error recorded"),
    "lab-07": (None, "no error recorded"),
    "lab-08": (None, "no error recorded"),
}
if len(rows) != 8 or denied_requests != ["lab-03"] or actions != expected:
    raise SystemExit("Unexpected worksheet results")
print("PASS: two issuances, one denied request, five API observations")
