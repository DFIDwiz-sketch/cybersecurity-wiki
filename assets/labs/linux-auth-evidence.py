"""Read the bundled synthetic Linux authentication worksheet offline."""
import csv
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

with Path(__file__).with_name("linux-auth-events.csv").open(encoding="utf-8", newline="") as source:
    rows = list(csv.DictReader(source))

def timestamp(row):
    return datetime.fromisoformat(row["utc"].replace("Z", "+00:00"))

def auth_key(row):
    return tuple(row[field] for field in ("host", "boot", "account", "remote_ip"))

def session_key(row):
    return tuple(row[field] for field in ("host", "boot", "account", "audit_session"))

failures = defaultdict(list)
opened = {}
candidates = []
sudo_rows = []
for row in sorted(rows, key=timestamp):
    event = row["event"]
    at = timestamp(row)
    if event == "auth_failed":
        failures[auth_key(row)].append(at)
    elif event == "auth_accepted":
        recent = sum(at - timedelta(minutes=5) <= t < at for t in failures[auth_key(row)])
        print(f'{row["host"]} {row["account"]} {row["remote_ip"]}: '
              f'{recent} preceding failures, accepted via {row["method"]}')
        if recent >= 3:
            candidates.append(auth_key(row))
    elif event == "session_open" and row["audit_session"]:
        opened[session_key(row)] = row
    elif event == "session_close":
        opened.pop(session_key(row), None)
    elif event.startswith("sudo_"):
        key = session_key(row)
        linked = bool(row["audit_session"] and key in opened)
        sudo_rows.append((row["host"], row["account"], event, linked))
        print(f'{row["host"]} {row["account"]} {event}: '
              f'{"session in worksheet" if linked else "session unlinked"}')

expected_sudo = [
    ("app01", "alex", "sudo_allowed", True),
    ("app01", "sam", "sudo_denied", True),
    ("app01", "sam", "sudo_allowed", True),
    ("app02", "sam", "sudo_allowed", False),
]
if len(rows) != 14 or candidates != [("app01", "b001", "sam", "198.51.100.23")] or sudo_rows != expected_sudo:
    raise SystemExit("Unexpected worksheet results. Check the data and filenames.")
print("PASS: 14 rows, one candidate and four scoped sudo observations")
