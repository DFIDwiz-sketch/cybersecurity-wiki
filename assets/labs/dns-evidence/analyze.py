#!/usr/bin/env python3
"""Analyze ORIGINAL SYNTHETIC normalized DNS worksheets, not native Zeek logs."""
import argparse
import collections
import datetime
import json
from pathlib import Path

ap = argparse.ArgumentParser()
ap.add_argument("path", nargs="?", type=Path, default=Path(__file__).with_name("events.jsonl"))
ap.add_argument("--self-test", action="store_true", help="check the unchanged bundled fixture")
args = ap.parse_args()
rows = []
for line_number, line in enumerate(args.path.read_text(encoding="utf-8").splitlines(), 1):
    if not line.strip():
        continue
    r = json.loads(line)
    required = {"time", "view", "sensor", "client", "resolver", "transaction_id",
                "query", "qtype", "rcode", "answers", "authority_soa", "referral"}
    if not required <= r.keys() or r["view"] not in ("client", "upstream"):
        raise ValueError(f"unsupported row schema at line {line_number}")
    datetime.datetime.fromisoformat(r["time"].replace("Z", "+00:00"))
    if not isinstance(r["answers"], list):
        raise ValueError(f"answers must be a list at line {line_number}")
    rows.append(r)

clients = [r for r in rows if r["view"] == "client"]
def nodata(r):
    # Narrow fixture rule: no CNAME/referral and SOA explicitly provided.
    return (r["rcode"] == "NOERROR" and not r["answers"]
            and r["authority_soa"] is True and r["referral"] is False)
nd = [r for r in clients if nodata(r)]
print(f"records={len(rows)} client_view={len(clients)} upstream_view={len(rows)-len(clients)}")
for client in sorted({r["client"] for r in clients}):
    events = [r for r in clients if r["client"] == client]
    counts = collections.Counter(r["rcode"] for r in events)
    nx = counts["NXDOMAIN"]
    print(f"{client}: responses={len(events)} nxdomain={nx} ratio={nx/len(events):.1%}")
print("NODATA-like fixture rows:", [(r["client"], r["query"], r["qtype"]) for r in nd])
txt = [r for r in clients if r["qtype"] == "TXT"]
print("TXT client responses:", len(txt))
print("Verdict: worksheet counts only; no infection or attribution conclusion.")
if args.self_test:
    checks = [
        len(rows) == 14,
        len(clients) == 13,
        sum(r["client"] == "192.0.2.10" and r["rcode"] == "NXDOMAIN" for r in clients) == 4,
        len(nd) == 1 and nd[0]["qtype"] == "AAAA",
        len(txt) == 2,
        len([r for r in rows if r["transaction_id"] == 42]) == 2
        and len([r for r in clients if r["transaction_id"] == 42]) == 1,
    ]
    if not all(checks):
        raise AssertionError("bundled fixture expectations failed")
    print("PASS: six fixture checks (volume, vantage point, NXDOMAIN, NODATA, TXT, ID scope)")
