#!/usr/bin/env python3
"""Read the bundled synthetic TCP worksheet using the Python standard library."""
import csv
from collections import defaultdict
from pathlib import Path

with Path(__file__).with_suffix(".csv").open(encoding="utf-8", newline="") as source:
    flows = defaultdict(list)
    for row in csv.DictReader(source):
        flows[row["flow"]].append(row)

assert {name: len(rows) for name, rows in flows.items()} == {"A": 9, "B": 2, "C": 2, "D": 3}
a, b, c, d = (flows[name] for name in "ABCD")
assert [p["flags"] for p in a[:3]] == ["SYN", "SYN+ACK", "ACK"]
assert int(a[1]["ack"]) == int(a[0]["seq"]) + 1
assert int(a[2]["ack"]) == int(a[1]["seq"]) + 1
assert int(a[4]["ack"]) == int(a[3]["seq"]) + int(a[3]["payload"])
assert all(int(a[ack]["ack"]) == int(a[fin]["seq"]) + 1 for fin, ack in ((5, 6), (7, 8)))
assert all(p["direction"] == "C>S" and p["flags"] == "SYN" for p in b)
assert b[0]["seq"] == b[1]["seq"]
assert c[1]["flags"] == "RST+ACK" and int(c[1]["ack"]) == int(c[0]["seq"]) + 1
assert (d[0]["seq"], d[0]["payload"]) == (d[1]["seq"], d[1]["payload"])
assert int(d[2]["ack"]) == int(d[0]["seq"]) + int(d[0]["payload"])

print("A: handshake, 40 data bytes cumulatively acknowledged, FIN in each direction")
print("B: two matching SYN observations, no response shown")
print("C: reset acknowledges the original SYN")
print("D: repeated 50-byte sequence range, no handshake shown")
print("PASS: 16 synthetic rows and all four evidence patterns verified")
