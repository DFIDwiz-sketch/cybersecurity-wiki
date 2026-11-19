import csv
from pathlib import Path

with Path(__file__).with_suffix(".csv").open(encoding="utf-8", newline="") as source:
    rows = list(csv.DictReader(source))

results = {}
for row in rows:
    methods = ("spf", "dkim")
    aligned = [method for method in methods if row[method] == "pass"
               and row[method + "_domain"].lower() == row["from_domain"].lower()]
    label = "+".join(aligned)
    if not label:
        label = "unresolved" if "temperror" in (row["spf"], row["dkim"]) else "no aligned pass"
    results[row["case"]] = label
    print(row["case"], label, "receiver:", row["disposition"])

expected = dict(A="spf", B="no aligned pass", C="dkim", D="spf+dkim", E="unresolved")
if len(rows) != len(expected) or results != expected:
    raise SystemExit("Fixture checks failed")
print("PASS: five synthetic cases")
