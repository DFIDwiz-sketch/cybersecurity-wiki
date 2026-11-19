"""Summarize the supplied synthetic Entra and resource records offline."""
import json
from collections import defaultdict
from pathlib import Path

with Path(__file__).with_name("entra-signin-cases.json").open(encoding="utf-8") as source:
    rows = json.load(source)

def scope(row):
    return row["tenant"], row["app"], row["link"]

actions = defaultdict(list)
for row in rows:
    if row["kind"] == "resource" and row["link"]:
        actions[scope(row)].append(row["id"])

results = {}
for row in rows:
    if row["kind"] != "signin":
        continue
    matched = actions.get(scope(row), []) if row["link"] else []
    result = (row["status"], row["mfa"], row.get("report_only", ""), matched)
    results[row["id"]] = result
    print(f'{row["id"]} {row["flow"]} {row["status"]}: '
          f'MFA={row["mfa"]}; CA={row["ca"]}; '
          f'report-only={row.get("report_only", "-")}; '
          f'resource={",".join(matched) or "unlinked"}')

expected = {
    "s-01": ("success", "performed", "", ["a-01"]),
    "s-02": ("success", "prior_claim", "", []),
    "s-03": ("failure", "unknown", "", []),
    "s-04": ("success", "unknown", "would_fail", []),
    "s-05": ("success", "not_user_flow", "", []),
    "s-06": ("interrupted", "unknown", "", []),
}
if len(rows) != 8 or results != expected:
    raise SystemExit("Unexpected worksheet results")
print("PASS: six sign-ins, one scoped resource match, five unlinked")
