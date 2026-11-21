"""Read the synthetic CSV next to this script. No AWS API or network calls."""
import csv
from pathlib import Path


def scope(row):
    return row["account"], row["region"], row["interface-id"]


def endpoints(row):
    return (row["srcaddr"], row["srcport"]), (row["dstaddr"], row["dstport"])


def accepted(row):
    return row["log-status"] == "OK" and row["action"] == "ACCEPT"


def reverse_candidates(row, records):
    """Find evidence candidates for this same-ENI direct-path exercise."""
    start, end = int(row["start"]), int(row["end"])
    reverse_direction = {"ingress": "egress", "egress": "ingress"}[row["flow-direction"]]
    return [
        other["id"] for other in records
        if scope(other) == scope(row)
        and accepted(other)
        and other["flow-direction"] == reverse_direction
        and other["protocol"] == row["protocol"]
        and endpoints(other) == endpoints(row)[::-1]
        and max(start, int(other["start"])) <= min(end, int(other["end"]))
    ]


def flag_labels(row):
    if row["protocol"] != "6" or row["tcp-flags"] == "-":
        return "UNAVAILABLE"
    flags = int(row["tcp-flags"])
    labels = [label for bit, label in ((1, "FIN"), (2, "SYN"), (4, "RST")) if flags & bit]
    if (flags & 18) == 18:
        labels[labels.index("SYN")] = "SYN-ACK"
    return "+".join(labels) or "NO_SUPPORTED_FLAG"


def main():
    with Path(__file__).with_name("vpc-flow-log-records.csv").open(
        encoding="utf-8", newline=""
    ) as handle:
        records = list(csv.DictReader(handle))
    by_id = {row["id"]: row for row in records}
    expected = [
        ("A01 reverse candidates", reverse_candidates(by_id["A01"], records), ["A02"]),
        ("A02 flags", flag_labels(by_id["A02"]), "SYN-ACK"),
        ("B01 decision and logging", (by_id["B01"]["action"], by_id["B01"]["log-status"]),
         ("REJECT", "OK")),
        ("B02 and B03 logging", (by_id["B02"]["log-status"], by_id["B03"]["log-status"]),
         ("NODATA", "SKIPDATA")),
        ("C01 interface and packet destination",
         (by_id["C01"]["dstaddr"], by_id["C01"]["pkt-dstaddr"]),
         ("10.10.0.9", "203.0.113.80")),
        ("C02 combined flags", flag_labels(by_id["C02"]), "FIN+SYN"),
        ("D01 flags", flag_labels(by_id["D01"]), "UNAVAILABLE"),
        ("E01 reverse candidates", reverse_candidates(by_id["E01"], records), []),
    ]
    for name, actual, wanted in expected:
        if actual != wanted:
            raise AssertionError(f"{name}: expected {wanted}, observed {actual}")
        print(f"{name}: {actual}")
    print(f"{len(expected)} synthetic checks passed.")


if __name__ == "__main__":
    main()
