"""Compare fictional capture observations. Does not send or capture packets."""

import csv
from pathlib import Path

RELEVANT = {"4": "frag_needed", "6": "packet_too_big"}


def interpret(row):
    if row["large_ack"] == "yes":
        return "large_data_acknowledged"

    feedback = row["feedback"]
    if feedback == "none":
        return "no_feedback_observed"
    if feedback != RELEVANT[row["ip_version"]] or row["matched_quote"] != "yes":
        return "feedback_not_linked"

    mtu = int(row["reported_mtu"])
    if row["ip_version"] == "4" and mtu == 0:
        return "legacy_mtu_unspecified"
    large, small = int(row["large_ip_bytes"]), int(row["small_ip_bytes"])
    if mtu <= 0 or mtu >= large or (row["ip_version"] == "6" and mtu < 1280):
        return "review_reported_mtu"
    if row["feedback_at_sender"] == "no" and row["coverage"] == "both":
        return "feedback_path_gap_candidate"
    if row["feedback_at_sender"] != "yes":
        return "feedback_delivery_unconfirmed"
    if row["smaller_retry_ack"] == "yes" and 0 < small <= mtu:
        return "smaller_retry_acknowledged"
    return "recovery_unconfirmed"


def main():
    path = Path(__file__).with_name("pmtu-cases.csv")
    with path.open(encoding="utf-8", newline="") as source:
        rows = list(csv.DictReader(source))
    for row in rows:
        print(f'{row["case"]}: {interpret(row)}')
    print(f"Reviewed: {len(rows)} synthetic cases")


if __name__ == "__main__":
    main()
