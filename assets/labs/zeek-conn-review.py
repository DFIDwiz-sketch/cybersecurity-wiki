"""Inspect selected Zeek-style records in the accompanying synthetic fixture."""
import json
from collections import defaultdict
from pathlib import Path


def direction_markers(history):
    return {
        "gap": "G" in history or "g" in history,
        "data_both_ways": "D" in history and "d" in history,
    }


def assess(row, related):
    state = row["conn_state"]
    proto = row["proto"]
    marks = direction_markers(row.get("history", ""))
    app = [(item["stream"], item["record"]) for item in related]

    byte_fields = (row.get("orig_bytes"), row.get("resp_bytes"))
    payload = ("unset" if None in byte_fields
               else f"{byte_fields[0]}/{byte_fields[1]}")
    if state == "S0" and proto == "tcp":
        result = "ATTEMPT_NO_OBSERVED_REPLY"
    elif state == "REJ" and proto == "tcp":
        result = "ATTEMPT_REJECTED"
    elif state == "OTH" and proto == "tcp":
        result = "NO_SYN_OBSERVED"
    elif (row.get("missed_bytes") or 0) > 0 or marks["gap"]:
        result = "CONTENT_GAP_REVIEW"
    elif state == "SF" and proto == "tcp":
        result = "TCP_NORMAL_LIFECYCLE"
    elif state == "SF" and proto == "udp" and marks["data_both_ways"]:
        result = "UDP_BIDIRECTIONAL"
    else:
        result = "READ_RAW_CONTEXT"

    evidence = []
    for stream, record in app:
        if stream == "http":
            evidence.append(f"HTTP {record.get('status_code', 'unset')}")
        elif stream == "dns":
            evidence.append(f"DNS {record['qtype_name']} {record['rcode_name']}")
    return result, payload, evidence


expected = {
    "C01": ("ATTEMPT_NO_OBSERVED_REPLY", "unset", []),
    "C02": ("ATTEMPT_REJECTED", "unset", []),
    "C03": ("TCP_NORMAL_LIFECYCLE", "100/250", ["HTTP 503"]),
    "C04": ("UDP_BIDIRECTIONAL", "108/174", ["DNS A NOERROR", "DNS AAAA NOERROR"]),
    "C05": ("NO_SYN_OBSERVED", "unset", []),
    "C06": ("CONTENT_GAP_REVIEW", "unset", []),
    "C07": ("TCP_NORMAL_LIFECYCLE", "0/0", []),
}

if __name__ == "__main__":
    fixture = Path(__file__).with_name("zeek-conn-cases.jsonl")
    with fixture.open(encoding="utf-8") as stream:
        rows = [json.loads(line) for line in stream if line.strip()]
    connections = []
    transactions = defaultdict(list)
    for entry in rows:
        key = (entry["source"], entry["record"]["uid"])
        if entry["stream"] == "conn":
            connections.append((key, entry["record"]))
        else:
            transactions[key].append(entry)
    actual = {key[1]: assess(row, transactions[key]) for key, row in connections}
    if actual != expected or len(connections) != len(expected):
        raise AssertionError(f"Expected {expected}, observed {actual}")
    for uid, (result, payload, evidence) in actual.items():
        print(f"{uid}: {result} | payload={payload} | {', '.join(evidence) or 'no match'}")
    print(f"{len(actual)} synthetic flows checked.")
