"""Read fictional HTTP and DNS header observations from JSONL."""
import argparse
import json
import struct
from pathlib import Path

RCODES = {0: "NOERROR", 2: "SERVFAIL", 3: "NXDOMAIN"}


def summarize(row):
    status = row.get("http")
    if status is None:
        if row.get("same_lookup_confirmed") and row.get("retry_resolver") == "system":
            return "linked_system_retry"
        return "no_http_observation"
    if not 200 <= status < 300:
        return f"non_success_http_{status}"
    if row.get("media", "").lower() != "application/dns-message":
        return "unexpected_media"

    try:
        wire = bytes.fromhex(row.get("wire", ""))
        _, flags, _, answers, _, _ = struct.unpack_from("!6H", wire)
    except (ValueError, struct.error):
        return "invalid_header"
    if not flags & 0x8000:
        return "not_a_dns_response"
    if flags & 0x0200:
        return "truncated_dns_response"

    rcode = flags & 0x000F
    label = RCODES.get(rcode, f"RCODE_{rcode}")
    result = f"{label} answers={answers}"
    if rcode == 0 and answers and "rr_ttl" in row and "age" in row:
        ttl = max(0, row["rr_ttl"] - row["age"])
        result += f" example_remaining_ttl={ttl}"
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cases", type=Path)
    args = parser.parse_args()
    with args.cases.open(encoding="utf-8") as source:
        for line in source:
            row = json.loads(line)
            print(f'{row["case"]}: {summarize(row)}')


if __name__ == "__main__":
    main()
