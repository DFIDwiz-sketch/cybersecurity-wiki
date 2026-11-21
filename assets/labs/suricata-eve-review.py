"""Review one synthetic EVE fixture. Does not run Suricata or replay traffic."""

from collections import defaultdict
import json
from pathlib import Path


def flow_key(record):
    event = record["eve"]
    if "flow_id" not in event:
        return None
    # Python decodes JSON integers exactly, including values above 2**53.
    return record["sensor"], record["run"], event["flow_id"]


def review(records):
    http_by_flow = defaultdict(list)
    for record in records:
        event = record["eve"]
        key = flow_key(record)
        if key is not None and event["event_type"] == "http":
            http_by_flow[key].append(event)

    for record in records:
        event = record["eve"]
        if event["event_type"] != "alert":
            continue
        key = flow_key(record)
        candidates = http_by_flow.get(key, [])
        tx_id = event.get("tx_id")
        prefix = f'{event["alert"]["signature_id"]} {record["sensor"]}/{record["run"]}'
        if key is None:
            outcome = "no flow ID; HTTP attribution unknown"
        elif tx_id is None:
            outcome = f"flow only; {len(candidates)} HTTP candidate(s)"
        else:
            exact = [http for http in candidates if http.get("tx_id") == tx_id]
            if len(exact) == 1:
                http = exact[0]["http"]
                outcome = f'tx={tx_id} {http.get("http_method", "?")} {http.get("url", "?")} status={http.get("status", "?")}'
            elif not exact:
                outcome = f"tx={tx_id}; no matching HTTP record"
            else:
                outcome = f"tx={tx_id}; {len(exact)} matching HTTP records, unresolved"
        verdict = event.get("verdict", {}).get("action", "unobserved")
        yield f'{prefix}: {outcome}; alert={event["alert"]["action"]}; verdict={verdict}'


def main():
    source = Path(__file__).with_name("suricata-eve-cases.jsonl")
    with source.open(encoding="utf-8") as fixture:
        records = [json.loads(line) for line in fixture if line.strip()]
    for line in review(records):
        print(line)


if __name__ == "__main__":
    main()
