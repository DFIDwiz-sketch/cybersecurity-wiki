"""Review fictional receiver records. This code does not verify mail or set policy."""

import json
from pathlib import Path


def review(case):
    if case["evidence_source"] != "receiver_log":
        return "receiver assessment unverified; disposition unknown"

    dmarc = case["local_dmarc"]
    chain = case["chain"]
    eligibility = (
        chain == "pass"
        and case["sealer_trust"] == "trusted"
        and case["prior_aligned"] is True
    )
    if case["decision_reason"] == "arc_override":
        observation = (
            "ARC override recorded"
            if dmarc == "fail" and eligibility
            else "ARC override conflicts with other evidence"
        )
    elif dmarc == "pass":
        observation = "local DMARC pass; no ARC override recorded"
    elif chain != "pass":
        observation = f"ARC chain {chain}; no override supported"
    elif case["sealer_trust"] != "trusted":
        observation = "ARC chain passes; trusted sealer unconfirmed"
    elif not eligibility:
        observation = "trusted chain; prior aligned pass unconfirmed"
    else:
        observation = "trusted prior pass; override unconfirmed"
    return f'dmarc={dmarc}; {observation}; disposition={case["disposition"]}'


def main():
    source = Path(__file__).with_name("arc-forwarding-cases.jsonl")
    with source.open(encoding="utf-8") as rows:
        for line in rows:
            if line.strip():
                case = json.loads(line)
                print(f'{case["id"]}: {review(case)}')


if __name__ == "__main__":
    main()
