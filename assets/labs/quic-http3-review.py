"""Review synthetic evidence for one completed or presumed request per case."""

import json
from pathlib import Path


def assess(case):
    protocols = set(case["client_request_protocols"])
    if len(protocols) > 1:
        return "conflicting client attribution"
    if protocols == {"h3"}:
        return "h3 on client hop"
    if protocols in ({"h2"}, {"http/1.1"}):
        protocol = next(iter(protocols))
        if case["same_request_quic_attempt"] == "failed":
            return f"{protocol} on client hop; linked failed QUIC attempt"
        return f"{protocol} on client hop; fallback unestablished"
    if protocols:
        raise ValueError(f"Unknown client protocol: {protocols}")
    if case["wire"] == "quic-initial":
        return "QUIC attempt clue; request protocol unknown"
    if case["wire"] == "udp-443":
        return "UDP metadata only; request protocol unknown"
    if case["advertised_h3"]:
        return "h3 advertisement; request protocol unknown"
    return "request protocol unknown"


def main():
    fixture = Path(__file__).with_name("quic-http3-cases.json")
    for case in json.loads(fixture.read_text(encoding="utf-8")):
        assessment = assess(case)
        upstream = case["edge_upstream_protocol"] or "unobserved"
        print(f'{case["case"]}: {assessment}; upstream={upstream}')


if __name__ == "__main__":
    main()
