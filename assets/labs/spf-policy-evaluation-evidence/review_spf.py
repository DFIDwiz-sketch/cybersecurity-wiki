import ipaddress
import json
from pathlib import Path
import sys

QUALIFIERS = {"+": "pass", "-": "fail", "~": "softfail", "?": "neutral"}
LIMIT = 10


def evaluate(domain, address, txt, trace):
    records = txt.get(domain, [])
    if records is None:
        return "temperror"
    if not records:
        return "none"
    if len(records) > 1:
        return "permerror"

    version, *terms = records[0].split()
    if version != "v=spf1":
        raise ValueError(f"Fixture needs a selected SPF record for {domain}")

    for term in terms:
        qualifier = term[0] if term[0] in QUALIFIERS else "+"
        if term[0] in QUALIFIERS:
            term = term[1:]
        mechanism, _, value = term.partition(":")

        if mechanism == "all" and not value:
            return QUALIFIERS[qualifier]
        if mechanism in {"ip4", "ip6"}:
            network = ipaddress.ip_network(value, strict=False)
            if network.version != int(mechanism[-1]):
                raise ValueError(f"Address family mismatch in {term}")
            if address in network:
                return QUALIFIERS[qualifier]
        elif mechanism == "include" and value:
            trace.append(f"{domain} -> {value}")
            if len(trace) > LIMIT:
                return "permerror"
            child = evaluate(value, address, txt, trace)
            if child == "pass":
                return QUALIFIERS[qualifier]
            if child in {"temperror", "permerror"}:
                return child
            if child == "none":
                return "permerror"
        else:
            raise ValueError(f"Unsupported fixture mechanism: {term}")
    return "neutral"


def main(path):
    data = json.loads(path.read_text(encoding="utf-8"))
    failures = 0
    for case in data["cases"]:
        sender = case["mail_from"]
        domain = case["helo"] if sender == "<>" else sender.rsplit("@", 1)[1]
        trace = []
        result = evaluate(domain, ipaddress.ip_address(case["ip"]), data["txt"], trace)
        observed = {"domain": domain, "result": result, "include_terms": len(trace)}
        expected = case["expected"]
        label = "OK" if observed == expected else "MISMATCH"
        print(f"{label} {case['case_id']}: {domain} {result} includes={len(trace)}")
        if observed != expected:
            failures += 1
            print(f"  expected: {expected}")
        if case["case_id"] == "over-limit":
            for count, step in enumerate(trace, 1):
                extra = " (limit exceeded before lookup)" if count > LIMIT else ""
                print(f"  {count:2} {step}{extra}")
    return int(failures != 0)


if __name__ == "__main__":
    fixture = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("spf-cases.json")
    raise SystemExit(main(fixture))
