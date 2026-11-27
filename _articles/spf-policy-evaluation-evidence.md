---
title: "SPF Policy Evidence · Follow the Envelope Domain and DNS Evaluation"
description: "Trace an SPF result to its SMTP hop and DNS evaluation path, then replay eleven offline cases."
category: network
tags: [SPF, DNS, SMTP, Email Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/spf-policy-evaluation-evidence/
---

A mail gateway records `spf=permerror` after a sender changes email providers. Which domain was actually tested, and which part of its policy caused the error? Start with the SMTP connection and work through the policy in the order the receiver evaluated it.

## 1. Identify the IP address and the domain

**Sender Policy Framework (SPF)** lets a domain owner publish which sending hosts are authorized to use that domain in SMTP. The receiver evaluates a domain and the IP address of the SMTP peer on that hop. A gateway can perform a separate HELO/EHLO check and a MAIL FROM check. An analyst should capture the identity type as well as the result.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/spf-policy-evaluation-evidence.svg' | relative_url }}" width="360" height="395" alt="Select the SMTP envelope identity, evaluate its DNS TXT policy with the connecting IP, then record the result and checked domain. DMARC separately considers alignment with the message From." />
  <figcaption>Describe one receiving hop at a time. Keep the evaluated domain alongside the result.</figcaption>
</figure>

| Evidence | Where it comes from | How to use it |
| --- | --- | --- |
| Connecting IP | Receiver's SMTP session or trusted gateway trace | The direct peer can be a forwarding service or local relay. Scope the observation to that hop. |
| `HELO` or `EHLO` | SMTP greeting sent by the peer | Can be evaluated on its own. With a null reverse-path, SPF constructs a MAIL FROM identity using `postmaster` at the HELO domain. |
| `MAIL FROM` | SMTP envelope, also called the reverse-path | For a nonempty sender, start from its exact domain. A parent domain's SPF record is not inherited. |
| Visible `From:` | Message header | DMARC compares this domain with a validated MAIL FROM identity or DKIM signing domain. A standalone HELO pass supplies no DMARC SPF pass. |
| `Return-Path:` | Usually inserted at final delivery | Useful as supporting evidence for the captured message. Intermediate systems can change the envelope, so recover the original hop from logs. |

## 2. Follow the DNS evaluation

1. Read the TXT record set at the exact domain being evaluated. Select the applicable version-1 SPF record. Multiple applicable SPF records at the same name cause `permerror`. One TXT record can contain multiple character strings. Those strings are joined, with no extra spaces inserted. Unrelated TXT records can coexist.
2. Evaluate mechanisms in order until one matches or an error stops evaluation. A matching mechanism normally produces `pass` with the implicit or explicit `+` qualifier, `fail` with `-`, `softfail` with `~`, or `neutral` with `?`. The `all` mechanism always matches when reached, so its qualifier matters.
3. An `include` evaluates the referenced domain's policy against the same connecting IP. A child `pass` matches the parent mechanism and the parent qualifier sets the result. Child `fail`, `softfail` or `neutral` lets the parent continue. Child `none` becomes `permerror` in the parent, and child temporary or permanent errors propagate. A `redirect` points to a replacement policy after the mechanisms fail to match, subject to the standard's rules. An `all` mechanism suppresses `redirect`.
4. Track evaluated DNS-triggering terms across recursion. The RFC sets a limit of **10** for `include`, `a`, `mx`, `ptr`, `exists` and `redirect` combined. The eleventh evaluated term causes `permerror`; the count differs from DNS packets, cache misses and the count of TXT records. `ip4`, `ip6` and `all` do not consume this term budget. The RFC separately recommends limiting void lookups, such as NXDOMAIN and successful replies with zero answers, to two.

| Result | Interpretation at the evaluating receiver |
| --- | --- |
| `pass` | The policy authorized this IP for the recorded identity. |
| `fail` / `softfail` | The domain made a negative assertion or a weaker negative assertion respectively. Check delivery policy separately. |
| `none` / `neutral` | No applicable SPF policy was found for the domain in the example, or the selected policy offered no positive or negative assertion. |
| `temperror` | A temporary failure, such as DNS timeout or server failure. |
| `permerror` | Evaluation cannot complete under the published configuration or evaluation limits. Check duplicate records, invalid dependencies and the actual evaluated path. |

## 3. Compare a routine delivery, a forward and an ambiguous pass

In the fictional direct example, the receiver sees `192.0.2.25` with MAIL FROM `notify@orders.example.test`. The root policy is `v=spf1 include:relay.provider.test -all`; the provider's policy authorizes that IP. The root returns `pass` for **orders.example.test**. The included domain supplies authorization evidence. If the exact visible From domain is also `orders.example.test`, the resulting SPF identity is strictly aligned.

A forwarding hop using `198.51.100.7` can leave the same envelope sender intact. The next receiver checks the forwarder's IP and can reach the parent's `-all`. If the forwarder instead uses an authorized envelope domain of its own, it can get an SPF pass for that domain. Use the From, DKIM and the receiving policy to determine DMARC and delivery separately. ARC may preserve an upstream assessment for downstream use. DKIM can survive some forwards when signed material remains intact.

An unrelated domain can legitimately authorize the host that sent a deceptive message. Treat SPF pass as evidence tied to the exact evaluated domain, with message identity and delivery checked separately. A forged result header can also imitate a pass. Match the result to the organization's trusted authentication boundary and gateway session. An overbroad provider authorization increases the set of systems that can obtain a pass for the domain, so review sender ownership and verified tenant controls before changing the policy.

## 4. Collect, detect and respond

1. Record the time in UTC, receiving gateway and connector, peer IP, SMTP HELO, envelope sender, visible From, recipient disposition and receiver trace or queue ID. Use original headers from the approved evidence source. In a gateway chain, recover the log where SPF was evaluated. Correlate the result's `authserv-id` with that boundary; a familiar name in an incoming header is insufficient. If a message was rejected during SMTP, check gateway logs rather than relying on headers that may never have reached a mailbox.
2. Capture the evaluated DNS name, selected TXT record and nested dependencies, DNS response codes, TTL when available and the observation time. Use a controlled resolver or mail-gateway diagnostics for an approved domain. Current DNS can differ from what the receiver saw. Preserve historical logs or zone-change records where available before claiming a past policy.
3. Separate failure patterns. Group by gateway, evaluated domain, result and time. A rise in `permerror` after a change suggests testing the include path for each sending source. Widespread `temperror` across otherwise independent senders warrants a check of resolver availability. Forwarded `fail` with consistent forwarding traces warrants a path and alignment review. A single SPF result does not establish an attack or an inbox delivery.
4. Compare the findings with approved senders and recent DNS edits. Remove obsolete delegations through normal change control, test early matches and deeper paths, and verify effects at the receiver before closing an incident. Preserve the message trace, DNS evidence and handling outcome as separate attachments to the incident record.

## 5. Offline lab · Reproduce eleven outcomes

Use Python 3 in a directory you own or have permission to use. Save <a href="{{ '/assets/labs/spf-policy-evaluation-evidence/spf-cases.json' | relative_url }}" download="spf-cases.json">spf-cases.json</a> and save the code below as `review_spf.py` in the same directory. Run `python3 review_spf.py`. The input contains synthetic SMTP facts, documentation IPs and selected TXT-policy fixtures. It opens no sockets and sends no mail. The program implements a deliberately small subset: `ip4`, `ip6`, `include`, and `all`. It takes the fixture's SPF candidates as input and models a temporary DNS error with JSON `null`. It does not implement real DNS, record selection, other SPF mechanisms, DMARC policy discovery, or SMTP delivery.

```python
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
```

| Cases | Expected comparison |
| --- | --- |
| `direct`, `direct-ipv6`, `forwarded` | Same root domain, one include each. The two authorized IPs pass; the forwarding IP fails. |
| `null-sender`, `missing-root` | Checked HELO-derived domain passes for the bounce; a missing root policy returns `none`. |
| `missing-include`, `duplicate-txt`, `transient-dns` | Missing child and duplicate root policies produce `permerror`. A modeled DNS failure produces `temperror`. |
| `early-match`, `at-limit`, `over-limit` | Early pass uses one term. Exactly 10 terms can pass. An attempted eleventh stops evaluation before resolving that target. |

Expect eleven `OK` lines and a numbered path for `over-limit`. If the script cannot locate the JSON file, run in the download directory or supply its path. To verify that the checker catches mistakes, make a copy of the JSON fixture and set `over-limit`'s expected result to `pass`. Run `python3 review_spf.py altered.json`. Expect a mismatch and exit status 1. This replay was executed in Python. The cited SPF, DMARC and product behavior was checked in documentation.

## 6. Check your understanding

1. **HELO passes and a nonempty MAIL FROM fails. Is there an SPF pass for DMARC?** No. DMARC uses the MAIL FROM result. For a null reverse-path, evaluate the derived MAIL FROM identity rather than assuming every HELO pass represents it.
2. **The same policy passes for one source and hits a term limit for another. How can both be true?** An earlier mechanism can match the first source. The second can take a longer branch with more evaluated terms.
3. **A current TXT lookup differs from the gateway's historical trace. Which supports what?** The lookup supports what the resolver returned now. Use timestamped historical records to establish what the receiver evaluated then.

You have completed the chapter when you can name the tested hop and domain, distinguish `fail`, `permerror` and `temperror`, explain the 10-versus-11 result, and identify the additional evidence needed for DMARC and disposition.

## Official references

Reviewed **2026-11-27**. RFC 7208 (April 2014, with updates from the RFC Editor) supersedes RFC 4408. RFC 8601 covers trustworthy result-header handling (May 2019). RFC 9989 (May 2026) supersedes RFC 7489 for DMARC. Microsoft Learn describes Microsoft 365 configuration; use the IETF specification for the exact term-counting model.

- [IETF · RFC 7208, SPF](https://www.rfc-editor.org/rfc/rfc7208.html)
- [RFC Editor · RFC 7208 updates and errata](https://www.rfc-editor.org/info/rfc7208/)
- [IETF · RFC 8601, Authentication-Results](https://www.rfc-editor.org/rfc/rfc8601.html)
- [IETF · RFC 9989, DMARC](https://www.rfc-editor.org/rfc/rfc9989.html)
- [Microsoft Learn · SPF for Microsoft 365](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-spf-configure)

[Previous · SPF, DKIM and DMARC basics]({{ '/wiki/mail-auth-evidence/' | relative_url }}) · [Next · SMTP delivery evidence]({{ '/wiki/smtp-delivery-evidence/' | relative_url }}) · [DMARC aggregate reports]({{ '/wiki/dmarc-aggregate-report-evidence/' | relative_url }}) · [ARC and forwarded mail]({{ '/wiki/arc-forwarding-evidence/' | relative_url }})
