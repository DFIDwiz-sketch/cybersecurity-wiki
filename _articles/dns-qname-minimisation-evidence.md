---
title: "DNS QNAME Minimisation · Explain What Each Server Sees"
description: "Compare client-side DNS with iterative queries, distinguish shortened names from cache, forwarding and compatibility retries, and verify eight offline cases."
category: network
tags: [DNS, QNAME Minimisation, DNS Privacy, Network Monitoring, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/dns-qname-minimisation-evidence/
---

A workstation asks for the mail records of `mail.lab.test.`. The organizational resolver records the full query, but a sensor on its upstream link shows only `test.` and `lab.test.` on queries to parent servers. Both observations can be correct. To explain them, first establish which side of the resolver you can see.

## 1. Follow the name down the tree

A **QNAME** is the domain name in a DNS question. A **QTYPE** asks for a record type such as A (IPv4 address) or MX (mail exchanger). A stub client typically gives a recursive resolver the complete question. If the resolver lacks a useful cache entry, it can issue its own iterative questions. A parent DNS server can return a **referral**, which points the resolver to servers for a child **zone**. The **zone cut** is the boundary at that delegation. The resolver follows the referral by making another query.

**QNAME minimisation** limits how much of the original question the resolver discloses while finding the proper authority. For a delegation probe it generally works from a known authoritative suffix and extends the name one label toward the original name. The resolver may change the QTYPE during these steps. The correct authority for the requested record gets the original question when it is needed. A label boundary matters: `lab.test.` is a suffix of `mail.lab.test.`; `ab.test.` is not.

<figure>
  <img src="{{ '/assets/diagrams/dns-qname-minimisation-evidence.svg' | relative_url }}" width="560" height="358" alt="The client gives its full MX question to the resolver. The resolver independently sends shortened questions for test and lab.test to parent servers, then a full MX question to the authority for lab.test." />
  <figcaption>These are questions from the resolver to different destinations in an illustrative cold-cache lookup.</figcaption>
</figure>

## 2. Read a normal trace from each vantage point

In this **fictional hierarchy** under the reserved `.test` suffix, the root delegates `test.` and the test parent delegates `lab.test.`. The mail name has no separate delegation. The table shows key observations, with possible additional probes and transport retries omitted.

| Where you observe | Example question or evidence | How to interpret it |
| --- | --- | --- |
| Client to recursive resolver | `MX mail.lab.test.` | The original application question. A cache hit can answer it locally. |
| Resolver to root | `A test.`, followed by a referral | The resolver is finding the next authority. There is no evidence here for the individual mail name. |
| Resolver to the `test.` parent | `A lab.test.`, followed by a referral | A delegation lookup can have an A QTYPE. Inspect the response authority section for the referral. |
| Resolver to the `lab.test.` authority | `MX mail.lab.test.` | The final query asks for the actual record. A full name is expected at this authority. |
| Resolver to a configured forwarder | The original question can be visible | Identify which upstream resolver performs recursion. Sending a full query to a forwarder does not establish how that resolver queries parents. |

The IETF's November 2021 [RFC 9156](https://www.rfc-editor.org/rfc/rfc9156.html) superseded the experimental RFC 7816. NS remains possible as a probe type, and A or AAAA are also valid choices under the standard's selection rules. The probe type should be chosen independently of the original QTYPE. The sequence depends on cached delegations and known zones. For parent-side record types such as DS, the final question can legitimately go to the parent. Alias processing can start a new lookup for a different name.

| Resolver documentation | Typical configured behavior under documented defaults | Evidence to verify |
| --- | --- | --- |
| ISC BIND 9.20.31 | `qname-minimization relaxed` by default. The resolver uses NS when walking the tree in this mode and may retry without minimisation after an unexpected reply. | Effective configuration for the view, the original probe and peer response, and the subsequent query to that peer. |
| NLnet Labs Unbound | `qname-minimisation: yes` and `qname-minimisation-strict: no` by default. Its best-effort mode uses A where possible and the manual describes fallback for errors, with an exception for NXDOMAIN from a DNSSEC-signed zone. | Installed release, effective settings, upstream RCODE and whether a full query followed. Verify behavior for the actual zone before generalizing. |

A warm delegation cache can skip the root and parent without changing the final question. A cached answer can eliminate upstream queries. Strict and best-effort modes trade off information disclosure and compatibility. Compare traces from the same resolver version, view and cache conditions before treating a difference as policy drift.

## 3. Collect and interpret the evidence

1. **Identify both sides of the resolver.** Record asset and sensor IDs, UTC time, resolver version, view and forwarding policy. Observe client ingress and iterative egress within your authorized scope. Confirm whether the upstream destination is a root, parent, final authority or forwarder using approved resolver and zone/delegation records. Destination IP alone is weak evidence for a server's role.
2. **Pair questions with replies on their own leg.** Keep source/destination addresses, ports, transport, DNS transaction ID, QNAME, QTYPE, RCODE and records used as referrals. Transaction IDs are reused and can differ between the client request and the recursive resolver's upstream requests. For Zeek `dns.log`, use `uid`, endpoints, time and `trans_id` to interpret one observed leg. Use raw PCAP or authorized resolver traces when the log cannot show referral details or causal links across legs. Zeek requires visible DNS traffic, its DNS analyzer and sufficient capture of each leg. Encryption can require a trusted endpoint or resolver log instead.
3. **Explain missing or unexpected names.** Check whether the response was cached, a delegation was already known, the resolver forwarded the question, a parent returned an error before a compatibility retry, or coverage was incomplete. Use resolver-side correlation where available. A short name by itself cannot recover the hidden original left-hand labels, establish an individual client, or prove a resolver setting.
4. **Scope and respond to unexpected exposure.** Full internal-looking names at a parent can disclose service labels to the server and to observers of unencrypted DNS. An unexpected forwarder or a wrongly scoped view can broaden disclosure. A full name at the correct authority or after a compatibility retry can be expected. Preserve the paired exchange and effective settings, compare with known-good data from the same path, then involve DNS operations to correct the confirmed cause and retest. Conduct privacy reviews with access controls and retention limits for full client-side names.

QNAME minimisation reduces disclosure during delegation. DNS over HTTPS or TLS protects an encrypted transport leg from passive readers on that path, while the selected resolver still receives the question. DNSSEC supports authenticity and integrity of DNS data and has a separate purpose. You need evidence from the relevant layer to assess each control.

## 4. Offline defense validation

Use Python 3 in your own or an explicitly approved workspace. Download <a href="{{ '/assets/labs/dns-qname-minimisation-evidence/qname-cases.csv' | relative_url }}" download="qname-cases.csv">qname-cases.csv</a> and save this code next to it as `review_qname.py`. Run `python3 review_qname.py`. The exercise reads fictional records and sends no DNS traffic.

The CSV groups already-correlated observations from one lookup per case, in order. The `point` and `target` labels come from the exercise's supplied topology. `outcome` summarizes a matched response or a known resolver cache observation. In a real case, substantiate these labels from raw traffic, resolver logs and network context before applying the interpretations. The script is a fixture checker for these ASCII names and observation patterns.

```python
import csv
from collections import defaultdict

expected = {
    "cold": "minimisation-shape",
    "warm-delegation": "authority-only",
    "answer-cache": "cache-evidence",
    "forwarding": "forwarder-path",
    "compatible-retry": "possible-compatibility-retry",
    "early-full": "full-name-at-parent",
    "point-unverified": "insufficient-context",
    "upstream-only": "insufficient-context",
}

def labels(name):
    return tuple(name.rstrip(".").lower().split("."))

def is_proper_suffix(short, full):
    return bool(short) and len(short) < len(full) and full[-len(short):] == short

def classify(records):
    client = next((r for r in records if r["point"] == "client"), None)
    if client is None:
        return "insufficient-context"
    full = labels(client["qname"])
    probes = set()
    refused = set()
    complete = False
    for row in records:
        if (row["point"], row["target"], row["outcome"]) == ("resolver", "cache", "hit"):
            return "cache-evidence"
        if row["point"] == "forwarder":
            return "forwarder-path"
        if row["point"] != "iterative":
            continue
        target = row["target"]
        queried = labels(row["qname"])
        if target in {"root", "parent"}:
            if queried == full:
                if target in refused and row["qtype"] == client["qtype"]:
                    return "possible-compatibility-retry"
                return "full-name-at-parent"
            if is_proper_suffix(queried, full):
                probes.add(target)
                if row["outcome"] == "REFUSED":
                    refused.add(target)
        elif target == "authority" and queried == full and row["qtype"] == client["qtype"]:
            complete = True

    if complete:
        return "minimisation-shape" if probes else "authority-only"
    return "insufficient-context"

with open("qname-cases.csv", encoding="utf-8", newline="") as stream:
    cases = defaultdict(list)
    for row in csv.DictReader(stream):
        cases[row["case"]].append(row)

actual = {name: classify(records) for name, records in cases.items()}
assert actual == expected, f"Expected {expected!r}, got {actual!r}"
for name, result in actual.items():
    print(f"{name}: {result}")
```

**Expected results.** Eight cases pass. Cold cache shows shortened questions and the final query. Authority-only, confirmed cache and forwarding are separate cases. A short parent query with REFUSED followed by the full original question at the same parent is consistent with a compatibility retry. A full parent question without that context leaves the cause open. Unknown topology and an upstream-only record lack enough context for this exercise.

**Failure check.** Copy the file and change the cold case's parent query from `lab.test.` to `mail.lab.test.`. The expected minimisation shape should fail with `full-name-at-parent`. If the file cannot be read, check the working directory and CSV header. The fixture and negative control were executed in the cloud. BIND, Unbound and Zeek behavior was reviewed against their documentation.

## 5. Check your understanding

1. **The root saw `test.`. Which host name did the client ask for?** This observation alone supplies the suffix only. Use authorized client-facing resolver evidence to answer.
2. **Only the full question to the final authority appeared. Is minimisation off?** A cached delegation can account for the same observation. Check destination role, cache state and prior traffic.
3. **A full query appeared at a parent. What can you conclude?** The parent was sent that name. Check whether it was a legitimate parent-side query, an expected retry, or an unexpected route or configuration.

Complete the chapter when you can label the leg, explain a full-name and a short-name observation with evidence, and state what a missing log leaves unresolved.

## Official references

Reviewed **2026-11-27**. RFC 9156 is the November 2021 Standards Track specification. Product scope is the ISC BIND 9.20.31 reference, the current NLnet Labs Unbound manual at review, and Zeek 9.0.1 field documentation.

- [RFC 9156 · DNS Query Name Minimisation](https://www.rfc-editor.org/rfc/rfc9156.html)
- [RFC 9076 · DNS Privacy Considerations](https://www.rfc-editor.org/rfc/rfc9076.html)
- [RFC 2606 · Reserved DNS names for test and documentation](https://www.rfc-editor.org/rfc/rfc2606.html)
- [ISC BIND 9 · qname-minimization configuration](https://bind9.readthedocs.io/en/stable/reference.html#qname-minimization)
- [NLnet Labs · Unbound configuration reference](https://unbound.docs.nlnetlabs.nl/en/latest/manpages/unbound.conf.html)
- [Zeek · DNS log fields](https://docs.zeek.org/en/current/scripts/base/protocols/dns/main.zeek.html)

[Previous · DNS fundamentals and investigation]({{ '/wiki/dns-investigation/' | relative_url }}) · [Next · DNS over HTTPS evidence]({{ '/wiki/doh-resolution-evidence/' | relative_url }}) · [Corroborate DNS errors]({{ '/wiki/dns-extended-error-evidence/' | relative_url }})
