---
title: "Extended DNS Errors · Distinguish Filtering, Refusal and Resolution Failure"
description: "Read EDNS Extended DNS Errors alongside the response code, trace policy decisions and decode twelve fictional DNS observations."
category: network
tags: [DNS, DNSSEC, Network Monitoring, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/dns-extended-error-evidence/
---

Two clients report that the same hostname stopped working. Both received `REFUSED`. One used an approved resolver that blocked the domain under a security policy. The other reached a resolver that rejected its client's access. A response code alone rarely answers which team should investigate. Extended DNS Errors (EDE) can help identify the next source of evidence.

## 1. Read the response code and the extended error

The **response code** (RCODE) describes the DNS outcome. `NOERROR` means DNS processing did not signal an error and can still carry an empty answer. `NXDOMAIN` indicates that the responding server reports a name does not exist. `SERVFAIL` reports a failure to complete resolution. `REFUSED` reports refusal to perform the requested operation. A timeout is a client observation without a usable response. No DNS RCODE was received for that observation.

**EDNS(0)** extends DNS with an **OPT pseudo-record** in the additional section. When the query includes OPT, the responding server can include an **Extended DNS Error** option in its OPT. Inside the options, the 16-bit **option code 15** identifies EDE. A separate 16-bit **INFO-CODE** identifies the reported reason. **INFO-CODE 15** happens to mean Blocked. A response can carry zero, one, or multiple EDE options, including on `NOERROR`. The client still processes RCODE normally.

Each option begins with the option code and payload length, both in network byte order. An EDE payload starts with INFO-CODE, followed by optional UTF-8 text for humans. Use the encoded length to locate the next option. In normalized logs, retain an array of numeric codes and track whether EDNS and the complete response were observed. Treat diagnostic text as untrusted. Keep it out of rule matching, redact before sharing, and escape controls before display.

| EDE INFO-CODE | What the responding server reports | Evidence to check next |
| --- | --- | --- |
| 4 Forged Answer | A policy-generated replacement answer was supplied | Returned records and the resolver's decision log |
| 15 Blocked | The resolving or forwarding operator's blocklist applied | Matching rule, active version, view and policy owner |
| 16 Censored | A requirement from outside that operator caused blocklisting | Policy provenance and the responsible owner's documentation |
| 17 Filtered | Filtering requested by the client applied | Client profile, service configuration and effective policy |
| 18 Prohibited | This client was not authorized for the operation | Source identity or subnet, view, recursion ACL and actual query path |
| 6 DNSSEC Bogus or 13 Cached Error | The resolver reports validation failure or cached SERVFAIL respectively | Validation logs, cache timing and the first failure |
| 22 No Reachable Authority or 23 Network Error | The resolver reports an upstream reachability or network problem | Resolver egress, retries and authorized upstream observations |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/dns-extended-error-evidence-en.svg' | relative_url }}" alt="The same REFUSED response code leads to different checks. Extended DNS Error 15 points to a reported domain policy decision. Extended DNS Error 18 points to reported client authorization. A missing extended error leaves the reason open." style="max-width: 100%; height: auto;">
  <figcaption>Figure 1. Interpret the reported reason separately from the DNS outcome, then corroborate it at the resolver.</figcaption>
</figure>

## 2. Follow one routine lookup and compare two refusals

In this fictional example, a managed client asks its recursive resolver for the A record of `docs.corp.test.`. At 10:00 UTC it receives `NOERROR` with `192.0.2.42`. A response without EDE can be entirely routine. At 10:05, an approved test policy update changes the domain's disposition in the managed view. The same requester receives `REFUSED` with EDE 15. The resolver's policy log records the chosen rule and matching QNAME for the same client and time. That independent record corroborates which policy acted.

At 10:06 a test client in another authorized segment reaches the same service address, receives `REFUSED` with EDE 18, and has no per-domain match. Its requests are assigned to a view that does not grant that segment recursion. Confirm that view and ACL from the resolver logs or effective configuration before changing anything. Record the actual client identity as seen by the resolver when a proxy, NAT or VPN can change the apparent source.

## 3. Recognize misleading answers and observation gaps

An unexpected resolving endpoint, compromised intermediary, or unauthorized policy change can present misleading answers or diagnostic codes. The same symptoms can come from legitimate split-horizon DNS, resolver selection after a VPN change, staggered policy deployment, or a failed upstream. EDE is not a DNSSEC-signed assertion. An authenticated encrypted connection to a known resolver protects that transport hop, while the diagnostic reason still describes the reporting server's view. Compare against its own policy or validation records. Do not treat the domain label, a user-agent or one code as proof of compromise or execution.

EDE is optional. The client might not have sent OPT, the implementation might not emit a code, or an intermediary might omit it. A UDP responder may remove EDE first when saving space and should set the truncation flag when it does so. With `TC=1`, capture the authorized retry and evaluate its own RCODE and EDE. Preserve an unknown code as a number and look it up in the current IANA registry. A private-use code needs the operator's mapping. Keep a timeout separate from a complete response that contains no EDE.

## 4. Collect, detect and respond

1. **Preserve the observed path.** Record UTC time, client or process if available, QNAME, QTYPE, resolver address and view, transport, RCODE, flags, records and all EDE options. Keep exact query/response correlation in the packet capture or resolver transaction log. A 16-bit transaction ID alone is not globally unique. For DoH or DoT, use permitted endpoint or resolver-side logs when a passive sensor cannot see the DNS payload.
2. **Verify the reporting layer.** Match the query with the resolver's policy decision log, client ACL or DNSSEC validation record. Compare the effective rule, release time and client view. Record which raw fields the collector kept. For an owned or explicitly approved resolver, the read-only BIND `dig` command below shows the header and OPT pseudosection. Substitute your lab resolver and name for the documentation values. Use a BIND build that displays EDE. This query exercises that resolver path and may differ from the application's normal resolver path.

~~~bash
dig @192.0.2.53 docs.corp.test. A +edns=0 +comments
~~~

3. **Alert on changes within comparable views.** Group complete observations by resolver and view, then by RCODE and INFO-CODE. Track ratio and volume of responses with parsed EDE, with no EDE, and without a response. Review sudden shifts alongside policy deployments, log parsing changes and request volume. Do not use EXTRA-TEXT to drive automatic action.
4. **Confirm restoration in the affected path.** Review EDE 15–17 against approved policy and EDE 18 against requester eligibility. Review SERVFAIL with validation or upstream logs when appropriate. After an authorized correction, repeat the same name, type, view and transport, and confirm both the DNS response and application outcome.

## 5. Authorized offline exercise

Save the <a href="{{ '/assets/labs/dns-extended-error-evidence.py' | relative_url }}" download>Python decoder</a> and <a href="{{ '/assets/labs/dns-extended-error-evidence.json' | relative_url }}" download>fictional observations</a> together. Run with Python 3 in your own or approved environment. The fixture represents the already-observed RCODE and OPT presence in JSON. Only the EDNS option bytes are wire-encoded in hex. This exercise reads a local file and neither opens a socket nor parses a full DNS message. It validates boundaries, skips unrelated options, retains multiple INFO-CODEs, and keeps each RCODE intact.

~~~bash
python3 dns-extended-error-evidence.py
~~~

| Cases | Expected observations |
| --- | --- |
| A, G, H | A routine OPT with no EDE, an NXDOMAIN without OPT, and a timeout are separate states |
| B, C, D, L | REFUSED with 15, REFUSED with 18, NXDOMAIN with 17, and REFUSED with 16 following an unrelated padding option |
| E, F | SERVFAIL with both 6 and 13. NOERROR with 4 and a replacement answer count |
| I, J, K | Invalid option length, preserved private-use code 49152, and a truncated response with no EDE |

Expect `12/12 observations matched.` For a negative control, copy the JSON and change case B's `opt_hex` from `000f0002000f` to `000f00020012` without changing `expected`. Pass the copy's filename as an argument. The observed code changes from 15 to 18 while `REFUSED` stays the same. The checker should exit 1. If the supplied fixture fails, check the exact filename and the option lengths. The Python tests used fictional data. The BIND query and provider behavior were reviewed in documentation without querying a live DNS service.

## 6. Check your reasoning

1. **Can a NOERROR response include EDE?** Yes. EDE 4 can describe a policy replacement answer. The answer section and resolver's policy log show what was returned and why.
2. **Does REFUSED with EDE 18 prove a domain was put on a blocklist?** It reports client authorization refusal. Confirm the observed source, the resolver view and the effective ACL.
3. **Does missing EDE prove that filtering was absent?** No. Inspect EDNS negotiation, truncation, intermediate hops and local decision records.
4. **What can you conclude from 6 and 13 together?** The response includes validation and cached-error diagnostics. Recover the original chronology from resolver evidence before diagnosing which component failed first.

**Completion criterion.** Reproduce the twelve results and the changed-code control. Given one refusal, write down the observed RCODE, all EDE codes, who reported them and which record could confirm the decision. Continue with [DNS investigation]({{ '/wiki/dns-investigation/' | relative_url }}) and [negative caching]({{ '/wiki/dns-negative-cache-evidence/' | relative_url }}).

## Official references

Reviewed 2026-11-26. The packet format follows the 2013 EDNS standard and the October 2020 EDE specification. Use the current IANA registry for later assignments. The product references describe BIND 9.20.16 output flags and the Cloudflare 1.1.1.1 implementation. Resolver coverage and messages can vary by provider and release.

- [RFC 6891 · EDNS(0)](https://datatracker.ietf.org/doc/html/rfc6891) and [RFC 8914 · Extended DNS Errors, §§ 2–4 and § 6](https://datatracker.ietf.org/doc/html/rfc8914)
- [IANA · Extended DNS Error Codes registry](https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml#extended-dns-error-codes)
- [ISC · BIND 9.20.16 dig manual](https://bind9.readthedocs.io/en/v9.20.16/manpages.html#dig-dns-lookup-utility) and [Cloudflare · 1.1.1.1 Extended DNS error codes](https://developers.cloudflare.com/1.1.1.1/infrastructure/extended-dns-error-codes/)

For an example of resolver retries after an upstream error, compare [DNS QNAME minimisation]({{ '/wiki/dns-qname-minimisation-evidence/' | relative_url }}).
