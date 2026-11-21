---
title: "DNS Negative Caching · Explain Missing Names, Failed Lookups and Recovery"
description: "Use SOA, alias targets, resolver evidence and a virtual-clock lab to distinguish NXDOMAIN, NODATA and cached resolution failures."
category: network
tags: [DNS, DNS Caching, DNSSEC, Network Monitoring, Blue Team, DFIR]
level: Beginner
updated: "2026-11-21"
translation_url: /ko/wiki/dns-negative-cache-evidence/
---

**Learning goal.** When an authoritative server has the correct record but some clients still cannot resolve it, determine which component gave which answer, whether caching could explain the difference and what would confirm the cause. For DNS query fields and basic response codes, start with [DNS investigation]({{ '/wiki/dns-investigation/' | relative_url }}).

## 1. Why the requested answer can be missing

A **stub resolver** on a device usually asks a **recursive resolver** for an answer. The recursive resolver can use its cache or query upstream servers. An **authoritative server** answers from the zone data it serves. A cache is local to its service, instance or view. A fix at an authoritative server does not flush clients or other resolvers.

An **RRset** is the set of records with the same owner, class and type. An **SOA (Start of Authority)** record describes a DNS zone. Its time-to-live (**TTL**) and its final **MINIMUM** field are separate values. **RCODE** is the response code carried in a DNS message. It is possible to get a response without getting the requested RRset.

| Outcome | What it says | Common evidence and cache scope |
| --- | --- | --- |
| NXDOMAIN | The applicable name does not exist in this response's view | RCODE NXDOMAIN. Check the alias chain and authority SOA. Usually cached by denied name and class, across types |
| NODATA | The requested RRset is absent, although the applicable name exists | RCODE NOERROR with no requested RRset. Inspect referral and alias context. Cached by name, class and type |
| Resolution failure | A usable resolution result could not be obtained | The recursive resolver may return SERVFAIL. Collect resolver errors, upstream attempts and optional EDE. Matching scope can vary by failure and implementation |
| Observer timeout | No reply was seen before this observer's deadline | A client or sensor observation, with no on-wire RCODE implied. Verify transport and capture coverage |
| Referral | A server points toward a child zone | Typically NOERROR and delegation NS records. Follow the delegation to determine the answer |

Empty NOERROR is not a sufficient NODATA test. First examine the answer and authority sections, CNAME or DNAME redirection, and whether the response is a referral. If a log export drops answer or authority records, go back to the fuller source. An empty nonterminal is a name with descendants and no RRsets of its own. Its absence of RRsets does not justify NXDOMAIN.

## 2. Compute the negative TTL and read the cache

Under RFC 2308, when an authoritative server gives an NXDOMAIN or NODATA answer, it includes the zone SOA in the authority section. The TTL placed on that record is the lesser of the zone's SOA RR TTL and its SOA MINIMUM. A cache returns the retained SOA with its remaining TTL. A displayed SOA TTL from a recursive answer can already be reduced. Grab a direct authoritative view before treating the displayed number as the initial duration. A negative reply without an SOA should generally not be cached by this mechanism.

<figure style="margin-inline:0">
  <img src="{{ '/assets/diagrams/dns-negative-cache-en.svg' | relative_url }}" width="400" height="396" alt="A resolver stores an upstream negative answer or resolution failure. A matching later query can use the stored result. After expiry, a new upstream query can see repaired data.">
  <figcaption>Figure 1. The zone repair and resolver expiry occur at different points. The illustration shows a regular cache without stale serving.</figcaption>
</figure>

An NXDOMAIN after an alias chain denies the **terminal target**, which may differ from the original question. In the example `alias.lab.example.` can exist as a CNAME even when its target is absent. RFC 8020 also describes using a cached NXDOMAIN for descendants of the denied name, with exceptions including already cached data and a resolver that restricts the behavior to DNSSEC-validated denials. It does not establish the absence of parents or siblings. A validating resolver can also synthesize certain negative answers from validated NSEC or NSEC3 cache entries under RFC 8198. A missing upstream packet therefore has several possible explanations.

## 3. Follow a normal repair from both sides

This is a **synthetic** timeline for a service zone, with the clocks in seconds relative to the first query. Assume one resolver view, no other caching layers or stale serving, and no configured TTL override. The requested name is `portal.lab.example.`.

| Time | Evidence | Explain the result |
| --- | --- | --- |
| 0 s | Authoritative zone has no name. SOA RR TTL 300 s, SOA MINIMUM 60 s | The negative TTL begins at min(300, 60) = 60 s |
| 15 s | Operator publishes the A record. A direct query to the correct authority now shows the address | The zone view is repaired at that server |
| 20 s | The same recursive resolver returns NXDOMAIN with SOA TTL 40 s | Consistent with that cached denial. An AAAA query may also match the denial of the name |
| 59 s | Same resolver returns NXDOMAIN with SOA TTL 1 s | The earlier entry can still apply |
| 60 s | A new uncached A lookup reaches current authority and receives the new record | This resolver can answer from the repaired record under the stated conditions |

Contrast that with an existing IPv4-only name. An AAAA query can receive cached NODATA while an A query returns an address. Adding AAAA does not have to change the A result. Real resolvers can be configured with cache TTL limits and support stale serving or other behaviors. A TTL decreasing at the expected rate supports a cache hypothesis. Pin the server, compare resolver and authority logs and ask whether an upstream query actually occurred to confirm it.

## 4. Investigate SERVFAIL and policy-generated responses

A resolver's attempt is a **resolution failure** when the available servers fail to provide usable data, a referral, or a meaningful negative answer. An individual retry may fail while another server eventually provides an answer. Treat a client-facing SERVFAIL as a response, and a client timeout as missing observed response. Neither answers whether the queried name exists.

RFC 9520 updated older optional failure-caching guidance in December 2023. A resolver caches resolution failures for at least 1 second and at most 5 minutes, suppressing matching upstream queries while the entry is valid. The standard does not prescribe one cache key for every failure. Timeout and retry behavior depend on the transport and implementation. As a product example, the BIND 9.20.31 manual documents a separate `servfail-ttl` default of 1 second and a maximum of 30 seconds for that setting. Check your version and effective configuration before predicting recovery. This timer is separate from the negative SOA TTL. The [DNSSEC validation guide]({{ '/wiki/dnssec-validation-evidence/' | relative_url }}) covers validation failures in more depth.

**Extended DNS Errors (EDE)** can provide optional context without replacing RCODE. For example, 13 indicates a cached error, 15 indicates blocking and 17 indicates filtering. An EDE is a diagnostic claim by the responding infrastructure. Its absence does not establish the absence of policy or caching. A local filtering service can generate an answer inconsistent with a public authority. Compare only views that should match. Never send an internal name to an unrelated DNS service for comparison.

## 5. Collect, detect and respond

Record UTC time and clock uncertainty, client or process where available, resolver endpoint and view, transport, QNAME/QTYPE/QCLASS, RCODE, answer and authority SOA or delegation, flags and EDE where present. Retain upstream-query or cache telemetry if available. DNS encryption can leave network sensors without query visibility. Collect at an approved resolver or endpoint and restrict access and retention for query names.

These **read-only** BIND `dig` examples are for an owned or explicitly authorized zone. Replace the documentation addresses with your recursive resolver and the authority serving the same view. The final dot prevents ambiguity about a search suffix. `+norecurse` clears the request's RD bit. Check the authority reply's AA flag, server identity and zone data to verify you queried the right authority. Capture results from both sides over time. For EDE, repeat without `+noall` and retain the full EDNS output.

```sh
dig @192.0.2.53 portal.lab.example. A +noall +comments +answer +authority
dig @192.0.2.54 portal.lab.example. A +norecurse +noall +comments +answer +authority
```

| Pattern | Confirm before attributing | Response |
| --- | --- | --- |
| One resolver still denies a just-created name | The authority serves the change, views match, cache lifetime and resolver hit or upstream timing agree | Verify expiry and retest with the same resolver. Coordinate targeted remediation with its owner if required |
| Multiple clients get SERVFAIL | Query type, validator errors, time, upstream reachability and whether errors are cached | Repair the upstream or validation issue. Keep validation and evidence intact while retesting |
| Sudden rise in NXDOMAIN | Client population, denominator, distinct names, requesting processes, search suffixes, deployments and policies | Separate typos and configuration issues from unexplained activity, then corroborate using endpoint evidence |
| Unexpected policy-generated denial or answer | Resolver identity and forwarding route, policy-change log, enterprise view and approved rule set | Preserve the raw responses and changes. Work with resolver owners to restore approved behavior |

A threat can misuse DNS through unauthorized policy or zone changes that send users to an unintended service or deny a name. Legitimate filtering and deployment mistakes can produce similar evidence. Repeated NXDOMAIN can also come from a malfunctioning or unwanted application. Group by observation point and known change windows, and relate suspicious DNS records to independent endpoint or configuration evidence. A single error code, name pattern or volume threshold cannot establish compromise.

## 6. Offline lab · Watch 17 steps on a virtual clock

Download the <a href="{{ '/assets/labs/dns-negative-cache-cases.json' | relative_url }}" download="dns-negative-cache-cases.json">synthetic cases</a> and the <a href="{{ '/assets/labs/dns-negative-cache-review.py' | relative_url }}" download="dns-negative-cache-review.py">Python replay script</a> into the same directory. Python 3.10 or later and its standard library suffice. The program reads preclassified upstream outcomes from the fixture, advances a virtual clock and checks what one simplified cache returns. It opens no sockets and requires no DNS privileges or external records.

```sh
python3 dns-negative-cache-review.py dns-negative-cache-cases.json --check
```

| Scenario | Check |
| --- | --- |
| N1 | NXDOMAIN from A also applies to AAAA at 20 s. A stays negative at 59 s and reaches upstream at 60 s |
| N2 | Negative AAAA cache lasts 40 s while A resolves. AAAA reaches upstream at 40 s |
| N3 | With the model's five-second failure entry scoped to A, an A retry at 2 s hits cache. AAAA can reach upstream. A is retried at 5 s |
| N4 | The model does not cache NXDOMAIN without SOA |
| N5 | The cached denied name is the terminal alias target. A direct AAAA query to it hits cache. The original alias can receive a repaired upstream response in this simplified model |

On 2026-11-21 Python 3.12.14 returned `17/17 simulated steps matched.` The lab models exact-name cache lookup and preclassified failures, with no positive or alias cache, descendant synthesis, DNSSEC validation, stale serving or real DNS packets. Application and resolver product behavior and the `dig` examples were checked against documentation. If the script cannot find its fixture, check both filenames and your working directory. If you change the input, omit `--check` to inspect your modified run before restoring the original data.

## 7. Check your reasoning

1. **Why do A and AAAA both receive a previous NXDOMAIN?** The cached denial is for the name and class. NODATA is narrower and includes the type.
2. **Does a NOERROR reply with no AAAA answer establish NODATA?** Inspect the authority and alias chain. It could be a referral, an alias response requiring follow-up, or a reduced log projection.
3. **What does SERVFAIL with EDE 13 add?** The resolver reports a cached SERVFAIL. To explain the original failure, inspect earlier resolver-side evidence and upstream health.
4. **One resolver is negative but authority is positive. What should you compare?** Check exact name, type, class, view, observation times and server identities. Then compare authority SOA, resolver behavior and the clock around expiry. Other caches may also matter.

Complete the chapter by reproducing all 17 steps and explaining a repair under each cache scope. Continue with [DNSSEC validation]({{ '/wiki/dnssec-validation-evidence/' | relative_url }}) for failure attribution and [DNS investigation]({{ '/wiki/dns-investigation/' | relative_url }}) for log aggregation and response-rate baselines.

## Official references

Reviewed 2026-11-21. The standards have different publication dates and scopes. Match product settings to the deployed release.

- [RFC 2308 §§ 3, 5, 6](https://www.rfc-editor.org/rfc/rfc2308.html), March 1998, negative answers, SOA and cache lifetime.
- [RFC 8020 §§ 2–3](https://www.rfc-editor.org/rfc/rfc8020.html), November 2016, denied names and descendant handling, and [RFC 8198](https://www.rfc-editor.org/rfc/rfc8198.html), July 2017, synthesis from cached DNSSEC proofs.
- [RFC 8914 §§ 3–4](https://www.rfc-editor.org/rfc/rfc8914.html), October 2020, EDE and its relationship to the response code.
- [RFC 9520 §§ 2–3](https://www.rfc-editor.org/rfc/rfc9520.html), December 2023, resolution failure caching and retry requirements.
- [ISC BIND 9.20 stable manual pages](https://bind9.readthedocs.io/en/stable/manpages.html#dig-dns-lookup-utility) and [configuration reference](https://bind9.readthedocs.io/en/stable/reference.html#namedconf-statement-servfail-ttl), checked in the 9.20.31 documentation for flags and `servfail-ttl`.
