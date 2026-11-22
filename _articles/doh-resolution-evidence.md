---
title: "DNS over HTTPS Evidence · Read TLS, HTTP and DNS Separately"
description: "Investigate DoH resolver choice, HTTP status, DNS RCODE, cache age and fallback with ten fictional observations."
category: network
tags: [DNS, DoH, Network Security, TLS, Network Monitoring, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/doh-resolution-evidence/
---

Start with this question: **Which resolver did this application use for this particular lookup, and what answer did it receive?** An encrypted connection, an HTTP response and a DNS result provide different parts of that answer. Review [DNS fundamentals]({{ '/wiki/dns-investigation/' | relative_url }}) first if names, records and recursive resolvers are new to you.

## 1. Why use HTTPS to carry DNS?

**DNS over HTTPS (DoH)** carries a DNS request and response inside HTTPS between a client and an HTTPS resolver service. After the TLS connection is authenticated, the local network generally cannot read the DNS question or response in the protected HTTP exchange. The resolver can still see and process the question. Its cache, its upstream connections and its privacy policy are separate issues. DNSSEC validates authenticity of signed DNS data where validation applies. DoH protects the transport to the HTTPS service.

Clients can be configured with an endpoint using a URI template. RFC 8484 uses HTTP GET or POST. In GET, the DNS message is carried in a base64url-encoded query parameter. In POST, the wire message goes in the body. A standard wire response uses `application/dns-message`. HTTP paths, URL query parameters and bodies may be exposed to the endpoints or authorized termination points, so restrict their logging and retention. Base64url provides a representation of the bytes and can be decoded.

RFC 9462 defines one way supporting clients can discover an encrypted resolver. RFC 9463 describes network-provided discovery options via DHCP and Router Advertisements. Discovery requires support and appropriate configuration. It does not establish that a particular lookup used a discovered resolver. Some applications use their own resolver selection, policy or cache independently of the operating system.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/doh-resolution-evidence-en.svg' | relative_url }}" alt="A lookup goes from the application over TLS to the DoH service via HTTP. The resolver uses its cache or upstream lookup, then returns the HTTP status and DNS message.">
  <figcaption>Collect evidence where each step is visible. A cache hit may let a resolver answer without an upstream query.</figcaption>
</figure>

## 2. Read three layers of evidence

| Observation | What it supports | What to verify next |
| --- | --- | --- |
| TLS connection to an approved resolver endpoint | Transport activity toward that endpoint | Application and HTTP transaction, if captured |
| HTTP 200 with decoded DNS NXDOMAIN | A DNS response reports a name error | Question, resolver view, negative cache and possible policy |
| HTTP 200 with decoded DNS SERVFAIL | Resolver reported a DNS failure using a successful HTTP exchange | Resolver diagnostics, upstream and DNSSEC validation |
| HTTP 200 with a different media type or unreadable body | A web response was observed | Proxy/error page, media type and message completeness |
| HTTP 502 without a DNS reply | HTTP-layer failure was observed | Gateway or upstream logs, and a separate retry if present |
| NOERROR and an empty answer section | No error code and no records in that section | Question type, authority section, aliases and policy before diagnosing NODATA |

Read the HTTP status before interpreting a body as a DNS reply. RFC 8484 uses HTTP success for valid DNS responses even when their DNS response code signals an error. HTTP caching can revalidate an existing representation separately. For example, an observed 304 has meaning in the context of the cached response. Avoid treating it as a fresh DNS reply. An HTTPS connection may carry several requests and may be reused for later lookups. Destination IP or TLS metadata alone cannot identify a question or its answer.

## 3. Walk one normal lookup and a fallback

In a fictional managed browser, an application asks for IN A `app.example.test`. Client diagnostics correlate the lookup with an HTTP 200 carrying `application/dns-message`. The decoded DNS response has `NOERROR` and one answer, `192.0.2.10`. The lab sets an RR TTL of 120 seconds and HTTP `Age` of 35 seconds, giving 85 seconds remaining for that example record. RFC 8484 requires clients to account for Age when calculating DNS TTL. The absence of an upstream query during this interval is compatible with a cache hit. Verify the cache or response evidence before attributing cause. The related [negative caching chapter]({{ '/wiki/dns-negative-cache-evidence/' | relative_url }}) explains why name errors can also persist.

In another fictional case the approved DoH connection fails. Client telemetry shows that the same lookup retried through the system resolver. Look for the shared lookup ID or reliable client diagnostics and a matching observation at the expected alternate resolver. A nearby plaintext DNS packet alone could belong to a different process, retry, or internal name. In Firefox, the enterprise `DNSOverHTTPS` policy documents `ProviderURL`, `ExcludedDomains`, and `Fallback`, including version requirements. Check effective policy and build, then observe the lookup. An excluded internal domain using the system resolver is a separate path from a failed DoH lookup falling back.

## 4. Collect, detect, and respond

1. **Establish the client baseline.** Record host, application, process, time, configured and effective resolver policy, and expected path for internal and public names. Check browser, OS and VPN context. Use owned test names and a clean lab cache where approved. Record which caches were cleared or preserved.
2. **Locate the decision and response.** Use authorized client diagnostics and resolver logs. At an approved HTTP termination point, preserve the request or transaction ID, status, media type and cache metadata where collected. Keep question, type, RCODE and answer or authority summary only where authorized. A passive capture may provide IP addresses and timing but typically cannot read the protected HTTP messages. Inspect sensor coverage, capture drops and log retention before interpreting absent records.
3. **Investigate exceptions to policy.** Unauthorized resolver selection can remove queries from an organization's usual resolver logs and policy controls. A managed rollout, resolver outage, selective internal routing or caching can change the same counts. Correlate process, effective policy, resolver path and independently observed requests. Escalate confirmed deviations to the owner and validate the restored path with a known positive name and an expected negative response. A resolver IP or a User-Agent value alone cannot identify an attacker.

## 5. Offline exercise · ten fictional observations

Download both files into one directory and run from there with Python 3.10 or later. The JSONL contains fictional observations and DNS-wire byte sequences. The reader decodes only the DNS header in this fixture. It checks the response and truncation bits, extracts the base four-bit RCODE and reads the answer count. It does not verify the entire wire message, decode EDNS extended response codes, or recompute a TTL from records. The TTL subtraction uses supplied fixture fields. It does not open network connections.

<a href="{{ '/assets/labs/doh-resolution-evidence.py' | relative_url }}" download="doh-resolution-evidence.py">doh-resolution-evidence.py</a> · <a href="{{ '/assets/labs/doh-resolution-evidence-cases.jsonl' | relative_url }}" download="doh-resolution-evidence-cases.jsonl">doh-resolution-evidence-cases.jsonl</a>

```bash
python3 doh-resolution-evidence.py doh-resolution-evidence-cases.jsonl
```

```text
answer: NOERROR answers=1 example_remaining_ttl=85
name_error: NXDOMAIN answers=0
resolution_failure: SERVFAIL answers=0
empty_answer: NOERROR answers=0
upstream_gateway_error: non_success_http_502
html_success: unexpected_media
short_dns_body: invalid_header
dns_query_body: not_a_dns_response
passive_tls_only: no_http_observation
correlated_retry: linked_system_retry
```

If the command fails, check your working directory and file names. In `short_dns_body` the DNS header cannot be read even though HTTP returned 200. `passive_tls_only` describes limited visibility and cannot establish resolver or lookup success. The retry case supplies an already correlated client observation. No retry is inferred from timing alone. This fixture was executed with Python 3.12. Browser, resolver and proxy behavior in the chapter was reviewed against official documents.

## 6. Check your reasoning

- **How can HTTP 200 carry NXDOMAIN?** The HTTP layer returned a valid DNS message. The DNS layer reports a name error in that resolver's view.
- **Does a zero answer count prove the name is absent?** It describes one section. Read the code, question type and authority section to interpret the response.
- **What distinguishes a fallback from an ordinary plaintext lookup?** Client evidence linking both attempts to the same lookup, paired where possible with logs from the expected alternate resolver.

Complete the exercise by reproducing all ten outputs, computing 120 minus 35, and stating what additional source could establish the result in `passive_tls_only`.

## Official references

Reviewed 2026-11-22. The RFCs define interoperable behavior. Verify vendor controls and defaults against the particular client release in scope.

- October 2018. HTTP encapsulation, response codes, caching and privacy. [RFC 8484 · DNS Queries over HTTPS](https://www.rfc-editor.org/rfc/rfc8484.html)
- November 2023. Discovery of a designated encrypted resolver. [RFC 9462 · Discovery of Designated Resolvers](https://www.rfc-editor.org/rfc/rfc9462.html)
- November 2023. DHCP and Router Advertisement discovery options. [RFC 9463 · Network-designated resolvers](https://www.rfc-editor.org/rfc/rfc9463.html)
- Firefox enterprise resolver, exclusions, fallback and version compatibility. [Mozilla · DNSOverHTTPS](https://firefox-admin-docs.mozilla.org/reference/policies/dnsoverhttps/)
- Firefox user-facing modes and fallback behavior. [Mozilla · DoH protection levels](https://support.mozilla.org/en-US/kb/dns-over-https)

[Previous · DNS fundamentals]({{ '/wiki/dns-investigation/' | relative_url }}) · [Related · TLS handshake evidence]({{ '/wiki/tls-handshake-evidence/' | relative_url }}) · [Related · DNS negative caching]({{ '/wiki/dns-negative-cache-evidence/' | relative_url }})

## Investigate Encrypted Client Hello

Read [TLS Encrypted Client Hello evidence]({{ '/wiki/tls-ech-evidence/' | relative_url }}) to distinguish the visible name, ECH acceptance and the resulting application request.
