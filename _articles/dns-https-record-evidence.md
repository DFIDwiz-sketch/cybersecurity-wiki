---
title: "DNS HTTPS Records · Trace Advertised and Used Endpoints"
description: "Read HTTPS Service Binding records, evaluate candidate endpoints, and corroborate real connections with offline cases."
category: network
tags: [DNS, HTTPS RR, SVCB, HTTP, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/dns-https-record-evidence/
---

**Learning goal.** Given a service name, a DNS answer and records from a client, explain what the DNS answer offered, which candidates the client could use, and what evidence establishes a connection or HTTP request.

## 1. An address is one part of connecting

A **resource record (RR)** is a typed piece of DNS data. An **RRset** groups records with the same owner, class and type. A and AAAA records provide IPv4 and IPv6 addresses. A **service binding** can tell a client where and how to connect before it attempts a connection. RFC 9460 defines a generic SVCB record (type 64) and an HTTPS record (type 65) for HTTP and HTTPS. For a web origin, a client implementing this mapping queries HTTPS, even though the two types share the same structure. **DNS over HTTPS (DoH)** is a transport for DNS queries. An HTTPS record can be retrieved over ordinary DNS or an encrypted DNS transport.

| What you see | How to read it | Evidence to check next |
| --- | --- | --- |
| AliasMode, priority `0` | Continue the HTTPS lookup at the target. Parameters in AliasMode are ignored. | Follow the next answer of the same type and track the name chain. |
| ServiceMode, positive priority | Advertises one endpoint and its parameters. Smaller values have higher preference among compatible choices. | Check compatibility and the effective target. A target of `.` means this record's owner. |
| `alpn` and `no-default-alpn` | Advertised protocols and whether the mapping's default protocol is also in the set | Compare the set with the client and the protocol actually negotiated. |
| `mandatory` | Keys that the client must understand and be able to use for this record | Confirm the keys are present. An unsupported required key can make the record incompatible. |
| `port`, address hints, `ech` | Alternative endpoint port, possible addresses, and ECH configuration when present | Resolve the candidate's address and check the socket, TLS outcome and request. |

An **origin** is identified by scheme, host and port. A **TargetName** is a name used to reach an endpoint. Changing the target or connection port via DNS does not rename the origin. For an HTTPS binding the client still indicates the origin name in TLS SNI, potentially in the protected inner ClientHello with ECH. The client authenticates the origin under its TLS policy and sends the origin in the HTTP authority. The target can be a shared edge service.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/dns-https-record-en.svg' | relative_url }}" alt="A client looks up the origin's HTTPS record, follows an alias if present, and evaluates compatible endpoint choices. Transport and TLS observations show the connection attempted. HTTP request evidence establishes which service was used.">
  <figcaption>Record the DNS offer, the chosen connection and the request outcome separately.</figcaption>
</figure>

## 2. Follow a routine connection

The following records are fictional. The client intends to open `https://reports.example/`.

```text
reports.example.      120 IN HTTPS 0 routes.example.
routes.example.       120 IN HTTPS 1 edge-a.example. alpn=h3,h2
routes.example.       120 IN HTTPS 2 edge-b.example. alpn=h2
edge-a.example.       120 IN A     192.0.2.20
edge-b.example.       120 IN A     192.0.2.21
```

1. The first record redirects the HTTPS **lookup** to `routes.example.`. This step does not issue an HTTP redirect or turn that target into the origin. If the same RRset includes AliasMode and ServiceMode, clients follow an alias and disregard ServiceMode records in that set. An AliasMode target of `.` instead signals advisory service unavailability. A ServiceMode dot has the different owner-name meaning shown above.
2. The second answer offers two endpoints. A client that supports h3 and h2 can prioritize `edge-a.example.`. In the HTTPS mapping, HTTP/1.1 is the default ALPN unless suppressed by `no-default-alpn`, which is used together with `alpn`. Advertising h3 by itself does not establish h3-only service or a successful QUIC connection. A compatible ALPN helps choose a transport. Within that transport, TLS negotiates a protocol from the actual ClientHello and endpoint capabilities.
3. The client obtains addresses for the effective target. If A/AAAA are locally available, RFC 9460 advises ignoring address hints. Otherwise a client may use a hint while seeking A/AAAA. For a different URI authority port, such as `https://reports.example:8443/`, the HTTPS query starts at `_8443._https.reports.example.`. A ServiceMode `port` value changes the port to dial for that endpoint, without changing the URI authority port.
4. Suppose a client trace associates a successful QUIC connection to `192.0.2.20:443` with h3 negotiation, origin authentication and an HTTP request to `reports.example`. Those records support h3 use for that request. A DNS offer or an isolated UDP packet alone supports less. If h3 times out and h2 later succeeds, a correlated client trace can establish a retry or fallback. Timing alone may confuse concurrent connection attempts.

## 3. Investigate an unexpected endpoint or failed connection

An unauthorized DNS change could direct traffic to a different endpoint, remove a privacy or performance option, or prevent connections. A wrong TLS certificate normally causes authentication to fail, even if DNS resolution succeeded. Legitimate CDN changes, a resolver's cache, region-specific answers and product compatibility can look similar at first. Cloudflare, for example, documents conditions under which it synthesizes HTTPS records for proxied names. Check the active provider configuration before treating a record that differs from the control panel as a change by an intruder.

1. **Preserve the view.** Record UTC time, client and resolver, transport, queried owner and type, response code, TTL, entire answer set, alias chain and A/AAAA results. A NOERROR response without the requested record differs from NXDOMAIN or SERVFAIL. An authoritative view and a recursive cache can differ for legitimate reasons. With encrypted DNS, use authorized endpoint or resolver evidence when an on-path capture cannot show the answer.
2. **Compare eligible choices.** Check required parameters, client protocol support and the target addresses. A successful query does not mean every advertised option was compatible. A client that can operate without a usable binding can sometimes use its conventional connection path. Account for RFC 9460's constraints on fallback after protected resolution failures and any applicable ECH policy. Certificate validation still applies.
3. **Follow the same connection.** Join client DNS and transport records with socket destination and port, TLS authentication and ALPN result, and an HTTP transaction carrying the intended authority. Use a client connection or request ID when possible. Keep each side of a proxy separate. A candidate IP in a hint or a CDN address shared by multiple origins cannot establish attribution.
4. **Respond and verify.** Compare the returned HTTPS RRset and target records with authorized DNS changes and provider history. Preserve unexpected changes before correcting them. Verify the same resolver and client path plus a known healthy control. Retain the old and new answers across applicable TTLs, track connection errors and verify that the expected protocol and origin return. DNSSEC validates DNS data where a chain of trust applies. DoH can protect the resolver connection. Neither replaces origin authentication.

### Read-only DNS collection

Use an authorized resolver and a zone you own or have approval to inspect. Substitute the documentation resolver address and fictional names. BIND `dig` with HTTPS support can read the type directly. An older build may present `TYPE65` in generic form. Keep the header and answer rather than collecting just short output. `HTTPS` in these commands selects the record type. It does not turn on DoH.

```bash
dig @192.0.2.53 reports.example. HTTPS +noall +comments +answer +additional
dig @192.0.2.53 routes.example. HTTPS +noall +comments +answer
dig @192.0.2.53 edge-a.example. A +noall +comments +answer
dig @192.0.2.53 edge-a.example. AAAA +noall +comments +answer
```

A query sent by `dig` is a new observation from that resolver, not a reconstruction of a past browser response. Compare the resolver as seen by the app and check whether it used a cache, proxy or another DNS transport.

## 4. Practice offline with synthetic evidence

Place the <a href="{{ '/assets/labs/dns-https-evidence.py' | relative_url }}" download="dns-https-evidence.py">Python script</a> and <a href="{{ '/assets/labs/dns-https-evidence-cases.json' | relative_url }}" download="dns-https-evidence-cases.json">case file</a> in the same directory in an authorized workspace. Use Python 3.9 or newer. The script reads normalized fictional data without networking. It checks a subset of the candidate rules. It uses explicit client capabilities and accepts independent, already-correlated connection findings from the fixture. It does not model every retry, wire format or TLS policy.

```bash
python3 dns-https-evidence.py dns-https-evidence-cases.json
```

| Case | Expected reading |
| --- | --- |
| `alias_offer_only` | An alias leads to eligible endpoints. No use was observed. |
| `priority_and_dot` | Two candidates are ordered. A ServiceMode dot resolves to the record owner. |
| `unknown_mandatory` | The preferred record requires an unsupported key. A second candidate remains. |
| `missing_mandatory_value` | The advertised record is inconsistent and cannot be used. |
| `hint_and_port` | The record offers a port and hint. A/AAAA is present and the fixture confirms a request to the resolved address. |
| `default_alpn` | The default adds a compatible protocol. A record with defaults suppressed has no usable protocol for this client. |
| `no_https_answer` | NOERROR with no HTTPS record. The fixture records a conventional HTTP/2 connection and request. |
| `attempt_without_request` | The trace shows a connection attempt without a confirmed request. |

All eight cases should print PASS. In a copy, change priority `1` to `9` in the first record of `priority_and_dot` and rerun. Candidate order should change and the old expectation should fail. If the file is unreadable, check the paths. If a candidate is missing, compare the alias chain and mandatory keys before comparing connection evidence. The Python lab was executed. The DNS commands and provider behavior were reviewed against official documentation. No live DNS zone, browser support matrix or Cloudflare configuration was tested in this lab.

## 5. Check your reasoning

- **An HTTPS answer lists h3. Can an analyst report an HTTP/3 request?** The answer advertises a candidate. Confirm the negotiated protocol and the HTTP request on that connection.
- **The connection went to a CDN target. Which name should be authenticated?** The intended origin. The DNS target and IP help reach the endpoint but are separate from the origin identity.
- **An answer with an unknown mandatory key has the smallest priority. Why might a different endpoint be used?** Compatibility is checked before preference. Once the incompatible record is excluded, the client chooses among remaining candidates according to policy.

Finish when all cases pass and you can describe one timeline with separate entries for DNS advertisement, candidate selection, connection and request evidence.

## Official references

Reviewed November 26, 2026. The SVCB and HTTPS base standard is from November 2023. The ECH specification and DNS mapping are from March 2026. Treat provider behavior as specific to the documented service and settings.

- Priority, alias following, compatibility and HTTPS mapping. [RFC 9460 §§2–3, 7–9](https://www.rfc-editor.org/rfc/rfc9460.html)
- Delivery of ECH configuration and handshake behavior. [RFC 9848](https://www.rfc-editor.org/rfc/rfc9848.html) · [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849.html)
- DNS diagnostic command. [BIND 9 dig manual](https://bind9.readthedocs.io/en/stable/manpages.html#dig-dns-lookup-utility)
- Provider-specific generation of HTTPS records for eligible proxied names. [Cloudflare DNS record types](https://developers.cloudflare.com/dns/manage-dns-records/reference/dns-record-types/#svcb-and-https)

[Previous · DNS fundamentals]({{ '/wiki/dns-investigation/' | relative_url }}) · [Next · QUIC and HTTP/3]({{ '/wiki/quic-http3-evidence/' | relative_url }}) · [Related · TLS Encrypted Client Hello]({{ '/wiki/tls-ech-evidence/' | relative_url }})
