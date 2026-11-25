---
title: "TLS Encrypted Client Hello Evidence · From Outer Name to HTTP"
description: "Distinguish advertised ECH, GREASE, TLS acceptance, recovery and HTTP evidence with eight offline cases."
category: network
tags: [TLS, ECH, DNS, Network Monitoring, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /ko/wiki/tls-ech-evidence/
---

**Learning goal.** Given a visible TLS name, a resolver answer and two connection attempts, explain which evidence can establish ECH acceptance and which can establish an HTTP request to the intended origin. Use this chapter after the [TLS handshake guide]({{ '/wiki/tls-handshake-evidence/' | relative_url }}).

## 1. Why protect the ClientHello?

A TLS connection begins with a **ClientHello**, which proposes parameters such as supported TLS versions. The **Server Name Indication (SNI)** extension tells a server which named service the client wants. On a shared address, that lets the server select the right configuration. In conventional TLS, the initial ClientHello can expose that name to an observer even though later HTTP data is encrypted.

**Encrypted Client Hello (ECH)** protects a genuine **ClientHelloInner**, which contains the origin SNI. The client puts the encrypted inner message in a visible **ClientHelloOuter**, which typically carries the configuration's **public name** as its SNI. Many origin names can share that public name. **HPKE** (Hybrid Public Key Encryption) protects the inner message using the public key and parameters in an **ECHConfig**. The corresponding private key belongs to the client-facing service. The separate TLS handshake still authenticates the intended service and establishes keys to protect TLS traffic.

| Term | Meaning in an investigation |
| --- | --- |
| Origin name | The service hostname the application intends to use, such as `reports.example`. |
| Public name | The name in the ECH configuration for the client-facing service, such as `edge.example`. It can be shared. |
| HTTPS DNS record | A DNS record type that can advertise service parameters, including `ech`. This record is distinct from an HTTP request or an encrypted DNS transport. |
| GREASE | A deliberately plausible-looking extension sent even when there is no usable ECH configuration, to help keep protocol implementations tolerant of extensions. |

ECH reduces name exposure on the TLS hop. Destination addresses, packet sizes and timings can still be observed. A plaintext DNS lookup can expose the original queried name. DNS over HTTPS protects the lookup between client and resolver, while the resolver still sees the question. A shared IP or public name is not enough to attribute a request to a particular origin.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/tls-ech-evidence-en.svg' | relative_url }}" alt="DNS can supply an ECH configuration. The outer ClientHello exposes a public name and contains an encrypted inner ClientHello with the origin name. Client or TLS endpoint evidence can establish ECH acceptance. A matching application log can establish the HTTP request.">
  <figcaption>Discovery, visibility on the wire, TLS acceptance and application outcome each have their own evidence.</figcaption>
</figure>

## 2. Follow a normal connection and a retry

Consider an invented service at `reports.example` behind a TLS endpoint with the public name `edge.example`.

1. The client obtains a usable ECH configuration, for example from an HTTPS DNS record. It checks the actual response and available configuration. An investigator's later query can return a different record because of caching, resolver policy or rollout timing.
2. The client seals the inner ClientHello for the TLS endpoint and sends the outer ClientHello. A sensor that captured and decoded it might report `edge.example` and an ECH extension. Those fields alone also cannot distinguish genuine ECH offers from GREASE on other connections.
3. If the service accepts ECH, the client cryptographically checks the acceptance signal and proceeds with the inner handshake. It authenticates the intended origin in the usual way. A matching client or authorized terminator diagnostic can attest to ECH acceptance. A matching HTTP log can show whether the application actually sent a request.
4. If an edge still serves an old key or the client cached an old configuration, the genuine ECH offer may be rejected. For a recovery handshake, the client verifies the certificate for the **public name**, validates the handshake and may retry on a new connection with authenticated, supported replacement settings. The rejected connection does not carry the client's application data. Read the retry as a separate connection and verify the outcome there. A failed public-name authentication cannot authenticate replacement settings.

This guide uses the March 2026 RFCs for ECH and DNS bootstrapping. Apply the relevant draft when interpreting a historical capture from a draft implementation. Cloudflare's April 2026 product documentation gives `cloudflare-ech.com` as its shared outer name. Treat that name as a provider example and check the actual configuration for the service under investigation.

## 3. Read each observation at its own layer

| Observation | What it can establish | What to look for next |
| --- | --- | --- |
| HTTPS DNS answer advertises `ech` | The observed resolver response advertised a configuration. | Check that the application used that resolver, received the answer and attempted ECH. |
| Outer SNI and an ECH extension appear | A decoder saw these fields on that hop. GREASE can look similar. | Confirm capture completeness and seek a diagnostic from either end of that TLS hop. |
| Client records ECH acceptance | ECH was accepted on the named connection, assuming the record and join are trustworthy. | Check origin authentication and separate HTTP evidence. |
| Public-name handshake followed by a retry | With client corroboration, this is consistent with ECH recovery. | Confirm authentication, any trusted replacement configuration and the result of the new connection. |
| Authorized HTTP terminator records authority and status | The terminator handled an HTTP request for that authority on the logged hop. | Join the connection or trace identifiers before attaching it to a particular TLS event. |
| No ECH extension was decoded | The sensor has no positive ECH extension observation. | Check placement, capture gaps, parser version and client policy before drawing conclusions. |

An ECH extension, a shared edge address and one apparent retry are individually weak security indicators. An observer that can affect discovery may be able to interfere with whether the client receives suitable settings. Failed handshakes and missing SNI also arise from ordinary rollout, stale caches, unsupported clients and capture loss. A failed, unauthenticated retry exchange does not by itself justify clearing ECH. An alert should preserve competing explanations until evidence narrows them.

## 4. Collect, detect and respond

1. **Scope the path.** Record UTC time, client version, connection or trace ID, capture location and the expected service. Label browser-to-edge and edge-to-origin hops separately. For TCP, record addresses and ports. For QUIC, use an endpoint connection ID where available and document how it joins to the capture.
2. **Collect the minimum useful data.** Request the client's actual resolver or diagnostic trace where authorized. Preserve record type, observed answer, TTL, resolver and collection time. Collect the outer SNI and decoder state. If permitted, ask the TLS terminator or client for a per-connection ECH result and hostname verification result, then join the HTTP request ID, authority and status. Product diagnostics vary. Keep private keys, session secrets and unrelated browsing history out of incident records.
3. **Compare a baseline that matches the environment.** Compare the fraction of ECH rejections or handshake errors across client versions, resolver paths and edge regions, with total attempts for each group. When errors rise after a planned key rotation, check the advertisement observed by affected clients, TTLs, certificate validity for the public name and edge key rollout. When evidence disagrees, preserve timestamps and logs, inspect join confidence and keep records with ambiguous matches unresolved.
4. **Validate the correction.** Ask the service owner to align published configurations and edge keys or to recover the authorized DNS path. Repeat the same approved test and confirm, separately, ECH acceptance, origin authentication and the HTTP outcome. If plaintext SNI drove a detection, measure the lost coverage and build any replacement around authorized endpoint, resolver or service telemetry.

## 5. Run an offline evidence exercise

Save the <a href="{{ '/assets/labs/tls-ech-evidence.py' | relative_url }}" download="tls-ech-evidence.py">Python script</a> and <a href="{{ '/assets/labs/tls-ech-evidence-cases.json' | relative_url }}" download="tls-ech-evidence-cases.json">fictional JSON cases</a> into the same approved workspace. Run with Python 3. The fixture uses simplified, already-correlated diagnostic fields and explicit same-connection HTTP evidence. The script reads local JSON; it neither captures packets nor performs TLS or DNS requests.

```bash
python3 tls-ech-evidence.py tls-ech-evidence-cases.json
```

```text
dns_only: configuration_advertised
wire_only: offer_or_grease
lab_grease: grease_confirmed
accepted_tls: accepted_check_http
accepted_http: accepted_http_observed
rotation_retry: rejected_retry_available
untrusted_outer: rejected_no_trusted_retry
capture_gap: insufficient_evidence
```

If the script cannot open its input, check your working directory and both filenames. If a case does not classify as an HTTP success, check whether the fixture has a confirmed ECH acceptance, authenticated origin and a matching HTTP record. In `rotation_retry`, availability of authenticated replacement settings leaves the new connection's outcome open. The eight fictional cases were executed with Python. The RFC and supplier behavior were reviewed in documentation; no live ECH endpoint was exercised.

## 6. Check your reasoning

- **Can the visible name `edge.example` identify `reports.example`?** The public name identifies the fronting service in this example. Correlated endpoint or application evidence is needed to identify the origin.
- **A packet decoder sees an ECH extension. Did the endpoint accept ECH?** The extension could represent a genuine offer or GREASE. Seek the client or service result for that connection.
- **A recovery handshake authenticated `edge.example`. Did it authenticate `reports.example`?** Check the separate origin handshake. The recovery connection is for obtaining trusted settings or a protocol-defined signal and cannot carry the client's HTTP request.
- **Did an accepted ECH handshake prove a GET was sent?** Obtain an HTTP record tied to the handshake. If the join is uncertain, keep the HTTP outcome open.

Finish when all eight outputs match and you can mark each of discovery, extension observation, ECH acceptance, origin authentication and HTTP outcome as observed or unresolved.

## Official references

Reviewed November 23, 2026.

- March 2026 ECH standard, including acceptance, rejection and GREASE. [IETF RFC 9849 §§6.1.4–6.2](https://www.rfc-editor.org/rfc/rfc9849.html#section-6.1.4)
- March 2026 ECH discovery and October 2023 service-binding record format. [IETF RFC 9848](https://www.rfc-editor.org/rfc/rfc9848.html) · [IETF RFC 9460](https://www.rfc-editor.org/rfc/rfc9460.html)
- February 2022 HPKE specification. [IETF RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html)
- Provider-specific outer-name example and deployment scope, updated April 17, 2026. [Cloudflare · ECH Protocol](https://developers.cloudflare.com/ssl/edge-certificates/ech/)

[Previous · TLS handshake evidence]({{ '/wiki/tls-handshake-evidence/' | relative_url }}) · [Next · DNS over HTTPS investigation]({{ '/wiki/doh-resolution-evidence/' | relative_url }}) · [Related · QUIC and HTTP/3]({{ '/wiki/quic-http3-evidence/' | relative_url }})

[Related · Trace DNS HTTPS records to actual connections]({{ '/wiki/dns-https-record-evidence/' | relative_url }})
