---
title: "QUIC and HTTP/3 · From UDP Traffic to Request Evidence"
description: "Distinguish HTTP/3 discovery, QUIC attempts, HTTP protocol selection and proxy hops using capture limits, client logs and an offline lab."
category: network
tags: [QUIC, HTTP, TLS, Network Monitoring, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/quic-http3-evidence/
---

**Learning goal.** Given UDP traffic, a browser request and a reverse-proxy log, explain which connection used QUIC, which HTTP version served the request, and what evidence would support fallback. Start with [TLS handshake evidence]({{ '/wiki/tls-handshake-evidence/' | relative_url }}) if the TLS roles are new to you.

## 1. What happens between the socket and the request?

**UDP** carries datagrams. **QUIC** is a secure transport over UDP. QUIC uses the TLS 1.3 handshake to establish keys and authenticate peers according to the configured TLS policy. QUIC itself provides reliable streams, loss recovery and congestion control. **HTTP/3** maps HTTP messages onto QUIC streams. **ALPN** negotiates an application protocol during the handshake, such as `h3` for HTTP/3. A browser can run several requests over one connection, so a connection record alone cannot identify a particular request.

A client can learn about an HTTP/3 endpoint through an **Alt-Svc** advertisement, such as `Alt-Svc: h3=":443"`, or supported endpoint discovery such as a DNS HTTPS record. An advertisement describes an available alternative. Observe the negotiated protocol and the request to tell whether the client used it.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/quic-http3-en.svg' | relative_url }}" alt="An HTTP/3 discovery hint can lead to a QUIC attempt. A request record can show h3 on QUIC or h2 on TCP. A separately terminated edge-to-origin hop may use another HTTP version.">
  <figcaption>Record the discovery hint, connection result and request protocol separately. If an edge terminates TLS, its origin connection is a separate hop.</figcaption>
</figure>

## 2. Follow a normal browser request

In a fictional trace, the browser first fetches `https://catalog.example.test/` over HTTP/2 and receives an `Alt-Svc` header advertising HTTP/3. A later request for `/items` uses QUIC. The browser's completed request row reports `h3`, and the edge log records HTTP/3 for the client-facing leg. The edge obtains the response over HTTP/2 from its upstream. The browser saw HTTP/3 even though the origin saw HTTP/2. Both statements can be true for the same application request.

Now suppose an approved test client records a failed QUIC connection attempt linked to its next attempt for the same request, which completes over HTTP/2. The linked failed attempt and completed protocol support fallback. A client may start TCP and QUIC attempts close together, race them, or reuse a connection. A neighboring UDP packet plus a successful TCP request makes a candidate timeline. Confirm the linkage and client outcome before diagnosing a protocol switch. Even a confirmed fallback leaves the failure cause open.

| Observation | What it supports | Next check |
| --- | --- | --- |
| Alt-Svc advertises `h3` | The origin advertised an alternative endpoint | Which protocol appears on the completed request? |
| UDP to port 443 | UDP activity on that path | Can a compatible decoder identify QUIC, or is there endpoint evidence? |
| Decoded client QUIC Initial | The client sent QUIC startup traffic on the observed path | Is a peer response visible, and does the client record the connection outcome? |
| Client reports `h3` on a completed request | HTTP/3 served that request on the observed client hop | Which edge handled it, and what happened on its upstream connection? |
| Client reports `h2` and links a failed QUIC attempt | Evidence consistent with fallback for that request | Inspect order, client errors, capture coverage and policy to assess the cause. |

## 3. What can a passive capture establish?

Capture position matters. A suitable capture can show UDP headers, timings and certain QUIC header fields, such as the version and connection IDs in long headers. A compatible decoder that observes the requisite Initial traffic can derive the Initial protection keys from public inputs for supported QUIC versions. It may recover the outer TLS ClientHello and metadata present there. Enough packets are needed to reassemble a fragmented handshake. With **Encrypted Client Hello (ECH)**, the inner ClientHello is protected separately. Treat an outer name as the name observed in that outer message. The negotiated application protocol and HTTP payload usually need authorized endpoint or TLS termination evidence. A client ALPN offer is a list of candidates.

A five-tuple combines source and destination IP addresses and ports with the transport protocol. QUIC can survive address or port changes through connection migration or NAT rebinding. Connection IDs can change and are relevant in a specific direction and observation context. Preserve tuple changes and the span of the capture, then confirm the connection relationship with endpoint telemetry. Treat capture-local and client-local IDs as scoped values. A QUIC connection ID cannot stand in for an HTTP request ID.

## 4. Triage alerts and coverage gaps

A policy gap can occur when a network sensor handles TCP web sessions and sees UDP only as flows. A hosted QUIC endpoint can carry ordinary web traffic or application traffic outside an expected policy. A protocol or port signal alone cannot establish the request, identity or intent. For protocol policy, check the rule and the actual enforcement result on the correct path. Use an approved endpoint test to confirm whether visibility and enforcement match expectations.

| Source | Collection needs | Review |
| --- | --- | --- |
| Firewall or flow export | Sensor location, direction, time, tuple and action fields | A matching UDP drop identifies a policy decision on that device. Compare times and matching requests before attributing fallback. |
| Packet capture | Relevant interfaces, both directions where possible, capture loss and compatible decoder | Identify the visible protocol and direction. One-sided UDP or Initial retransmissions can also reflect loss, path issues or a capture gap. |
| Browser or client | Completed request protocol and time, plus transport diagnostics for attempt relationships | For Chrome DevTools, enable **Protocol** in the Network request table. Add **Remote address** as needed. The request row alone does not show all failed connection attempts. |
| Edge and origin logs | Explicit hop and protocol fields, time, endpoint and trusted correlation ID | Verify which hop each protocol describes. Scope any shared request ID by service and time, and determine who set it. |

Start with the symptom and an affected device, URL and time range. Compare the client result with edge logs, firewall actions and capture coverage. Check whether failures are isolated to an edge, path, policy change or client cohort. Compare against a known-good approved request with similar configuration. Review readiness for QUIC at the destination and check [path MTU evidence]({{ '/wiki/pmtu-icmp-evidence/' | relative_url }}) where packet size or path changes are plausible. Preserve the initial evidence and escalate to the responsible network or application owner. Logs or exports may include sensitive URLs and session identifiers. Use the minimum retained data needed for the case.

## 5. Practice on synthetic observations

Place [quic-http3-review.py]({{ '/assets/labs/quic-http3-review.py' | relative_url }}){: download="quic-http3-review.py" } and [quic-http3-cases.json]({{ '/assets/labs/quic-http3-cases.json' | relative_url }}){: download="quic-http3-cases.json" } in the same directory in an owned workspace. Run `python3 quic-http3-review.py` with Python 3.8 or later. The fixture summarizes eight fictional cases and contains no packets. The program uses the standard library and makes no network calls.

| Case | Expected interpretation |
| --- | --- |
| `client-used-h3` | Client request used h3. |
| `fallback-supported` | Client request used h2 with a linked failed QUIC attempt. |
| `parallel-traffic-unlinked` | Client request used h2. Relationship to the nearby QUIC Initial remains unknown. |
| `advertisement-only`, `udp-port-only`, `quic-initial-only` | An advertisement, UDP activity and QUIC startup have different meanings. None establishes the request protocol. |
| `edge-terminates-h3` | Client h3 and upstream h2 are two distinct hop observations. |
| `conflicting-client-records` | Two protocols claim the same client request. Recheck request identity, redirects and intermediate hops. |

If the script cannot find the JSON file, check the directory and filenames. Compare the labels and outputs with the table. The fixture supplies an existing attempt relationship where known. The script does not infer one from timestamps. All eight cases were executed with Python 3.12.14.

### Optional live comparison on an approved endpoint

Use a trusted HTTPS endpoint you own or have explicit permission to test. Set `H3_LAB_URL` to its URL and record the client build, proxy settings and network path. The example assumes a POSIX shell and curl with the HTTP3 feature. Use an approved URL that serves a small public test response. curl's `--http3-only` requires 7.88.0 or later and fails if QUIC cannot be established. The fallback-enabled `--http3` can use an older HTTP version. Keep certificate verification enabled.

```sh
curl --version
curl --http3-only --max-time 15 --silent --show-error --output /dev/null \
  --write-out 'http=%{http_version} status=%{response_code} peer=%{remote_ip}\n' "$H3_LAB_URL"
curl --http3 --max-time 15 --silent --show-error --output /dev/null \
  --write-out 'http=%{http_version} status=%{response_code} peer=%{remote_ip}\n' "$H3_LAB_URL"
```

Record the exit status of each run, the negotiated response version and the destination reported by curl. The HTTP status reflects the application response. A successful HTTP/3 response reports `http=3`. A timeout does not prove a UDP block. If the fallback-enabled command returns HTTP/2, seek client transport diagnostics before inferring a failed attempt or a particular policy decision. The curl and Chrome examples were reviewed against official documentation. The optional live comparison was outside the verification scope.

## 6. Check your reasoning

1. **The only evidence is an `Alt-Svc` header from an HTTP/2 response. Which protocol served that response?** HTTP/2. The header advertised a future alternative.
2. **A capture has a QUIC Initial and the completed request row says h2. Did the client fall back?** You know the request used h2 and QUIC started on a visible flow. Find client-side evidence linking an attempt for that request and its outcome.
3. **The edge records h3 and the origin h2 with a validated shared request ID. Which evidence is wrong?** Both can be correct. A reverse proxy can terminate the client connection and open an independent connection upstream.

**Completion check.** Reproduce the eight cases. For each, identify the hop, the strongest supported conclusion, and one missing check.

## Official references

Reviewed 2026-11-22. The RFCs identify their publication dates. curl and Chrome references describe the documented interfaces at review time. Capture and client support depend on version and configuration.

- IETF [RFC 9000 · QUIC transport, May 2021](https://www.rfc-editor.org/rfc/rfc9000.html) · [RFC 9001 · TLS with QUIC, May 2021](https://www.rfc-editor.org/rfc/rfc9001.html)
- IETF [RFC 9114 · HTTP/3 and discovery, June 2022](https://www.rfc-editor.org/rfc/rfc9114.html) · [RFC 9460 · DNS SVCB and HTTPS records, November 2023](https://www.rfc-editor.org/rfc/rfc9460.html)
- IETF [RFC 9312 · QUIC manageability, September 2022](https://www.rfc-editor.org/rfc/rfc9312.html) · [RFC 9849 · TLS ECH, March 2026](https://www.rfc-editor.org/rfc/rfc9849.html)
- [curl manual · HTTP/3 options](https://curl.se/docs/manpage.html#--http3) · [Chrome DevTools · Network reference](https://developer.chrome.com/docs/devtools/network/reference#columns)

[Previous · TLS handshake evidence]({{ '/wiki/tls-handshake-evidence/' | relative_url }}) · [Next · HTTP proxy response evidence]({{ '/wiki/http-proxy-response-evidence/' | relative_url }})

## Investigate Encrypted Client Hello

Read [TLS Encrypted Client Hello evidence]({{ '/wiki/tls-ech-evidence/' | relative_url }}) to distinguish the visible name, ECH acceptance and the resulting application request.

## Trace UDP datagram delivery

Use [UDP datagram evidence]({{ '/wiki/udp-datagram-evidence/' | relative_url }}) to distinguish packet capture from application receipt and verify a short receive buffer on loopback.
