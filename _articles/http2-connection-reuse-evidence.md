---
title: "HTTP/2 Connection Reuse · Trace Authority, Streams and 421"
description: "Separate TLS identity from per-stream request routing and reproduce a 421 response and a successful retry over local HTTP/2."
category: network
tags: [HTTP, HTTP/2, TLS, Network Monitoring, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/http2-connection-reuse-evidence/
---

A client loads two related sites. One request works, while another returns `421 Misdirected Request` and then succeeds on retry. The first connection’s certificate may be valid for both names. To diagnose the issue, compare what the connection negotiated with what each request targeted and what the server actually served. Read [TLS handshake evidence]({{ '/wiki/tls-handshake-evidence/' | relative_url }}) first if SNI and ALPN are new to you.

## 1. Identify the scope of each field

An **origin** is identified by scheme, host and port. A **connection** carries HTTP/2 frames. A **stream** is a numbered sequence of frames within that connection. One connection can carry several streams concurrently. An ordinary client request and its response share a stream, whose ID has meaning only within that connection.

| Observation | Scope | What to infer |
| --- | --- | --- |
| TLS SNI | TLS handshake for one connection | The requested server name used in TLS configuration selection. Later HTTP requests can name a different origin on an eligible reused connection |
| Certificate and hostname check | Peer identity checked by the client | A certificate can cover several names. Check trust and hostname policy for each eligible origin, alongside the server’s authority |
| Selected ALPN `h2` | Negotiated application protocol for one TLS connection | The endpoints selected HTTP/2. Individual requests and their results need separate evidence |
| HTTP/2 `:authority` | One request stream | Authority of the target URI. If it is present, `Host` does not determine the target |
| HTTP/2 `:status` | One response stream | Result for that request on that hop. It does not describe other streams or identify the original responder by itself |

**Connection coalescing** means reusing a connection for more than one authority. RFC 9113 permits reuse when the server is authoritative for the target. For HTTPS, the certificate has to pass the checks the client would use for a new connection to that host. Address sharing, the certificate and any applicable origin-selection policy each answer different questions. A common IP or matching SAN alone is insufficient to establish appropriate routing. A client may choose not to reuse even an eligible connection. Clients implementing the optional HTTP/2 ORIGIN frame can use the advertised Origin Set. The frame does not replace certificate verification.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/http2-connection-reuse-evidence-en.svg' | relative_url }}" alt="One connection starts with SNI for alpha and negotiated HTTP/2. A stream for alpha gets 200, and a stream targeting beta gets 421. Beta gets 200 after a new connection uses SNI for beta." style="max-width: 100%; height: auto;">
  <figcaption>Figure 1. The connection carries multiple requests and the status applies to one stream. The example retry opens a new connection.</figcaption>
</figure>

## 2. Follow a normal request and one misdirected request

In a fictional deployment, `alpha.example.test` and `beta.example.test` share an address, and the certificate includes both names. A TLS connection starts with SNI `alpha.example.test` and ALPN `h2`. Stream 1 sends `GET /catalog` to `alpha.example.test`. The alpha service returns `200`. Another request for alpha on the same connection has a different stream ID and can succeed normally.

Now assume a second request targets beta on the existing connection. Reuse can succeed if the connected service can serve beta and the client’s origin checks pass. In this deployment, however, the listener selected by alpha’s SNI serves alpha only. The beta request reaches that listener on stream 3 and receives `421`. The client opens another TLS connection with beta’s SNI and retries. The beta listener handles its own stream 1 and returns `200`. Two stream 1 records belong to separate connections.

RFC 9110 permits a client that receives 421 to retry over a different connection, even for a non-idempotent method. The exercise uses GET and a deliberate retry. Audit and application systems should still distinguish the original attempt from the retry. A generic proxy must not generate 421 under RFC 9110. When a product called a reverse proxy emits it, determine whether it responded in its role as an origin-facing gateway or merely forwarded an upstream response. Product labels alone do not identify the responder.

## 3. Distinguish routing failures from misuse

A legitimate 421 can follow a certificate expansion, virtual-host change, or mismatch between a connection-level route and the per-request target. A status spike after deployment suggests a concrete rollout hypothesis. Unexpected authorities can also reflect probing or attempted cross-tenant routing. Compare the target with the authorized listener and tenant configuration. Use authenticated client or request evidence and the resulting route decision before attributing intent. Protocol negotiation, shared certificates and apparent name mismatches supply context.

A passive capture can show connection timing and, in a suitable unencrypted ClientHello, the offered ALPN and SNI. ECH changes which names or extensions the observer can see. In TLS 1.3 the selected ALPN is in encrypted handshake material. HTTP/2 stream headers over TLS are encrypted. Use an authorized client or TLS termination point to distinguish a request authority from a connection name. A connection can carry many requests. Packet counts and stream IDs from different hops cannot replace a request identifier.

## 4. Collect, detect and respond

| Where | Record and qualification |
| --- | --- |
| Client or edge TLS log | UTC handshake time, connection ID scoped to that process or node, requested SNI where visible, selected ALPN, certificate identifier or validation result, and transport peer |
| HTTP request log at each accessible hop | Local connection and stream IDs if available, normalized and raw authority as appropriate, method, status, route identifier, upstream peer, request or trace ID, and timestamps |
| Origin, gateway and deployment records | Whether the status was generated locally or received upstream, route policy active at the time, listener and certificate rollout, and success on another connection |

Join by an identifier whose scope you know. An HTTP/2 connection and its stream IDs normally end at the TLS/HTTP termination point. For a gateway that opens another upstream connection, use a trustworthy request or trace ID across hops. Correlate attempts using an explicit retry relationship where available. A timestamp alone is prone to joining concurrent requests incorrectly.

For a detection baseline, group 421 responses by listener, request authority and route after splitting local from forwarded statuses. Compare the rate with total requests, known rollout intervals and recovery on fresh connections. Validate with an approved hostname pair. If routing changed outside a change window, preserve configuration and logs, then reconcile the configured origin set, certificate coverage and virtual-host policy. Correct the mismatched route through change control and verify normal requests including legitimate reuse. A 421 does not establish data exposure. Investigate a request that returned unexpected tenant data as a separate outcome.

## 5. Authorized loopback exercise

<a href="{{ '/assets/labs/http2-connection-reuse-evidence.cjs' | relative_url }}" download>Download the Node.js lab</a> and run it in an environment you own or may use. It starts an HTTP/2 origin simulator on `127.0.0.1` using a temporary port and certificate covering two reserved test names. The client trusts that certificate only for the lab and keeps hostname verification enabled. The lab has no external network dependencies and needs Node.js 22 or later with HTTP/2 and OpenSSL 3.x for certificate generation.

```bash
node http2-connection-reuse-evidence.cjs
```

The lab explicitly places two requests on one connection and makes a separate retry. It does not implement a browser’s origin-selection or retry algorithm. The origin simulator compares the test SNI with the test request host and returns 421 when its connection route does not serve that host.

| Expected observation | Check |
| --- | --- |
| Both endpoints negotiate `h2` on both sessions | The records come from actual local HTTP/2 over TLS |
| First connection’s certificate matches both test names | Hostname coverage can coexist with a route refusal |
| Alpha gets 200 and beta gets 421 on different streams of one connection | A stream names its own authority |
| Beta gets 200 on a new connection with a reset stream number space | Combine connection and stream IDs when interpreting records |

Expect `4/4 HTTP/2 controls passed.` If binding fails, check whether the runtime allows local sockets. Certificate generation requires `openssl` on PATH, and the local trust check uses only the generated test certificate. A production listener’s routing and browser retry behavior are outside the lab. The production discussion is based on the standards reviewed below.

## 6. Check your understanding

1. **SNI is alpha and `:authority` is beta. Is that enough to declare an attack?** No. First check whether reuse was eligible and how the listener routed or refused that stream.
2. **A certificate covers beta but the response is 421. What can explain both?** The certificate check can succeed while the server refuses beta on that connection. Compare the listener’s routing rule and the target origin.
3. **Two logs both show stream 1. What else identifies the request?** Find each stream’s connection and local observation point. A propagated request ID helps cross termination boundaries.

**Completion criterion.** Reproduce the 421 and the retry, identify which layer each recorded field describes, and explain which observation identifies the responder. Continue with [HTTP request and response investigation]({{ '/wiki/http-evidence/' | relative_url }}) or compare [QUIC and HTTP/3]({{ '/wiki/quic-http3-evidence/' | relative_url }}).

## Official references

Reviewed 2026-11-26. RFC years mark the standards editions. The lab uses the Node.js 24 line, and production client behavior depends on version and configuration.

- [RFC 9113 (2022), HTTP/2 sections 5, 8.3.1 and 9.1.1](https://www.rfc-editor.org/rfc/rfc9113.html) and [RFC 9110 (2022), 421 semantics](https://www.rfc-editor.org/rfc/rfc9110.html#section-15.5.20)
- [RFC 7301 (2014), ALPN](https://www.rfc-editor.org/rfc/rfc7301.html), [RFC 8446 (2018), TLS 1.3](https://www.rfc-editor.org/rfc/rfc8446.html) and [RFC 8336 (2018), optional HTTP/2 ORIGIN frames](https://www.rfc-editor.org/rfc/rfc8336.html)
- [Node.js v24 HTTP/2 API](https://nodejs.org/download/release/v24.22.1/docs/api/http2.html)

## Follow ALPN negotiation evidence

Use [TLS ALPN evidence]({{ '/wiki/tls-alpn-evidence/' | relative_url }}) to check how `h2` was selected on the relevant connection before investigating individual streams.
