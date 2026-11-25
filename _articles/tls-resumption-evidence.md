---
title: "Investigate TLS 1.3 Resumption and 0-RTT"
description: "Distinguish session resumption, early data and application outcomes, then verify TLS resumption on loopback."
category: network
tags: [TLS, TLS 1.3, TLS Resumption, HTTPS, QUIC, Network Security, Blue Team]
level: Beginner
updated: "2026-11-25"
translation_url: /ko/wiki/tls-resumption-evidence/
---

Your TLS terminator records a resumed connection, and an API log shows two requests for the same operation. The TLS entry tells you how a connection was established. To explain the duplicate, check whether the terminator accepted early data and whether the application committed the operation more than once.

## 1. A ticket, a TLS connection and an HTTP session

**TLS resumption** lets two peers establish a new TLS connection using cryptographic state from an earlier one. In TLS 1.3 the server can send a **NewSessionTicket** after it receives the client's Finished message. The ticket identifies a resumption **pre-shared key (PSK)** derived from the earlier handshake. On a subsequent connection the client can offer the ticket as a PSK identity and supply a **binder** that proves knowledge of the associated PSK. The server can decline the offer, in which case a full handshake can proceed when otherwise possible.

A resumed handshake derives fresh traffic keys for the new connection. A resumed handshake that uses PSK with ephemeral Diffie–Hellman (`psk_dhe_ke`) also includes a fresh key exchange, as recommended for forward secrecy by RFC 9325. **0-RTT early data** is optional. It is application data the client can send before receiving the server's handshake flight. It is encrypted with early traffic keys derived from the offered PSK and the ClientHello. It lacks the new connection's fresh key exchange at that point. Accepting resumption and accepting early data are separate decisions. An HTTP session cookie or application token is a separate credential and can outlive several TLS connections.

| Observation | What it supports | What to check next |
| --- | --- | --- |
| Ticket received | Client has an opportunity to offer resumption | Check the next connection |
| PSK offered in an observable ClientHello | Client offered a PSK identity | Server selection and endpoint logs |
| PSK selected in ServerHello | Server selected a PSK for this handshake | Handshake completion and endpoint resumption status |
| Early data accepted by the terminator | TLS accepted application bytes in the early-data phase | HTTP request and application audit |
| Completed request or committed action | App processed a request or changed state, depending on the audit | Check operation identity, retries and effects |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/tls-resumption-evidence-en.svg' | relative_url }}" alt="A full handshake supplies a ticket. A new connection offers a PSK, then the observer verifies server selection and the request timing.">
  <figcaption>Ordinary resumption. In this example the client sends the request after the handshake, without early data.</figcaption>
</figure>

## 2. Follow a routine pair of connections

In this fictional example, a client reads a public status page through an edge terminator. At 10:00:00 UTC, the client connects over TCP, verifies the server certificate in a full TLS 1.3 handshake, reads the response and processes a post-handshake ticket. At 10:00:05 UTC, it opens a different TCP connection and offers the prior ticket. The terminator accepts resumption. The client waits until its handshake finishes, then sends the second HTTP request. The facts to record are **two TCP connections**, **one resumed TLS handshake**, **no early data in this example**, and **two application requests**. Reusing the original open connection, as with HTTP keep-alive, would have had no second TLS handshake.

For a different client that offers early data on resumption, verify whether the edge accepted it. The acceptance indication is in encrypted `EncryptedExtensions`, so a normal passive capture without secrets cannot confirm it. A visible `early_data` extension in ClientHello is an offer, and a PSK extension may not be visible if carried in an ECH inner ClientHello. A later HTTP service could receive the request through an intermediary even if the edge-to-origin hop used ordinary post-handshake data. RFC 8470 defines `Early-Data: 1` to propagate that prior-hop risk. Treat the header as a request signal within the trusted proxy configuration. By itself it does not prove which hop accepted early bytes.

## 3. Why duplicate requests need investigation

TLS 1.3 does not inherently make 0-RTT application data replay-proof. A repeated early request may arrive at more than one accepting edge, especially when replay protection has gaps across independent nodes. Ordinary retries after timeouts or policy rejection can also produce similar request records. A repeated request ID, cookie or 2xx response is insufficient to attribute an attack. Determine whether there was one committed change, multiple changes, or a retry served the recorded outcome of the same operation.

In HTTP, a safe method is defined by semantics. An endpoint exposed as GET can still contain unintended application side effects. Review the route and its implementation before classifying it as suitable for early processing. Keep state-changing or otherwise replay-sensitive operations out of early data unless applicable protocol guidance and the application policy address the risk. For HTTP, a server can return **425 Too Early** when it declines to risk processing a potentially replayed request. A retry for that response is sent outside early data. A TLS-level early-data rejection is an independent event and can happen without any HTTP status.

## 4. Collect, detect and respond

1. **Collect where TLS terminates.** Ask whether the edge logs TLS version, completed handshake, resumption, early-data offer or acceptance, termination node, connection ID and UTC time. Field names and availability vary. Record whether values were unavailable, false or suppressed. Use periodic approved controls to confirm logging. Avoid logging raw tickets, PSKs, key logs, session cookies or unneeded payloads.
2. **Join across the actual request path.** Keep downstream and upstream connection IDs distinct. Carry a trusted request ID from edge to origin and record HTTP method, route and status. Compare with service audit records containing the business operation ID, outcome and deduplication decision where relevant. Capture policy version and node identity so differing deployments do not become one undifferentiated result.
3. **Triage competing explanations.** In a defined time window, compare early-data outcomes and 425 rates by edge node, route and policy version. If a route with side effects saw accepted early data, review it even if no duplicate is observed. For duplicate effects, check timeout retries, application workers, deduplication scope, and independent edge or application records before assigning a cause. A drop in resumption alone can follow a rollout, expiry or a new TLS terminator.
4. **Confirm the approved policy.** Verify that replay-sensitive routes do not process early data at every entry point. Review application deduplication at the operation boundary, including consistent storage across nodes where required. Use benign controls and confirm both the response and the committed outcome. Keep early-data handling and ordinary resumption as separate observability checks. For QUIC, check the provider's HTTP/3 and 0-RTT instrumentation and the transport limits in RFC 9001.

## 5. Authorized loopback lab · observe resumption

<a href="{{ '/assets/labs/tls-resumption-lab.py' | relative_url }}" download="tls-resumption-lab.py">Download the Python loopback lab</a>

Run on an authorized Linux environment with Python 3 and the OpenSSL 3.x command-line tools available on PATH. This script starts a temporary TLS server on `127.0.0.1` and trusts its short-lived test certificate only in the test client. It sends three read-only local requests after handshakes. The server and client use TLS 1.3. The script performs no 0-RTT, replay, production traffic or trust-store changes.

~~~bash
python3 tls-resumption-lab.py
~~~

| Connection | Session offered | Expected OpenSSL result |
| --- | --- | --- |
| 1 · full handshake | None; save the issued session | `New, TLSv1.3`, HTTP 200 |
| 2 · resume | Session from connection 1 | `Reused, TLSv1.3`, HTTP 200 |
| 3 · full control | No saved session passed | `New, TLSv1.3`, HTTP 200 |

The first client reads the server's HTTP response while allowing OpenSSL to process post-handshake tickets. A client that exits just after the handshake may miss a ticket. If the resume check yields `New`, inspect whether the ticket was saved and whether the same TLS server instance was running. A missing ticket, bind failure, hostname verification failure or timeout is an error, not a successful control. The test directory and session file are removed when the script exits normally. Treat exported session files as sensitive.

## 6. Check your reasoning

1. **An OpenSSL client says Reused. Was the request sent early?** There is evidence of a resumed handshake. Confirm early data separately in the terminator and client.
2. **The client offered early data, but the origin received nothing. Where do you look?** Check TLS acceptance, the edge forwarding decision and request path before interpreting the origin's silence.
3. **One request got 425 and its retry got 200. Is that a replay incident?** This is compatible with protocol-defined retry handling. Confirm that the retry was outside early data and examine application processing before assigning a cause or impact.
4. **Two nodes logged the same business operation ID. What establishes impact?** Compare committed effects in the authoritative application audit, including whether deduplication returned an existing result.

Finish when you can reproduce the three local connections and describe the evidence needed to distinguish a PSK offer, a successful resumption, early-data acceptance, and an application action.

## Official references and next reading

Reviewed **2026-11-25**. The primary specifications below cover 2018–2022. The local lab was run with OpenSSL 3.5.9. Server frameworks, CDN and QUIC early-data behavior were reviewed against protocol documents, with no product environment exercised.

- TLS 1.3, PSK and replay properties (August 2018). [RFC 8446 §§2.2–2.3, 4.6.1, 8](https://www.rfc-editor.org/rfc/rfc8446.html)
- Early-Data and 425 (September 2018). [RFC 8470 §5](https://www.rfc-editor.org/rfc/rfc8470.html#section-5)
- QUIC replay considerations (May 2021), HTTP method semantics (June 2022), and TLS best practice (November 2022). [RFC 9001 §9.2](https://www.rfc-editor.org/rfc/rfc9001.html#section-9.2) · [RFC 9110 §9.2](https://www.rfc-editor.org/rfc/rfc9110.html#section-9.2) · [RFC 9325 §§3.4, 3.10](https://www.rfc-editor.org/rfc/rfc9325.html#section-3.4)
- OpenSSL 3.5 loopback commands. [s_client](https://docs.openssl.org/3.5/man1/openssl-s_client/) · [s_server](https://docs.openssl.org/3.5/man1/openssl-s_server/) · [req](https://docs.openssl.org/3.5/man1/openssl-req/)

Previous · [TLS handshake evidence]({{ '/wiki/tls-handshake-evidence/' | relative_url }})  
Next · [QUIC and HTTP/3 evidence]({{ '/wiki/quic-http3-evidence/' | relative_url }}) · [Encrypted Client Hello]({{ '/wiki/tls-ech-evidence/' | relative_url }})
