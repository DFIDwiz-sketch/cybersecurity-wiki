---
title: "TLS ALPN Evidence · From Offered Protocols to the Selected Protocol"
description: "Locate the negotiated application protocol on each TLS connection and verify five OpenSSL controls on loopback."
category: network
tags: [TLS, ALPN, HTTP/2, HTTP/3, Network Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/tls-alpn-evidence/
---

**Learning path** · [TLS handshake evidence]({{ '/wiki/tls-handshake-evidence/' | relative_url }}) → ALPN evidence → [HTTP/2 streams and 421]({{ '/wiki/http2-connection-reuse-evidence/' | relative_url }}) or [QUIC and HTTP/3]({{ '/wiki/quic-http3-evidence/' | relative_url }}).

## 1. What ALPN decides

**Application-Layer Protocol Negotiation (ALPN)** lets TLS endpoints select the protocol that will use their connection. It helps a shared listener distinguish protocols such as HTTP/1.1 and HTTP/2 on the same port. The client sends ordered protocol identifiers in **ClientHello**. The server selects one from the offered list according to its policy. The client list describes its preferences. The first entry need not be the server's choice.

An **application protocol** defines how the endpoints interpret messages after the handshake. `http/1.1` identifies HTTP/1.1, `h2` identifies HTTP/2 over TLS, and `h3` is the standard identifier used to negotiate HTTP/3 over QUIC. The old `h2c` upgrade token is obsolete in RFC 9113 and is not an ALPN selection for TLS. **SNI** is a requested server name that can influence which listener policy the server uses. Certificate identity, selected ALPN and the application result answer different questions.

## 2. Trace the offer, selection and request

1. **Offer.** Find the ClientHello at the relevant hop. Identify its TLS version offer, requested name where visible, and ALPN list. If the packet capture begins late or is missing fragments, record that limitation. With Encrypted Client Hello (ECH), the visible outer message may differ from the inner ClientHello used by the server. Do not treat the outer list as an authenticated inner offer.
2. **Select.** For ALPN in TLS 1.2, the server's choice is in ServerHello. In TLS 1.3 it is in **EncryptedExtensions**, protected by handshake keys. Unencrypted ClientHello visibility therefore does not imply visibility into the server choice. An endpoint trace can display the message after decryption.
3. **Complete or refuse.** A server participating in ALPN that finds no common offered protocol is required by RFC 7301 to send the fatal alert `no_application_protocol`. When no ALPN was offered or selected, an otherwise valid TLS handshake can complete. The application and its listener policy determine what happens next.
4. **Confirm use.** The selected value applies to that TLS connection. Request logs, HTTP framing or application results establish how a request was handled. A proxy that terminates TLS and opens another connection negotiates independently on the second leg.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/images/tls-alpn-evidence-en.svg' | relative_url }}" alt="Client to edge negotiates h2. Edge to origin makes a separate TLS connection and negotiates http/1.1. Each leg has its own offer, selected value and connection ID." width="540" height="330" style="max-width: 100%; height: auto">
  <figcaption>At a TLS-terminating reverse proxy, compare each leg separately and join request evidence across the proxy.</figcaption>
</figure>

**Fictional normal example.** The browser offers `h2,http/1.1` to the edge, and the edge selects `h2` over TLS 1.3. The edge opens TLS to the origin and selects `http/1.1` with that server. Both certificates validate on their respective legs. The edge and origin access logs show request ID `training-42` and record a 200 response. The values describe two valid negotiations and one forwarded request. Comparing the edge choice with the origin choice alone would suggest a difference without explaining its cause.

## 3. Read the evidence you have

| Observation | What it supports | What to check next |
|---|---|---|
| ClientHello includes `h2` | The captured handshake message offered `h2`. | Identify the leg and look for selected ALPN at an endpoint. |
| Complete TLS 1.2 capture shows `h2` in ServerHello | The server chose `h2` on that connection. | Check handshake completion, certificate validation and request telemetry separately. |
| Passive TLS 1.3 trace shows no selected value | The negotiation may be encrypted or outside the observation window. | Check the endpoint or termination log before concluding it selected nothing. |
| A verified endpoint records no ALPN | This handshake finished without selecting an ALPN identifier. | Check omitted extensions, listener settings and the application's actual default. |
| Endpoint reports `no_application_protocol` | That handshake failed at application protocol negotiation. | Compare the offered list and the policy on that listener, host and deployment revision. |
| One proxy leg uses `h2`, another uses `http/1.1` | The legs negotiated different protocols. | Correlate the same request across the proxy before calling it an unexpected downgrade. |

An unexpected listener policy, a wrong virtual host, or an unapproved TLS termination change can remove expected protocol support. A routine proxy configuration or a different client build can produce the same observation. Record what changed and which protocol the endpoint actually selected. Initiate incident attribution only with corroborating change and request evidence. Port 443, a fingerprint, or one offer cannot establish compromise.

## 4. Collect, detect and respond

- **Collect.** Save UTC, interface and capture point, transport tuple, TLS version, requested name when observable, offered and selected ALPN as separate fields, certificate verification and handshake outcome. On an edge, record both leg identifiers and any end-to-end request ID. Preserve scoped logs and packet copies under the approved evidence process.
- **Detect.** Baseline by service, listener, deployment and client cohort. Look for new negotiation failures or unexpected selection changes alongside application errors. A missing selected field from a passive TLS 1.3 sensor is a visibility limitation. Compare the same leg and the same class of observer before comparing counts.
- **Respond.** Start at the TLS endpoint that recorded the failure. Compare the deployed listener and proxy protocols with the approved baseline and the actual offer. Once corrected, repeat a controlled handshake and then an application-level request on the relevant leg. When a proxy is involved, verify the upstream result as well.

In Wireshark, `tls.handshake.extensions_alpn_str` finds frames whose dissected TLS messages expose that field. Use an authorized capture with enough bytes and reassembly support. Open the TLS handshake tree to identify ClientHello, ServerHello or EncryptedExtensions before labeling the value. An ordinary passive TLS 1.3 capture cannot reveal the protected selection without an authorized source of handshake secrets. This exercise uses endpoint traces and requires no capture decryption or key export.

## 5. Authorized loopback exercise

Use Python 3 and OpenSSL 3.x in an environment you own or may use. The script binds only to `127.0.0.1` on a temporary port. Its client validates the hostname and trusts only the temporary test certificate supplied for this run. The test sends no HTTP requests, even when `h2` is selected. The temporary private key is removed on normal exit.

- <a href="{{ '/assets/downloads/tls-alpn-evidence/alpn_loopback.py' | relative_url }}" download>Download the OpenSSL loopback exercise</a>

~~~sh
python3 alpn_loopback.py
python3 alpn_loopback.py --trace
~~~

| Test | Expected observation |
|---|---|
| TLS 1.3, client offers `http/1.1,h2` | This lab's OpenSSL server selects `h2`, its preferred common value. |
| TLS 1.3, client offers only `http/1.1` | Selection is `http/1.1`. |
| TLS 1.3, client omits ALPN | The authenticated handshake completes with no selected ALPN. |
| TLS 1.3, disjoint offers | The client receives an alert for no application protocol. |
| TLS 1.2, both offers | Selection is `h2`. With `--trace`, the selection is in ServerHello. |

Both runs should report `5/5 ALPN controls passed.` The optional trace uses OpenSSL's endpoint decoder. It shows ClientHello for the offer, ServerHello for the TLS 1.2 selection and EncryptedExtensions for the TLS 1.3 selection. If the CLI is missing, check PATH. If binding fails, check loopback permission and try a fresh port by rerunning. If only trace mode fails, compare the installed OpenSSL build and trace output support. A verification failure is a separate result. Preserve it rather than disabling name or trust validation.

**Execution check, 2026-11-27.** OpenSSL 3.5.9 and Python 3.12.14 passed all five controls in both modes. Wireshark fields, ECH, proxy behavior and HTTP/3 were reviewed in documentation. The local exercise neither tests a production endpoint nor sends HTTP/2 or QUIC traffic.

## 6. Check your reasoning

- **Does offering `h2` establish HTTP/2 use?** It supports an offer. Find the server selection and application evidence.
- **Why does a passive TLS 1.3 capture often hide the server choice?** The selection is sent in protected EncryptedExtensions. Use endpoint evidence or authorized decryption.
- **Can one edge request use different protocols on different legs?** Yes. Each TLS connection negotiates independently. Join request identifiers and times to validate forwarding.

Finish when you can reproduce the five cases, show both selection locations with the endpoint trace, and name the evidence needed to verify actual protocol use for a specific request.

## Official references

Reviewed **2026-11-27**. RFC 7301 describes ALPN's original TLS framing. RFC 9846 (July 2026) supersedes the original TLS 1.3 RFC 8446 (2018) and defines the current placement. The TLS 1.2 example compares older handshake framing, not a recommendation to change version policy. The HTTP, ECH and product references below describe current interpretation for the covered versions.

- IETF · [RFC 7301, ALPN (2014)](https://www.rfc-editor.org/rfc/rfc7301.html), [RFC 9846, TLS 1.3 (2026)](https://www.rfc-editor.org/rfc/rfc9846.html), [RFC 9849, ECH (2026)](https://datatracker.ietf.org/doc/rfc9849/).
- IETF HTTP · [RFC 9113, HTTP/2 (2022)](https://www.rfc-editor.org/rfc/rfc9113.html), [RFC 9114, HTTP/3 (2022)](https://www.rfc-editor.org/rfc/rfc9114.html).
- OpenSSL 3.5 · [s_client](https://docs.openssl.org/3.5/man1/openssl-s_client/), [s_server](https://docs.openssl.org/3.5/man1/openssl-s_server/).
- [Wireshark TLS display-filter reference](https://www.wireshark.org/docs/dfref/t/tls.html).

[Compare TLS group selection with ALPN on each connection leg]({{ '/wiki/tls-hybrid-key-agreement-evidence/' | relative_url }})
