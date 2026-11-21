---
title: "TLS Handshake Evidence · From Connection to HTTP"
description: "Distinguish network and endpoint TLS 1.3 evidence with four offline verification cases."
category: network
tags: [TLS, Network Security, Zeek, Blue Team, DFIR, OpenSSL]
level: Beginner
updated: "2026-11-20"
translation_url: /ko/wiki/tls-handshake-evidence/
---

**Learning goal.** Read TCP connectivity, TLS authentication and HTTP outcomes as separate stages. Use sensor metadata to narrow a case, then locate evidence for verification errors and application responses.

## 1. Break down an HTTPS request

A browser reaching a health endpoint needs transport, a secure channel and an application exchange. In HTTPS over TCP, peers establish the connection first. TLS negotiates cryptographic parameters and keys and verifies the server identity. HTTP requests and responses then travel through the channel. The illustration simplifies a full certificate-authenticated TLS 1.3 handshake. Resumption, PSKs, 0-RTT and client authentication add other paths.

![TCP connection · transport → ClientHello / ServerHello · negotiation → Protected TLS 1.3 · server authentication → HTTP request and response · app result]({{ '/assets/diagrams/tls-handshake-en.svg' | relative_url }})

| Stage | Question | Representative evidence |
| --- | --- | --- |
| TCP | Was a transport connection established? | SYN, SYN-ACK, ACK and connection state |
| TLS | Did the peers negotiate protection and verify identity? | Negotiation and client validation records |
| HTTP | Which request and response occurred? | Request ID, route and status at the TLS terminator |
| Application login | Which user session did the app authorize? | Application or identity provider authentication and session records |

HTTP/3 runs over QUIC, which integrates TLS and does not use a TCP three-way handshake. UDP port 443 by itself does not establish HTTP/3 or a successful handshake.

## 2. Follow ClientHello through application data

1. **ClientHello.** The client offers versions, key agreement values, cryptographic settings and extensions. Server Name Indication (SNI) tells the server a requested name for virtual-host selection. Application-Layer Protocol Negotiation (ALPN) can offer protocols such as h2 for HTTP/2.
2. **ServerHello.** The server selects settings including the version and cipher suite. In an ordinary full TLS 1.3 handshake, the following EncryptedExtensions, certificate messages and Finished are protected with handshake keys. The client evaluates the certificate and signature under its trust and name policy.
3. **Application data.** The peers exchange HTTP data through the established protection. One TLS connection can carry several HTTP requests. With a terminating proxy, track client-to-proxy and proxy-to-app connections separately.

SNI is a requested name. A certificate SAN is a name asserted by the certificate. HTTP Host or :authority names the application target. Preserve each where available. Observing SNI alone does not establish the certificate chosen or whether the app handled a request.

## 3. Establish what a passive sensor could see

| Information | Typical passive capture limits | Corroboration |
| --- | --- | --- |
| Addresses, ports, time and direction | NAT, proxies, packet loss and mirror location matter | Firewall and connection records |
| Offered TLS versions and SNI | Initial packets may be missing. ECH can protect the inner name | Sensor, client and authorized terminator |
| Negotiated TLS version and cipher suite | Depends on observing and parsing ServerHello | TLS sensor or endpoint records |
| TLS 1.3 server certificate and selected ALPN | Relevant messages in a full handshake are encrypted | Endpoint verification or termination records |
| URL path, headers and cookies | Plaintext is unavailable on the protected segment | Authorized proxy and application records |

An older full TLS 1.2 capture may show plaintext certificate messages. Apply the TLS 1.3 visibility model to TLS 1.3. RFC 9846, published July 2026, supersedes RFC 8446 as the TLS 1.3 specification. ECH, defined in RFC 9849 in March 2026, encrypts the inner ClientHello while leaving an outer ClientHello visible. A visible outer name may differ from the service name. An ECH extension or absent SNI alone does not establish ECH acceptance or an attack.

Zeek writes TLS metadata under **ssl.log**. Fields such as version, server_name and established depend on the analyzer and observed traffic. Treat established as a sensor observation. Confirm client name and trust decisions or user login using independent records. Check installed behavior against the product documentation.

## 4. Compare routine failure and security hypotheses

| Observation | Ordinary explanation | Evidence to gather |
| --- | --- | --- |
| TCP connects, TLS verification fails | Wrong target name, missing private CA or expiry | Client error, hostname, certificate path and change records |
| TLS establishes, HTTP 404 follows | Mistyped route, routing or application policy | Terminator and app request IDs, route and responding layer |
| New certificate or trust path | Renewal, approved proxy or migration | Certificate, issuer, target and change approval |
| SNI missing or a different name observed | Capture gap, ECH, proxy or client behavior | Capture placement, handshake and endpoint logs |

For unexpected redirection or trust changes, check approved proxy and administrative changes. Attribution to interception or compromise requires corroboration. Record UTC, sensor position, addresses and ports, client error, request ID and both proxy legs. Use one ordinary authorized test to verify field coverage. Correct the underlying certificate verification failure, then retest.

## 5. Run the offline TLS exercise

[tls-handshake-evidence.py]({{ '/assets/labs/tls-handshake-evidence.py' | relative_url }})

Use Python 3 linked to an SSL library supporting TLS 1.3 and ALPN, plus an OpenSSL 3.x executable. The script creates a disposable certificate and key and explicitly trusts the certificate in a dedicated client. Python MemoryBIO passes **real TLS records in memory** and exchanges HTTP messages. It uses no TCP sockets, external destinations or operating-system trust changes. The temporary private key is removed on normal exit.

~~~bash
python3 tls-handshake-evidence.py
~~~

| Test | Expected outcome | Interpretation |
| --- | --- | --- |
| Correct name and trust, /health | TLSv1.3, http/1.1, 200 OK | Application response after authenticated TLS |
| Same TLS configuration, /missing | TLSv1.3, http/1.1, 404 Not Found | Different application result after TLS success |
| Wrong name | Hostname mismatch | Client rejects server name |
| Test certificate absent from trust store | self-signed certificate | Client rejects trust path |

Expect `PASS: two authenticated HTTP exchanges and two TLS verification failures`. If the CLI cannot be found, check the OpenSSL installation and PATH. For version errors, inspect the CLI and the library used by Python separately. Publication tested actual TLS processing in memory. HTTP statuses are scripted examples. Zeek, TCP, QUIC and ECH capture require separate testing.

## 6. Check your understanding

- **A TCP connection succeeds and certificate validation fails. Did HTTP reply?** Record transport and TLS evidence separately. Look for HTTP evidence at the endpoint or terminator.
- **Can successful TLS be followed by a 404?** Yes. The application can return 404 over a valid protected channel.
- **Does visible SNI prove TLS authentication?** It shows a proposed name. Check the certificate and client verification outcome.

Finish by identifying the proven stage and one piece of operational evidence you would still collect for each of the four lab cases.

[Previous · Certificate validation]({{ '/wiki/certificate-validation/' | relative_url }}) · [Next · HTTP log investigation]({{ '/wiki/http-evidence/' | relative_url }})

## Official references

Reviewed 20 November 2026. Match standards and analyzer behavior to the actual deployment.

- [IETF RFC 9846 · TLS 1.3, July 2026](https://datatracker.ietf.org/doc/html/rfc9846)
- [IETF RFC 9849 · Encrypted Client Hello, March 2026](https://datatracker.ietf.org/doc/html/rfc9849)
- [IETF RFC 9001 · TLS with QUIC, May 2021](https://www.rfc-editor.org/rfc/rfc9001.html)
- [Zeek · ssl.log](https://docs.zeek.org/en/current/reference/logs/ssl.html)
- [Python 3.12 · SSL and Memory BIO](https://docs.python.org/3.12/library/ssl.html)
- [OpenSSL 3.5 · openssl req](https://docs.openssl.org/3.5/man1/openssl-req/)

## Connect a TLS Observation to Certificate Transparency

[Compare the observed leaf with independently collected issuance evidence.]({{ '/wiki/certificate-transparency-evidence/' | relative_url }})

## Client authentication next

[Mutual TLS (mTLS)]({{ '/wiki/mtls-client-identity-evidence/' | relative_url }}) · Follow client authentication through TLS termination and application authorization, then compare six loopback outcomes.

## Follow QUIC and HTTP/3 Evidence

[QUIC and HTTP/3 request evidence]({{ '/wiki/quic-http3-evidence/' | relative_url }}) · Compare discovery, QUIC startup and request protocols on each proxy hop.
