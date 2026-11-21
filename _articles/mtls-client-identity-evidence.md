---
title: "Mutual TLS (mTLS) · Client Identity and Authorization Evidence"
description: "Follow both certificate checks, distinguish rejected handshakes from denied actions, and investigate six loopback TLS 1.3 cases."
category: network
tags: [TLS, mTLS, PKI, Network Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-21"
translation_url: /ko/wiki/mtls-client-identity-evidence/
---

**Learning goal.** Given one failed connection and one denied request, identify which side made each decision, what it verified, and which evidence to collect next. Start with [TLS handshake evidence]({{ '/wiki/tls-handshake-evidence/' | relative_url }}) and use [certificate validation]({{ '/wiki/certificate-validation/' | relative_url }}) for the details of chains, names and key usage.

## 1. Why authenticate the client at the TLS layer?

Imagine a reporting service that accepts automated status requests from several jobs. HTTPS lets a job verify that it reached the correct service. The service also needs to know which job it is talking to. With **mutual TLS (mTLS)**, both sides authenticate the peer during TLS. In this chapter each presents an X.509 certificate and proves possession of the corresponding private key. The service can then use that verified client identity as an input to its permission check.

A **certificate authority (CA)** signs certificates. A **trust anchor** is where a verifier starts its trust decision, often a configured root CA. A **leaf certificate** belongs to the endpoint. **Subject Alternative Name (SAN)** carries typed identifiers such as a DNS name or a URI. **Extended Key Usage (EKU)** describes allowed usages when present. A **principal** is the identity an application uses to make permission decisions, such as the job named `reporter`.

| Decision | Who makes it and what they check | What success tells you |
| --- | --- | --- |
| Server authentication | Client checks the chain, validity, permitted usage, expected service identity and proof of key possession | The peer authenticated as the configured service under the client's trust policy |
| Client authentication | TLS terminator checks the client chain, validity, permitted usage and proof of key possession under its configured policy | The peer authenticated with an acceptable client certificate at this terminator |
| Application authorization | Application maps the verified client identity to a principal, then checks the requested action against policy | Policy permitted this principal to attempt this action. The application outcome still shows whether it completed |

A service certificate typically uses a DNS SAN that matches the intended service name. This example maps a client URI SAN to a principal by explicit service policy. RFC 9525 covers service identity verification by clients. Client identity mapping comes from your application's policy.

## 2. What happens in a full TLS 1.3 handshake?

1. The client sends **ClientHello** and the server responds with **ServerHello**. For this example the peers negotiate TLS 1.3 and derive handshake keys using their key agreement. The server then sends EncryptedExtensions and a **CertificateRequest** asking for client authentication. The request can communicate acceptable signature algorithms and can list CAs to help the client select a credential.
2. The server sends its **Certificate**, **CertificateVerify** and **Finished**. The client checks the server certificate under its trust and service-name policy. CertificateVerify is a signature over the handshake transcript in its role-specific context. Finished authenticates the transcript using a key derived from the handshake secrets.
3. The client responds with its Certificate, CertificateVerify and Finished. If it has no suitable certificate, it sends an empty certificate list and omits CertificateVerify. With client certificates required, the server rejects that handshake. A server configured to request a certificate optionally can instead allow an unauthenticated client.
4. Application traffic is protected with symmetric TLS traffic keys. For the service in this chapter, an operation is evaluated after the TLS terminator has authenticated the client and the application has resolved its principal. Both private keys stay at their respective endpoints or in the signing facilities they use.

<figure>
  <img src="{{ '/assets/diagrams/mtls-client-identity-en.svg' | relative_url }}" width="420" height="376" alt="In a full TLS 1.3 handshake the client checks the server identity, the TLS terminator checks the client certificate and key proof, and the application evaluates permissions for the verified principal.">
  <figcaption>Figure 1. Where to find the three decisions. A TLS rejection ends this path before the application can authorize a request.</figcaption>
</figure>

The certificate messages in this full handshake are encrypted after ServerHello. A passive capture may show a connection, negotiation metadata or termination timing. The plaintext SAN, verification outcome and application policy decision come from the relevant endpoint records unless the capture can be lawfully decrypted. With resumption or post-handshake client authentication, check the handshake mode and authentication state before interpreting the absence of a certificate exchange.

## 3. Read a normal request from both sides

Suppose the job expects `reports.lab.example`. The TLS endpoint presents a server certificate with DNS SAN `reports.lab.example` from the Service CA, which the job trusts. The job presents a client certificate with URI SAN `urn:wiki:lab:reporter` from a separately configured Client CA. After verification the application maps that URI to `reporter`, permits the read-only status operation and records completion.

These rows are **synthetic**, with simplified field names. In this service, the gateway creates a connection ID, then assigns a request ID only after it accepts an application request.

| Source and UTC time | Example record | Conclusion |
| --- | --- | --- |
| TLS gateway, 10:00:00.045 | `conn=t42 version=TLS1.3 client_mode=required verify=pass client_id=reporter issuer=client-ca serial=01` | Gateway authenticated this certificate under its active policy |
| Application, 10:00:00.060 | `request=r17 conn=t42 principal=reporter action=status decision=allow result=completed` | The mapped principal was authorized and the operation completed |
| Application, 10:00:02.060 | `request=r18 conn=t43 principal=observer action=status decision=deny` | The application denied a request. Look up `t43` at the gateway to confirm the client verification result |

A reused connection can carry multiple requests. Correlate the request ID and its recorded connection or gateway trace ID. Where IDs are absent, use service instance, time window, known clock drift and available connection fields, and record how certain the match is. A public IP can be shared by many clients or represent a proxy.

## 4. When a trusted connection can still be risky

- **A private key is compromised.** A peer that controls an acceptable cert and usable private key can authenticate as that credential while it remains accepted. Review issuance, key custody and activity on the originating workload. Scope the affected issuer, serial or fingerprint and service, request containment and replacement through the certificate owner, and confirm that each relevant terminator applies your revocation or credential-removal policy. Check active connections and session paths as part of containment.
- **The trusted CA scope is too broad.** A chain that validates only answers the configured trust policy. A dedicated client CA or appropriately scoped trust, explicit SAN mapping, and per-operation authorization reduce the chance that a certificate accepted for TLS earns privileges it should not have. Observe new principals or a certificate accepted across an unexpected service boundary, then compare with deployment and inventory records.
- **The proxy-to-app path has a separate trust decision.** When a gateway ends mTLS, the origin's TLS peer on the next hop is the gateway. The origin can use verified identity metadata only across a controlled path. With the optional RFC 9440 `Client-Cert` and `Client-Cert-Chain` HTTP fields, the terminating proxy removes or replaces incoming copies before forwarding. Restrict the origin to trusted proxy paths and authenticate that hop, or use a platform-supported equivalent. Treat caller-supplied values as untrusted. Review direct-origin exposure, proxy routes and gateway identity logging together.

## 5. Collect evidence and triage a failure

**At deployment:** Identify the component that terminates TLS and the owner of each CA bundle. Confirm TLS handshake failures and successes relevant to this service are enabled and reach the collector, along with app authorization and credential inventory. Capture UTC time, emitting component and side, connection or trace ID where created, policy/config revision, version and failure stage. Record the minimal needed verified SAN or principal, issuer plus serial or fingerprint where available, service and decision. Treat identifiers as sensitive according to your access and retention policy. Private keys, raw secrets and session key material do not belong in general-purpose logs.

| Observed pattern | First check | Response based on corroboration |
| --- | --- | --- |
| Gateway reports missing client cert | Confirm client credential selection, key availability and required/optional listener mode | Restore expected client configuration. Use a known-good job and a no-cert control to retest |
| Gateway rejects client chain or purpose | Compare active client trust bundle, issuer chain, current time, EKU and rollout records | Repair the specific issuance, chain or policy mismatch. Avoid loosening trust to clear an alert |
| Client reports server name mismatch | Compare intended service name, target, DNS SAN and deployed listener/certificate | Correct name or deployment. Keep verification enabled |
| Client verification passes but app denies | Match connection and request evidence, then compare principal mapping, action and policy version | Investigate authorization or expected role limits. Rerun both permitted and denied cases |
| Failure spike after a rollout | Group by verifier, reason, service and policy revision. From the same collection point compare to connection volume and unaffected peers | Confirm collector health and rollout timing before assuming misuse. Preserve a few representative failure and success records |

Handshake errors can occur before HTTP exists. An empty application access log alone leaves several possibilities, including early TLS rejection, log loss, sampling and querying the wrong service. A later client-side alert can reflect a rejection made by the server. Start with the verifier that made the decision and compare nearby known-good evidence.

## 6. Authorized lab · Six loopback connections

Download and inspect the [Python lab]({{ '/assets/labs/mtls-client-identity-lab.py' | relative_url }}) before running. Use a machine or sandbox you control with Python 3.10 or later linked to a TLS 1.3-capable library and OpenSSL 3.x on `PATH`. The standard-library program uses only `127.0.0.1` and OS-assigned ports. It generates ephemeral CAs, certificates and keys in a temporary directory and removes them on normal exit. The application sends a single `status` line and reads a reply over TLS. It uses no HTTP, proxy, SIEM or cloud service.

```sh
python3 mtls-client-identity-lab.py
```

The service trusts only the lab Client CA. The client trusts only the lab Service CA and expects the DNS SAN `localhost`. The app allows one exact URI SAN for its lab principal. Compare one change at a time with the valid reporter case.

| Case | Expected decision | What the run showed |
| --- | --- | --- |
| Trusted reporter | TLS works and app allows | `ALLOWED` on both sides |
| Trusted observer | TLS works and app denies | `DENIED` on both sides |
| Missing client certificate | Server-side TLS rejection | Missing peer certificate |
| Client from untrusted CA with reporter SAN | Server-side TLS rejection | Issuer chain could not reach a trusted CA |
| Trusted client with server-only EKU | Server-side TLS rejection | Unsuitable certificate purpose |
| Client expects `wrong.lab.example` while connecting to the same socket | Client rejects service identity | Client hostname mismatch. Server sees a TLS alert |

**Execution record.** On 2026-11-21, all six outcomes matched using Python 3.12.14 linked to OpenSSL 3.5.8, with OpenSSL CLI 3.5.7. The result names and certificate details are local lab output. Literal alert strings can vary with the library. In the server rejection cases the client can learn about failure on its first I/O after the local handshake call. Read both columns. Production proxy and logging behavior was reviewed against documentation.

**Troubleshooting.** If `openssl` is missing, check `openssl version` and `PATH`. If you see a socket error or timeout, check whether the sandbox allows local listeners and loopback traffic. For unexpected validation failures, compare platform time, the printed library versions, direction of verification and the first case that failed. The script exits with an error if a case differs from the expected decision. Do not import the test CAs into a system trust store.

## 7. Check your reasoning

1. **The observer case reaches `DENIED`. Did client authentication fail?** No. The application could read the TLS request and evaluate the verified observer identity. The status operation was outside the lab permission.
2. **A packet capture shows ServerHello followed by encrypted traffic. Can you read the client SAN from those packets?** In this full TLS 1.3 flow, certificate messages are encrypted. Look for the verified identity at the TLS terminator and join it to the request record.
3. **Why is a copied reporter SAN from a different CA rejected in this lab?** The string is considered for authorization only after authentication. The server trusts the lab Client CA, so the other chain fails verification first.
4. **A client reports hostname mismatch and the gateway's HTTP log is empty. Where do you start?** Record the client-side verification result and compare the intended service name with the deployed certificate and listener. The TLS failure can stop the request before any HTTP log entry.

You have completed the chapter when you can reproduce all six cases, label the deciding side and stage for each, and name the record you would use to tell whether a real action completed. Continue with [certificate validation]({{ '/wiki/certificate-validation/' | relative_url }}) for chain, EKU and revocation details, or return to [TLS handshake evidence]({{ '/wiki/tls-handshake-evidence/' | relative_url }}) to compare what sensors can observe.

## Official references

Reviewed 2026-11-21. The dates and versions identify the source material.

- [RFC 9846 §§ 4.4.2, 4.5 and 4.7.2 · TLS 1.3](https://www.rfc-editor.org/info/rfc9846/), July 2026, superseding the 2018 RFC 8446 and covering certificate requests, authentication messages and post-handshake authentication.
- [RFC 5280 §§ 4.2 and 6 · Internet X.509 PKI](https://www.rfc-editor.org/rfc/rfc5280.html), May 2008, covering certificate extensions and path validation.
- [RFC 9525 · Service Identity in TLS](https://www.rfc-editor.org/rfc/rfc9525.html), November 2023, covering reference identifiers and service identity checks.
- [RFC 9440 · Client-Cert HTTP Header Field](https://www.rfc-editor.org/rfc/rfc9440.html), July 2023, informational guidance for sending certificate information from a TLS-terminating reverse proxy.
- [Python 3.12 `ssl`](https://docs.python.org/3.12/library/ssl.html), and OpenSSL 3.5 [`openssl req`](https://docs.openssl.org/3.5/man1/openssl-req/) and [`openssl x509`](https://docs.openssl.org/3.5/man1/openssl-x509/), covering the lab APIs and commands.
