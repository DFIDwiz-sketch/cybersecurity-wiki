---
title: "Certificate Transparency · Verify Log Evidence and Investigate Unexpected Issuance"
description: "Distinguish a certificate log entry from an SCT, a proof of inclusion and a certificate served by an HTTPS endpoint."
category: network
tags: [PKI, Certificates, TLS, Certificate Transparency, Blue Team, DFIR]
level: Beginner
updated: "2026-11-21"
translation_url: /ko/wiki/certificate-transparency-evidence/
---

**Learning goal.** A monitor alerts on a certificate for a domain your team manages. Find out what the log actually contains, whether the issuance was expected, and what evidence would show that a service presented the certificate.

## 1. Why public issuance needs visibility

**Certificate Transparency** (CT) makes public TLS certificate issuance observable. A certificate authority (CA) can submit a certificate or a **precertificate**, an issuance artifact intended for logging, to a public append-only log. In the common CT v1 embedded-SCT flow, the precertificate is unsuitable for ordinary TLS validation. The CA can put the log's **Signed Certificate Timestamp** (SCT) into the final certificate. An SCT is a signed commitment by the log to incorporate the entry within its **Maximum Merge Delay** (MMD).

The log combines entry hashes into a **Merkle tree**. Its root hash commits to the contents and order for one tree size. A **Signed Tree Head** (STH) authenticates a snapshot under the log's key. A **monitor** reads log entries to look for relevant names or changes. Its index or alert may lag behind the source.

| Evidence | Question it answers | Further evidence to seek |
| --- | --- | --- |
| SCT | Did this log sign a commitment for this entry? | Check the signature, log identity, entry type and time |
| Inclusion proof and authenticated tree head | Is this entry at the specified position in this snapshot? | Validate the log identity, size, root and proof |
| Consistency proof for two authenticated heads | Does the later snapshot preserve the earlier entries in order? | Compare two sizes from the same log. Compare views independently when investigating a split view |
| Endpoint's observed leaf certificate | Which certificate did the service present at the captured time and vantage point? | Retain TLS context, service name and endpoint details. Confirm path, hostname, purpose and revocation separately |

## 2. Follow a normal renewal

A company renews the public certificate for fictional `reports.example`. At 09:00 UTC a CA creates a precertificate and obtains SCTs from applicable logs. Later the monitoring feed sees a precertificate entry, and the approved platform deploys the final leaf to its CDN at 09:30. A TLS observation at 09:40 shows the leaf from one edge. An old leaf from another edge can indicate a rollout still in progress. The SCT timestamp, log or monitor observation time, certificate validity start and deployment time describe different things.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/ct-evidence-en.svg' | relative_url }}" alt="A certificate authority submits a precertificate. The log returns an SCT commitment and later incorporates a leaf. A monitor examines log evidence while a separate TLS observation checks the served certificate.">
  <figcaption>Trace issuance and deployment separately. A precertificate in the log and a leaf observed on the service have different encodings and often different fingerprints.</figcaption>
</figure>

An inclusion proof supplies sibling hashes on the path from a leaf to the root. For four ordered entries A, B, C and D, the proof for B supplies the hash of A and the combined hash of C and D. Hash the entry bytes for B, place A to its left, then place C–D to the right of that parent. Compare the result to the independently authenticated root for tree size four. Leaf hashes use a leading byte `0x00` and parent hashes use `0x01` before the ordered child hashes. These prefixes distinguish the two inputs. In CT, the leaf input is a protocol-defined entry structure, so hashing only a final certificate's DER file does not necessarily give the CT leaf hash.

## 3. Interpret unexpected names and gaps

Unexpected issuance could reflect unauthorized control of the CA account or a domain validation path. It can also come from a planned CDN migration, managed renewal or a newly approved CA. A public log helps expose issuance for review. It neither revokes a certificate nor identifies the operator of a service. Public CT is not a complete inventory of privately trusted enterprise certificates.

| Observation | Useful next check |
| --- | --- |
| Unfamiliar issuer for an owned name | CA and managed-service inventory, order audit, approval and validity window |
| Several alerts for what appears to be one renewal | Log identities, entry type and CA records. One renewal can produce copies across logs, or both precertificate and final-certificate entries |
| SCT exists but an index has no record | Check the particular log, its MMD, the relevant tree head, collection lag and index coverage |
| Log entry for a wildcard | Record the SAN exactly. A wildcard issuance is not evidence that every subdomain uses it |
| Issuer list changed around the event | Preserve historical DNS and CA account records. Current CAA entries can help review future issuance controls but cannot reconstruct prior authorization by themselves |

Chrome checks CT compliance for publicly trusted TLS under its own policy. It considers where the SCTs were delivered, the certificate lifetime, log state and operator diversity. Chrome's published policy notes that only versions before 148 accept SCTs via stapled OCSP for this purpose. Its log policy also allows RFC 6962 logs to reject final-certificate submissions received on or after 1 November 2026. Check the log's actual API and entry type. C2SP static CT exposes signed checkpoints and hash tiles and retains RFC 6962 cryptographic operations. RFC 9162 specifies experimental CT v2 and obsoletes RFC 6962 in the RFC series. That publication status does not identify the protocol deployed by a particular log.

## 4. Collect, classify and respond

1. **Preserve the alert and source.** Record the monitored name, UTC observation, source index, log ID, entry type, SCT time, leaf index or proof when available, and tree size. Save the original entry. Scope monitoring filters to your authorized domain inventory and use DNS label boundaries. A substring hit or a monitor's deduplication key can merge or misclassify names.
2. **Correlate issuance.** Compare the exact SAN, issuer, serial and validity with change records, CA audit and CDN inventory. Preserve any precertificate and final leaf separately. A final-certificate fingerprint identifies the encoded certificate, not the precertificate.
3. **Check serving evidence independently.** On an authorized service, retain the leaf observed with time, service name and endpoint context. Inspect a locally saved PEM leaf using the command below. A matching observation establishes presentation from that vantage point. Compare other managed edges where relevant.
4. **Respond to corroborated unauthorized issuance.** Work with the CA and service owner to preserve the order evidence and arrange revocation and safe replacement as appropriate. Review CA account access and domain validation records. Continue monitoring the domain and validate what affected services are actually presenting.

The following read-only command requires OpenSSL and a locally saved PEM leaf. It displays certificate metadata. Trust chain checks, CT signature verification and live endpoint identity each require their own evidence.

```bash
openssl x509 -in observed-leaf.pem -noout -issuer -serial -dates \
  -sha256 -fingerprint -ext subjectAltName
```

## 5. Offline lab · Verify a four-leaf inclusion proof

Download <a href="{{ '/assets/labs/ct-inclusion-lab.py' | relative_url }}" download>ct-inclusion-lab.py</a> and run `python3 ct-inclusion-lab.py` using Python 3. The bytes are fictional labels. There is no network access or certificate submission. The exercise assumes a trusted root for a fixed tree, computed independently with OpenSSL, and tests proof reconstruction with Python's standard library.

| Variation | Expected observation |
| --- | --- |
| Original B with leaf index 1 and correct siblings | Verified against the known root |
| Change a byte, position or sibling order | Rejected because the reconstructed root differs |
| Remove a sibling or provide a different root | Rejected |
| Claim five entries without changing the fixture | Rejected by the lab's four-entry scope check |

Expect `7 synthetic checks passed.` If the positive case fails after editing, compare the exact bytes, zero-based index, sibling order and fixed root. An arbitrary tree may be uneven, so the lab's fixed two-sibling calculation cannot be applied to a production proof. The lab does not verify an SCT or tree head signature. In a real investigation, authenticate the snapshot under the correct log key and confirm proof metadata before comparing the root. Python tests ran on 3.12, and the OpenSSL command above ran on OpenSSL 3.5.7 with a disposable self-signed certificate. Browser policy and live logs were reviewed in documentation.

## 6. Check your understanding

- **A valid SCT just appeared. Is inclusion already proven?** It establishes a commitment under the log key. Verify an inclusion proof against an authenticated tree head to confirm inclusion in a particular snapshot.
- **An unexpected precertificate is in a public log. Did users see it?** Preserve the entry and verify issuance. Obtain separate endpoint or TLS client evidence for presentation.
- **Two proof roots differ. Does that mean entries were deleted?** Compare sizes and identities first. Append-only growth normally changes the root. Verify a consistency proof for the two snapshots when applicable.
- **Will the same SCTs validate on every client?** Identify the browser or library, applicable policy and log list for the observation.

**Completion.** Record one alert's exact name, source and UTC evidence, the issuance hypothesis and the next check needed to distinguish an approved renewal from unauthorized issuance.

[Previous · Certificate validation]({{ '/wiki/certificate-validation/' | relative_url }}) · [Continue · TLS handshake evidence]({{ '/wiki/tls-handshake-evidence/' | relative_url }})

## Official references

Reviewed 21 November 2026. Protocol scope and vendor policy are tracked separately.

- [RFC 6962 · CT v1, June 2013](https://www.rfc-editor.org/info/rfc6962/) · [RFC 9162 · Experimental CT v2, December 2021](https://www.rfc-editor.org/info/rfc9162/)
- [Chrome · Browser CT policy](https://googlechrome.github.io/CertificateTransparency/ct_policy.html) · [Chrome · CT log operator policy](https://googlechrome.github.io/CertificateTransparency/log_policy.html) · [C2SP · Static CT API v1.1.0](https://c2sp.org/static-ct-api@v1.1.0)
- [CT project · How monitoring fits into the Web PKI](https://certificate.transparency.dev/howctworks/) · [RFC 8659 · CAA, November 2019](https://www.rfc-editor.org/info/rfc8659/)
- [OpenSSL 3.5 · openssl x509 command reference](https://docs.openssl.org/3.5/man1/openssl-x509/)
