---
title: "Certificate Revocation · Follow the CRL to the Verifier"
description: "Read signed certificate status, distinguish revocation from missing or stale evidence, and reproduce six OpenSSL controls offline."
category: network
tags: [PKI, Certificates, TLS, OpenSSL, Blue Team, DFIR]
level: Beginner
updated: "2026-11-21"
translation_url: /ko/wiki/certificate-revocation-evidence/
---

**Learning goal.** When the CA says a certificate was revoked, find out whether the relevant client or gateway had the evidence needed to reject it. This chapter extends [certificate validation]({{ '/wiki/certificate-validation/' | relative_url }}), whose lab checks the chain and service name without examining revocation.

## 1. Why expiration and revocation have different jobs

**Expiration** comes from the validity interval signed into the certificate. **Revocation** distributes an issuer-side status decision before that end date, for example after a confirmed private-key compromise. A certificate is a signed binding between a public key and an identity. Revocation does not erase the issued certificate or make a compromised private key unusable. The relying party, such as a client validating a TLS server or a gateway validating an mTLS client, has to apply its policy to the status evidence it has.

Use the issuer and certificate serial together. A serial is assigned within an issuer's scope. A SHA-256 certificate fingerprint identifies the actual certificate bytes for your evidence notes. The same name can appear in more than one certificate and key. Track key replacement and certificate replacement separately.

| Source or check | What it answers | Common limit |
| --- | --- | --- |
| Certificate path, name, purpose and validity | Can this certificate satisfy these validation checks? | Passing those checks alone leaves revocation open |
| **CRL**, certificate revocation list | Which certificates did the authorized signer list in this scope and edition? | The list can be stale, partitioned or intended for another issuer or reason scope |
| **OCSP**, Online Certificate Status Protocol | What status did an authorized responder sign for the specific certificate ID? | Status, response errors and freshness are separate. The response neither validates the TLS service name nor proves issuance in every profile |
| Relying-party result | What did this consumer do using its configured validation and status sources? | Other consumers, connection modes and times can give different results |

## 2. Follow a normal revocation through four stages

Consider a **fictional** reporting service. Its CA records revocation for issuer I and serial 1000 at 09:06 UTC after the service owner confirms a compromised key. The CA issues CRL 74 at 09:08, with the next update due by 10:08. The CRL covers this leaf and includes serial 1000. At 09:12 an approved gateway obtains that CRL, validates its signature, scope and time, and rejects a new connection presenting the leaf under its enforced policy. A different gateway still using CRL 73 may make a different decision. A CRL publication timestamp alone never establishes gateway enforcement.

<figure style="margin-inline:0">
  <img src="{{ '/assets/diagrams/certificate-revocation-en.svg' | relative_url }}" width="400" height="396" alt="The CA records a revocation by issuer and serial and publishes signed status. The relying party obtains and verifies it and applies its local policy.">
  <figcaption>Figure 1. Record the time and evidence at each stage. Publication and client enforcement are separate observations.</figcaption>
</figure>

1. **Confirm scope.** Match the certificate serial and issuer, the valid signing chain for the CRL and the relevant distribution point or scope. CRLs can cover only certain certificate kinds or reasons. Some deployments use a base CRL plus delta CRLs. In that case identify the applicable pair and updates before interpreting absence.
2. **Check time.** CRL `thisUpdate` is its issue time. `nextUpdate` is the latest time by which a newer CRL is due under the RFC 5280 profile. OpenSSL's printed `lastUpdate` is the CRL's `thisUpdate` field. Preserve actual fetch time and the verifier's clock separately. A list retrieved after an incident may not be the list used during it.
3. **Read the entry.** Match the issuer and certificate serial in the applicable CRL. The entry can record a revocation date and reason. That date is not evidence of the first misuse or the time the verifier learned the status.
4. **Confirm the decision.** Identify the product, version, policy, cache source, certificate presented and result on a fresh connection. Existing sessions and resumed sessions need their own evaluation.

## 3. Separate revoked, unavailable and unknown

| Observation | What to record | What to verify next |
| --- | --- | --- |
| Applicable, current CRL lists the leaf | Issuer, serial, CRL number when present, signature and time window | Did the consumer actually have and enforce this CRL? |
| Serial absent from the CRL inspected | Document its issuer, scope, time and completeness | The absence supports only the applicable status check. It does not cover a different partition, an unexamined delta, or other certificate validation |
| Required list unavailable or stale | Exact error, lookup path and verifier clock | Distinguish an enforcement failure from a revoked result. Check distribution, caches and the configured fail behavior |
| OCSP `unknown` | Verified response for the requested certificate ID, if present | The responder did not establish status. An HTTP or protocol error is a different observation |
| No revocation check | Product settings and collected evidence | A successful chain check leaves revocation status untested |

OCSP `good`, `revoked` and `unknown` are signed certificate status values. Verify that the signer is authorized, the certificate ID matches, and the times fit the policy. `thisUpdate` is when the status was known. `producedAt` is when the response was signed, and `nextUpdate`, when present, indicates when newer information is due. Some profiles require it. **Stapling** lets a TLS peer deliver an OCSP response during the handshake. Presence of a staple leaves signature, applicability, freshness and final verification to the consumer.

Provider behavior varies. Let's Encrypt turned off its OCSP service on **2025-08-06** and now publishes revocation information through CRLs. Mozilla announced production use of CRLite in Firefox 142. These public Web PKI examples are scoped to those providers. For an enterprise CA, browser, or TLS gateway, consult the actual product release and applied policy. A certificate's CRL Distribution Point or Authority Information Access URL advertises a location. It does not show that a consumer contacted it.

## 4. Investigate and respond

Collect the exact leaf and intermediate certificates if available, their issuer/serial and fingerprints, service name, UTC timestamp and clock uncertainty, validator version, policy and error, and relevant connection mode. Preserve the status artifact and hash, its metadata, signed scope and verifier/cache observation. Use authorized CA records to match publication history. Avoid transmitting internal inventory details to unrelated responders.

| Signal | Compare before attributing | Response |
| --- | --- | --- |
| Same revoked leaf still accepted on a new connection | Confirm the observed peer and issuer/serial, consumer policy, list edition and cache update, and whether the check ran | Coordinate key and certificate replacement across terminators. Verify fresh handshakes at affected consumers under enforced policy |
| Many connections fail after a CRL time boundary | Compare validator clocks, list freshness, issuer scope and distribution health | Restore trusted status delivery and retest. Preserve the original errors and lists |
| Successful use of a certificate linked to an unexpected key | Check platform and CA issuance records, independent endpoint evidence, status and key custody | Scope affected consumers and sessions, and coordinate containment with the CA and service owners |

A stolen private key can still satisfy a TLS proof while the certificate remains locally acceptable. Authorized rotations, delayed distribution and stale caches can explain mixed results without demonstrating misuse. Treat a revocation incident as a sequence of actions across systems. Reissuing with the same compromised key fails to remove that risk. Revocation also cannot retroactively erase traffic or close already-established sessions by itself. See [mTLS client identity]({{ '/wiki/mtls-client-identity-evidence/' | relative_url }}) for client-authentication and gateway evidence.

## 5. Offline lab · Six actual OpenSSL checks

Download the <a href="{{ '/assets/labs/certificate-revocation-lab.py' | relative_url }}" download="certificate-revocation-lab.py">Python lab</a>. Use a host or sandbox you control, with Python 3.10 or later and OpenSSL 3.x on PATH. The script builds one disposable CA, two TLS leaves and two signed CRLs in a temporary directory. It passes only the test CA to verification, with no network requests or system trust changes. It deletes the generated material on normal exit. The sample key-compromise reason is a lab control, with no actual compromise.

```sh
python3 certificate-revocation-lab.py
```

| Control | Actual OpenSSL result and meaning |
| --- | --- |
| Service leaf with the fresh list before revocation | `OK`. That CRL does not list the service |
| Same leaf after revocation, chain/name checks alone | `OK`. Revocation inputs were not enabled |
| Same leaf with the new, applicable CRL | `certificate revoked` |
| CRL required but absent | `unable to get certificate CRL`, a different failure |
| Unrevoked sibling with the list evaluated two days ahead | `CRL has expired`. The list lasts one day and the leaf remains valid |
| Same-issuer, different-serial sibling with the current list | `OK`. Only the selected leaf was revoked |

The script uses `openssl verify -crl_check -CRLfile` for leaf revocation, and `-attime` for the future-time control without changing the system clock. `-crl_check_all` extends checks along the chain and can require additional inputs. The script reports issuer, leaf serial, CRL time window and number. Separate list editions by CRL number even if their timestamps round to the same second.

On 2026-11-21, Python 3.12.14 and OpenSSL 3.5.7 produced `6/6 CRL controls matched.` The CRLs and verification results are real outputs generated from disposable lab credentials. The service timeline is fictional. OCSP, browser status engines and production TLS policies were reviewed in documentation. If the script fails, verify the OpenSSL version and PATH, writable temporary storage, platform clock and first failed control. The test exits with an error when the expected outcome differs.

## 6. Check your reasoning

1. **Does an OpenSSL `OK` without CRL options conflict with a revoked result?** The two runs applied different checks. The lab records the exact policy and inputs for each.
2. **Can a newer CRL for a different partition clear the original leaf?** No. Verify issuer, scope, signature, coverage and time first.
3. **A client has a CRL error and the leaf remains within its validity interval. What do you query next?** Preserve the error and check the expected status artifact, clock and retrieval path. Certificate lifetime and CRL lifetime are separate.
4. **What shows that a specific gateway enforced the revocation?** The matching leaf and status artifact, applied policy and result on that gateway under an equivalent connection mode.

Complete the chapter when you reproduce all six controls and can explain a disagreement between CA publication and verifier enforcement. Continue with [Certificate Transparency]({{ '/wiki/certificate-transparency-evidence/' | relative_url }}) for issuance visibility and [certificate validation]({{ '/wiki/certificate-validation/' | relative_url }}) for chain, name and purpose.

## Official references

Reviewed 2026-11-21. Provider dates describe specific rollouts. Match product settings to your deployed versions.

- [RFC 5280 §§ 5, 6.3](https://www.rfc-editor.org/rfc/rfc5280.html), May 2008, CRL format and processing.
- [RFC 6960 §§ 2, 4.2.2](https://www.rfc-editor.org/rfc/rfc6960.html), June 2013, OCSP status, times and authorized responders. [RFC 5019](https://www.rfc-editor.org/rfc/rfc5019.html), September 2007, lightweight OCSP timing profile.
- [RFC 9846 § 4.5.1.1](https://www.rfc-editor.org/info/rfc9846/), July 2026, TLS 1.3 status extensions. It supersedes RFC 8446.
- [Let's Encrypt OCSP retirement](https://letsencrypt.org/2025/08/06/ocsp-service-has-reached-end-of-life.html), August 2025, and [Mozilla's Firefox 142 CRLite rollout](https://blog.mozilla.org/en/firefox/crlite/).
- OpenSSL 3.5 [ca](https://docs.openssl.org/3.5/man1/openssl-ca/), [crl](https://docs.openssl.org/3.5/man1/openssl-crl/) and [verify](https://docs.openssl.org/3.5/man1/openssl-verify/).
