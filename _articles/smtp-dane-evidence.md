---
title: "SMTP DANE and TLSA · Trace MX Trust and Key Rotation"
description: "Distinguish DNSSEC validation, a TLSA mismatch, and the SMTP queue outcome, then verify a mail key rollover offline."
category: network
tags: [SMTP, DANE, DNSSEC, TLS, Email Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/smtp-dane-evidence/
---

A partner’s mail is delayed just after a certificate change. The MX is reachable and an ordinary TLS client can connect. A sending mail server can still hold the message because it sees a DNSSEC-validated association for the old key. This chapter follows one direct server-to-server SMTP hop on TCP 25. For the preceding concepts, read [DNSSEC validation]({{ '/wiki/dnssec-validation-evidence/' | relative_url }}) and [SMTP delivery evidence]({{ '/wiki/smtp-delivery-evidence/' | relative_url }}).

## 1. What is bound to what?

An **MX record** names a mail exchanger to which a sender may deliver for a recipient domain. An **RRset** is the set of records with the same DNS owner name, class and type. **DNSSEC** lets a validating resolver authenticate an RRset or an assertion that a record does not exist. A DNSSEC signature says the data came through the validated DNS trust chain. An administrator can still sign a mistaken association.

**DANE** uses DNSSEC to convey how the sender should authenticate the receiving TLS service. That data lives in a **TLSA** RRset. For a direct connection to `mx1.example.test` on port 25, without aliases, the TLSA owner is `_25._tcp.mx1.example.test.`, even if the recipient address ends with `@example.test`. MX and TLSA validation are distinct. A TLSA match for a host selected from an insecure MX RRset does not authenticate that choice of host for the recipient domain.

| TLSA component | Meaning of `3 1 1` | A value with a different scope |
| --- | --- | --- |
| Certificate usage `3` | DANE-EE, involving the endpoint’s leaf certificate | `2` is DANE-TA. Construct a valid chain to the indicated trust anchor and check the applicable server name |
| Selector `1` | DER SubjectPublicKeyInfo (SPKI), which contains the public key and its algorithm information | `0` selects the entire DER certificate |
| Matching type `1` | SHA-256 digest of the selected bytes | `0` is the selected bytes themselves and `2` is SHA-512 |
| Association data | Hexadecimal SHA-256 digest of leaf SPKI for this tuple | A certificate fingerprint, a PEM text hash, and a DNSSEC DS digest cover different bytes |

For SMTP DANE-EE, the signed association supplies the identity binding. The sender does not apply public-CA path or certificate-name checks to establish that DANE-EE identity. The TLS handshake still has to succeed and establish possession of the corresponding key. The RFC 7672 SMTP profile leaves usages 0 and 1 undefined and clients may treat them as unusable. Microsoft documents that behavior for Exchange Online. Generic HTTPS validation, SMTP DANE-TA, and MTA-STS apply different checks.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/smtp-dane-evidence-en.svg' | relative_url }}" alt="A sender validates the MX lookup and the selected host’s TLSA record, then checks STARTTLS and the certificate association. A mismatch sends the attempt to the next eligible MX or to the retry queue. A match allows SMTP to continue, with acceptance recorded separately." style="max-width: 100%; height: auto;">
  <figcaption>Figure 1. Each step produces separate evidence. The diagram shows the path with at least one usable, securely validated TLSA record.</figcaption>
</figure>

## 2. Follow a normal delivery

1. At 10:00 UTC a fictional sending MTA resolves `example.test`. The validator returns a secure MX RRset containing `10 mx1.example.test.` and `20 mx2.example.test.`. The sender starts with the lower preference number.
2. It resolves the TLSA owner of `mx1`. The result is secure, and it contains a usable `3 1 1` record for key A.
3. The sender sees `STARTTLS` in the server’s EHLO response, upgrades the connection, and checks the leaf SPKI digest against the association. Key A matches. A temporary key used to establish the session is a different key from the certificate’s public key.
4. The sender continues SMTP over TLS. A final `250` after the message body records peer acceptance on that hop. The receiver’s queue and delivery records tell you what it did afterward. A successful handshake by itself records neither acceptance nor inbox delivery.

## 3. Read the failure stage before interpreting it

The table summarizes opportunistic DANE for an eligible MX under RFC 7672 §2.2. Other configured requirements and vendor behavior matter. See the sender’s active route and connector policy before predicting its exact queue action.

| Sender-side observation | Interpretation and immediate check |
| --- | --- |
| Secure TLSA with a usable match and successful TLS | DANE authentication for this endpoint. Check the SMTP transaction for acceptance |
| Secure TLSA with usable records, but mismatch or no working STARTTLS | This endpoint cannot be used for the attempt. Try the next eligible MX or defer. Compare the presented leaf and the RRset the sender saw |
| Secure, nonempty TLSA with every record unusable | TLS encryption is required under §2.2, with no DANE authentication requirement in this case. Check supported tuples and whether TLS completed |
| Insecure TLSA or authenticated absence of TLSA | Opportunistic TLS is the baseline recommendation. Check any stronger local policy or MTA-STS before concluding that plaintext was possible |
| DNS lookup error, including bogus DNSSEC | Try the next eligible MX when applicable or defer. Diagnose the validator and delegation. Preserve the error separately from authenticated absence |

A network intermediary can interfere with a plaintext STARTTLS advertisement. A usable, authenticated TLSA record makes a DANE-capable sender require authenticated TLS, so that interference can produce a delay on a protected route. Unauthorized DNS administration can instead change what an otherwise validly signed record authorizes. Unexpected changes to DNS, mail endpoints or keys deserve cross-checking against change records. A stale cached RRset, a single node presenting the wrong key and a wrong selector all provide ordinary explanations for mismatches. When both policies apply, RFC 8461 prohibits allowing a successful MTA-STS validation to override failed DANE validation.

## 4. Collect, detect and respond

| Where to collect | Fields and collection conditions |
| --- | --- |
| Sending MTA or provider trace | UTC event and attempt time, policy actually applied, queue ID scoped to that MTA, destination domain, chosen MX and IP, STARTTLS/TLS outcome, certificate association outcome and final SMTP response. Retain per-attempt diagnostics where supported |
| Resolver serving the sender | Resolver identity, owner name, qtype, validation state, negative proof or error, response TTL, and records as seen then. Validate locally or use a trusted validator over a trusted path. A packet’s AD bit from an arbitrary server is insufficient |
| Receiving service and change system | Connection time, backend and certificate or SPKI digest, rollout identifier, DNS publication audit, key activation and rollback time. Retain separate evidence for each MX, address family and backend when available |
| TLS-RPT from participating senders | UTC reporting interval, reporter, policy domain, MX fields if present, policy type `tlsa` and result such as `tlsa-invalid` or `dnssec-invalid`. Use aggregates to find affected routes. For Exchange Online traces or NDRs, Microsoft also documents `4.7.323` and `4.7.324`. These are provider diagnostics |

Group failed **attempts** by sender, MX, failure stage and time. Count distinct messages separately using a queue or message identifier whose scope you know. Compare the same sender’s last successful attempt and the first failure with the DNS change and certificate activation times. If only one address family or one backend fails, compare the keys each actually presented. If multiple validators report bogus DNSSEC for different record types, start at the affected DNSSEC chain. Retain both original and normalized timestamps.

During routine rotation publish associations for old and new material before serving the new key. Allow the previous RRset to age out of caches, based on the TTL in effect before the change. Verify publication and the overlap from the sender’s vantage point, then roll out the key to every intended endpoint. Remove the old association once the old key is retired and rollback no longer relies on it. If compromise is suspected, coordinate containment and key replacement with DNS and mail owners. A routine overlap that still authorizes a compromised key may be inappropriate. Confirm recovery from actual queue outcomes, and preserve enough monitoring to detect retry failures.

**Fictional incident.** The old-only RRset had a 3,600-second TTL. At 10:05 UTC the DNS operator publishes A and B, and at 10:10 UTC one backend begins serving B. A sender that cached A alone at 10:04 UTC can still see it at 10:12 UTC. If that sender’s snapshot shows A alone and the backend shows B, the two records explain a TLSA mismatch. The deployment timestamp and the DNS state explain why other senders may still succeed. The queue record is required to learn whether the sender retried successfully.

## 5. Authorized offline lab

Download the [Bash and OpenSSL lab]({{ '/assets/labs/smtp-dane-evidence.sh' | relative_url }}){: download="smtp-dane-evidence.sh"}. Run it in an environment you own or have permission to use. It creates disposable certificates in a private temporary directory, extracts the DER SPKI, hashes the SPKI and whole certificate separately, then removes its temporary files. It sends no mail and makes no DNS or network requests. Requires Bash, OpenSSL with EC P-256 support, and standard Unix utilities.

```bash
openssl version
bash smtp-dane-evidence.sh
```

| Control | Expected |
| --- | --- |
| Certificate A and renewed certificate A′, same key and different serials | Same SPKI hash, distinct whole-certificate hashes |
| Old-only association, server presents new key B | Mismatch |
| Overlapping A and B associations | Match for either key |
| New-only association after retirement | Match for B, mismatch for A |
| Whole-certificate digest supplied in place of an SPKI digest | Mismatch for `3 1 1` |

The script exits with a nonzero status when a check fails. If key generation fails, confirm OpenSSL can load an EC provider. If a manually calculated digest differs, confirm the input was binary DER from `openssl pkey -pubin -outform DER`, the certificate was the leaf, and the correct selector was applied. Compare the full hex digest. This tests byte selection and rollover coverage only. It uses fresh, local test material. The table in section 3 is a standards review. A real sender’s resolver, TLS handshake, product trace and queue were outside the lab.

## 6. Check your understanding

1. **A partner sees a valid public-CA certificate and reports `tlsa-invalid`. Can those coexist?** Yes. A successful CA check and the authenticated TLSA association answer different questions. Recover the sender’s RRset and leaf SPKI for the specific attempt.
2. **Can a DNSSEC `SERVFAIL` establish TLSA absence?** No. Recover the validator’s reason. Secure denial and a failed lookup lead to different decisions.
3. **Both candidate endpoints have working authenticated TLS. Which accepted the message?** Obtain the sender’s result for the specific transaction and the receiving queue record. Endpoint testing cannot establish which accepted it.
4. **What crosses the rotation cutover safely?** Old and new associations are published first, cached old-only data has time to age out, and each endpoint then presents a key covered by the active policy.

**Completion criterion.** Explain `3 1 1` without referring to the table, reproduce both match and mismatch controls, and label the failed stage and missing evidence for one fictional attempt. Continue with [MTA-STS and TLS-RPT]({{ '/wiki/smtp-mta-sts-evidence/' | relative_url }}).

## Official references

Reviewed 2026-11-26. The dates identify the standards editions. Microsoft Learn documents Exchange Online product behavior as reviewed on that date.

- [RFC 6698 (2012)](https://www.rfc-editor.org/rfc/rfc6698.html) and [RFC 7671 (2015)](https://www.rfc-editor.org/rfc/rfc7671.html) define TLSA fields and DANE operational guidance.
- [RFC 7672 (2015), §§2–4](https://www.rfc-editor.org/rfc/rfc7672.html#section-2) specifies direct SMTP DANE, validation outcomes and key changes.
- [RFC 8461 (2018), §2](https://www.rfc-editor.org/rfc/rfc8461.html#section-2) and [RFC 8460 (2018), §4](https://www.rfc-editor.org/rfc/rfc8460.html#section-4) cover coexistence and aggregate reports.
- [Microsoft Exchange Online SMTP DANE](https://learn.microsoft.com/en-us/exchange/security-and-compliance/how-dane-secures-email) and [Exchange Online delivery diagnostics](https://learn.microsoft.com/en-us/troubleshoot/exchange/email-delivery/ndr/non-delivery-reports-in-exchange-online) document supported mail flow and error labels.
