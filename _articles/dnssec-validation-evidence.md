---
title: "DNSSEC Validation · Trace a Signed Answer and Diagnose SERVFAIL"
description: "Follow the parent DS, child DNSKEY and answer RRSIG, then verify six offline controls with disposable keys."
category: network
tags: [DNS, DNSSEC, Cryptography, Network Monitoring, Blue Team]
level: Beginner
updated: "2026-11-21"
translation_url: /ko/wiki/dnssec-validation-evidence/
---

**Learning goal.** Trace the trust path that lets a recursive resolver validate a DNS answer. Use evidence from the client and the resolver to locate a broken link before attributing a DNS outage.

## 1. What a validating resolver checks

A **zone** is an administratively managed part of DNS. A parent zone delegates part of the namespace to a child. An **RRset** groups records with the same owner name, class and type. If a name has two IPv4 addresses, its two A records belong to the same A RRset. DNSSEC signs the set together.

| Record or concept | Who publishes or configures it | Role in validation |
| --- | --- | --- |
| Trust anchor | Resolver operator or software distribution, using a trusted source | Starting point for validation, normally the root for public DNS |
| DS (Delegation Signer) | Parent zone at the child name | Digest that links the authenticated parent to a particular child DNSKEY |
| DNSKEY | Child zone | Public key and parameters used to verify signatures |
| RRSIG | Zone that signs the covered RRset | Signature and metadata, including covered type, signer name and validity interval |
| NSEC or NSEC3 | Signed zone | Supplies authenticated proof of absence when validated, for example at a delegation without DS |

Many zones use a **key-signing key (KSK)** for the DNSKEY RRset and a **zone-signing key (ZSK)** for other RRsets. A zone can also use a combined signing key. The DS includes an algorithm, digest type, key tag and digest. The key tag helps find candidates. The digest is calculated from the canonical child owner name and the DNSKEY record data and must match for a candidate under that DS.

![Starting from trusted parent data, match the DS to a child key, verify the DNSKEY set and use an authenticated key to verify the answer.]({{ '/assets/diagrams/dnssec-chain-en.svg' | relative_url }})

The resolver repeats this procedure down the delegation chain. DNSSEC authenticates the origin and integrity of DNS data under that chain. Query privacy, destination reputation and the web server's TLS identity require separate evidence.

## 2. Follow one normal response

For the fictional name `www.training.example.`, suppose the resolver already authenticated the parent's DS for `training.example.`. It calculates the advertised digest for a candidate child DNSKEY and checks the match. It then uses that key to verify the signature on the child's DNSKEY RRset. Next, it selects an authenticated key that matches the answer signature, checks the signature time window and verifies the A RRset containing `192.0.2.10`. The response data may become authenticated on that resolver.

| Outcome | Typical reason | Investigation implication |
| --- | --- | --- |
| Secure | The chain and required signatures validate | Record the verifying resolver and observation time |
| Insecure | The resolver has authenticated evidence that a delegation is unsigned, for example a validated no-DS proof | An unsigned answer is expected at that delegation |
| Bogus | The resolver expects signed data, and the validation path fails | Check parent DS, child DNSKEY, signatures, clock and authoritative consistency |
| Indeterminate | The resolver lacks the trust anchor needed to determine signing status | Inspect the resolver's trust and policy configuration |

`DO` in EDNS signals that the requester can receive DNSSEC records. `AD` in the response reports that the responding resolver treats relevant data as authentic. With RFC 6840, a query can signal interest in AD via the query's AD or DO bit. Give the response bit weight only when the resolver and the path to it are trusted. `CD` asks the resolver to return data even if checking fails, subject to resolver behaviour. Use it only as a diagnostic on an authorised resolver and treat the returned data accordingly. An absent AD bit, an available RRSIG or a single `SERVFAIL` does not establish the validation status.

## 3. Separate tampering from operational failure

An altered A RRset no longer verifies under the authentic key and signature. A compromised signer or an unauthorised delegation change can produce data that validates under the resulting chain. Review administrator activity, registrar changes and signing-system evidence if the validated answer itself is unexpected.

Operational faults can produce the same symptoms as tampering. A child key rollover can leave caches with an old DS while an authoritative server has already removed the matching key. A signing job can stop renewing RRSIGs. A resolver clock can drift outside a valid signature window. Missing data can also come from timeouts, stale replicas, broken TCP fallback or a forwarding policy. Check the scope before changing production settings.

**Current root example.** IANA lists KSK-2024, key tag 38696, as signing the root from 11 October 2026. ICANN advised validating resolver operators to verify that their deployed trust anchor configuration contains it. The older key's revocation is scheduled for January 2027. Confirm current status with IANA and use the resolver vendor's supported update procedure. The example illustrates trust-anchor maintenance. It does not explain an arbitrary `SERVFAIL`.

## 4. Collect, detect and respond

1. **Start with the affected view.** Record UTC query time, QNAME/QTYPE, client subnet or view, resolver address, response code, AD/DO/CD, transport and Extended DNS Error (EDE) if present. Record whether the observation came from the stub, resolver log, upstream trace or authoritative answer.
2. **Compare the failing link.** Ask the DNS owner for the parent DS and coverage of its authentication, the child DNSKEY RRset, signatures for both the DNSKEY and affected answer, and each authoritative server's result. Compare full digests and signature inception/expiry against a reliable UTC clock. Track cache state and current TTLs during a rollover. Scope the comparison to the correct view, including deliberately different internal answers.
3. **Alert on failures with context.** Where supported, use resolver validation logs or EDE. RFC 8914 defines examples such as 6 (DNSSEC Bogus), 7 (Signature Expired) and 9 (DNSKEY Missing). Their absence is inconclusive. Compare failure counts with query volume, by resolver and zone, while watching unsigned and known-good signed controls. Simultaneous failures across unrelated signed zones justify checking a shared resolver, clock or trust anchor.
4. **Recover at the responsible layer.** Preserve resolver logs and the record samples. Coordinate with the DNS owner, registrar or resolver operator for the specific fault. After an authorised fix, retest through the affected resolver and one independent, approved observation point. Allow for caching and confirm normal validation. Keep production validation enabled during investigation.

## 5. Offline exercise · Verify six controls

Download [dnssec-delegation-lab.py]({{ '/assets/labs/dnssec-delegation-lab.py' | relative_url }}). Use Python 3.9 or later and OpenSSL 3.x with Ed25519 support on PATH. Run from the download folder. The script creates two disposable keys in a temporary folder, exercises Ed25519 signatures over DNSSEC input bytes and computes a SHA-256 DS digest. It opens no sockets and deletes the temporary folder on exit. The domain, addresses and fixed validation times are synthetic. The parent DS in the fixture is supplied as an already-authenticated input.

```sh
python3 dnssec-delegation-lab.py
```

| Case | Changed evidence | Expected result |
| --- | --- | --- |
| LAB-01 | Original DS, DNSKEY set and A record | `validated_fixture_chain` |
| LAB-02 | A address changed and its signature retained | `answer_rrset_signature_failed` |
| LAB-03 | DS digest changed, key tag unchanged | `parent_ds_mismatch` |
| LAB-04 | Verification time advances past both signatures | `dnskey_signature_outside_validity` |
| LAB-05 | The ZSK is missing from the signed DNSKEY set | `dnskey_rrset_signature_failed` |
| LAB-06 | Authenticated parent DS evidence is unavailable | `no_authenticated_delegation_evidence` |

The key tag varies with each freshly generated key. LAB-04 fails at the DNSKEY signature first because the checker evaluates the chain in order. Missing OpenSSL or incompatible crypto policy can prevent the script from starting. Check `openssl version` and whether the installation supports Ed25519. The executable lab covers this fixed fixture and does not implement a recursive resolver, parent validation, DNS packets or NSEC/NSEC3. The six cases ran using OpenSSL 3.5.7, and the DS digest and key tag were checked against the public example in RFC 8080. Resolver flags and EDE were reviewed in official documentation.

## 6. Check your understanding

- **The key tag matches. Does this establish the delegation?** No. Compare the algorithm and full digest, then verify the DNSKEY RRset signature.
- **An answer appears after adding CD to a diagnostic query. Was it safe?** That query asked for data even if validation fails. Record the change and use the normal query result and resolver diagnostic to find the cause.
- **Could a zone be insecure without being misconfigured?** Yes. A validating resolver can legitimately establish that a delegated zone is unsigned. A missing row in a packet trace is weaker evidence than a validated no-DS proof.
- **Why inspect the client-side resolver as well as the authoritative server?** Their views, cache and policy can differ. A correct authoritative answer does not prove that the affected resolver has current or valid inputs.

**Completion.** Describe the failing link in LAB-02, LAB-03 and LAB-04. For a real `SERVFAIL` alert, name the first two records or logs you would collect and the conclusion they could support.

[Previous · DNS foundations and evidence]({{ '/wiki/dns-investigation/' | relative_url }}) · [Related · Certificate validation and trust chains]({{ '/wiki/certificate-validation/' | relative_url }})

## Official references

Reviewed 21 November 2026. The RFC dates describe the covered standards. Use the latest IANA status and vendor guidance for operational changes.

- [RFC 4033 · DNSSEC overview and states, March 2005](https://www.rfc-editor.org/rfc/rfc4033.html) · [RFC 4034 · Records and signed data](https://www.rfc-editor.org/rfc/rfc4034.html) · [RFC 4035 · Validation and protocol](https://www.rfc-editor.org/rfc/rfc4035.html)
- [RFC 6840 · Clarifications, including AD/CD, February 2013](https://www.rfc-editor.org/rfc/rfc6840.html)
- [RFC 8080 · EdDSA for DNSSEC and public vectors, February 2017](https://www.rfc-editor.org/rfc/rfc8080.html)
- [RFC 8914 · Extended DNS Errors, October 2020](https://www.rfc-editor.org/rfc/rfc8914.html)
- [IANA · DNSSEC trust anchors and 2025–2027 rollover milestones](https://www.iana.org/dnssec/files) · [ICANN · October 2026 status and guidance](https://www.icann.org/resources/pages/ksk-rollover-en)
