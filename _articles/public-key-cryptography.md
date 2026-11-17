---
title: "Public Keys, Private Keys and Digital Signatures: From First Principles to TLS and Evidence"
description: "Separate encryption, signing and key agreement; understand hybrid TLS, investigate trust failures and run an offline OpenSSL lab with positive and negative controls."
category: network
tags: [Cryptography, PKI, Certificates, TLS, Blue Team, Red Team, OpenSSL]
level: Beginner
updated: "2026-11-18"
translation_url: /ko/wiki/public-key-cryptography/
---

> **Foundation chapter.** No cryptography background is required. Read sections 1–6 for the mental model, 7–8 for investigation, and 9–11 for practical proof. Continue with [AD CS security]({{ '/wiki/ad-cs-security/' | relative_url }}) and [network observation]({{ '/wiki/network-monitoring/' | relative_url }}).

## 1. Start with the question, not the algorithm

Suppose Alice sends Bob a change approval. Three different questions arise: can an observer read it, did its bytes change, and which key authorized it? **Confidentiality**, **integrity** and **authenticity** answer different questions. A confidential message can contain a lie. A signed message can be public. A valid signature can belong to the wrong organization.

A **key** is a parameter used by a cryptographic algorithm. A public/private pair is mathematically related, but a properly chosen public key should not make computing its private counterpart feasible. Publish the public key when appropriate; restrict the private key and permission to use it. A password protecting a key file is a separate secret, not the private key itself.

**Symmetric cryptography** uses shared secret key material and efficiently protects bulk data. **Asymmetric cryptography** uses a pair and enables operations between parties that do not already share that secret. It still needs an answer to “whose public key is this?” More mathematics does not solve identity distribution by itself.

## 2. Five operations that must stay separate

| Operation | Key use | Intended result | Does not alone prove |
| --- | --- | --- | --- |
| Public-key encryption | Recipient public key encrypts; recipient private key decrypts | Confidentiality to the intended recipient | Sender identity |
| Digital signature | Signer private key signs; signer public key verifies | Integrity and authenticity relative to that key | Secrecy, human approval or trustworthy content |
| Key agreement, such as ECDHE | Each side combines its private contribution with the peer public contribution | Establish shared secret material | Peer identity unless authenticated |
| Cryptographic hash | No secret key; digest of input bytes | Compact integrity comparison against a trusted reference | Who created the bytes |
| MAC / HMAC | Shared secret authenticates a message | Integrity/authenticity among secret holders | Which holder created it to an outside verifier |

![Separate paths for recipient encryption and sender signing]({{ '/assets/diagrams/public-key-purpose-en.svg' | relative_url }})

**Diagram reading:** the encryption path uses Bob's pair; the signature path uses Alice's pair. The signed document travels alongside its signature and can remain readable. “Encrypt with the private key” is a misleading description of signing: signature schemes have their own encoding, checks and security requirements.

**Algorithm** and **purpose** are also different axes. RSA has distinct encryption and signature schemes: this lab uses RSA-OAEP and RSA-PSS. ECDSA and Ed25519 are signature schemes; X25519 is used for key agreement. They are not interchangeable names for encrypting arbitrary files. Base64 is a reversible representation, not encryption. Hashing a password once with a fast general-purpose hash is not a password-storage design.

## 3. A normal confidential message

1. Bob creates a pair and protects the private part.
2. Alice obtains Bob's public key through an authenticated channel.
3. Alice encrypts suitable input with the supported scheme and Bob's public key.
4. Bob uses his private key to recover it.
5. If Alice must authenticate herself, a separate authenticated construction is needed.

An attacker who substitutes their own public key at step 2 can become the intended cryptographic recipient. Encryption may work perfectly while the human security goal fails.

Public-key encryption is not normally used directly on a large document. Generate fresh symmetric key material, protect the document with a suitable authenticated-encryption construction, and protect/establish the key through a supported asymmetric mechanism. An envelope must define algorithm identifiers, nonces, authentication tags and recipient metadata correctly. Use a maintained protocol or library rather than inventing this format.

## 4. A normal signature and the identity gap

Alice signs an exact byte sequence with her signing key. Bob verifies the signature, the same bytes, the intended algorithm parameters and a trusted Alice public key. A successful check means the mathematical relationship holds under that key; it does not tell Bob who controlled the signing service at the time.

A **certificate** is a signed statement binding a public key to certificate information. A **CA** issues certificates; a **trust anchor** is trusted by local policy. An intermediate certificate can connect a leaf to that anchor. A self-signed certificate can be valid in a deliberately configured private system; an unexpected self-signed certificate is not automatically malware.

Validation involves a permissible path, validity time, constraints, purpose and the application's reference identity, plus applicable status/revocation policy. Merely parsing a certificate or seeing a familiar issuer name is not validation. For a website, check the requested hostname against the applicable name rules, not a certificate's marketing name.

A **fingerprint** identifies certificate/key bytes depending on what was hashed. It is not a private key or proof of trust. A CSR requests certification and normally demonstrates possession of a key; approval and the final issued certificate remain separate facts. See the [AD CS lifecycle]({{ '/wiki/ad-cs-security/' | relative_url }}) for issuance versus later authentication.

## 5. How TLS combines the parts

![Simplified certificate-authenticated TLS 1.3 with ephemeral key agreement and symmetric application traffic]({{ '/assets/diagrams/public-key-tls-en.svg' | relative_url }})

For the illustrated full, certificate-authenticated TLS 1.3 handshake, ephemeral key shares establish secret material, the server certificate and handshake signature authenticate the server, and a key derivation function derives traffic keys. Finished messages confirm handshake integrity/key possession. Application records use symmetric AEAD, such as AES-GCM or ChaCha20-Poly1305. Directional keys and changing handshake/application secrets are omitted from the picture.

The certificate's signing key and the ephemeral key-agreement key have different jobs. TLS 1.3 does not use the old RSA key-transport model where a client encrypts a premaster secret with the server certificate key. Resumption/PSK and client authentication have additional paths; the diagram does not cover every handshake.

With correctly implemented ephemeral exchange and erased ephemeral secrets, later theft of the certificate private key alone does not reveal previously captured sessions. That is **forward secrecy**, not protection against a compromised endpoint reading plaintext or a stolen session secret. Retained PCAP plus a server certificate key is therefore not a universal decryption recipe.

## 6. Key lifecycle and present-day boundaries

Inventory the purpose, owner, consumers, location, exportability and renewal/recovery process for each key. Separate signing, decryption and other purposes. Limit who may invoke operations as well as who may export a key. Hardware-backed non-exportability does not prevent an already authorized compromised process from requesting misuse.

Rotate/revoke according to the system's incident and lifecycle procedures. Revoking a certificate does not instantly erase every cached trust decision, access token or established session. Losing a decryption key can mean losing data; losing a signing key can mean losing trust. Recovery requirements differ.

This chapter teaches classical RSA/ECDHE concepts, not a universal 2026 deployment profile. Post-quantum ML-KEM is a standardized key-encapsulation mechanism, not a signature scheme or direct large-file encryption tool. Product support, negotiated groups and migration requirements must be assessed separately; using TLS 1.3 does not by itself prove a post-quantum exchange.

## 7. Attack mechanisms and defensive evidence

| Mechanism | What goes wrong | Evidence to seek / control |
| --- | --- | --- |
| Public-key substitution | Correct crypto reaches the wrong party | Approved key source, fingerprint comparison via an independent trusted channel |
| Signing-key misuse | Unauthorized bytes get an otherwise valid signature | Signing-service identity, approval, artifact digest, key ID, time and outcome; restrict signing authority |
| Validation bypass | Client accepts the wrong peer | Application trust/name-check configuration, proxy path and error handling; repair validation rather than disabling checks |
| Private-key exposure | Export, backup or secret-store access enables misuse | Endpoint/storage access records and key-use audit where configured; protect backups and rotate affected material |
| Replay | Previously signed bytes accepted again in the wrong context | Application transaction ID, nonce/expiry and replay state; signatures alone do not supply freshness |
| Encryption for abuse | A malicious process uses ordinary encryption | Process, file changes, access and impact; an algorithm name is not an incident verdict |

An unfamiliar certificate or TLS fingerprint is a lead. Do not assign malware or an actor from it, a User-Agent or a single IP. A legitimate signer can also sign harmful software: cryptographic authenticity and safety are different judgements.

## 8. Blue-team collection and response

First define the claim: failed verification, unexpected trust, unauthorized signing or confirmed key theft? Collect original artifacts and signatures, hashes, trusted key provenance, certificate chain and policy, timestamps/time offsets, application verification output and endpoint process context. Keep private keys and session secrets out of public reports and routine SIEM logs.

TLS metadata and failure logs depend on the sensor and termination point. A passive sensor does not automatically see TLS 1.3 server certificates inside encrypted handshake messages. An authorized endpoint/proxy can offer different evidence. [Zeek, Suricata and Arkime]({{ '/wiki/network-monitoring/' | relative_url }}) explain visibility and packet-retention limits.

Before creating an alert, generate a known benign event and verify local generation, forwarding, parsing, timestamp and retention. There is no universal Windows Event ID or Splunk field meaning “private key stolen.” Signing service and HSM audit coverage is product/configuration specific. Preserve raw records and documented field mappings.

If misuse is substantiated, restrict the affected signing/decryption route, preserve evidence, identify affected artifacts and consumers, replace compromised keys and publish applicable revocation information. Test consumer enforcement and existing-session handling. Coordinate trust-anchor changes with recovery owners because dependent services can fail.

## 9. Authorized offline lab

Use Python 3 and an OpenSSL 3.x executable on your own lab system. The downloadable script creates three disposable 3072-bit RSA pairs in a temporary directory, performs the five checks below and removes the temporary files on normal exit. It never contacts a server, imports a trust anchor or uses production keys.

[Download the complete runnable lab]({{ '/assets/labs/public-key-lab.py' | relative_url }}). Save it as `public-key-lab.py`, inspect it, then run:

```bash
openssl version
python3 public-key-lab.py
```

Lab keys are unencrypted only for this temporary offline exercise; this is not a storage recommendation. A crash or interruption may leave temporary files; inspect your own temporary directory after an abnormal exit. File deletion is not a guarantee of physical secure erasure.

The core signing operation, once the script's key/message files exist, is:

```bash
openssl dgst -sha256 -sign signer.pem -out signature.bin \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
  -sigopt rsa_mgf1_md:sha256 message.txt
openssl dgst -sha256 -verify signer.pub.pem -signature signature.bin \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest \
  -sigopt rsa_mgf1_md:sha256 message.txt
```

These are explanatory excerpts; use the complete script for file creation. The script explicitly selects OAEP SHA-256/MGF1-SHA-256 and PSS parameters so defaults do not silently define the exercise. RSA-3072 OAEP/SHA-256 accepts at most 318 input bytes (384 − 2×32 − 2); its tiny message illustrates a primitive, not bulk document encryption. Independent recipient and signer keys demonstrate purpose separation.

## 10. Expected results, failure diagnosis and limits

| Test | Expected result | What it establishes |
| --- | --- | --- |
| Recipient decrypts | Exact byte comparison passes | Positive encryption/decryption control |
| Wrong private key decrypts | Nonzero exit | Negative key control |
| Original message verifies | Zero exit | Signature agrees with bytes/key/parameters |
| Change 42 to 43 | Nonzero exit | Content-change negative control |
| Wrong public key verifies | Nonzero exit | Verification-key negative control |

Expect five `PASS:` lines followed by `DONE: temporary lab keys and files removed`. Randomized OAEP ciphertext and PSS signatures vary each run; equality of output ciphertext is not expected.

If OpenSSL is missing, install a supported build through your normal system process. If a provider or policy prohibits an operation, record the version/configuration and resolve it in the lab rather than weakening production policy. Verification failure can come from changed line endings, encoding, wrong key, padding or digest settings: preserve the inputs before diagnosing an attack. A Python assertion failure is a failed lab, not a pass.

**Execution record:** these five controls were run in the cloud publication environment with OpenSSL 3.5.7. This is not a live TLS handshake, CA/path-validation test, HSM audit test, Windows test or production SIEM validation. The fictional approval is educational data.

## 11. Questions, answers and completion criteria

1. **Can Bob prove Alice sent an OAEP ciphertext just because he decrypted it?** No. Anyone with Bob's public key can create ciphertext.
2. **The signature verifies with a key downloaded beside the file. Is the publisher established?** No. Authenticate that key independently or through a validated trust mechanism.
3. **The signed file changes only its line endings. Should verification still succeed?** Not generally: the signed byte sequence changed unless a specified format canonicalizes it.
4. **A certificate is revoked. Are old TLS sessions and every signed artifact immediately invalid?** No. Consumers, caches, protocol state and signature-validation policy matter.
5. **Does failed verification prove malicious tampering?** No. It establishes a failed check; diagnose parameters and acquisition before assigning intent.

Finish when you can draw both key directions, explain symmetric TLS traffic keys, reproduce all five controls, identify the key-trust gap and write a finding separating a cryptographic result from identity and malicious intent.

**Learning path:** this foundation → [AD CS and certificate authentication]({{ '/wiki/ad-cs-security/' | relative_url }}) → [network evidence and visibility]({{ '/wiki/network-monitoring/' | relative_url }}). A future PKI/TLS chapter can deepen path building, hostname validation and revocation without duplicating these primitives.

## 12. Official references and review scope

**Reviewed: 18 November 2026.** The standards below have different publication dates; old foundation documents are not evidence of current product defaults. RFC 9846 supersedes RFC 8446; do not label the 2018 text as the newest TLS specification. Commands were checked against the versioned OpenSSL manuals and the execution record above. Diagrams, narrative scenarios and lab are original educational material.

- [RSA schemes: RFC 8017, November 2016, sections 7–9](https://www.rfc-editor.org/rfc/rfc8017.html)
- [TLS 1.3: RFC 9846, July 2026, sections 2, 4 and 7](https://datatracker.ietf.org/doc/html/rfc9846) (supersedes the August 2018 RFC 8446).
- [X.509 PKI foundation: RFC 5280, May 2008, sections 4 and 6](https://www.rfc-editor.org/rfc/rfc5280.html), read with its linked updates and application policy.
- OpenSSL 3.5 manuals: [genpkey](https://docs.openssl.org/3.5/man1/openssl-genpkey/), [pkeyutl](https://docs.openssl.org/3.5/man1/openssl-pkeyutl/), [dgst](https://docs.openssl.org/3.5/man1/openssl-dgst/).
- [NIST SP 800-57 Part 1 Rev. 5, May 2020: key-management foundation](https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final).
- [NIST FIPS 203, August 2024: ML-KEM](https://csrc.nist.gov/pubs/fips/203/final).

## Certificate validation checkpoint

[Distinguish trust, SAN, purpose and expiry with six offline controls]({{ '/wiki/certificate-validation/' | relative_url }})
