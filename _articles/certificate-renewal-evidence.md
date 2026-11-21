---
title: "TLS Certificate Renewal · Verify the Request, Staged Bundle and Live Leaf"
description: "Trace a signed CSR through authorized issuance and deployment, then confirm which certificate a client actually receives."
category: network
tags: [TLS, PKI, Certificates, Cryptography, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/certificate-renewal-evidence/
---

**Learning goal.** Given an approved renewal, verify that the intended key and certificate match, that the issued certificate covers the service, and that each TLS terminator presents the expected leaf. For chain and service identity fundamentals, see [certificate validation]({{ '/wiki/certificate-validation/' | relative_url }}).

## 1. From a key to a client-visible certificate

A **private key** performs signing operations and stays under the operator's control. The corresponding **public key** can be shared. A **certificate signing request (CSR)** packages a public key, subject information and optional attributes in a signed request. With PKCS #10, the signature covers the request data and can be verified with the public key in the request. It shows that a signer could use the corresponding private key at signing time. Authority over a DNS name and authority to request issuance require separate checks.

A **certificate authority (CA)** issues a signed X.509 certificate after applying its validation rules and issuing policy. A **leaf certificate** is the service's certificate. **Subject Alternative Name (SAN)** carries the identities that a conforming TLS client uses to match a DNS name, through the `dNSName` entry type. **SubjectPublicKeyInfo (SPKI)** encodes the public key and its algorithm. A SHA-256 digest of DER-encoded SPKI identifies the encoded key. A SHA-256 certificate fingerprint identifies the whole DER-encoded certificate. Renewing with the same key changes the certificate fingerprint while SPKI can stay the same.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/certificate-renewal-en.svg' | relative_url }}" alt="A signed CSR proceeds through CA validation, staging and deployment. The staging gate checks public key, identities, trust and dates. A fresh TLS probe verifies the name and compares the observed leaf to the release manifest.">
  <figcaption>Keep proof of signing, CA authorization, the staged bundle and the certificate actually presented as separate evidence.</figcaption>
</figure>

## 2. Follow a planned key rotation

The following records are fictional. The owner of `inventory.example.test` approves a renewal with a fresh key and the same DNS name. At 09:00 UTC a signer creates the CSR. At 09:10 the CA issues a new leaf with the approved SAN. At 09:15 staging records the new key's SPKI match, successful chain and name checks, and an approved leaf fingerprint. An edge rollout starts at 09:25. At 09:30 the west edge presents the new leaf. The east edge still presents the previous leaf, which is valid for the same name. After the final rollout, a fresh east-edge handshake presents the expected fingerprint. The 09:30 result is evidence of partial deployment. Its significance depends on the rollout phase and certificate expiry.

| Checkpoint | Evidence | What remains to verify |
| --- | --- | --- |
| Request | CSR signature, SPKI digest, requested names and change approval | CA authorization and actual issuance |
| Issuance | CA order or request ID, issuer and serial, issued SAN, key and validity dates | Staged key match and applicable client trust |
| Staging | Expected leaf fingerprint, matched key, trusted chain and service identity checks | Which listener loaded the bundle |
| Observation | Time, target listener, SNI, service identity, verified peer leaf and vantage point | Coverage of other edges, routes and clients |

With ACME, the **order** holds requested identifiers. A CA authorizes them through its validation process. The CSR submitted at finalization must request the same identifier set as the order. The issued certificate and whether each listener loaded it are separate checks. In a managed service you may get a certificate resource ID and deployment status instead of a raw CSR or exportable key. Use the authorized provider metadata and verify via the client-facing listener.

## 3. Investigate errors and unauthorized changes

Ordinary failures include pairing a new leaf with the previous key, selecting the wrong hostname at issuance, omitting an intermediate, and loading the right certificate into the wrong listener. An attacker with access to a signing service may be able to request a valid CSR without exporting the private key. Unauthorized access to an enrollment identity or validation workflow can affect issuance. Correlate CA audit records, signer activity and approved inventory before concluding what happened. For public issuance alerts, use [Certificate Transparency evidence]({{ '/wiki/certificate-transparency-evidence/' | relative_url }}). A CT entry establishes an issuance observation. Which listener presented the certificate is a different question.

| Symptom | First checks and response |
| --- | --- |
| Signed CSR, wrong issued SAN | Compare the authorized names with the actual SAN. Review the CA order and issuing policy. Hold deployment until reissued for the correct identity. |
| Leaf and key mismatch | Compare SPKI from the staged leaf with an authorized public-key view of the selected key. Fix the bundle association. Keep key export and material logging disabled. |
| Chain fails for only some clients | Compare presented intermediates and the affected client's trust policy, name, time and verification error. Document any policy mismatch. |
| Only one edge serves an old leaf | Compare the expected fingerprint for that edge, SNI tenant and release wave. Check reload outcomes and test a fresh connection on the same route. |
| Unexpected issuer, names or key | Preserve the leaf, timestamps, enrollment records and rollout history. Escalate to the CA and service owners. If compromise is confirmed, coordinate rotation and revocation under the incident plan. |

**Public TLS validity in November 2026.** CA/Browser Forum Baseline Requirements v2.3.1 cap publicly trusted subscriber certificates issued from 2026-03-15 to before 2027-03-15 at 200 days. The scheduled limits are 100 days for issuance from 2027-03-15 and 47 days from 2029-03-15. These issuance windows are for the public TLS scope. Private trust domains can have different policies. Measure time to expiry across every terminator and schedule renewal with room to detect a partial rollout.

## 4. Collect evidence without copying private keys

Before rollout, use an approved runner that can already access the staging artifacts. Capture the approved names, key identifier, order ID, issuer and serial, validity and expected certificate fingerprint. A digest match answers which encoded key is associated with an artifact. It does not test DNS authorization, trust path or name. For HSM-managed keys, compare an authorized public-key result from the provider rather than exporting key material.

These read-only OpenSSL 3.5 commands inspect a PEM CSR and leaf. Use authorized artifacts on the runner. For the chain command, `SERVICE_NAME` is the intended DNS name, `roots.pem` holds the intended trust anchors and `intermediates.pem` holds any required intermediate certificates. Omit `-untrusted intermediates.pem` for a leaf directly signed by the trust anchor. Require the correct SAN entry explicitly. OpenSSL's hostname checker can fall back to Common Name in some cases, while RFC 9525 uses DNS SAN entries for service identity.

```sh
openssl req -in service.csr -noout -verify
openssl x509 -in leaf.pem -noout -issuer -serial -dates -ext subjectAltName
openssl x509 -in leaf.pem -noout -sha256 -fingerprint
openssl verify -CAfile roots.pem -no-CApath -no-CAstore \
  -untrusted intermediates.pem -purpose sslserver -verify_hostname "$SERVICE_NAME" leaf.pem
```

To compare the encoded public keys in the signed request and issued leaf, run the following in Bash. Treat any failed pipeline as a failed check.

```bash
set -o pipefail
openssl req -in service.csr -pubkey -noout |
  openssl pkey -pubin -outform DER | openssl dgst -sha256
openssl x509 -in leaf.pem -pubkey -noout |
  openssl pkey -pubin -outform DER | openssl dgst -sha256
```

After rollout, use a fresh, authorized TLS exchange with the expected **Server Name Indication (SNI)** and identity check. Test the distinct listeners in scope, including different edge addresses or regions where applicable. For OpenSSL diagnostics the relevant options are `-servername`, `-verify_hostname` and `-verify_return_error`, plus the intended CA trust. If you use `-showcerts`, it shows the certificates the server sent. Record the public leaf fingerprint and verification outcome, and avoid retaining session secrets or raw diagnostic transcripts. Compare each observation with its release manifest. A test through one edge or trust store does not establish every client's result.

## 5. Reproduce a partial renewal offline

Download [certificate-renewal-lab.py]({{ '/assets/labs/certificate-renewal-lab.py' | relative_url }}){: download="certificate-renewal-lab.py" }. Use Python 3.12 and the OpenSSL 3.5 CLI in your own workspace. The script creates short-lived lab keys and a private test CA inside a temporary directory. It leaves the system trust store untouched. Two real TLS handshakes run through Python memory buffers without opening a socket.

```sh
python3 certificate-renewal-lab.py
```

Expect eight `PASS` lines. The CSR signatures verify, the renewal CSR, key and leaf share SPKI, and the earlier key differs. An intentionally wrong SAN is rejected for the intended hostname even though its CA chain and key match. The 14-day leaf is inside a 15-day expiry window and outside a one-day window. Both simulated listeners authenticate correctly. One presents the previous fingerprint and the other presents the staged fingerprint.

If generation fails, check the OpenSSL CLI on PATH and the version shown by Python's SSL library. If a time check fails, verify the machine clock and rerun from a fresh temporary directory. If the handshake fails, review trust, name and the leaf/key association before changing any settings. All eight checks passed with Python 3.12.14, OpenSSL CLI 3.5.7 and Python's OpenSSL 3.5.8. No production CA, listener or ACME service was contacted.

## 6. Check your reasoning

1. **A CSR signature verifies for a request naming a production service. Can you approve issuance on that evidence?** The signature supports key control. Require identity validation and authorization from the applicable workflow.
2. **A leaf matches the staged key and builds a trusted chain. Is it ready for the service?** Also verify the SAN, purpose, validity and client policy. The wrong-name lab leaf illustrates why.
3. **The rollout reports success but one verified connection shows the old fingerprint. What next?** Confirm the listener, SNI, route, time and approved rollout wave. Recheck after the reload and record whether that edge serves the newly expected fingerprint.

**Completion check.** Reproduce the eight results. Write an evidence note with the authorized service name, expected leaf fingerprint, observed peer fingerprint and outcome for each simulated listener.

## Official references

Reviewed 2026-11-22. The RFC dates identify the specification versions. The OpenSSL references apply to the 3.5 series. Public TLS validity changes follow the cited issuance dates.

- IETF [RFC 2986 · PKCS #10, November 2000](https://www.rfc-editor.org/rfc/rfc2986.html) · [RFC 8555 · ACME, March 2019](https://www.rfc-editor.org/rfc/rfc8555.html) · [RFC 9525 · TLS service identity, November 2023](https://www.rfc-editor.org/rfc/rfc9525.html)
- [CA/Browser Forum · TLS Baseline Requirements v2.3.1, October 2026, §6.3.2](https://cabforum.org/working-groups/server/baseline-requirements/requirements/#632-certificate-operational-periods-and-key-pair-usage-periods)
- OpenSSL 3.5 [req](https://docs.openssl.org/3.5/man1/openssl-req/) · [x509](https://docs.openssl.org/3.5/man1/openssl-x509/) · [verification options](https://docs.openssl.org/3.5/man1/openssl-verification-options/) · [s_client](https://docs.openssl.org/3.5/man1/openssl-s_client/)
- [Python 3.12 · TLS Memory BIO support](https://docs.python.org/3.12/library/ssl.html#memory-bio-support)

[Previous · Certificate validation]({{ '/wiki/certificate-validation/' | relative_url }}) · [Next · Certificate Transparency evidence]({{ '/wiki/certificate-transparency-evidence/' | relative_url }})
