---
title: "OpenSSH User Certificates · Verify the CA, Principal and Revocation"
description: "Read signed user certificates, distinguish identity from authorisation, and verify an OpenSSH key revocation list offline."
category: blue-team
tags: [SSH, OpenSSH, Linux, Authentication, Cryptography, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/ssh-user-certificate-evidence/
---

**Learning goal.** Given an SSH user certificate and a failed or successful login, explain which party was verified, which local account was requested, and which evidence shows whether a revocation reached the destination server. For host identity, start with [SSH host-key evidence]({{ '/wiki/ssh-host-key-evidence/' | relative_url }}).

## 1. What the certificate binds

A **user key pair** has a public key and a private key. The client proves it can use the private key during authentication. A **certificate authority (CA)** signs a statement binding the user's public key to particular attributes. In OpenSSH, a **user certificate** can carry principals, a validity interval, restrictions, a serial and a key ID. The CA signature lets a server trust that statement if it already trusts the CA for user authentication. It does not replace the client's proof of possession. OpenSSH certificates are an SSH-specific format. X.509 browser certificate stores and OCSP are separate systems.

| Object or field | What it means | Investigation limit |
| --- | --- | --- |
| Server host key or host certificate | The client verifies the server during SSH setup. | Does not establish who logged in. |
| User certificate and corresponding private key | The server verifies a CA statement and evidence that the client can sign using the subject key. | Possession may involve an agent or device. It does not prove who was sitting at the keyboard. |
| Principal | A name contained in the signed certificate for authorisation. | The destination still applies its mapping to the requested operating-system account. |
| Serial and key ID | Serial identifies an issuance within a CA's scope when allocated. Key ID is a signed label that can help investigate. | Serial alone is ambiguous across CAs. Key ID is not necessarily unique and is not the principal. |
| Key revocation list (KRL) | An OpenSSH-format file specifying revoked keys or certificates. | Requires deployment and enforcement at the verifier. A local query covers only the supplied file. |

<figure style="margin-inline: 0">
<img src="{{ '/assets/diagrams/ssh-user-certificate-evidence-en.svg' | relative_url }}" alt="The client checks the host. The server checks possession of the user key and the certificate policy. Evidence for a later shell or action is collected separately.">
<figcaption>Host authentication, user authentication and what happens in the resulting session are separate checkpoints.</figcaption>
</figure>

## 2. Follow a normal authentication

In a fictional organisation, a role called `lab-auditor` is allowed to use local account `audituser` on one maintenance host. The approved issuer signs the employee's public key for that role. The short-lived certificate has serial 43 and key ID `lab-issued-43`. The issuer records the CA fingerprint, serial, subject key fingerprint, principal and approval.

1. The client checks the server host key or host certificate using previously established trust.
2. The client requests `audituser` and proves possession of the private key corresponding to the certified public key. The server validates the certificate signature under its allowed CA and checks certificate type, time, restrictions and revocation.
3. On the **TrustedUserCAKeys** authentication path, the daemon checks the principal for the requested local account. `AuthorizedPrincipalsFile` or `AuthorizedPrincipalsCommand` can supply allowed principals. The fictional account must map to `lab-auditor` for this example to work. For the standard TrustedUserCAKeys path without such a mapping, the requested username must appear in the principals list. The principal file does not govern the separate CA trust path in `authorized_keys`.
4. A verified credential can still be refused by account rules or require another authentication method. An accepted authentication record establishes the login decision. Use session and process evidence to establish subsequent activity.

On a trusted administrative workstation, these two read-only commands can inspect a public certificate and check it against a **specific local KRL**. Use authorised copies, keep the original bytes and record the file version and origin. No server connection is made.

```bash
ssh-keygen -L -f sample-cert.pub
ssh-keygen -Q -f deployed-copy.krl sample-cert.pub
```

`-L` prints certificate fields. It does not establish a server's trust or authorisation decision. With `-Q`, a successful query of an unlisted certificate can print `ok`, even after expiry. When the command exits nonzero, inspect its diagnostics to distinguish a listed entry from a file or input error.

## 3. Understand failures and misuse

| Observation | Plausible causes | Evidence to compare |
| --- | --- | --- |
| Certificate rejected after a rollout | CA mismatch, unexpected principal mapping, wrong host policy or certificate restrictions | Effective daemon config for that account and connection, issuer record, certificate fields |
| A still-approved user is rejected around expiry | Clock skew, old certificate still selected, or issuance outage | Host UTC and offset, exactly which certificate the client offered, and issuer timeline |
| Same serial reported on two systems | Different issuing CAs or duplicate issuer serial allocation | CA fingerprint plus serial, then subject key, key ID and time |
| KRL was built but a host still accepts the credential | Stale or unused list, different CA scope, direct user-key path, or observation from an existing connection | Effective `RevokedKeys`, deployed content, authentication method and fresh connection evidence |

A stolen private key can be paired with its still-usable certificate. Short validity limits the certificate's future use, while issuer compromise or overbroad principal mappings can expose more accounts. Certificate expiry and KRL updates govern later verification attempts. They do not by themselves prove that existing sessions ended. Check raw-key or other permitted authentication paths separately when judging containment.

## 4. Collect, detect and respond

1. **Read the destination record first.** Keep UTC, clock uncertainty, host, requested local account, source network metadata, the actual authentication method and session identifier if available. Keep CA and subject fingerprints, serial and key ID where logged. Coverage varies with OpenSSH build, log settings and collection. See [Linux authentication evidence]({{ '/wiki/linux-auth-evidence/' | relative_url }}). A client error alone does not reveal the server's effective policy.
2. **Correlate issuance and host policy.** Join on CA fingerprint plus a recorded nonzero serial, corroborating with subject key fingerprint, key ID, principal and validity. Recover the server's CA trust, authorised principals and `RevokedKeys` as they stood at event time. Current configuration can differ, especially with conditional settings and fleet rollout. Preserve public evidence and policy hashes. Keep private keys out of investigations and general logs.
3. **Check revocation deployment.** An authorised offline query against the KRL copied from the host is useful. Compare the configured path and version to the narrowly scoped change. OpenSSH documents that an unreadable configured `RevokedKeys` file can cause public-key authentication to be refused for all users. Check configuration and availability before interpreting failures as selective revocation.
4. **Verify containment with the owner.** Use an approved new connection to a controlled test destination after rollout. Check a revoked credential and an unaffected positive control under the intended policy. Separately identify affected existing sessions and review commands or access with appropriate telemetry. If an issuing CA is compromised, coordinate CA trust changes and reissuance rather than treating one serial as the whole scope.

## 5. Offline lab · test what the KRL actually says

Download <a href="{{ '/assets/labs/ssh-user-certificate-lab.py' | relative_url }}" download>the OpenSSH certificate lab</a> and run `python3 ssh-user-certificate-lab.py` in an authorised test environment with Python 3 and OpenSSH client tools in PATH. It creates two disposable CAs, a disposable subject key and four real user certificates in a temporary directory. Do not add the keys to any trust store. The lab opens no sessions and removes its temporary files on exit.

| Case | Control | Expected |
| --- | --- | --- |
| A | Read the user certificate with serial 42, key ID `lab-issued-42` and principal `lab-auditor` | Inspection confirms the fields |
| B | Query serial 42 signed by CA A against the KRL for CA A's serial 42 | `REVOKED` |
| C | Query serial 43 from CA A | `ok` for that KRL |
| D | Query serial 42 from CA B | `ok` for that KRL |
| E | Query an expired certificate, CA A serial 44 | `ok` for that KRL, even though the expiry interval is past |

Expect `5/5 OpenSSH tool checks matched. No SSH session was attempted.` If `ssh-keygen` is missing or Ed25519 is unavailable under the environment's policy, check the installed tools and test scope. If D appears revoked, inspect which CA public key scoped the KRL rule. If E looks like login success, distinguish the KRL result from time and server authorisation checks. The five checks were executed with Debian OpenSSH 10.0p2. Server authentication and log collection were reviewed from the official manuals and were not exercised.

## 6. Check your reasoning

1. **A certificate lists `lab-auditor`. Does that alone allow login as `audituser`?** Check CA trust and the destination mapping for that account, plus validity and other server rules.
2. **A KRL lists CA A's serial 42. What about CA B's serial 42?** A serial-scoped rule for one CA does not match the other CA. Use the issuer fingerprint and serial together.
3. **An expired certificate is `ok` in a KRL query. Is expiry ignored by the server?** The query only evaluates the supplied list. Server time policy is a separate check.
4. **An accepted certificate is in the log. What proves commands ran?** Correlate independent session, process or application evidence.

**Completion criteria.** Distinguish host identity, subject-key proof and account authorisation. Predict all five results and name one source that could confirm which KRL a server used.

## Official references

Reviewed 2026-11-22. The offline lab used Debian OpenSSH 10.0p2. Defaults, log details and accepted algorithms depend on the deployed version.

- [OpenBSD ssh-keygen(1)](https://man.openbsd.org/ssh-keygen) for certificate fields, signing and KRL operations.
- [OpenBSD sshd_config(5)](https://man.openbsd.org/sshd_config) for trust, principal mapping and revocation.
- Debian trixie [ssh-keygen(1)](https://manpages.debian.org/trixie/openssh-client/ssh-keygen.1.en.html) and [sshd_config(5)](https://manpages.debian.org/trixie/openssh-server/sshd_config.5.en.html) for distribution-version context.
