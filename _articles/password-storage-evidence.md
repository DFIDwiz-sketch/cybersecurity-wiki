---
title: "Password Storage Evidence · From Salt to Sign-in"
description: "Follow password registration and verification, investigate verifier exposure, and run four real scrypt checks."
category: blue-team
tags: [Cryptography, Password Storage, IAM, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /ko/wiki/password-storage-evidence/
---

**Learning goal.** Explain why an application stores a password verifier, how it checks a password, and what an analyst can infer if the verifier database was copied.

## 1. What does the server store?

A **password verifier** is the stored data the service uses to check a supplied password. In the design covered here, a **password hashing scheme** derives a value from the password, a random **salt** and **cost parameters**. The salt is generated separately for each record and stored with the result. The costs make every calculation consume time and, with memory-hard schemes, memory. A version identifies how to read and verify the record.

| Mechanism | Its role in password storage |
| --- | --- |
| Fast hash, such as one SHA-256 operation | Calculates a digest quickly. Even with a salt, a single fast digest makes guesses inexpensive. |
| Password hash, such as Argon2id or scrypt | Makes each guess cost more. The application uses a maintained verification library and benchmarks its settings. |
| Encryption | Recovers the original value with a decryption key. Ordinary password verification needs no recovery of the original password. |
| Salt | Separates records so the same password normally produces different outputs. The salt is stored with the verifier. |
| Pepper | A separate secret used by some deployments to protect stored verifiers. Its protection depends on separate custody and the threat model. |
| Passkey | The service stores a public key and verifies a signature on a challenge. The authenticator holds the signing credential. |

This chapter covers centrally verified application passwords. Directory protocols, operating-system credential formats and device-unlock PINs have different requirements and possibilities for evidence.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/password-storage-evidence-en.svg' | relative_url }}" alt="At signup the verifier combines a password with a fresh salt and policy costs and stores the result and metadata. At login it derives a candidate using the stored metadata, compares it with the saved value, then records an authentication decision without storing the password.">
  <figcaption>The registration and login calculations agree when the same password and stored settings are used.</figcaption>
</figure>

## 2. Follow a normal registration and login

A service registers two fictional test accounts that use the same test phrase. It obtains a fresh salt for each account from a cryptographically secure random generator. It stores the version, salt, cost parameters and derived value. The two records normally differ because their salts differ.

1. The application receives the supplied password over an authenticated protected connection. Use a consistent input encoding and normalization policy. Changing it can break verification of existing records. Avoid recording inputs in application logs or telemetry.
2. Locate the account's verifier and select the trusted library and matching version. Read the salt and policy-bounded costs. The verifier derives a candidate value and uses the library's comparison procedure. The example uses a constant-time comparison function for fixed-length byte values.
3. A match establishes that the supplied password matched the verifier. The login can still require another factor or deny the session under an access policy. Log the outcome for the relevant stage. A successful password check and an issued session answer different questions.
4. On a successful check under an older supported policy, the application can derive a fresh record using the submitted password, new parameters and a fresh salt. Apply the update so it cannot overwrite a concurrent password reset. Track the remaining old records. Accounts that never log in may need a reset to finish migration.

The comparison function only addresses the value comparison. Different account lookup paths, expensive parameter choices and concurrent requests can still affect timing and resource use. Production services need bounded parameters, admission controls, rate limiting and capacity testing.

## 3. Interpret possible exposure

With a copied verifier database, someone can test guesses away from the login service. Rate limits cannot reach those offline guesses. Unique salts make identical passwords harder to link across rows and prevent sharing one precomputed result across different salts. Password hashing raises the cost per guess, but a weak password can still be guessed. Separate custody of a pepper can help when the database alone was exposed. Check whether the application process, backups or secret infrastructure were also accessible before assuming that protection held.

Online password reuse produces different evidence. Credential stuffing uses credentials obtained elsewhere and submits them to the service. Logs may show failed and successful sign-ins, but do not identify the source of the credentials on their own. The absence of repeated failures leaves offline exposure possible. One successful sign-in, an unfamiliar IP or a shared network address alone cannot establish account takeover.

| Record or finding | Question it can help answer |
| --- | --- |
| Database read/export or backup audit | Was there a successful access path to the verifier data? Identify the principal, objects, time and destination where recorded. A denied request establishes only the result of that request. |
| Verifier policy and deployment inventory | Which algorithm and costs applied to new and legacy records at the time? Count vulnerable versions from controlled metadata rather than exporting hashes. |
| Secret-manager or hardware-service audit, where deployed | Was pepper access, or use of the service performing the keyed operation, observed? Check audit coverage and permissions. |
| Authentication and session telemetry | Were passwords accepted, second factors satisfied or sessions issued and used? Correlate timestamps and identifiers in the relevant application. |

## 4. Collect, detect and respond

1. **Scope the incident.** Record the suspected window in UTC, database or backup objects, principal and operation result. Check retention, routing and read coverage. Preserve original records in a restricted location.
2. **Compare expected access.** Reconcile bulk exports or backup reads against scheduled jobs, maintenance approvals and expected identities. Compare database activity with storage and destination evidence. For login abuse, look for a pattern across accounts or unexpected successful sessions, not only failed requests.
3. **Confirm exposure and contain it.** Restrict the affected access path, preserve evidence and identify which verifier versions and accounts were in scope. Validate what sensitive material and supporting logs actually existed. Use the incident plan to determine password resets, session revocation and recovery actions. A compromise-triggered reset is distinct from routine password expiration.
4. **Validate recovery.** Check that affected sessions are revoked where intended and newly reset or upgraded records use the new policy. For pepper deployments, confirm authenticated key use and follow the application's recovery design. Replacing a compromised pepper can require password resets when verification cannot be migrated without the password. Keep passwords, hashes, salts tied to account records, recovery tokens and secret keys out of shared tickets and alert bodies.

## 5. Run the offline verification lab

Download the <a href="{{ '/assets/labs/password-storage-evidence.py' | relative_url }}" download="password-storage-evidence.py">Python script</a>. Run it in your own approved workspace with Python 3.13 or another supported Python 3 runtime providing OpenSSL-backed `hashlib.scrypt`, and enough memory. It uses embedded fictional inputs, generates two random 16-byte salts, and prints checks without printing the derived values. It reads no account database and makes no network requests.

```bash
python3 password-storage-evidence.py
```

```text
PASS: separate salts and verifier values
PASS: both records accept the matching password
PASS: an incorrect password is rejected
PASS: changing the stored salt breaks verification
```

The lab uses scrypt with `N=2^17, r=8, p=1`, an OWASP example when Argon2id is unavailable. Each derivation uses about 128 MiB for its main memory requirement. The example gives OpenSSL a 256 MiB memory limit for that call, including overhead. If Python reports that scrypt is unavailable, use a Python build with OpenSSL support. If allocation fails, check the environment's memory and crypto configuration. The exercise runs sequentially and does not measure service capacity or implement a full authentication service.

## 6. Check your reasoning

- **The two accounts used the same test phrase. Why do their records differ?** Each uses a separately generated salt. Knowing a salt does not supply a password or the verifier's optional secret key.
- **Does a password match prove the account was taken over?** Use the surrounding authentication, session and activity evidence to determine who used the account and what followed.
- **There were no bursts of failed sign-ins. Does that rule out exposure?** Offline testing of a copied database is outside the login service. Check database, backup and secret access separately.

Finish when the four checks pass and you can distinguish a password match, a successful session, a database export and evidence of subsequent misuse.

## Official references

Reviewed November 23, 2026. NIST's final 2025 revision gives requirements for verifiers in its scope. OWASP publishes algorithm and parameter recommendations for applications. Legacy bcrypt records may need migration. Choose controls appropriate to deployment and compliance requirements.

- Password verifier storage, migration metadata, protected transport and rate limiting. [NIST SP 800-63B-4, July 2025](https://pages.nist.gov/800-63-4/sp800-63b.html#passwordver)
- Algorithm recommendations, work factors and pepper handling. [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- scrypt algorithm and parameters. [RFC 7914, August 2016](https://www.rfc-editor.org/rfc/rfc7914.html)
- Standard library behavior. [Python 3.13 hashlib](https://docs.python.org/3.13/library/hashlib.html#hashlib.scrypt)

[Related · Public-key cryptography]({{ '/wiki/public-key-cryptography/' | relative_url }}) · [Next · Passkey sign-in evidence]({{ '/wiki/passkey-signin-evidence/' | relative_url }})
