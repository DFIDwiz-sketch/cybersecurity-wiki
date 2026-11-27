---
title: "Windows Authenticode · Verify Publisher, File Hash, and Policy Evidence"
description: "Distinguish embedded and catalog signatures, interpret trusted timestamps, and correlate Windows signature verification with the software release and App Control evidence."
category: blue-team
tags: [Windows, Authenticode, Code Signing, PKI, App Control, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/windows-authenticode-evidence/
---

An analyst sees `Valid` in PowerShell for an executable that App Control blocked. Both results can describe the same file. Authenticode evaluates signed content and signer trust under a verification policy. App Control evaluates whether a file meets the host's configured execution policy. A baseline hash answers a third question about the exact file collected.

## 1. Identify the four checks

A **code-signing certificate** binds a public key to a publisher identity under a certificate authority’s process. The publisher signs format-specific content using its private key. A verifier checks the digital signature, recomputes the covered digest, and evaluates a certificate chain and trust policy. On Windows, a **Subject Interface Package** (SIP) defines how supported formats such as the Portable Executable (PE) are digested or how embedded signature data is located.

| Evidence | What it can support | Where it stops |
| --- | --- | --- |
| Embedded Authenticode signature | Verification of the signing information carried in the file itself. | A valid result applies to the content covered by the signature under the verification policy. |
| Signed catalog and a matching member hash | Verification that the file matches an entry protected by a signed external catalog. | A valid catalog signature alone does not establish that this file is a member. Catalog discovery can depend on the verifier and host. |
| Whole-file SHA-256 | The exact byte sequence agrees with a trusted release digest or a preserved copy. | The digest needs its own trusted source. It does not identify a publisher by itself. |
| App Control result | An observed policy block, or an audit-mode decision about what would be blocked. | It applies to a particular policy and attempt. It is not a full record of launches or a malware verdict. |

The PE Authenticode digest and a whole-file SHA-256 digest can cover different bytes. Microsoft documents PE fields excluded by the format-specific calculation, including the checksum and Certificate Table directory. A signature result therefore cannot substitute for a whole-file comparison. If two copies both verify but have different whole-file digests, preserve the two artifacts and determine which release and signature evidence applies to each.

<figure>
  <img src="{{ '/assets/diagrams/windows-authenticode-evidence.svg' | relative_url }}" width="560" height="334" alt="A collected file is checked three ways. Its Windows signature and applicable timestamp answer the trust question. A whole-file SHA-256 and trusted baseline answer the release question. App Control events answer the observed policy question.">
  <figcaption>Keep the file, the signature decision, and the original host’s load policy tied to their own evidence.</figcaption>
</figure>

## 2. Follow an ordinary release

1. A publisher produces `Viewer.exe` and signs it. The resulting release has both a documented signer and a SHA-256 value published through an independently trusted release channel. In a catalog-signed package, preserve the corresponding catalog information as well.
2. The publisher can obtain a **trusted timestamp**. For Authenticode it is bound to the signature and can establish that the signature existed at the recorded time. A timestamp that verifies under the applicable policy can support validity after the publisher certificate expires. Do not make this inference from an unvalidated time string, from merely seeing a timestamping certificate, or without accounting for chain, revocation, and applicable policy. Preserve the timestamp authority, time, and result if the verifier exposes them.
3. The analyst hashes a preserved copy and obtains a local signature verdict. The verifier may use a registered catalog or an embedded signature. The analyst records which path was used, the verifier and options, the OS build, and the time and trust conditions of the check.
4. A load attempt, if one occurred, is a different observation. Verify the deployed App Control mode and policy version, then investigate the Code Integrity record and separate process or module telemetry.

**Fictional result.** The preserved file matches the approved release SHA-256 and the signer selected by the verifier is the expected publisher. A previous host log still records Event 3077 because the policy on that host did not permit that load. Report the matching release and signature verification alongside the policy block. Investigate policy scope and version before concluding that the application behaved unexpectedly.

A stolen signing key or a compromised release pipeline can produce signed harmful files. A legitimate but inappropriate signed utility can also be used in an incident. Review source, behavior, change approval, known-good digests and revocation advisories. A name resembling a trusted publisher is weaker than comparing the expected certificate fingerprint or issuer and serial when these are available.

## 3. Collect the right records

| Source | Collect when available and authorized | How to use it |
| --- | --- | --- |
| Collected file and release system | UTC collection time, reported source and path, whole-file SHA-256, approved release identity, and trustworthy manifest or release record | Establish exactly which artifact each source describes. Record acquisition before comparing an apparently identical filename. |
| Windows verification | Command, executable/tool version and options, effective trust and catalog context, signer subject and fingerprint, status/message, certificate validity and validated timestamp details, if exposed | Preserve why it verified or failed. Compare the incident host’s trust state with the review system before inferring what happened earlier. |
| App Control and endpoint logs | With the applicable policy and event collection in place, collect `Microsoft-Windows-CodeIntegrity/Operational`, policy metadata, and relevant process or module data | Event 3076 reports an audit-mode would-block. Event 3077 reports a block by enforced policy. Event 3089 carries signature details for related evaluations and can be joined using the System correlation ActivityID on the same host. Preserve each signature index when several records match. |

If the digest differs from the trusted release, preserve the exact copy, collection method, manifest and signature evidence. Confirm whether the file came from a different legitimate release, has an unexpected publisher, or lacks a required trust result. If you suspect release or key compromise, scope by authenticated release metadata and artifact digests, preserve affected endpoints' records, and coordinate with the publisher and incident lead before changing allow rules. If verification could not establish trust, record the exact error and whether the verification environment had the relevant catalogs, trust chain and approved revocation access. Do not treat a failed lookup as proof of revocation.

## 4. Read-only Windows examples

These examples are for an approved Windows analysis machine and a preserved copy in a controlled folder. Replace the path with your own copy. They read metadata and do not launch the file. Verification may use the host’s certificate or catalog state and may need approved access to certificate services, depending on policy. Do not alter trust stores just to reproduce the incident result.

```powershell
$file = 'C:\Evidence\Viewer.exe'
Get-FileHash -LiteralPath $file -Algorithm SHA256
Get-AuthenticodeSignature -LiteralPath $file |
  Select-Object Status, StatusMessage, SignatureType, SignerCertificate, TimeStamperCertificate
```

The cmdlet is Windows-only. Microsoft documents catalog selection when both an embedded signature and a Windows catalog signature apply. Windows SDK **SignTool** gives a separate documented check using default Authenticode policy for user-mode files (`/pa`). The first command uses the embedded path. The second searches registered catalogs first and falls back to embedded verification if no catalog matches. Keep the commands, full output, and exit codes separately.

```powershell
signtool verify /pa /v /tw $file
$LASTEXITCODE
signtool verify /a /pa /v /tw $file
$LASTEXITCODE
```

Here `/tw` requests a warning if a timestamp is missing. SignTool distinguishes success (0), failure (1), and completion with warnings (2). Use applicable driver-specific verification guidance for drivers. Microsoft’s July 2026 guidance recommends SHA-256 or stronger for new signatures and RFC 3161 timestamping. Older SHA-1 or legacy timestamps require historical context. These Windows commands were reviewed against the documentation.

## 5. Offline exercise · Compare six cases

Use Python 3.9 or later in a directory you control. Download the script, the fictional Windows records, and the harmless text sample. The script really hashes the text sample. Signature, timestamp, and Code Integrity decisions are fictional inputs and the script never loads or verifies a Windows executable.

- <a href="{{ '/assets/labs/windows-authenticode-evidence/review_signature.py' | relative_url }}" download="review_signature.py">Download review_signature.py</a>
- <a href="{{ '/assets/labs/windows-authenticode-evidence/cases.json' | relative_url }}" download="cases.json">Download fictional Windows observations</a>
- <a href="{{ '/assets/labs/windows-authenticode-evidence/release-note.txt' | relative_url }}" download="release-note.txt">Download the text sample</a>

```sh
python3 review_signature.py cases.json release-note.txt
```

| Fictional case | What the comparison should establish |
| --- | --- |
| Approved release and trusted embedded result | Digest matches and the verifier reports `Valid`. There is no matching App Control observation. |
| Catalog match | Catalog-aware verification gives `Valid` while an embedded-only check reports no signature. An audit-mode record is not a block. |
| Hash mismatch | The verifier reports `HashMismatch` and the whole-file SHA-256 also differs from the release. |
| Expired publisher certificate | A verified historical timestamp is present and the verifier reports `Valid` in the modeled environment. |
| Valid signature, unexpected digest, enforced block | Signature trust, release mismatch and policy block are distinct results. Two related signature-detail events are preserved. |
| Trust could not be completed | The verifier result is uncertain. A same-ActivityID event from another host is excluded. |

Expect six passes and a successful whole-file hash comparison. For a negative control, append a line to a copy of the sample and rerun with the copy. The evidence cases still pass but the file comparison fails and the script exits 1. For a log-join check, change one related `3089` record’s host in the fifth case. The expected signature-detail count fails. If the original text file fails, compare its bytes with a fresh download. Some editors change line endings on save. The offline comparisons and negative controls were executed in the cloud. Windows trust and event behavior were verified against Microsoft documentation.

## 6. Check your reasoning

1. **One tool reports no embedded signature and another reports a valid catalog result. Which is right?** Both can be right. Check the verifier's selected path, the host’s catalog state and whether the file is a matching member.
2. **A timestamp field is present and the signing certificate has expired. Is the file valid?** The field does not by itself answer that. Confirm that the timestamp verifies under the applicable policy and collect the actual signature and trust result.
3. **The signer is expected, but the digest differs and the original host reports 3077. Was the file launched successfully?** Event 3077 supports a blocked attempt under the enforced policy. The digest mismatch needs release investigation. Seek separate process or module telemetry for any other attempt.

**Completion criteria.** Reproduce the six cases and both negative controls. Write one line each for the captured file's release match, selected signature path and timestamp result, and the original host's execution policy evidence.

## Official references

Reviewed 2026-11-27. Microsoft’s executable signing reference was updated July 2025 and its timestamp guidance July 2026. The PowerShell commands were checked against the 7.5 documentation. App Control examples follow Microsoft’s documented Windows client and server scope on the review date.

- Microsoft [Understanding executable file signing](https://learn.microsoft.com/en-us/windows/win32/secbp/understanding-pe-signatures) and [Authenticode timestamps](https://learn.microsoft.com/en-us/windows/win32/seccrypto/time-stamping-authenticode-signatures).
- Microsoft [Get-AuthenticodeSignature](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.security/get-authenticodesignature?view=powershell-7.5), [Get-FileHash](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash?view=powershell-7.5) and [SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool).
- Microsoft [App Control event IDs](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/operations/event-id-explanations).
- IETF [RFC 3161 · Time-Stamp Protocol, August 2001](https://www.rfc-editor.org/rfc/rfc3161.html).

[Previous · Public-key signatures]({{ '/wiki/public-key-cryptography/' | relative_url }}) · [Next · App Control decisions]({{ '/wiki/app-control-evidence/' | relative_url }}) · [Interpret Mark of the Web separately]({{ '/wiki/windows-motw-evidence/' | relative_url }})
