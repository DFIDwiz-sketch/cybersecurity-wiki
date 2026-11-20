---
title: "Preserving Digital Evidence · SHA-256 and Custody"
description: "Preserve acquisition provenance and verify working copies and ZIP payloads in an offline SHA-256 lab."
category: dfir
tags: [DFIR, Incident Response, Evidence, SHA-256, Blue Team]
level: Beginner
updated: "2026-11-20"
translation_url: /ko/wiki/evidence-preservation/
---

**Learning goal.** Decide what to record for an acquired file, a working copy and a derived artifact. Verify matching bytes with SHA-256 and describe precisely what the result supports.

## 1. Start with the source and scope

Suppose a network operator exports a firewall log for 00:00–00:15 UTC. Record the account and device, query range, filters, export time and acquisition method. The file is the **preserved acquisition** of that query result. Its scope differs from the device’s complete history or a full disk acquisition. A later export can differ because of retention, late arrivals or ordering.

![Record scope and source → Preserve acquisition and reference hash → Make and verify a working copy → Record derivatives and transformations → Verify transfer and document custody]({{ '/assets/diagrams/evidence-custody-en.svg' | relative_url }})

| Item | Purpose | Example |
| --- | --- | --- |
| Provenance | Who acquired what and how | Device, log type, query period and method |
| Preserved acquisition | Retained first acquired bytes | JSONL in access-controlled storage |
| Working copy | Verified duplicate for analysis | Copy in the analyst workspace |
| Derivative | Output of a documented transformation | UTC-normalized CSV or redacted report |
| Custody record | Trace changes in possession and handling | Transfer time, personnel, purpose and checks |

Volatile data capture, disk images and cloud API exports need different methods. Follow the authorized acquisition procedure and document changes or limits introduced by live acquisition.

## 2. Understand what the hash supports

SHA-256 maps input bytes to a 256-bit digest usually displayed as 64 hexadecimal characters. A match against a protected reference digest gives strong evidence that file content bytes match. A conventional content hash does not cover the path, filename, access permissions or filesystem timestamps.

| Result | What it supports | Evidence still needed |
| --- | --- | --- |
| SHA-256 match | Bytes agree with the reference | Source, completeness and pre-acquisition state |
| SHA-256 mismatch | Bytes read under the same procedure differ | Transfer damage, line endings, compression, version or deliberate change |
| Valid digital signature | The signature verifies under a trusted key | Key ownership and acquisition trust |
| Custody record exists | Handling is traceable | Verification outcomes and missing steps |

Someone who can replace a file and its reference digest can hide a change from a simple comparison. Keep the reference in controlled records with authorship and timing. Capture important metadata separately.

## 3. Preserve, copy and hand over

1. **Record scope.** Capture case and artifact IDs, source and vantage point, time range, tool and version, operator and approval scope. For SIEM exports, retain query, time zone and result limits.
2. **Preserve the acquisition.** Store the acquired bytes in approved storage. At the earliest feasible point, record size, SHA-256 and UTC. If only the export can be hashed, specify that the digest applies to the export.
3. **Verify a working copy.** Compare the copy’s digest with the reference. On mismatch, pause affected analysis and compare paths, tool settings and transfer details. Retain both files and record copying and verification.
4. **Link derivatives.** Give filtered, normalized or redacted outputs their own artifact IDs and hashes. Record parent ID, transformation, tool options, scope and time.
5. **Verify the handover.** Record who transferred and received the item, the purpose, UTC, received digest and verifier. Keep separate references for a ZIP and its extracted payload.

Example note. **“Artifact E-07 contains edge-a events from 00:00–00:15 UTC in an approved export. Operator A recorded SHA-256 at 00:22 UTC and operator B verified the received file at 00:30 UTC. Application logs are outside this acquisition’s scope.”** Use the identities and storage reference required by your procedure in actual records.

## 4. Investigate inconsistencies and possible misuse

| Observation | Possible explanation | Evidence to gather |
| --- | --- | --- |
| ZIP hash differs from its file | They represent different byte streams | Their separate reference digests |
| Text looks the same and hash changed | Line endings, encoding or whitespace changed | Original file and transformation history |
| Stored digest differs from first recorded value | Transfer error, wrong version or unauthorized change | Storage and access audits, file sizes and independent copies |
| Acquisition scope is missing | Filters or result limits were omitted | Tool output, query, time range and gaps |
| File and reference both changed | Authorized replacement or possible evidence tampering | Independent custody record, versions and access history |

Keep the original reference when a mismatch occurs. Record observed values and paths separately and retain files and audit records. If a mismatching copy was used, mark it and review affected analysis once the scope is established.

## 5. Offline exercise · Similar text, different bytes

[evidence-sample.jsonl]({{ '/assets/labs/evidence-sample.jsonl' | relative_url }}) · [evidence-hash-lab.py]({{ '/assets/labs/evidence-hash-lab.py' | relative_url }})

Save both files in one folder and use Python 3.11 or later. The input contains two fictional log lines. Use the original download because saving through an editor can change line endings. The script reads the input and changes only disposable copies in a temporary directory.

~~~bash
python3 evidence-hash-lab.py
~~~

| Test | Expected result |
| --- | --- |
| Exact copy | Matches the reference SHA-256 |
| Rename the copy | Digest stays the same because the bytes stay the same |
| Convert LF to CRLF | Digest changes even though the lines look similar |
| Create ZIP and read its payload | ZIP gets a separate digest and its extracted file matches the reference |

Expect `DONE: four checks passed; original fixture unchanged`. If loading fails, check the filenames and folder. If the line-ending check fails, download the original again. Archive metadata such as timestamps can change the ZIP digest between runs. Verify each transferred archive against the digest recorded for that archive. Publication verified local copy, archive and hash handling. Production collection and formal custody procedures require validation in context.

## 6. Check your understanding

- **Does a matching hash establish that the evidence is true and complete?** It supports byte agreement with the reference. Check source, filters, missing data and pre-acquisition integrity separately.
- **Can a redacted report have a different digest?** Give the derivative its own digest and record the parent ID and transformation.
- **Does a ZIP digest different from the contained file imply corruption?** Compare each byte stream with its own reference.

Finish by explaining the expected working and transformed copy results. Write a fictional custody entry with artifact ID, origin, UTC, reference digest and recipient.

[Previous · Incident timelines]({{ '/wiki/incident-timeline-evidence/' | relative_url }}) · [Next · Windows incident response lab]({{ '/wiki/windows-incident-response-lab/' | relative_url }})

## Official references

Reviewed 20 November 2026. The 2006 NIST guide provides acquisition foundations. See the separate incident response, digest and runtime references.

- [NIST SP 800-86 · Forensic techniques, August 2006](https://csrc.nist.gov/pubs/sp/800/86/final)
- [NIST SP 800-61 Rev. 3 · Incident response, April 2025](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [NIST FIPS 180-4 · Secure Hash Standard, August 2015](https://csrc.nist.gov/pubs/fips/180-4/upd1/final)
- [Python 3.12 · hashlib and file_digest](https://docs.python.org/3.12/library/hashlib.html)

## Velociraptor Endpoint Collection

[Go from a network lead to reviewed host evidence]({{ '/wiki/endpoint-collection-evidence/' | relative_url }})

## Apply Integrity Checks to Backup Recovery

[Follow a matching digest with database, checkpoint and service checks]({{ '/wiki/backup-restore-evidence/' | relative_url }})
