---
title: "Windows Mark of the Web Evidence · Read Zone.Identifier"
description: "Compare an NTFS download marker, file bytes, Sysmon stream creation and process evidence without confusing their meanings."
category: dfir
tags: [Windows Security, NTFS, Mark of the Web, Sysmon, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/windows-motw-evidence/
---

**Learning goal.** Two copies of a download have the same SHA-256. One carries an Internet-zone marker. Identify how that is possible, what a Sysmon stream creation event adds, and which evidence would support a claim that the file ran.

## 1. What Windows stores alongside a file

An NTFS file can have multiple **data streams**. The **unnamed stream** is the file's contents as ordinarily read by an application. A **named stream**, often called an alternate data stream (ADS), attaches separate bytes to the same file. Windows and participating applications can store zone information in a stream named **Zone.Identifier**. This form of **Mark of the Web (MOTW)** can help Windows or applications decide how to handle content.

A typical stream begins with `[ZoneTransfer]`. `ZoneId` describes a security zone. Microsoft lists 0 for Local Computer, 1 for Local Intranet, 2 for Trusted Sites, 3 for Internet and 4 for Restricted Sites. Optional producer fields such as `HostUrl` and `ReferrerUrl` can be useful leads. Their availability and meaning depend on the writer. An archive extractor, for example, may record an archive path as the referrer. Treat all values as untrusted metadata. A zone number cannot establish the file's publisher, true origin or safety.

| Observation | What it answers | What you still need |
| --- | --- | --- |
| SHA-256 of the unnamed stream | Whether the examined file bodies have the same digest | A separate ADS read or digest to compare zone metadata |
| A readable Zone.Identifier | What marker values were present at acquisition | Writer evidence and independent download or transfer records |
| Sysmon Event ID 15 | A named stream creation observed by the configured sensor | Object lifetime evidence to connect it to the file acquired later |
| Process or application evidence | Whether a relevant image started or a particular action was observed | A match to the correct image or document, plus evidence for later behavior |
| Office or application policy event | What a particular control evaluated and decided | Effective application version, configuration and the object it evaluated |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-motw-evidence-en.svg' | relative_url }}" alt="An NTFS file contains its unnamed content stream and a separate Zone.Identifier stream. Sysmon can record creation of a named stream. A separate process or application observation establishes what later ran or opened." width="480" height="378">
  <figcaption>The body, marker, creation event and later behavior are separate points of evidence.</figcaption>
</figure>

## 2. Follow a benign download

In a fictional workflow, a browser saves `report.txt` on NTFS. It records `ZoneId=3` and a source hint in `Zone.Identifier`. If Sysmon covers the event, it records the stream creation at about the same time. Later, an analyst acquires two copies. Copy A retains the marker and copy B has no observed stream after a different transfer. The unnamed-stream SHA-256 is identical. That establishes a match of the examined bodies. The transfer workflow and each acquisition explain which marker evidence was retained. Neither case supplies a process-start observation.

The producer, policy and storage all matter. Microsoft's Attachment Manager policy can affect zone preservation. The documented NTFS marker requires a filesystem that can preserve it in the relevant workflow. Microsoft notes that FAT32 does not preserve this marker. Archive extraction, synchronization and copying can alter what metadata the destination receives. Check the actual tool, version, options and destination. A browser, installer or extraction tool may write a stream for reasons other than a direct download to that final pathname.

Microsoft's Office guidance describes default blocking of internet macros on applicable Office for Windows installations. For a real decision, verify the Office build, effective policy, file location and trust settings. An Office document is typically opened *by* an application. Use application or document-access evidence and independent evidence of any later action. An Office process-start event alone does not establish that a particular document opened or that its macro ran.

## 3. Investigate misleading or missing markers

| Finding | Plausible explanations | Evidence that helps distinguish them |
| --- | --- | --- |
| Internet marker on an approved file | Normal download, expected archival workflow or a writer adding metadata | Approved source, verified publisher or artifact provenance, and matching download records |
| Marker absent at collection | The producer never wrote it, the transfer lost it, policy changed, or a different object was acquired | Source and destination file identities, stream-aware acquisition, host policies and earlier telemetry |
| Marker could not be read | Tool limitation, permission failure, unsupported storage or a vanished object | Collector result, filesystem and read method. Keep unavailable separate from a successful observation of absence. |
| Event 15 on the same pathname as the acquired file | The same file lifetime or a replacement that reused the name | Device, volume/file identity where available, create/rename/replacement timeline and content hash |
| URL looks suspicious or contradicts other evidence | Incomplete redirects, extraction metadata, inaccurate producer details or deliberate misrepresentation | Browser/proxy history, source and destination events, and application context. Avoid visiting untrusted URLs during triage. |

Zone metadata is writable by software. An adversary could misrepresent it or rely on incomplete metadata preservation to influence risk decisions. Use defenses such as policy enforcement, content inspection and verified provenance where appropriate. Absence of a marker, an Internet zone or a URL alone cannot determine maliciousness or execution.

## 4. Collect, detect and respond

1. **Preserve the file lifetime and both streams.** Record UTC, acquisition host, volume, path, file ID when available, collectors and errors. Preserve the unnamed stream and relevant named streams with a stream-aware procedure. Verify preservation on the acquired copy. Record which stream each digest covers and keep URL data inside the approved evidence store. Query strings may contain identifiers or secrets.
2. **Confirm coverage before joining events.** An enabled Sysmon configuration must collect `FileCreateStreamHash` (ID 15) and retain it in `Microsoft-Windows-Sysmon/Operational` or downstream. Microsoft documents the unnamed-stream hash and the named-stream contents for that event. Review the actual raw XML, configured hash algorithm, host, record ID, event time, full target path and writer identity. ID 15 covers named streams generally. Scope to the exact `Zone.Identifier` suffix when investigating MOTW. Scope ID 1 separately, when collected, to the process image and time. The process that wrote the stream is the writer, so its `ProcessGuid` can explain creation. A later process opening or executing the file requires its own evidence.
3. **Use a scoped detection.** Alert on stream creation relevant to the investigation, for example on monitored download paths where a subsequent execution or document-control event is independently correlated. Require the same host and an aligned lifetime and digest when available. Test normal browser downloads, an unrelated named stream, a reused pathname and a telemetry gap. A common digest can span multiple copies. Use file identity, time and movement records instead of joining solely by digest or path.
4. **Resolve the response with independent evidence.** Confirm the file against an approved source or release signature, correlate network and delivery records, and preserve evidence of any control decision. If execution is suspected, look for process identity, descendants and effects and apply the endpoint incident procedure. Keep a documented unknown when the source, execution or marker history cannot be established.

On an authorized Windows evidence copy on NTFS, with PowerShell's Windows FileSystem provider and read access, the following commands enumerate streams and compute an unnamed-stream SHA-256. Replace the path with your controlled copy. Use `Get-Content` after confirming the named stream exists. Its output can include private URLs.

```powershell
$item = 'C:\Evidence\report.txt'
Get-Item -LiteralPath $item -Stream *
Get-Content -LiteralPath $item -Stream Zone.Identifier
Get-FileHash -LiteralPath $item -Algorithm SHA256
```

For an authorized host with Sysmon and log-read access, list recent stream records, then inspect the XML only in the approved review system. A permission error, missing log or disabled event rule limits coverage.

```powershell
Get-WinEvent -FilterHashtable @{
  LogName = 'Microsoft-Windows-Sysmon/Operational'
  Id = 15
  StartTime = (Get-Date).AddHours(-24)
} | Select-Object TimeCreated, MachineName, Id, RecordId
```

## 5. Offline evidence drill

Download <a href="{{ '/assets/labs/windows-motw-evidence.py' | relative_url }}" download>the Python 3 checker</a> and <a href="{{ '/assets/labs/windows-motw-evidence-cases.json' | relative_url }}" download>the fictional evidence</a>. In one controlled folder, run:

```sh
python3 windows-motw-evidence.py
```

The checker reads local JSON and computes real SHA-256 on the stand-in body text. It compares current marker status, matching stream creation and independent process-start evidence. The example `lifetime` and image-match flags are invented collector metadata. Native Sysmon fields do not guarantee them. The case representing an executable uses harmless stand-in text.

| Cases | Expected reasoning |
| --- | --- |
| A, B, H | Equal unnamed-stream hashes coexist with Internet, absent and Trusted Sites markers. |
| C, D | Earlier stream creation can coexist with current absence. A different lifetime cannot be joined. |
| E, G, J | Unavailable read, duplicate zone keys and a URL without a zone give different evidence limits. |
| F, L | A matching creation and independently linked process start support F. Other stream names and unmatched image observations do not support L's claims. |
| I, K | A conflicting digest or event before the lifetime blocks the association. |

Expect `12/12 MOTW evidence cases matched.` and two true digest comparisons. For a negative control, copy the JSON, change the host of case A's **event** to `fixture-b`, and pass the copied filename as the argument. A remains Internet zone and changes to `stream-create-unconfirmed`. Expect 11 matches and exit status 1. For an input error, check Python 3, filenames and JSON syntax. If the mismatch is missing, check that you edited the event host and used the modified file. These tests ran in cloud Python. NTFS, PowerShell, Office and Sysmon behavior were verified by reviewing official documentation.

## 6. Check your understanding

1. **Why can two files with the same SHA-256 have different MOTW?** The digest covers the unnamed stream. Zone metadata is stored separately.
2. **Does missing Zone.Identifier prove a local origin?** It establishes absence only for an applicable, successful stream observation. Establish origin through the transfer history and independent logs.
3. **What does a relevant Event 15 contribute?** It records named-stream creation at that sensor and time. Match it to the file lifetime. Corroborate later execution separately.
4. **Does `ZoneId=3` establish an Office decision?** It establishes an observed marker value. Correlate the application, version, effective policy and actual decision.

**Completion.** Explain A/B and A/H, distinguish C from E and reproduce the negative control. Name one independent source to confirm download origin and one to assess actual execution.

## Official references

Reviewed 2026-11-26. The Windows and Office behavior described here follows current vendor documentation. Microsoft's 2018 hunting article documents historical telemetry examples and explains why producer-supplied fields vary. Check the installed build and capture configuration for your incident.

- Stream layout and attachment policy. [Microsoft NTFS file streams](https://learn.microsoft.com/en-us/windows/win32/fileio/file-streams) · [Attachment Manager policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-attachmentmanager)
- Windows Office default behavior and zone values. [Microsoft Office internet macro guidance](https://learn.microsoft.com/en-us/microsoft-365-apps/security/internet-macros-blocked#mark-of-the-web-and-zones)
- Stream creation and source metadata. [Microsoft Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-15-filecreatestreamhash) · [Microsoft download hunting analysis, 2018](https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/hunting-tip-of-the-month-browser-downloads/220454)
- Read-only commands. [Get-Item](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-item) · [Get-Content](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-content) · [Get-FileHash](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/get-filehash) · [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)

[Previous · NTFS USN evidence]({{ '/wiki/ntfs-usn-evidence/' | relative_url }}) · [Next · Sysmon investigation]({{ '/wiki/sysmon-investigation/' | relative_url }})
