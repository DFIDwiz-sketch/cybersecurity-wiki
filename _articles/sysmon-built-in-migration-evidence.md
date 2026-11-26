---
title: "Built-in Sysmon Migration · Verify Telemetry After the Switch"
description: "Compare Windows built-in and standalone Sysmon, validate a pilot with named XML fields, and locate post-migration telemetry gaps."
category: blue-team
tags: [Windows, Sysmon, Windows Event Logs, Detection Engineering, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/sysmon-built-in-migration-evidence/
---

**Learning path** · [Sysmon event investigation]({{ '/wiki/sysmon-investigation/' | relative_url }}) → migration verification → [Windows Event Forwarding]({{ '/wiki/wef-delivery-evidence/' | relative_url }}).

## 1. What changes when Sysmon becomes a Windows feature?

**Sysmon** is a Windows service and driver that records selected activity in the event log. The **standalone** release comes from Sysinternals. **Built-in Sysmon** is an optional Windows feature. Microsoft's documentation covers supported Windows 11 builds and Windows Server 2025. Check availability on the exact build and cumulative update you operate. Sysinternals dates the Windows 11 built-in option to February 2026. Earlier standalone instructions assume a different installation and update path.

| Item | Standalone Sysmon | Built-in Sysmon |
|---|---|---|
| Servicing | Track the separately deployed Sysinternals release. | Track the Windows build and update channel. Built-in binaries are serviced through Windows updates. |
| Coexistence | Microsoft requires removal of the standalone installation before enabling its built-in counterpart. | Plan a controlled transition on each host. Compare separate pilot cohorts or the same host before and after. |
| Rendered event message | Text presentation can differ from the built-in feature. | Windows can localize the rendered text. Microsoft describes the underlying event XML data as language-independent. |
| Proof of coverage | Compare the installed build, effective policy and observed events. | Compare the same evidence after migration. Feature state and service state alone leave event coverage unverified. |

An **event provider** names the component that published the record. The **channel** is the log where the source records it. The XML **System** section contains fields such as provider, event ID, computer and creation time. **EventData** contains named event-specific fields, such as `Image` and `ProcessGuid` in Process Create (Event ID 1). The **rendered message** is a display string generated for a reader. A **canary** is a harmless, uniquely labeled activity used here to verify that one expected record reaches its destination.

## 2. Trace a normal pilot

1. **Baseline.** Record the approved policy artifact and hash, binary or Windows build, locally observed event fields, and downstream events. Use a comparable host role and input. Store timestamps in UTC.
2. **Mark the transition.** Record operator, change ticket, prior coverage and start/end of the authorized change. Stop comparing different editions as if they were running concurrently on one host. Use the support requirements for the actual build.
3. **Verify local telemetry.** After the change, confirm feature and service state, review local records, then make one controlled Event ID 1 canary. Compare provider, source computer, UTC, `Image`, `ProcessGuid` and the marker in `CommandLine`.
4. **Verify delivery and search.** Follow the same event through the first receiver and the SIEM. Compare named XML values to normalized fields. Record arrival times separately from source creation time. Do not assume the collector's local record number equals the source channel's record number.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/images/sysmon-built-in-migration-evidence-en.svg' | relative_url }}" alt="An approved pilot records the Windows build and policy, a unique local process event, its forwarded copy, and the normalized SIEM record. The marker links the stages independently of rendered language." width="540" height="370" style="max-width: 100%; height: auto">
  <figcaption>Find the first stage where the matched event or a required field is missing.</figcaption>
</figure>

**Fictional normal case.** A pilot endpoint `LAB-WS01` runs a console command that prints a unique marker. Its local Sysmon XML shows Event ID 1, the expected executable, the marker and a process GUID. The forwarded copy from the same source carries those XML values even though its display message is Korean. The SIEM search returns the same canary and GUID. This proves the tested Process Create path in the observed window. Additional event types and workloads need their own tests.

## 3. Explain a gap before attributing it

| Observation | Supported conclusion | What to check next |
|---|---|---|
| Event ID 4 | Sysmon reported a service-state change. | Date it against the approved change, service inventory and last/first known good event. |
| Event ID 16 | Sysmon recorded a configuration update. | Compare the active and approved policies and the change history. The event alone leaves actor and resulting coverage open. |
| Event ID 255 | Sysmon reported an error. | Preserve the full event. Examine timing, producer health and affected event types. Avoid estimating event loss from the ID alone. |
| Local canary exists, collector does not show it in the documented window | Local generation succeeded. Delivery remains unconfirmed. | Verify subscription or agent selection, identifiers, backlog and lateness. |
| Collector has named XML fields, SIEM lacks a field | The matching event reached the collector. | Compare raw ingestion, index routing, transforms, parser and field mappings. |
| A generic ID 1 search matches a different provider | The number was reused by another provider. | Check provider, source and canary identity together. |

A mis-scoped policy or unauthorized change can remove visibility. A migration, a rendering-language change or a receiver backlog can produce a similar symptom. Compare independent evidence of the change, such as the approved ticket and system-management logs, with the coverage test. Escalate unexpected changes supported by those records. A missing canary alone does not establish tampering.

## 4. Collect, detect and respond

Use this read-only example on an authorized Windows host with PowerShell and access to the local Sysmon Operational log. The DISM query is for current, supported Windows images and may require an elevated session. An absent feature or unreadable channel is a separate observation. For evidence acquisition, preserve EVTX or raw XML instead of relying on formatted console output. Use exact times for the incident rather than the illustrative two-hour window.

~~~powershell
Get-WindowsOptionalFeature -Online -FeatureName Sysmon
Get-CimInstance Win32_Service -Filter "Name LIKE 'Sysmon%'" |
  Select-Object Name, State, PathName
$channel = 'Microsoft-Windows-Sysmon/Operational'
$since = (Get-Date).AddHours(-2)
Get-WinEvent -FilterHashtable @{
  LogName = $channel
  ProviderName = 'Microsoft-Windows-Sysmon'
  Id = 1,4,16,255
  StartTime = $since
} -MaxEvents 100 | ForEach-Object { $_.ToXml() }
~~~

The service inventory covers conventional names. Verify the intended binary against your inventory and deployment record. With the already trusted binary, `-s` displays its configuration schema and `-c` without a filename displays its current configuration. A policy-file SHA-256 and a hash field in an event can describe different inputs. Compare equivalent bytes and algorithms before using a hash mismatch as evidence. Record the effective filters as well as the intended policy artifact.

For an authorized pilot with Process Create collection configured, generate an inert marker with the following command. It prints a string and does not connect to the network. Capture the marker and UTC before searching the local Event ID 1 XML and downstream copies. If your approved policy excludes this executable, use an approved equivalent and document expected coverage.

~~~powershell
$marker = 'SYSMON-LAB-' + [guid]::NewGuid().ToString('N')
$startedUtc = (Get-Date).ToUniversalTime().ToString('o')
& "$env:SystemRoot\System32\cmd.exe" /d /c "echo $marker"
[pscustomobject]@{ Marker = $marker; StartedUtc = $startedUtc }
~~~

Collect the pre/post policy and relevant local, collector and indexed evidence. Establish the source clock and the delivery interval. Flag unexplained drops per host cohort and event type. If the local canary is absent, inspect policy, service, provider and channel first. If it reaches the collector, locate the change in ingestion or normalization before adjusting endpoint policy. Restore approved coverage through the change owner and repeat the same canary plus any required field checks.

## 5. Offline exercise · Six migration cases

Download both files into one directory in an approved workspace with Python 3. The fixtures combine fictional namespace-qualified Windows event XML and normalized SIEM rows. Rendered messages are illustrative rather than strings taken from Windows. The checker uses provider, computer, ID, UTC window and XML fields, then compares the process GUID and marker across the stages. It makes no changes to Windows and sends no traffic.

- <a href="{{ '/assets/downloads/sysmon-built-in-migration-evidence/inspect_migration.py' | relative_url }}" download>Download the Python checker</a>
- <a href="{{ '/assets/downloads/sysmon-built-in-migration-evidence/migration_cases.json' | relative_url }}" download>Download six fictional cases</a>

~~~sh
python3 inspect_migration.py migration_cases.json
~~~

| Case | Expected result |
|---|---|
| Localized messages | The test passes because the XML fields and SIEM row agree. |
| Configuration update only | No matching local process canary was observed. |
| Delivery gap | Matching local XML exists and the collector copy is missing. |
| Field lost at indexing | The indexed process identity matches but its command-line marker is missing. |
| Provider collision | A different provider's Event ID 1 is excluded. |
| Stale copy | An indexed event with matching identifiers outside the window is excluded. |

All six cases should match. To check the exercise's failure path, copy the JSON and replace the first case's indexed `command_line` with an empty string. The first comparison should fail and the script should exit 1. If it stops before case comparison, check filenames, JSON and namespace-qualified XML. The offline checker was executed. The PowerShell and real Sysmon migration steps were reviewed against Microsoft documentation.

## 6. Check your reasoning

- **Why can a message-text rule break while the sensor is healthy?** The presentation language can change while the named event data survives. Compare raw XML and the downstream parser.
- **Do IDs 4 and 16 prove a rule now generates Event ID 1?** They document service state and a configuration update. A matching local canary tests output under the effective configuration.
- **Is a passing canary enough to sign off a fleet migration?** It tests one event and one path. Repeat per required event type, build, host role, locale and forwarding route.

You have finished when you can locate each missing stage, reproduce the intentional checker failure, and define the evidence needed to sign off a named event type and delivery path.

## Official references

Reviewed **2026-11-27**. Guidance uses Microsoft's 2026 Windows Sysmon documentation, its Sysinternals release documentation and the current Microsoft PowerShell references. Verify your Windows build, servicing state and agent variant before applying the procedure.

- [Microsoft Learn · Built-in Sysmon, servicing and localization](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/overview)
- [Microsoft Learn · Configure built-in Sysmon](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon)
- [Microsoft Learn · Built-in Sysmon event reference](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)
- [Sysinternals · Standalone Sysmon and event IDs](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Microsoft PowerShell · [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent) and [Get-WindowsOptionalFeature](https://learn.microsoft.com/en-us/powershell/module/dism/get-windowsoptionalfeature).
