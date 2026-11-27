---
title: "Windows Process Creation Evidence · Correlate 4688 and 4689"
description: "Read creator and target identities, distinguish PID lifetimes, and verify process evidence in an offline Windows event XML lab."
category: dfir
tags: [Windows, Windows Security, Event Logs, Process Creation, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/windows-process-creation-evidence/
---

**Learning goal.** Determine which process Windows recorded starting, which identity requested the start, which process lifetime could have created it, and what evidence is needed to show a later effect.

## 1. Read the event as a record of creation

A **process** is a running instance of a program. Its **PID** is unique among active processes on that host and can be reassigned after exit. A **logon session** is the security context of a logon. A **Logon ID** identifies that context on its own system within the applicable boot. It is a different identifier from a PID. An **access token** represents the process's identity and security context, including groups and privileges.

| Record or field | What it supports | What to retain |
| --- | --- | --- |
| Security 4688 | A process started when success auditing for Process Creation was effective | Host, UTC time, version, record ID, new image and PID |
| Creator Subject | Account and session requesting creation | Subject SID and Logon ID |
| Target Subject | A distinct run context when recorded in version 2 | Target SID and Logon ID, kept separate from the creator |
| Creator Process ID and Name | The event's recorded creator PID and image when available | XML `ProcessId` and `ParentProcessName` in 4688 |
| Security 4689 | A process exited when success auditing for Process Termination was effective | Exit time, `ProcessId`, `ProcessName` and reported exit status |
| Sysmon 1 and 5 | Creation and termination, when Sysmon is installed and those events are collected | `ProcessGuid`, host, UTC time, PID and image |

In native 4688 XML, the child PID is `EventData/NewProcessId`. `EventData/ProcessId` is the creator PID. Read the named `Data` elements inside `EventData`. The `System/Execution` attribute is event-provider execution metadata and gives neither of these process roles. Microsoft's event versions explain why `CommandLine` appears from version 1, while target subject, integrity label and creator filename were added in version 2. Parse by name and keep absent and empty values distinct.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-process-creation-en.svg' | relative_url }}" alt="On the same host and boot, a candidate creator starts, then a 4688 records the new process and its creator. A 4689 can close a PID lifetime. Later reuse of the number represents a different process.">
  <figcaption>Start with host and boot. Use creation and exit records to place a creator PID in its observed lifetime.</figcaption>
</figure>

## 2. Walk through a normal start

Suppose a fictional reporting service on `workstation-a.example` starts a read-only status worker.

1. At 08:00 UTC a 4688 records the report launcher at `0x410` (decimal 1040). At 08:02 another 4688 has Creator Process ID `0x410` and New Process ID `0x5b0` (decimal 1456), with distinct images for the two executables. Compare their paths, host, boot and times. Verify whether anything in the collected timeline contradicts the creator candidate.
2. The creator SID is the service account. A version-2 Target Subject may identify a different run context. When a valid target is recorded, use its SID and Logon ID to research the worker's corresponding 4624 separately from the creator's session. A placeholder SID such as `S-1-0-0` or a zero Logon ID does not establish a second session. Keep an omitted target context unresolved when it matters.
3. At 08:04 a 4689 reports that the worker exited. At 08:09 an editor receives PID `0x5b0`. Those are separate lifetimes. Later observations keyed to 1456 require their own time and image context. Sysmon's ProcessGuid can provide a stronger join across covered Sysmon events. There is no ProcessGuid in native 4688. Correlate sources using the original endpoint, time, PID and image before carrying a GUID across.
4. A recorded command line describes launch arguments. It does not show that every argument was acted on, every command in a script succeeded, or a file or network action completed. Confirm the operation in its own telemetry. A high integrity label and an elevated token describe execution context. They do not show that a particular privilege was exercised.

## 3. Collect, detect and respond

Unexpected launcher–child combinations can reveal execution through legitimate administrative tools. Authorized deployment, accessibility tooling and scheduled jobs can create unusual combinations too. Compare the image path, creator, session, host role and maintenance window before attributing intent.

1. **Verify coverage at the source.** Check effective Advanced Audit Policy for Audit Process Creation and, if needed, Audit Process Termination. Command lines require the separate **Include command line in process creation events** setting and the applicable event version. A blank value does not prove the process had no arguments. Compare the native XML with the forwarded copy and check policy, event version, channel retention and parser mapping. Command lines can contain credentials or private values in plain text. Limit raw log access and share a redacted working copy.
2. **Preserve IDs and time.** Keep provider, channel, source computer, original UTC timestamp, version and record ID. A collector's hostname or ingestion time describes the collection path. Gather boot context separately because 4688 does not carry a boot ID. Normalize hexadecimal PIDs against decimal sensor PIDs while retaining original values. Use a known earlier start, observed exit and any succeeding reuse to bound a candidate. A missing exit may reflect configuration or retention. Treat a PID-only join as conditional.
3. **Test the observed behavior.** For a new creator–child pair, compare the usual image locations, service or task inventory and approved change history. Verify a suspected write with appropriately collected file evidence, or a suspected connection with endpoint or network records. Check telemetry coverage before using absence to rule an action out. A launcher name, token level or one argument is insufficient to infer a compromise.
4. **Respond with corroboration.** Preserve the raw timeline and relevant logs before changing a workload. In a supported incident, scope the affected lifetime and sessions, then coordinate containment with the asset owner. Validate the same collection and joins with a known benign execution after policy or parser changes.

### Read-only event collection

On an authorized Windows host with the relevant audit policy and permission to read Security, use PowerShell's filtered query for the affected host and time. The example targets the latest 15 minutes. Replace that window for an investigation. The data may be sensitive and should stay in approved storage. Inspect XML names rather than positions in `Properties`.

```powershell
$end = Get-Date
$start = $end.AddMinutes(-15)
Get-WinEvent -FilterHashtable @{
  LogName = 'Security'
  ProviderName = 'Microsoft-Windows-Security-Auditing'
  Id = 4688, 4689
  StartTime = $start
  EndTime = $end
} | ForEach-Object { $_.ToXml() }
```

This emits separate event XML strings. It is not an EVTX export or the fixture format below. For a known control, use a harmless tool launch in an approved test system and note its host and time. If an expected creation or termination is missing, verify the source policy and native log before debugging forwarding. A current control cannot repair a historical collection gap.

## 4. Practice with synthetic event XML

Save the <a href="{{ '/assets/labs/windows-process-creation-evidence.py' | relative_url }}" download="windows-process-creation-evidence.py">Python script</a> and <a href="{{ '/assets/labs/windows-process-creation-cases.xml' | relative_url }}" download="windows-process-creation-cases.xml">fixture XML</a> together in an authorized workspace. Use Python 3.9 or newer. The file contains abbreviated, synthetic namespaced Windows events. Case labels, boot annotations and expected results are supplied by the fixture wrapper. They are not native 4688 fields. The script reads files locally and neither starts a Windows process nor changes audit settings.

```bash
python3 windows-process-creation-evidence.py windows-process-creation-cases.xml
```

| Case | Expected finding |
| --- | --- |
| `routine_creator` | One prior creator candidate, arguments recorded |
| `reuse_after_exit` | Match the later lifetime. The prior PID holder exited. |
| `different_target` | Creator and target session identifiers are distinct |
| `blank_command` | Command field exists and is empty |
| `older_schema` | Command field is absent in version 0 |
| `different_boot` | Same PID in a different boot does not join |
| `reuse_without_exit` | A later start supersedes the earlier holder. Its exact exit remains unobserved. |
| `creator_image_mismatch` | Earlier PID exists, but the documented creator path disagrees |

All eight should print PASS. In a copy of the XML, change the routine creator's boot annotation while leaving the new process in the original boot. The former creator candidate should disappear and the original expectation should fail. If the script cannot read the fixture, check the names and directory. For an unexpected join, inspect each case's boot annotation, UTC order, named PID fields and creator image.

The XML lab was executed in the cloud. The PowerShell query, audit settings and Sysmon behavior were checked against Microsoft documentation. No Windows audit policy or Sysmon collector was exercised here.

## 5. Check your reasoning

- **4688 has a new PID, creator PID and System Execution PID. Which locates the possible creator?** Use the named `EventData/ProcessId` field and constrain the lifetime. The system attribute describes event generation.
- **A current task list has the right decimal PID. Does that prove it is the process from yesterday?** Compare host, boot, lifetime and image. A PID may have been reused.
- **Does an empty native command line prove there were no arguments?** Check event version, effective command-line policy and collection. The field can be empty even when arguments existed.

Finish when the eight cases pass and you can write a finding with what started, the requesting and recorded run contexts, the creator candidate and one independent effect record you would seek.

## Official references

Reviewed November 26, 2026. Event versions and fields follow Microsoft's Windows auditing reference. Confirm effective policy and event version on the Windows and Sysmon builds in your environment.

- Event XML, version history and fields. [4688 process creation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688) · [Execution element](https://learn.microsoft.com/en-us/windows/win32/wes/eventschema-execution-systempropertiestype-element) · [4689 process exit](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4689)
- Process auditing and command-line policy. [Audit Process Creation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-process-creation) · [Audit Process Termination](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-process-termination) · [IncludeCmdLine policy](https://learn.microsoft.com/en-us/windows/client-management/mdm/policy-csp-admx-auditsettings#includecmdline)
- Supplementary telemetry and filtered queries. [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) · [Get-WinEvent FilterHashtable](https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable)

[Previous · Windows security event analysis]({{ '/wiki/windows-logs/' | relative_url }}) · [Next · Sysmon process investigation]({{ '/wiki/sysmon-investigation/' | relative_url }}) · [Related · Privileged logon evidence]({{ '/wiki/windows-privileged-logon-evidence/' | relative_url }})

## Correlate a registry write with its writer

Read [Windows registry change evidence]({{ '/wiki/windows-registry-change-evidence/' | relative_url }}) to compare Security 4657 with Sysmon registry and process-lifetime records.

Practice independent execution corroboration in [Defender ASR rule evidence]({{ '/wiki/windows-asr-rule-evidence/' | relative_url }}).
