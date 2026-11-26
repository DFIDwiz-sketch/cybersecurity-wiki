---
title: "Windows Registry Change Evidence · Correlate Security and Sysmon"
description: "Distinguish key and value operations, trace the writer, and verify correlation across providers with fictional XML."
category: dfir
tags: [Windows, Registry, Sysmon, Event Logs, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/windows-registry-change-evidence/
---

After an application update, a workstation applies the wrong settings. An investigator finds a changed registry value, but which account requested the change and which process wrote it? Would the change have affected the reported user? To answer, preserve the object, operation, process lifetime and collection conditions. Start with [Windows log analysis]({{ '/wiki/windows-logs/' | relative_url }}) if event channels are new to you.

## 1. Keys, values and the writer

A **key** is a named container that can hold subkeys and values. A **value** has a name (which may be empty), a type and data. A **hive** is a group of registry keys and values backed by supporting files. `HKEY_LOCAL_MACHINE` (HKLM) refers to machine settings. User profile hives appear under `HKEY_USERS` (HKU) when loaded. `HKEY_CURRENT_USER` (HKCU) is a mapped handle. Its meaning depends on the calling process and the Windows mapping rules, so an analyst’s HKCU may show a different user’s view. Keep the target SID and the writer SID separate. An administrator or service can write to a different user’s hive.

WOW64 can redirect portions of the registry into separate 32-bit and 64-bit logical views, while some keys are shared. Compare the OS, process architecture, actual key and chosen view before collapsing paths. The example uses straightforward HKU paths. Keep `Wow6432Node` and `CurrentControlSet` as observed unless you can substantiate the mapping and its context.

| Source and operation | What it supports | Collection condition |
| --- | --- | --- |
| Security 4657, value change | Target key and value separately, operation, requesting account, caller PID, and old/new fields where available. Read the operation and value types before comparing the data | Effective Audit Registry success policy and a matching Set Value audit entry in the key’s SACL. A SACL specifies what to audit |
| Sysmon 12, object create or delete | Check `EventType` and target for the key or value operation | Sysmon installed and active, with effective `RegistryEvent` coverage for the operation and target |
| Sysmon 13, value set | Value write, target and writer context. Microsoft documents written data for DWORD and QWORD. Check actual event details and type coverage before using other data | Same Sysmon and filtering conditions |
| Sysmon 14, rename | A key or value rename and its new name. Read `EventType` and preserve old target and recorded new name | Same Sysmon and filtering conditions |
| Hive or live snapshot | State at capture, with key, value name, type and data where available | Collect the correct machine or user hive and view. A later snapshot does not identify the writer or reconstruct every prior value |

Security records above come from `Microsoft-Windows-Security-Auditing` in `Security`. Sysmon records come from `Microsoft-Windows-Sysmon` in `Microsoft-Windows-Sysmon/Operational`. Use provider and channel with the event ID. In 4657 the writer PID is `EventData.ProcessId`. `System.Execution.ProcessID` describes the event emission context and can be different.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-registry-change-evidence-en.svg' | relative_url }}" alt="One registry action can be observed by Security auditing and Sysmon independently. Correlate records by host, time, object and process context, then seek evidence of configuration use." style="max-width: 100%; height: auto;">
  <figcaption>Figure 1. A comparable object and a matching process lifetime make a cross-provider join stronger.</figcaption>
</figure>

## 2. Read a normal, fictional change

At 10:02:00 UTC on `WKSTN-01`, an approved example editor changes a per-user display preference `ShowGrid` from DWORD `0` to `1`. The change ticket covers that update. A Security 4657 reports `ObjectName=\REGISTRY\USER\[SID]\Software\WikiLab\Preferences` and `ObjectValueName=ShowGrid`. Its `EventData.ProcessId` is `0x1388`, or decimal `5000`. A nearby Sysmon 13 shows `HKU\[SID]\Software\WikiLab\Preferences\ShowGrid`, PID `5000` and a `ProcessGuid`. The namespaces and lengths of both paths are consistent with the same user-hive value. `[SID]` stands for the matching target SID.

Find that Sysmon identity in Event 1 and check Event 5 if available. At 10:05 the example editor exits. At 10:06 a separate invocation of the same editor starts with PID 5000 and a different GUID. A registry event at 10:07 belongs to the new lifetime if the records resolve to that GUID. The time, process image, host and lifetime matter even when the value name and number match. A SID from 4657 describes the security subject that asked for the change. It does not prove that a human typed it. A later application log that shows the preference was loaded provides another piece of evidence.

## 3. Separate change, misuse and effect

An unauthorized change to a security-relevant setting can alter a later decision or register a later trigger. Configuration management, policy refresh, software updates and repair can produce similar edits. A value set alone does not show that the application read it or that a registered action ran. Keep evidence of the write, the state after the change and later application or process behavior in the timeline.

A key rename can change the path even when the contents remain the same. A value can be deleted and then recreated. A current snapshot might appear normal after such a sequence. Check Sysmon 12 or 14 where coverage exists and preserve separately captured state. An empty value, missing field and a display placeholder all have different meanings. Preserve raw XML and types before turning any of them into a missing-data flag.

## 4. Collect, detect and respond

1. **Collect narrowly.** Preserve host and time context, raw source records, channel, provider, record ID, object identifiers and available data type. Check the source before blaming forwarding. On a Windows endpoint with permission to read the channels, the following read-only queries use a 30-minute sample window. They require PowerShell and active event generation for the target actions. Channel reads do not enable policy or configure Sysmon.

```powershell
$since = (Get-Date).AddMinutes(-30)
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ProviderName = 'Microsoft-Windows-Security-Auditing'
    Id = 4657
    StartTime = $since
}
Get-WinEvent -FilterHashtable @{
    LogName = 'Microsoft-Windows-Sysmon/Operational'
    ProviderName = 'Microsoft-Windows-Sysmon'
    Id = 1, 5, 12, 13, 14
    StartTime = $since
}
```

2. **Correlate two ways.** Match a write by host, time, operation and concrete hive key/value, then resolve the writer. Compare 4657’s data PID and image with the Sysmon writer within a known lifetime, using `ProcessGuid` within Sysmon. Correlate `SubjectLogonId` with Security 4624 only in the same host and boot context where available. Allow for sensor time granularity and gaps. One recorded process or account is not necessarily the service or operator that orchestrated the change.
3. **Investigate and verify.** Track changes to inventoried settings that fall outside the approved writer and deployment window. Include the target user SID or view as appropriate. Measure coverage by comparing a known authorized write at source and collector, and keep successful upgrades as controls. An absent 4657 may reflect audit policy, SACL or log retention. An absent Sysmon event may reflect configuration or transport. Before remediation, capture the relevant current state and process evidence. Restore the approved setting through change control and verify the application outcome. Registry data may contain sensitive paths or configuration, so limit collection and sharing to the investigation scope.

## 5. Authorized offline exercise

Download <a href="{{ '/assets/labs/windows-registry-change-evidence.py' | relative_url }}" download>the Python checker</a> and <a href="{{ '/assets/labs/windows-registry-change-events.xml' | relative_url }}" download>the fictional XML</a> into the same directory. Use Python 3 in an environment you own or are authorized to use. The checker uses only local fixture files and leaves registry settings untouched.

```bash
python3 windows-registry-change-evidence.py
```

The XML contains one Security 4657, matching and misleading Sysmon writes, two synthetic writer lifetimes, and examples of create and rename. The checker tests the channel/provider pair, PID encoding, exact supported hive aliases, alternate SIDs, and the reused PID. It accepts only explicit HKU user targets and their native equivalents in this exercise. Its fixed time window and lifecycle completeness are assumptions of the fixture. A production join needs clock and coverage checks and must handle missing or ambiguous start/stop events.

Expect `8/8 controls passed.` For a negative control, change `ObjectValueName` in the Security fixture from `ShowGrid` to `ShowOther`. The expected pair should disappear and the checker should exit with an error. If nothing matches on an unedited fixture, check file pairing, XML namespaces and the original saved character encoding. The reduced XML is synthetic and uses rendered English labels for the operation and types. The checker ran on Python 3.12. Windows audit generation, collection and application behavior were reviewed in Microsoft documentation.

## 6. Check your understanding

1. **Security shows a write to a user hive by a service account. Whose settings were edited?** Read the target hive’s SID. The subject identifies who requested the operation.
2. **Two records have PID 5000. What would make the link defensible?** Same host, verified lifetime and matching image, object and operation, with a Sysmon GUID where available.
3. **The registry change registers a later action. Did it run?** Collect evidence for the actual trigger and resulting process or application action.

**Completion criterion.** Reproduce eight controls and the negative control. Explain what the write proves and which additional event would support an observed effect. Continue with [process creation]({{ '/wiki/windows-process-creation-evidence/' | relative_url }}) and [persistence investigation]({{ '/wiki/windows-persistence/' | relative_url }}).

## Official references

Reviewed 2026-11-26. The Security event documentation describes version 0 and includes historical samples. Compare the deployed Windows build and Sysmon schema when validating coverage.

- Microsoft Windows audit reference, [Event 4657](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4657) and [Audit Registry](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-registry)
- Microsoft Sysinternals, [Sysmon event families and filters](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Microsoft Win32, [Predefined Keys](https://learn.microsoft.com/en-us/windows/win32/sysinfo/predefined-keys), [Registry Hives](https://learn.microsoft.com/en-us/windows/win32/sysinfo/registry-hives) and [WOW64 Registry Redirector](https://learn.microsoft.com/en-us/windows/win32/winprog64/registry-redirector)
