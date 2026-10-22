---
title: "Windows Credential Protection: LSASS, SAM, LSA Secrets, Credential Guard and Dumping Detection"
description: "Distinguish Windows credential stores and protection boundaries, verify Credential Guard and LSA protection, investigate LSASS access with Sysmon and Splunk, and practice evidence-based containment."
category: blue-team
tags: [Windows Security, Credential Access, Credential Guard, LSA Protection, LSASS, Blue Team, DFIR, Sysmon, Splunk, Detection Engineering, MITRE ATT&CK]
level: Intermediate
updated: "2026-10-22"
translation_url: /ko/wiki/windows-credential-protection/
---

> **Windows identity-defense extension.** Continue from [Sysmon investigation]({{ '/wiki/sysmon-investigation/' | relative_url }}), [Windows persistence]({{ '/wiki/windows-persistence/' | relative_url }}) and [NTLM authentication]({{ '/wiki/ntlm-authentication/' | relative_url }}). Examples inspect state, policy or logs. No process memory, registry hive, password hash or authentication ticket is extracted. All exercise identities and GUIDs are fictional.

## 1. Credential access is a separate investigation claim

Credential dumping seeks reusable authentication material from operating-system memory or stores. It can precede account abuse and lateral movement, but process execution, access to LSASS, a suspicious filename and a successful remote logon are four different observations. [MITRE T1003](https://attack.mitre.org/techniques/T1003/).

Investigate a sequence: **which process acted, which material was reachable, what protection applied, what operation actually succeeded, and whether any identity was later abused**. Do not convert one alert into an unsupported claim that every account on the machine was stolen.

This guide covers common Windows credential stores and defensive triage. It does not teach dumping commands, protection bypasses, offline cracking or production exploitation. Domain-controller compromise and directory replication abuse require a separate identity-infrastructure response.

## 2. LSASS, SAM and LSA Secrets are different

| Surface | Role / material | Investigation boundary |
| --- | --- | --- |
| LSASS | Authentication process and associated session/security state | Contents depend on logon, protocol, OS and enabled protections; not a guaranteed plaintext-password cache |
| SAM | Local-account credential database | Local accounts are not the entire domain directory |
| LSA Secrets | Protected system secrets, potentially including service/machine-related material | Not synonymous with SAM or all LSASS memory |
| Cached domain credentials | Local verifier used for applicable offline domain logon | DCC2 is not an NT hash usable directly for NTLM pass-the-hash |
| AD database / replication | Domain identity secrets and replication trust | DC/replication scope differs from local host stores |
| Application secrets / certificates | Application-specific tokens, generic saved credentials or private-key access | Separate storage, policy and response requirements |

For classification and boundaries, see [SAM](https://attack.mitre.org/techniques/T1003/002/), [LSA Secrets](https://attack.mitre.org/techniques/T1003/004/) and [cached credentials](https://attack.mitre.org/techniques/T1003/005/). “Hash” is not one interchangeable credential type. A verifier, NT hash, Kerberos ticket and certificate/private key have different uses.

An account that has never exposed usable material on the host should not be added to an exposure list merely because it belongs to the same domain. Equally, a host cleanup does not invalidate material already copied elsewhere.

## 3. Layer protections by the surface they cover

![Different controls protect different credential surfaces]({{ '/assets/diagrams/credential-boundaries-en.svg' | relative_url }})

| Control | Intended boundary | Do not infer |
| --- | --- | --- |
| LSA protection / PPL | Restricts untrusted interaction with protected LSASS and plug-in loading | All secrets on disk are isolated |
| Credential Guard | VBS isolation of supported credential material | SAM, AD database and every application secret are protected |
| LSASS ASR rule | Restricts LSASS-memory access under supported Defender conditions | Every credential-access path is blocked |
| Least privilege / protected administration | Reduces who can reach sensitive hosts and identities | An admin account is harmless once authenticated |
| Unique local credentials / managed service identities | Reduces credential reuse and unmanaged secrets | Rotation removes already running malicious code |
| Application/driver control and patching | Reduces untrusted execution and kernel attack surface | A valid signature alone guarantees safe behavior |

These controls have overlapping but different scopes. Evaluate the effective combination rather than summing feature names into a security score. Document gaps by asset role and permitted authentication workflows.

## 4. LSA protection: configured versus protected at startup

Additional LSA protection runs LSASS as a protected process and imposes plug-in requirements. A configured registry value is not enough to prove the intended state for the current boot. Microsoft documents **System / WinInit event 12** for protected startup. [Configure added LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection).

Review supported OS/build, policy, boot context, UEFI-lock choices and plug-in compatibility before changes. Preserve the event message/provider and its boot time. A historical startup record is not an independent real-time health check.

Do not disable protection to make a diagnostic tool work during triage. Determine whether the tool needs that access and use an approved compatible workflow. Credential-provider, smart-card and authentication extensions need controlled compatibility testing.

## 5. Credential Guard: isolation with explicit limits

Credential Guard uses VBS to isolate supported NTLM, Kerberos TGT and domain-credential material. It does **not** protect the SAM or AD database. Eligibility, edition, hardware, role and explicit policy matter; do not assume every Windows 11 or Server 2025 system is running it. Microsoft discourages enabling it on DCs because it adds no DC security benefit and can cause compatibility issues. [Credential Guard overview](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/).

For verification, inspect the **running** service array, not only configuration. A value of 1 in `SecurityServicesRunning` represents Credential Guard. VBS running by itself is not the same claim. [Verify Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/configure).

Generic saved credentials and some legacy authentication/delegation workflows have separate limitations. Pilot dependent Wi-Fi/VPN, remote administration and authentication extensions instead of weakening controls after an unexplained failure. [Compatibility considerations](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/considerations-known-issues).

If credentials were exposed before protection was enabled, enabling it is not retroactive revocation. Treat the earlier exposure window separately.

## 6. The LSASS ASR rule and what a block means

The Defender rule **Block credential stealing from the Windows local security authority subsystem** has ID `9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2`. It does not support Warn mode. Microsoft's current reference says it adds no extra protection when LSA protection is enabled and can be not applicable in Defender management. Do not prescribe it as a mandatory additional layer on every PPL-enabled device. [ASR rule reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference).

A block concerns the targeted memory-access action; it does not necessarily stop the initiating process. Audit is not block. One blocked action does not prove no earlier access, no other technique and no remaining compromise.

Record exact rule, action, source process, device, event time and policy applicability. Approved software can make unnecessary LSASS access calls; classify using actual behavior and ownership instead of excluding a product's whole directory. Test deployment on a representative cohort with measured compatibility and rollback.

## 7. Evidence: access, extraction and subsequent abuse

| Evidence | What it can support | What it cannot establish alone |
| --- | --- | --- |
| Sysmon 1 / Security 4688 | Process creation and available execution context | Dumping success |
| Sysmon 10 | Recorded process-access interaction | Bytes read, reusable credentials recovered or exfiltration |
| Sysmon 11 / EDR file evidence | File creation/overwrite and originating context | That a .dmp file contains LSASS data |
| Defender/ASR records | Rule-specific audit/block context | Global containment or termination |
| Policy/runtime inventory | State at the observed time | State throughout an earlier incident |
| Resource logons / DC events | Later authentication and access context | That credentials came from this host |
| Approved forensic analysis | Artifact content and supported exposure assessment | Unrelated accounts being compromised |

See [Sysmon event definitions](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon) and [Security 4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688). Security audit policy, command-line policy, Sysmon filtering, retention and transport must be verified before relying on missing events.

For 4688, `NewProcessId` is the new process; `ProcessId` is the creator. Normalize hexadecimal/decimal deliberately. For Sysmon 10, keep **SourceProcessGUID and TargetProcessGUID separate**. Use source endpoint + source GUID to investigate the actor; target LSASS GUID is not the actor.

Registry value-change events do not provide a complete history of reads. Missing 4657 or Sysmon 13 cannot rule out access to a credential store. Offline acquisition and other paths can fall outside the chosen live telemetry.

## 8. Access rights and false-positive control

`GrantedAccess` is a rights mask, not a malware score. Interpret the requested/recorded operation against the provider's semantics and Windows rights definitions. A memory-read capability is not proof that a useful secret was extracted. Do not build a universal verdict around one hexadecimal mask. [Process access rights](https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights).

Review source image, signer/hash, full command, parent, account, token context, call trace when available, frequency and change authorization. Preserve raw values. Signature and path checks help identify a candidate; they do not authorize its behavior.

Baseline EDR, backup, diagnostic and identity tools with their owners. A stable approved pattern may reduce priority, while a new binary under a familiar name can deserve escalation. Avoid broad exclusions that hide the very process interactions needed for investigation.

## 9. Read-only state and log checks

Run on an authorized Windows host with appropriate privileges and available management components. These commands do not access secret values or process memory. Record permission/unsupported-class failures as visibility limits.

### A. Credential Guard runtime state

```powershell
$credentialGuardState = Get-CimInstance -Namespace root\Microsoft\Windows\DeviceGuard -ClassName Win32_DeviceGuard -ErrorAction Stop
$credentialGuardState |
  Select-Object VirtualizationBasedSecurityStatus,SecurityServicesConfigured,SecurityServicesRunning
[pscustomobject]@{
  CredentialGuardRunning = @($credentialGuardState.SecurityServicesRunning) -contains 1
}
```

The array membership check distinguishes Credential Guard from other Device Guard services. Save OS/build, collection time and policy context with the output. A configured service that is not running requires investigation, not a claim of protection.

### B. Selected LSA policy metadata and boot records

```powershell
Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' |
  Select-Object RunAsPPL,LsaCfgFlags

$credentialBootWindow = (Get-Date).AddDays(-2)
Get-WinEvent -FilterHashtable @{
  LogName='System'
  ProviderName='Microsoft-Windows-Wininit'
  Id=12,13,14
  StartTime=$credentialBootWindow
} -MaxEvents 30 |
  Select-Object TimeCreated,Id,ProviderName,MachineName,Message
```

This reads selected values from the LSA configuration key, not the LSA Secrets store. Absent values, policy defaults and firmware-backed configuration need documented interpretation. The two-day window and 30-record cap can omit the current boot or older records; correlate actual boot time and raw messages. Event 12 and 13/14 answer different questions.

### C. One ASR rule's configured action

```powershell
$credentialAsrId = '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2'
$credentialPreferences = Get-MpPreference -ErrorAction Stop
$credentialRuleIds = @($credentialPreferences.AttackSurfaceReductionRules_Ids)
$credentialRuleActions = @($credentialPreferences.AttackSurfaceReductionRules_Actions)
if ($credentialRuleIds.Count -ne $credentialRuleActions.Count) {
  throw 'ASR ID/action array lengths differ; inspect the source before mapping.'
}
for ($credentialRuleIndex = 0; $credentialRuleIndex -lt $credentialRuleIds.Count; $credentialRuleIndex++) {
  if ([string]$credentialRuleIds[$credentialRuleIndex] -eq $credentialAsrId) {
    [pscustomobject]@{
      RuleId = $credentialRuleIds[$credentialRuleIndex]
      ConfiguredAction = $credentialRuleActions[$credentialRuleIndex]
    }
  }
}
```

The code pairs rule IDs/actions by array position and refuses unequal lengths. In the applicable API, 0/1/2 represent Disabled/Block/Audit; do not recommend Warn for this rule. If it returns no row, the rule was not found in this returned configuration view, not proof of effective protection or its absence. Validate applicability and effective Defender policy. [Get-MpPreference](https://learn.microsoft.com/en-us/powershell/module/defender/get-mppreference), [ASR mode reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-configure).

### D. A bounded Sysmon sample

```powershell
$credentialSince = (Get-Date).AddHours(-2)
Get-WinEvent -FilterHashtable @{
  LogName='Microsoft-Windows-Sysmon/Operational'
  Id=1,10,11
  StartTime=$credentialSince
} -MaxEvents 100 |
  Select-Object TimeCreated,Id,ProviderName,MachineName,Message
```

At most 100 records from two hours are selected. Filter and inspect named XML fields for a case; displayed messages can omit details or be localized. Preserve original EVTX/XML through approved evidence handling. Never generate a real dump just to verify that collection works.

## 10. Splunk investigation templates

Map actual indexes, channel/provider fields and GUID names before use. Here `Computer` must be the original endpoint; `host` is an acceptable fallback only if it has that meaning. Missing channel fields are excluded by these searches and need separate parser checks.

### A. Process access targeting the LSASS filename

```spl
index=sysmon (EventCode=10 OR EventID=10)
| eval channel=coalesce(Channel,LogName), endpoint=coalesce(Computer,host)
| where channel="Microsoft-Windows-Sysmon/Operational"
| regex TargetImage="(?i)\\\\lsass[.]exe$"
| table _time endpoint SourceImage SourceProcessGUID SourceProcessGuid SourceProcessId
    TargetImage TargetProcessGUID TargetProcessGuid TargetProcessId GrantedAccess CallTrace
| sort 0 _time
```

The case-insensitive suffix selects a filename, not a verified identity. Confirm the target's actual path/process and source/target GUIDs. This search does not filter by one presumed “malicious” access mask and does not prove memory extraction.

### B. One actor across process, access and file events

```spl
index=sysmon (EventCode IN (1,10,11) OR EventID IN (1,10,11))
| eval channel=coalesce(Channel,LogName), endpoint=coalesce(Computer,host)
| where channel="Microsoft-Windows-Sysmon/Operational"
| eval actor_guid=lower(coalesce(SourceProcessGUID,SourceProcessGuid,ProcessGuid,ProcessGUID))
| where endpoint="WS02" AND actor_guid="{00000000-0000-0000-0000-000000000102}"
| eval event_id=coalesce(EventCode,EventID)
| table _time endpoint event_id actor_guid Image SourceImage CommandLine
    TargetImage GrantedAccess TargetFilename
| sort 0 _time
```

Replace the fictional host/GUID. For event 10 the actor comes from the source field; for 1/11 it comes from the event's own process field. Retain raw aliases when normalizing. A timeline supports review but does not establish file content, causal certainty or account exposure.

### C. Dump-extension file candidates

```spl
index=sysmon (EventCode=11 OR EventID=11)
| eval channel=coalesce(Channel,LogName), endpoint=coalesce(Computer,host)
| where channel="Microsoft-Windows-Sysmon/Operational"
| where like(lower(TargetFilename),"%.dmp")
| table _time endpoint Image ProcessGuid ProcessGUID TargetFilename
| sort 0 _time
```

This is an extension-based candidate search. It includes legitimate crash/diagnostic output and misses other names or fileless activity. The same actor GUID and close timing strengthen a hypothesis; content validation still needs a protected forensic workflow. Do not upload unknown dumps to public reputation services.

### D. Exported Defender ASR observations

```spl
index=endpoint_protection sourcetype=defender_deviceevents_normalized
    ActionType IN ("AsrLsassCredentialTheftAudited","AsrLsassCredentialTheftBlocked")
| table _time DeviceName ActionType InitiatingProcessFileName
    InitiatingProcessCommandLine InitiatingProcessAccountName
    InitiatingProcessId ReportId
| sort 0 _time
```

This uses an **illustrative normalized export of Defender DeviceEvents**, not native Windows XML or a KQL query. `_time` must be mapped from the source timestamp; map the remaining fields during ingestion. The action types are documented in the ASR reference. No Sysmon GUID is assumed to exist in this export. Correlate by independently verified process identity/lifetime and device; a PID or nearby time alone is insufficient.

These are investigation starting points, not tested production alerts. Validate parsing, benign workloads, duplicate events and rule applicability before operational use.

## 11. Synthetic credential-access triage

[Download 12 fictional observations]({{ '/assets/labs/windows-credential-protection-events.csv' | relative_url }}). This shared English worksheet combines events, an inventory snapshot and an analyst note; blank event IDs are intentional. It is not raw XML or an import-ready detection dataset. `actor_guid` is normalized; the Defender row's GUID is explicitly fictional enrichment.

| UTC | Observation | Initial interpretation |
| --- | --- | --- |
| 05:00 | WS01 WinInit protected-LSASS and Credential Guard startup | Separate boot-state claims, not every-store protection |
| 05:05 | WS02 configured CG includes 1; running excludes 1 | Configuration does not prove runtime |
| 05:10 | WS01 diagnostic actor interacts with LSASS | Verify approved query context; no extraction demonstrated |
| 05:12 | WS02 support actor, access record, ASR block and support.dmp creation | Escalate review without assuming dump content or complete containment |
| 05:14 | APP01 logon for reader_lab | Source credential and mechanism unconfirmed |
| 05:15 | Separate security-agent candidate accesses LSASS | Different actor; validate approval independently |
| 05:20 | Analyst isolates the file for review | Handling action, not proof of secret extraction |

**Answer guide:** the WS02 state mismatch deserves review. Its support process sequence is suspicious enough to preserve evidence and investigate, but the worksheet supplies neither rights details, file contents nor confirmed account exposure. An ASR block can coexist with a file-creation event without proving that the file contains LSASS memory. APP01's logon is not automatically downstream credential abuse. WS01's PPL and CG startup do not protect WS02, and the separate agent must not be merged into the support actor.

List facts, hypotheses and unknowns. Request original access fields, source process creation, rule records, active policy/runtime state, protected artifact analysis and destination authentication evidence. Do not execute the candidate or extract credentials to fill missing evidence.

## 12. Containment and credential-response scope

![Contain the host, assess exposure, address identity and verify recovery]({{ '/assets/diagrams/credential-response-en.svg' | relative_url }})

1. Record hosts, identities, timing, source/target processes and collection gaps; preserve evidence where feasible.
2. Coordinate host isolation and immediate containment when active risk requires it; an ASR block is not an incident closure.
3. Determine the reachable stores, accounts/logon sessions, actual artifacts and protection state during the exposure window.
4. From a trusted administrative environment, rotate/revoke affected credentials using the identity owner's approved recovery plan.
5. Address sessions, tickets, tokens, certificates and service dependencies according to the material implicated.
6. Remove the initial access and persistence, recover/rebuild when integrity cannot be established, and validate controls/telemetry.
7. Monitor related hosts and identities for recurrence and record what remains unconfirmed.

Password rotation does not universally kill existing sessions, invalidate every token or revoke certificates. Updating one service password without dependency planning can cause outages. DC secrets or suspected replication abuse require identity incident leadership; do not apply disruptive domain-wide recovery procedures based on a single LSASS access record.

Never kill LSASS as an ad hoc containment step. Diagnostic artifacts can themselves contain secrets and require restricted access, retention and transfer controls.

## 13. Hardening and completion evidence

| Priority | Action | Evidence of completion |
| --- | --- | --- |
| Reduce exposure | Separate privileged administration; avoid unnecessary privileged logons | Reviewed access paths and logon policy |
| Protect supported material | Validate PPL and Credential Guard where applicable | Current runtime/boot evidence plus compatibility tests |
| Control execution | Patch, restrict untrusted applications/drivers and manage local admin rights | Tested policy and approved exceptions |
| Reduce reuse | Use unique managed local credentials and supported managed service identities | Managed rotation and dependency validation |
| Preserve visibility | Verify Sysmon/EDR, ASR applicability, audit and retention | Known benign tests arrive end to end |
| Recover identities | Scope affected credentials and dependent services | Trusted rotation/revocation and session review |

Do not equate “administrator” with guaranteed access to every protected secret, “PPL configured” with verified runtime, “CG running” with SAM protection, or “no dump file” with no credential access.

Map only supported behavior: [T1003.001 LSASS Memory](https://attack.mitre.org/techniques/T1003/001/), [T1003.002 SAM](https://attack.mitre.org/techniques/T1003/002/), [T1003.004 LSA Secrets](https://attack.mitre.org/techniques/T1003/004/) or [T1003.005 Cached Domain Credentials](https://attack.mitre.org/techniques/T1003/005/). Subsequent credential use is a separate behavior requiring separate evidence.

## 14. Completion checks and related learning

Explain LSASS/SAM/LSA Secrets/cached-verifier differences, identify one protection limitation, distinguish configured/running state, and interpret a source-to-target process interaction without claiming unsupported extraction. Scope a response without assuming every domain identity was exposed.

Review [NTLM]({{ '/wiki/ntlm-authentication/' | relative_url }}), [Kerberos]({{ '/wiki/kerberos-authentication/' | relative_url }}), [AD CS]({{ '/wiki/ad-cs-security/' | relative_url }}), [Windows lateral movement]({{ '/wiki/windows-lateral-movement/' | relative_url }}) and [Sysmon]({{ '/wiki/sysmon-investigation/' | relative_url }}). Apply these concepts in the [Windows Incident Response Lab]({{ '/wiki/windows-incident-response-lab/' | relative_url }}), with a synthetic timeline, evidence worksheets and response decisions.

**Source review: 22 October 2026.** Microsoft references support product/field behavior and current protection guidance; MITRE supports technique boundaries. Diagrams, searches and the synthetic worksheet are original teaching material. Publication checks cover document consistency, syntax and delivery; no credential dumping, protection change, live attack or production Splunk test was performed.
