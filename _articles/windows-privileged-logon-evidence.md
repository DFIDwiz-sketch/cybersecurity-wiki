---
title: "Windows Privileged Logon Evidence · From Assignment to Use"
description: "Join 4624, 4672, 4688 and privilege-use events while keeping session assignment, token elevation and observed operations separate."
category: dfir
tags: [Windows Security, Windows, Event Logs, Privileges, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /ko/wiki/windows-privileged-logon-evidence/
---

An alert says a new logon received a sensitive privilege. Did a process use it? Was the operation successful? Start by separating what Windows granted to the logon session from what any later record shows.

## 1. Read the four kinds of evidence

A **logon session** is a security context created when an account logs on. The destination Windows host gives it a **Logon ID**. A **security identifier (SID)** identifies the security principal. An **access token** describes a process's or thread's security context, including identity, groups and privileges. A **privilege** is a specific system capability and can have an enabled or disabled state in a token. This is distinct from an ACL's permissions on a particular object. **User Account Control (UAC)** can affect which token a process starts with.

| Security event | Evidence | Audit requirements |
| --- | --- | --- |
| 4624 | Successful logon on the computer where the session was created. Read New Logon SID and Logon ID | Audit Logon, Success |
| 4672 | Listed sensitive privileges assigned to that new logon. Read Subject SID, Logon ID and `PrivilegeList` | Audit Special Logon, Success |
| 4688 | New process and, where recorded, token elevation type, creator and target contexts | Audit Process Creation, Success. Command-line capture needs a separate policy |
| 4673 / 4674 | Attempted privileged service call / attempted operation on a privileged object | Applicable Privilege Use subcategory and Success or Failure auditing for the outcome |
| Job or object record | Workload-level result or observed state change | Application or object telemetry configured for the operation |

A 4672 does not enumerate every token attribute or prove a privilege was enabled or exercised. A 4688 Type 2 (raw value `%%1937`) describes an elevated process token. Type 1 (`%%1936`) is a full token, common in contexts such as services or Local System, and Type 3 (`%%1938`) is limited. Read the raw value in the OS and account context. The 4688 result does not show which specific privilege the process used.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-privileged-logon-evidence-en.svg' | relative_url }}" alt="Join the successful logon to privilege assignment on the originating Windows host. Check new-process token evidence and any privilege-use audit records separately, then look for workload-level outcomes.">
  <figcaption>Follow the session as you move from privilege assignment to process creation, an attempted operation and its independently observed result.</figcaption>
</figure>

## 2. Follow a normal session

In this fictional example, a maintenance service starts on `lab-ws-a`. On its current boot, a type 5 (Service) 4624 New Logon entry records SID `S-1-5-21-110-220-330-1042` and Logon ID `0x4d2`. A 4672 Subject contains the same SID and ID and lists `SeSecurityPrivilege`, the privilege associated with managing auditing and the security log. Compare the account, service and expected grant against the approved maintenance plan.

A 4688 v2 records the service process. In this example the service manager is the creator and the service account is the Target Subject, so use the meaningful Target Logon ID to join the new process to the service account. If the target fields are missing or placeholders, record which context your schema actually provides. Older event versions can show the creator without a Target Subject. A `TargetLogonId` of `0x0` is not a join key for attributing the new process to another session.

A subsequent 4674 for the service account shows an attempt on a privileged object with the same privilege listed. Use the event's audit success/failure keyword, relevant object and process fields and the scope described by Microsoft. A success keyword describes that audited operation. To conclude the scheduled maintenance task finished, look for its job result and any expected output or state change. Likewise, a failure keyword shows an unsuccessful attempt in that audit record without establishing why the larger task failed.

## 3. Collect and investigate

1. **Keep source identity and scope.** Preserve the original Security event XML or EVTX, provider, source `Computer`, event version, channel, record ID, UTC time and the relevant boot boundaries. Join 4624 `TargetLogonId` to 4672, 4673 and 4674 `SubjectLogonId` on the original device and within the boot window. Check the SID too. Use the originating endpoint rather than the collector's hostname. Logon IDs and process IDs are local identifiers. Use process creation time, lifetime and a process GUID when available for a process-level join. A matching session alone does not identify a specific process.
2. **Separate policy from collection.** Confirm the effective subcategory settings, auditing outcomes captured, retention, forwarding filters and arrival delay. Windows documents additional audit requirements for use of backup and restore privileges. An empty result can reflect those settings or missing evidence. Command lines can contain sensitive data. Capture them only under approved policy, restrict access, and redact them from reports when appropriate.
3. **Explain routine activity before attributing intent.** SYSTEM commonly receives these privileges. Compare a candidate account and SID against the host role, approved service identity, logon type, maintenance window and expected process. An unexpected service or interactive logon from a low-use administrative identity warrants checking the source context and follow-on records. A 4672 alert alone does not establish privilege escalation, compromise or the identity of the person operating an account.
4. **Respond to supported findings.** Preserve the event interval and collection health before an approved account or host change. Check the relevant service or privilege assignment with its owner before narrowing access. If a privileged action is suspected, collect the affected object or workload evidence and document what remains unknown. Verify that routine administration still works after a policy correction.

On an authorized Windows host with access to the Security log, this read-only PowerShell query retrieves a bounded sample. It neither changes audit policy nor invokes a privileged operation. Adjust the time window to your incident and preserve the original material separately for evidence.

```powershell
$filter = @{
    LogName = 'Security'
    ProviderName = 'Microsoft-Windows-Security-Auditing'
    Id = 4624, 4672, 4673, 4674, 4688
    StartTime = (Get-Date).AddHours(-2)
}
Get-WinEvent -FilterHashtable $filter -MaxEvents 100 |
    ForEach-Object { $_.ToXml() }
```

The 100-event limit is for inspection. It can omit relevant events on a busy host. Access denied is a collection error. If records are absent, verify the correct host, time window, audit settings and retention before interpreting the absence. This query was reviewed against Microsoft documentation.

## 4. Try the offline evidence join

In an approved training workspace, download the <a href="{{ '/assets/labs/windows-privileged-logon-evidence.py' | relative_url }}" download="windows-privileged-logon-evidence.py">session join script</a> and <a href="{{ '/assets/labs/windows-privileged-logon-evidence.json' | relative_url }}" download="windows-privileged-logon-evidence.json">fictional evidence</a>. Run with Python 3.8 or later:

```bash
python3 windows-privileged-logon-evidence.py windows-privileged-logon-evidence.json
```

Each scenario is a separate set of normalized records. The process field `target` represents an explicitly observed Target Subject. The script joins records by source host, boot identifier, SID and numeric Logon ID. For 4688 it reports only an explicit target context and never substitutes a creator. It reports whether an audited operation in the session listed a privilege from the assignment. This is a session-level join. It does not parse Windows logs, establish process causality or verify an application outcome.

| Case | Expected evidence |
| --- | --- |
| `assignment_only` | Logon and assignment. No linked process or privilege-use record in the fixture |
| `elevated_without_use` | Assignment and Type 2 process. No linked privilege-use record |
| `same_session_audit_success` | Matching assigned privilege in a successful audited operation |
| `same_session_audit_failure` | Matching privilege in a failed audited operation |
| `different_host` | Similar SID and Logon ID on another host do not join |
| `different_boot` | The same host's ID from another boot does not join |
| `creator_only` | Creator context is present, but no explicit target process context joins |
| `different_privilege` | An operation in the session lists a privilege outside this assignment record |

If no process joins, check the event version and whether the target fields were present and meaningful. If no privilege use joins, check host, boot, SID and comparable Logon ID fields before examining audit coverage. In a copy of the fixture, change the privilege-use host in `different_host` to match the assignment host. The successful audit record should now join. The Python exercise was executed on synthetic evidence. No privilege-use operations were run on a Windows host.

## 5. Check your reasoning

1. **Can 4672 alone prove a successful privileged action?** It shows listed privileges assigned to a new logon. Follow operation records and check their outcomes.
2. **Why not join 4688 Creator Subject directly to the new process's target identity?** The creator can launch a process in another context. Preserve both, and attribute only what the recorded fields establish.
3. **What does audit success in 4674 prove?** It describes the recorded privileged-object operation. Use the service or object evidence to establish the separate task outcome.
4. **Does no 4673 or 4674 show that the privilege was never used?** The conclusion depends on audit policy, the operation covered and collected data. State the interval and evidence gap.

Complete the chapter when you can explain the expected service case, reject both false joins, and name what you would collect before claiming an action completed.

## Official references and next steps

Reviewed November 23, 2026. Microsoft's event schemas below are Windows 10-era references with documented event versions. The current Windows Server audit guidance and PowerShell documentation are separate references. Validate effective policy and schemas on the Windows build you collect.

- [Microsoft Security events 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624), [4672](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4672) and [4688](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4688)
- [Microsoft Security events 4673](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4673) and [4674](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4674)
- [Windows Server advanced audit policy](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration), [Audit Sensitive Privilege Use](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/audit-sensitive-privilege-use) and [PowerShell Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)

[Previous · Windows security event analysis]({{ '/wiki/windows-logs/' | relative_url }}) · [Next · RDP session evidence]({{ '/wiki/rdp-session-evidence/' | relative_url }})

[Related · Investigate process creation with 4688 and 4689]({{ '/wiki/windows-process-creation-evidence/' | relative_url }})
