---
title: "RDP Session Evidence · From Disconnect to Logoff"
description: "Reconstruct an RDP session on its destination host, use the correct Logon ID, and tell transport loss from session termination."
category: dfir
tags: [Windows Security, Windows, RDP, Event Logs, Blue Team, DFIR]
level: Beginner
updated: "2026-11-21"
translation_url: /ko/wiki/rdp-session-evidence/
---

**Learning goal.** A remote desktop window closes at 01:05. Was the user signed out? Did a connection at 01:08 create a fresh desktop? Learn to answer from destination Windows events, identify gaps, and report what still needs corroboration. Start with [Windows Security events]({{ '/wiki/windows-logs/' | relative_url }}) for the log basics or [Windows remote management paths]({{ '/wiki/windows-lateral-movement/' | relative_url }}) to see where RDP fits.

## 1. Connection, logon and desktop are different layers

**Remote Desktop Protocol (RDP)** lets a client interact with a Windows desktop hosted on another system. **Remote Desktop Services (RDS)** can host and broker such sessions. The **session host** is the destination system actually running the desktop and its applications. An **RD Gateway** can mediate access. Its decision and recorded client address are evidence at the gateway, while the session host's records describe activity there.

The **connection** carries remote interaction. A **Windows logon session** associates a security context with a user or service after successful logon. A **desktop session** holds the user's environment and running applications. The user can disconnect, intentionally or because of a network outage, while the desktop and its applications remain on the host. A policy or an administrator can later terminate the session. A **reconnect** can return to the existing desktop. Locking the desktop can also leave it running. Use host and gateway evidence to distinguish which layer changed.

<figure style="margin-inline: 0">
<img src="{{ '/assets/diagrams/rdp-session-evidence-en.svg' | relative_url }}" alt="A successful remote interactive logon starts a session. A disconnect leaves the session on the host, and a reconnect can return to it. A matching 4634 records logon-session end.">
<figcaption>Connection loss and logoff are separate paths. The event IDs are examples from destination Security auditing with the required subcategories enabled.</figcaption>
</figure>

## 2. Read the events on the destination

These IDs refer to the **Security** channel and the **Microsoft-Windows-Security-Auditing** provider. Audit policy and collection must include the relevant events. Other logon types can appear during remote authentication. Use type 10 for a successful RemoteInteractive record and carry surrounding types as context.

| Event and policy prerequisite | What it supports | What to correlate |
| --- | --- | --- |
| 4624 type 10 · Audit Logon success | The destination created a RemoteInteractive logon session. | New Logon SID/account, XML `TargetLogonId`, type and available source fields. XML `SubjectLogonId` describes a different role. |
| 4625 · Audit Logon failure or Audit Account Lockout context | A logon attempt failed on the system that recorded it. | Attempted account, type, status, substatus and available source fields. Keep it as context without assigning it a successful session ID. |
| 4779 / 4778 · Audit Other Logon/Logoff Events success | An existing session was disconnected / reconnected. These IDs also occur outside ordinary RDP, including Fast User Switching and Hyper-V enhanced sessions. | XML `LogonID`, account/domain, `SessionName`, `ClientName` and `ClientAddress` where present. Confirm the transport and session context. |
| 4647 · Audit Logoff success | The account initiated logoff. | XML `TargetLogonId` and account. Look for termination evidence. |
| 4634 · Audit Logoff success | The matching logon session ended. Other logon types also generate this event. | XML `TargetLogonId` and `LogonType`. It does not specify the reason or prove a user clicked Sign out. |

**Join by destination computer, boot interval and Logon ID.** A Logon ID is local and may be reused after reboot. Keep the raw fields and normalise hexadecimal values, for example `0x2A1` and `0x2a1`. The device label and boot interval need to come from trusted inventory and host records. If you cannot establish a reboot boundary, check for intervening restarts and keep the join provisional. A Windows Security Logon ID, the numeric session ID in `quser`, and the name `RDP-Tcp#4` are different identifiers. Account is a cross-check. Use the SID when available and check that account/domain context is consistent. A shared account, IP or session-name suffix alone is a weak join.

## 3. Follow a normal example and test alternatives

On a fictional destination `rdsh-a`, a support user has 4624 type 10 at 01:01 for Logon ID `0x2a1`. At 01:05, 4779 for the same ID records a disconnect. At 01:08, 4778 for that ID records a reconnect. The client address shown on the reconnect differs. At 01:10, 4647 records initiation of logoff. One second later, 4634 type 10 records logon-session termination. The strongest timeline links the five records within the same boot. The apparent client change is a separate question.

| Observation | Normal explanations to check | What would raise concern |
| --- | --- | --- |
| Reconnect with a different client address | VPN address change, gateway path or approved workstation change | Unapproved device or access path confirmed independently, account owner denies it, or session performs actions outside the approved change. |
| Repeated 4625s near one 4624 | Repeated mistyped credentials or retrying client | Failures for several accounts or unusual paths, followed by confirmed access and suspicious post-logon activity. |
| 4779 without 4634 | User closed the client, network interruption, active disconnected session or missing log coverage | Live snapshot shows a long-lived privileged session and the activity or timing conflicts with policy. |
| 4778 without early 4624 | Collection began after logon, retention gap, or records are on the wrong host | Independently verified gateway and host activity without a matching approved access record. |

Misuse can involve an account being used by someone other than its owner, or unauthorised use of an existing disconnected desktop. Network outages, lock policies and maintenance can leave a similar series. Record the outcome of each layer and distinguish authentication, session state and activity. A direct firewall connection, gateway allow or 4624 by itself supplies no evidence of particular commands or file access.

## 4. Collect and respond without losing the timeline

1. **Confirm the path and time.** Identify the actual session host behind any gateway or broker. Preserve UTC event time, ingestion time, host boot boundaries and clock offset. Gather destination Security and available TerminalServices operational records, gateway/broker records where used, and related endpoint telemetry within the authorised scope. Keep raw XML, event version, channel, provider, original computer and record ID. The same record ID can recur in different logs or hosts.
2. **Check audit and forwarding coverage.** On the destination, confirm the relevant Audit Logon, Audit Logoff and Audit Other Logon/Logoff Events settings and that events reach the collector. Verify the relevant versions and fields with a known approved session. If a required ID is absent, compare the local source with forwarding and retention before inferring a missing action. See [Windows log continuity]({{ '/wiki/windows-log-continuity/' | relative_url }}).
3. **Build a timeline with separate evidence columns.** Place session events under the destination session key. Keep gateway identities and client addresses in their own columns. Check VPN, gateway and device records before linking a changed address to a person or endpoint. For post-logon actions, look for available process creation/EDR or application audit events. Correlate the correct destination and time range, and use the documented logon ID field for that event when present.
4. **Confirm current state and scope any action.** `quser` can show active/disconnected sessions on an authorised session host with appropriate permission. It is a live snapshot, not a historical timeline. Preserve that snapshot before changing session state when feasible. Coordinate containment of confirmed unauthorised access with the host owner, and confirm whether an affected desktop and its applications actually stopped. A network disconnect alone may leave them running.

On an authorised Windows destination with permission to read Security and the required auditing already enabled, this PowerShell query reads the last two hours. Change the time window to fit the case. It returns candidates across logon types, so inspect each record's XML and match the fields above. Use `.ToXml()` on a selected event when an Event Viewer label or collector field is ambiguous.

```powershell
$filter = @{
    LogName      = 'Security'
    ProviderName = 'Microsoft-Windows-Security-Auditing'
    Id           = 4624, 4625, 4634, 4647, 4778, 4779
    StartTime    = (Get-Date).AddHours(-2)
}
Get-WinEvent -FilterHashtable $filter |
    Select-Object TimeCreated, MachineName, RecordId, Id, Message
```

## 5. Offline lab · rebuild the session timeline

Download the <a href="{{ '/assets/labs/rdp-session-events.csv' | relative_url }}" download>fictional event CSV</a> and the <a href="{{ '/assets/labs/rdp-session-lab.py' | relative_url }}" download>Python checker</a> into the same directory. The CSV is a teaching export with invented hosts and addresses. `boot` is supplied enrichment, not a Windows event field. The checker deliberately recognises the sample's `RDP-Tcp#` names. It is not a complete RDS classifier. This read-only exercise needs Python 3 and the supplied CSV. It does not connect to a host or generate events.

1. Locate event 4624 type 10 on host A in boot A1. Compare the XML-inspired fields `target_logon_id` and `logon_id` across event types.
2. Group by host, boot and normalised ID. Within each group, order by UTC time. Explain why the matching number in rows 5 and 11 must stay separate.
3. Compare row 12 with row 9. State which records show disconnect and which show logon-session termination.
4. Run `python3 rdp-session-lab.py` and compare with your reasoning.

| Group or control | Expected reading |
| --- | --- |
| Host A, A1, `0x2a1` | Rows 2 → 4 → 6 → 8 → 9. RemoteInteractive logon, disconnect, reconnect, logoff initiation and termination. |
| Host B, B1, `0x2a1` | Row 5 only. The same number on another host does not join. |
| Host A, A2, `0x2a1` | Rows 11 → 12. A separate boot and a disconnect with no termination record in the sample. |
| Host A, A2, `0x404` | Row 13. Reconnect observed without a captured start. |
| Context retained outside groups | Rows 1, 3, 7 and 10. Failed attempt, type 3 logon, console switch, and type 3 logoff. |

Expect `5/5 grouping controls matched.` If the CSV cannot be opened, confirm its name and path. If too many rows join, verify host and boot scoping and reject type 3 from this specific type-10 timeline. If row 4 is missing, normalise the hexadecimal ID. The checker ran against the fictional CSV in the cloud. Windows event generation and the PowerShell example were reviewed against Microsoft documentation.

## 6. Check your reasoning

1. **Is 4779 proof that programs stopped?** It records a disconnect. Check the current session state or the matching termination and process evidence.
2. **Two events have the same account and Logon ID but different hosts. Can they share a key?** No. Logon IDs are host-local and scoped to a boot interval.
3. **A 4778 shows a different address. What would support unauthorised access?** Verify the gateway/VPN route and permitted device, then correlate the session and activity with authorisation records. Keep the observed address distinct from a person.
4. **Why preserve 4647 and 4634?** The first records initiation by the account. The second records termination of the corresponding logon session.

**Completion criteria.** Rebuild the five lab controls, distinguish a disconnect from a logoff, and state one inference that still requires a second source.

## Official references

Reviewed 2026-11-21. The legacy Windows audit reference is used for event XML and audit subcategories. Current Windows Server guidance covers supported Server releases, including the session and permission conditions described by `quser`. Confirm behaviour on the versions in your environment.

- Microsoft Security audit event schemas. [4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) · [4625](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625) · [4778](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4778) · [4779](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4779) · [4647](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4647) · [4634](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4634)
- Windows Server RDS state, timeout and current session query. [Unexpected session locks or disconnections](https://learn.microsoft.com/en-us/troubleshoot/windows-server/remote/troubleshoot-unexpected-rds-session-locks-or-disconnections) · [quser](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/quser)
- Windows-only PowerShell event query, version 7.5 reference. [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
