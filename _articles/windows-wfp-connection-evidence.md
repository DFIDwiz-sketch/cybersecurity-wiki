---
title: "Investigate Windows WFP Connection Decisions"
description: "Correlate Security 5156 and 5157 with process lifetimes, filter origin and connection outcomes."
category: blue-team
tags: [Windows, Windows Firewall, WFP, Windows Event Logs, Sysmon, Blue Team, DFIR]
level: Beginner
updated: "2026-11-25"
translation_url: /ko/wiki/windows-wfp-connection-evidence/
---

A workstation records Event ID 5156 for TCP port 443. A few seconds later, it records 5157 against the same remote address. Treat them as two decisions until you can match the host, direction, endpoints, protocol and process lifetime. This chapter shows how to establish what the local filter decided and what happened after that decision.

## 1. What Windows Filtering Platform records

**Windows Filtering Platform (WFP)** is the filtering infrastructure in the Windows network stack. Windows Firewall uses it, and other providers can install filters. A **filter** evaluates conditions such as addresses, application and protocol at a **layer**, a point in network processing. Application Layer Enforcement (ALE) layers authorize operations such as an outbound connect or inbound receive/accept. Read the layer and direction with the decision. A connection authorization event and a packet-drop event observe different operations.

The Security channel's **Audit Filtering Platform Connection** subcategory controls success and failure auditing for these connection events. With the applicable auditing enabled, **5156** records that WFP permitted a connection, and **5157** records that it blocked a connection. Success refers to the Windows audit category. Application success still needs evidence. The EventData `ProcessID` describes the application in the event. `System/Execution/@ProcessID` belongs to the event publisher's execution context. Keep those two fields distinct.

| Source | Direct evidence | Follow-up question |
| --- | --- | --- |
| Security 5156 | A local WFP connection authorization | Did traffic traverse the path and reach the service? |
| Security 5157 | A local WFP connection block at the reported layer | Which filter and policy applied to this operation? |
| Security 5152 | WFP blocked a packet, with its own audit subcategory | What packet and filter were involved? |
| Sysmon 1 and 3 | Process creation and configured TCP/UDP telemetry, linked by ProcessGuid | Which process instance can you corroborate? |
| Firewall text log, packet capture, service log | Profile-dependent firewall logging, packets at a capture point, or application processing | Which later outcome can each source confirm? |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-wfp-connection-evidence-en.svg' | relative_url }}" alt="Scope the originating host and tuple, then correlate the WFP decision with process, network and service evidence.">
  <figcaption>The local filter decision is one step. Verify transport and application processing with independent evidence.</figcaption>
</figure>

## 2. Follow one expected connection

In this fictional example, an approved agent on `ws-12.example.test` requests a status page from a documentation address. All times are UTC.

1. At 09:02:05 a process start record gives `status-agent.exe` PID 914 and a process instance identifier. Record its start time, image path and termination if available.
2. At 09:02:08 a Security 5156 record identifies TCP (`Protocol=6`) and outbound direction on that host, `192.0.2.12:50811` → `198.51.100.20:443`. Join the application PID to the lifetime of PID 914 on that host with a consistent image. Device paths such as `\device\harddiskvolume2\...` require the relevant host's volume mapping before you compare them to drive-letter paths.
3. A capture at an approved point shows a TCP handshake. A corresponding server access log records the status request. Correlate time, endpoints, NAT or proxy mappings if present, and a request ID when available. The handshake establishes transport. The service record establishes request processing.
4. A later 5157 has source port 50812. Record it separately. A shared remote address can host several services, and every retry or parallel request might create a different observation. A block for 50812 does not explain the already observed result for 50811.

Windows may reuse PIDs. Join by original computer, PID, UTC time and executable with a process creation at or before the event and, when known, termination after it. A restart or timestamp uncertainty may make the candidate ambiguous. Sysmon 3, when installed and configured (network logging is disabled by default), can give you a ProcessGuid. Security 5156 or 5157 alone does not contain that Sysmon identifier.

## 3. Collect, detect and respond

**Confirm audit coverage.** Record host role, OS build, audit success/failure settings, Security log retention and collector filters. 5156 can be high-volume. Pilot collection on a defined set of hosts and measure local and forwarded retention before relying on it. Preserve the original `Computer`, `Channel`, provider, `EventRecordID`, version, raw `SystemTime` and ingestion time. Keep raw `Direction`, `Application`, protocol, addresses and ports alongside normalized values. Rendered text varies with language. Interpret direction relative to the reporting host and preserve address family and local versus remote roles. Validate local-to-collector delivery with an approved benign control.

**Identify the block's origin.** Read `FilterRTID`, `LayerRTID` and layer context. Scope run-time identifiers to the host and a contemporaneous WFP snapshot. Even unchanged policy can receive a new run-time filter ID. On Windows 11 and Windows Server 2022 and later families, Microsoft documents additional Filter Origin and Interface Index fields in the updated 5157 and 5152 audits. Inspect actual schema and raw XML before depending on them. Filter Origin can refer to a rule identifier or a default block filter. A default has no corresponding user rule to look up. For an explicit rule ID, compare the current effective policy with the incident-time policy and source (local, Group Policy or MDM). Record profile and interface at the time. Current configuration may have changed.

**Test competing explanations.** A newly blocked destination can reflect a policy rollout, a profile change, a broken update endpoint or unauthorized outbound activity. A permitted connection from an unexpected executable can be worth triage. Check expected software and signer, process ancestry, target service and destination history. A blocked event establishes a control decision for one operation. It leaves other attempts and paths open to investigation. A permitted event does not establish credentials were sent, a request completed, data left the host, or the host was compromised.

**Use a scoped detection and response.** For a pilot, group blocked outbound events by original computer, normalized image, protocol, remote endpoint and 15-minute interval. Compare with the asset's approved destination and software baseline. Keep counts of distinct process lifetimes and event records where possible. Repeated retries are counts of observations, not counts of successful connections. For an approved workflow that breaks, compare policy source and profile before adjusting anything. If independent process and service evidence supports misuse, preserve records, scope affected hosts and follow authorized containment. Verify recovery with a known benign workflow and confirm the application result separately.

### Read-only inspection on an authorized Windows host

Use Windows PowerShell or PowerShell on Windows with authorized read access to the Security channel and audit policy. The AuditPol name below is English. On a localized system, list subcategories and use the local name or corresponding GUID. The query shows retained events in the last 30 minutes. A blank result may reflect policy, retention or an inspection-scope issue.

~~~powershell
auditpol /get '/subcategory:Filtering Platform Connection'
Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    ProviderName = 'Microsoft-Windows-Security-Auditing'
    Id = 5156, 5157
    StartTime = (Get-Date).AddMinutes(-30)
} -MaxEvents 30 | ForEach-Object { $_.ToXml() }
~~~

Review original `EventData` keyed by name. Keep output in approved incident storage. Remove `-MaxEvents` only when the intended collection window and volume have been reviewed. Record this query's execution time. Current audit settings cannot reconstruct historical coverage.

## 4. Offline lab · five decisions from synthetic XML

<a href="{{ '/assets/labs/windows-wfp-review.py' | relative_url }}" download="windows-wfp-review.py">Download the Python review script</a> · <a href="{{ '/assets/labs/windows-wfp-cases.xml' | relative_url }}" download="windows-wfp-cases.xml">Download the synthetic XML</a>

Save both files in the same directory. Use Python 3 on an authorized machine and run:

~~~bash
python3 windows-wfp-review.py windows-wfp-cases.xml
~~~

The fixture uses a simplified native-like namespaced Security event inside each case, plus separate synthetic process and service observations. It is not an EVTX export. The helper accepts only the bundled structure, uses no network or Windows APIs, and changes no policy. Process entries provide pre-mapped image paths and explicit lifetime bounds. Service records contain a correlated client endpoint and host. In this controlled fixture the tuple is exact and clocks are aligned. Production correlation can need NAT, proxies, record loss and time uncertainty.

| Case | Distinguishing evidence | Expected result |
| --- | --- | --- |
| 01 | 5156, matching live process and same-tuple service record | Permitted; process and service corroborated |
| 02 | 5157, live process and service record on a different source port | Blocked; service outcome unconfirmed |
| 03 | 5156, same PID but process ended before this event | Permitted; process unresolved |
| 04 | 5156, matching tuple at a different reporting host in the fixture | Permitted; service outcome unconfirmed |
| 05 | 5157, correct PID and lifetime, mismatched image | Blocked; process unresolved |

Expect five PASS lines. A file-not-found error usually means the files are in different directories or the working directory is wrong. If a result differs, compare the named XML fields, time and entire endpoint tuple. Change case 02's service source port on a copy and predict whether a later service record can be safely attached to a blocked operation without an attempt identifier. The helper leaves that outcome unconfirmed.

## 5. Check your reasoning

1. **Does 5156 to TCP/443 establish an HTTPS transfer?** It records local permission. Inspect TCP, TLS and application evidence for subsequent steps. The port alone does not determine the protocol above TCP.
2. **Can you look for the event's FilterRTID next week on the same host?** A new state dump may be informative, but a run-time ID can change. Prefer a contemporaneous snapshot, and compare a reported Filter Origin and historical configuration where available.
3. **Can a matching PID from a later process start identify the application?** First establish the candidate's lifetime around the event and corroborate image and host. Leave the instance unresolved when evidence overlaps or is missing.
4. **What does an empty SIEM search establish?** Only the result for that scope and time. Check the source's audit settings, retention and delivery before drawing conclusions about activity.

Finish by reproducing all five cases and recording one 5157 finding with its host, direction, layer, tuple, process evidence and one remaining uncertainty.

## Official references and related reading

Reviewed **2026-11-25**. Microsoft’s Windows 10 audit examples (2021 documentation) describe the base fields. The current Filter Origin article describes additions introduced in Windows 11 and Windows Server 2022. The Python exercise was run against synthetic data. The Windows inspection commands and audit behavior were reviewed against documentation.

- Platform and authorization layers. [WFP overview](https://learn.microsoft.com/en-us/windows/win32/fwp/windows-filtering-platform-start-page) · [ALE layers](https://learn.microsoft.com/en-us/windows/win32/fwp/ale-layers)
- Security event schema and volume. [5156](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5156) · [5157](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5157) · [5152](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5152) · [Audit Filtering Platform Connection](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-filtering-platform-connection)
- Newer fields and profile-specific file logging. [Filter Origin](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/filter-origin-documentation) · [Windows Firewall logging](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/configure-logging)
- Read-only query references and process telemetry. [AuditPol](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/auditpol-get) · [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent) · [Sysmon v15.22, 2026-09-10](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

Previous · [Windows Security logs]({{ '/wiki/windows-logs/' | relative_url }})  
Next · [Sysmon process and network evidence]({{ '/wiki/sysmon-investigation/' | relative_url }}) · [Firewall and NAT evidence]({{ '/wiki/firewall-nat-evidence/' | relative_url }})
