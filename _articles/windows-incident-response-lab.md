---
title: "Windows Incident Response Lab: Authentication, Remote Access, Persistence and Credential-Access Evidence"
description: "Investigate one synthetic Windows case using 20 observations and six response actions; build a defensible timeline, scope local joins, separate facts from hypotheses and define recovery criteria."
category: dfir
tags: [Windows Security, Incident Response, DFIR, Blue Team, Active Directory, Kerberos, SMB, Persistence, Credential Access, Sysmon, Splunk]
level: Intermediate
updated: "2026-10-22"
translation_url: /ko/wiki/windows-incident-response-lab/
---

> **Integrated investigation exercise.** Combine [Windows lateral movement]({{ '/wiki/windows-lateral-movement/' | relative_url }}), [persistence]({{ '/wiki/windows-persistence/' | relative_url }}), [Sysmon]({{ '/wiki/sysmon-investigation/' | relative_url }}) and [credential protection]({{ '/wiki/windows-credential-protection/' | relative_url }}). This is a fictional desk exercise. No malware, real credentials, memory dumps, executable payloads or host-changing commands are supplied.

## 1. Objective and response framework

Your assignment is to explain what the evidence supports, choose proportionate response actions and identify what is still needed before recovery. A good answer can conclude that an event warrants urgent investigation while credential theft or exfiltration remains unproven.

[NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final), published in April 2025, supersedes Rev. 2 and integrates incident response with CSF 2.0 cybersecurity risk management. Use preparation, detection, response, recovery and improvement as connected organizational work. The exercise workflow and scoring below are original teaching aids.

Deliver five items: a sourced timeline, a host/account scope table, a fact-versus-hypothesis assessment, a response decision log and a recovery/closure checklist. Do not manufacture a complete attack story to fill missing evidence.

## 2. Fictional environment and boundaries

![Hosts and evidence roles in the integrated case]({{ '/assets/diagrams/windows-ir-scope-en.svg' | relative_url }})

| Asset | Role / documentation address | Available evidence |
| --- | --- | --- |
| WS01 | Workstation, 192.0.2.10 | Process A, DNS and network observations |
| FILE01 | Member file server, 192.0.2.20 | Logon, share check, tasks, processes and access records |
| DC01 | Domain controller, 192.0.2.30 | Service-ticket request |
| WS02 | Separate managed workstation | Same task path and numeric logon ID as a noise example |
| APP01 | Application member server, 192.0.2.40 | Later network logon |
| Collection system | Transport/indexing layer | Not a substitute for the original event host |

External documentation addresses 192.0.2.50 and 192.0.2.60 and names under `example.test` are placeholders. They are not live targets or indicators to block. The case account is `LAB\reader_lab`; deployment, inventory and responder accounts have separate roles.

The case window is **22 October 2026, 06:00–06:35 UTC**. Device addresses are fixed in this fictional window. In reality, establish address history, NAT/proxies, endpoint identity, clock alignment and data gaps before joining sources.

## 3. Evidence pack and provenance

Download both worksheets:

- [20 synthetic evidence observations]({{ '/assets/labs/windows-ir-evidence.csv' | relative_url }})
- [Six response decisions/actions]({{ '/assets/labs/windows-ir-actions.csv' | relative_url }})

The shared CSV text is English. These are normalized teaching worksheets, not raw EVTX/XML, packet captures or production parser fixtures. `evidence_id` values E001–E020 and action IDs R001–R006 are worksheet keys, not Windows EventRecordIDs. Blank event IDs on normalized exports are intentional.

| Field | Meaning and limit |
| --- | --- |
| case_id / evidence_id | Stable reference for this exercise |
| time_utc / host / channel | Stated source time and origin; channel labels include normalized exports |
| account | Relevant account selected for the row; not one universal native field |
| logon_id | 4624 TargetLogonId; 5145/4698/4699 SubjectLogonId |
| actor_guid | Sysmon own/source process normalized by event type |
| object / source_ip | Human-readable summary, not guaranteed native property names |
| detail | Fictional context, enrichment and explicit unknowns |

The Defender row's actor GUID is fictional enrichment; do not expect a native Sysmon GUID in every Defender export. Task XML is summarized, not supplied as a full artifact. Signed-file status, full commands, file content and original access rights are not included.

In a real case, maintain a protected evidence manifest with source, collector, acquisition time, tool/version, hash, access history and transformation notes. A file hash helps check integrity; it does not establish origin, completeness or chain of custody by itself.

## 4. First pass: facts and urgent questions

At 06:05 FILE01 records a helper process interacting with LSASS, a normalized ASR block and a .dmp file creation. This warrants escalation and preservation. It does not prove a successful credential dump, all-account compromise or exfiltration.

Ask immediately:

1. Is the source actor identified consistently across these records?
2. What did the ASR action block, and was the process still active?
3. What are the current host/protection state and business dependencies?
4. Are WS01's earlier activity and FILE01's session connected by reliable evidence?
5. What collection gaps prevent a safe conclusion?
6. Has containment actually completed?

Prioritize active risk with the incident lead and system owners. Preserve volatile evidence where feasible, but do not delay necessary containment merely to make the timeline perfect. Record the reason and cost of each decision.

## 5. Build the timeline before assigning intent

| UTC / evidence | Observation | Supported statement |
| --- | --- | --- |
| 06:00 E001–E003 | WS01 process A, DNS and connection | Same actor has supplied endpoint observations; payload/intent unknown |
| 06:03 E004–E006 | DC ticket request, FILE01 logon and share check | Authentication/access context; not proof of transferred file contents |
| 06:04 E007–E008 | HealthCheckLab and approved InventoryLab registration | Two distinct task objects and actors |
| 06:05–06:06 E009–E013 | FILE01 process B, LSASS access, ASR block, file and termination | B's sequence warrants review; extraction remains unknown |
| 06:08 E014–E016 | New process C reuses PID; same task path exists on WS02 | Separate lifetimes and separate host objects |
| 06:12–06:13 E017–E018 | Task deleted; Sysmon error recorded | Scoped cleanup and a visibility issue |
| 06:15–06:16 E019–E020 | APP01 logon; FILE01 process C connection | Later activity before completed isolation |
| 06:20 R004 | Isolation acknowledgment | First supplied completed acknowledgment; validate actual scope |

Sorting is a starting point. Separate source-event time from collector receipt and response-action time. A delayed ingestion can make a later-arriving record describe an earlier event. The worksheet supplies only source/action time, so it cannot quantify transport delay.

## 6. Correlate authentication on the correct host

Security **4624** creates a logon session on the destination. In the case, FILE01's TargetLogonId `0x7a01` links as a candidate to FILE01 SubjectLogonId `0x7a01` in share/task records. Type 3 is network logon; it is not interactive desktop access. [Microsoft 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624).

DC **4769** describes a service-ticket request. Its service account name does not automatically provide a full SPN or prove use of a particular remote-execution protocol. The worksheet reports success status but supplies no reliable cross-host logon-GUID join. [Microsoft 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769).

**5145** is an access-check observation. Inspect share, relative target, requested rights and outcome; the row alone supplies no file content or transferred-byte count. [Microsoft 5145](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5145).

The share target helper.txt and task action helper.exe are different names; no content/hash evidence connects them. Do not infer a payload transfer or rename from their similar names.

Do not join DC01, FILE01, WS02 or APP01 by the same numeric logon ID. A username and nearby time strengthen a hypothesis but do not identify a particular process or stolen credential.

## 7. Persistence registration is not triggered execution

E007 reports an enabled logon-triggered task whose action references `C:\Lab\helper.exe`. E009 shows that executable name later running as process B. This is a useful candidate relationship, not supplied proof of a task run.

Obtain full XML, trigger/principal/conditions, task history and compatible action-process identifiers. A preceding Type 3 network logon is not, by itself, evidence that the relevant task logon trigger fired. Confirm actual trigger semantics and execution history. Creation authorization and effective rights are also unresolved.

E008's InventoryLab has an approved change reference. That supports a baseline lead, not automatic approval of every nearby process. E016 has the same HealthCheckLab path and numeric session value on **WS02**; keep it separate. E017 proves a task deletion record, not complete eradication. [Microsoft 4698](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698), [persistence guide]({{ '/wiki/windows-persistence/' | relative_url }}).

## 8. Credential-access and process-lifetime boundaries

The FILE01 actor GUID ending **0202** belongs to process B; **0203** belongs to later inventory process C. Both use PID 5200 in the worksheet. E013 terminates B before C's creation. Do not attach C's DNS/network events to B.

For process-access event 10, the actor is the **source** process, not target LSASS. The normalized actor field on Defender E011 is enrichment rather than a guaranteed native join. Re-check original fields and provenance before treating a cross-product correlation as confirmed.

E010 supports an access observation; E012 supports a file-creation observation. Neither supplies recovered credentials or file content. An ASR block concerns a specific action and does not necessarily terminate the actor. Later APP01 NTLM logon does not establish pass-the-hash or identify where the material came from. [Sysmon definitions](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon), [ASR reference](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference), [credential protection guide]({{ '/wiki/windows-credential-protection/' | relative_url }}).

E018's error requires scope investigation. An error is not proof that all telemetry was lost, and a quiet search after the error is not proof of no activity.

## 9. Read-only worksheet inspection

Save the two downloads under their published filenames in your exercise folder. These commands read only those local files and do not interact with a host agent.

### A. Inspect a chronological worksheet view

```powershell
$irEvidence = Import-Csv -LiteralPath '.\windows-ir-evidence.csv'
$irEvidence |
  Sort-Object time_utc,evidence_id |
  Select-Object evidence_id,time_utc,host,event_id,account,logon_id,actor_guid,object
```

The ISO UTC format sorts chronologically for this dataset. Display formatting can truncate columns; inspect selected records in full when needed. Do not execute anything named in the `object` column.

### B. Record local worksheet integrity

```powershell
Get-FileHash -Algorithm SHA256 -LiteralPath '.\windows-ir-evidence.csv'
Get-FileHash -Algorithm SHA256 -LiteralPath '.\windows-ir-actions.csv'
```

Record the acquisition time and download source with the hashes. A later hash difference may mean modification or a changed download; compare the exact revision. These public files are educational artifacts, not original incident evidence.

## 10. Splunk case searches

The first four searches use **manually installed laboratory CSV lookups** with the exact filenames and headers. Downloading a file does not install a lookup. Use an authorized exercise workspace with the appropriate lookup permissions; do not assume the sample is already in a production index.

### A. Complete case timeline

```spl
| inputlookup windows-ir-evidence.csv
| where case_id="IR-LAB-01"
| eval _time=strptime(time_utc,"%Y-%m-%dT%H:%M:%SZ")
| table _time evidence_id host channel event_id account logon_id actor_guid object source_ip detail
| sort 0 _time evidence_id
```

The time parser matches the supplied UTC format. Keep evidence IDs in every analysis output so an assertion can be traced to a row. No response action is merged into this evidence timeline automatically.

### B. FILE01's local session

```spl
| inputlookup windows-ir-evidence.csv
| where case_id="IR-LAB-01" AND host="FILE01" AND logon_id="0x7a01"
| table time_utc evidence_id host event_id account logon_id object detail
| sort 0 time_utc evidence_id
```

Expected IDs: **E005, E006, E007**. E016 must not appear because WS02 is another host. E004 lacks this local session key; do not force a DC join.

### C. Process B's normalized actor sequence

```spl
| inputlookup windows-ir-evidence.csv
| where case_id="IR-LAB-01" AND host="FILE01"
    AND actor_guid="{00000000-0000-0000-0000-000000000202}"
| table time_utc evidence_id channel event_id actor_guid object detail
| sort 0 time_utc evidence_id
```

Expected IDs: **E009–E013**. The Defender row is included because the worksheet explicitly provides fictional enrichment. This does not demonstrate a generally available production GUID join. C's later activity and the WS01 process must remain separate.

### D. Response work not completed

```spl
| inputlookup windows-ir-actions.csv
| where case_id="IR-LAB-01" AND status!="completed"
| table time_utc action_id host action status evidence_ref detail
| sort 0 time_utc action_id
```

Expected IDs: **R001, R005, R006**. R001 remains a historical request row even though R004 later acknowledges isolation; the worksheet records history, not automatically reconciled current action state. Group related actions and inspect chronology before saying isolation is still pending at the end.

### E. Native Windows session investigation template

```spl
index=windows (EventCode IN (4624,5145,4698,4699) OR EventID IN (4624,5145,4698,4699))
| eval channel=coalesce(Channel,LogName), endpoint=coalesce(Computer,host)
| where channel="Security" AND endpoint="FILE01"
| eval event_id=coalesce(EventCode,EventID)
| eval local_session=case(event_id=4624,TargetLogonId,
    in(event_id,5145,4698,4699),SubjectLogonId)
| where local_session="0x7a01"
| table _time endpoint event_id local_session TargetUserName SubjectUserName
    LogonType AuthenticationPackageName IpAddress ShareName RelativeTargetName TaskName
| sort 0 _time
```

This last search uses hypothetical real Windows ingestion, not the CSV schema. Map parser fields and actual endpoint names first. It explicitly chooses TargetLogonId for 4624 and SubjectLogonId for the other listed events. A missing field is a parsing/coverage question, not an invitation to substitute an unrelated ID.

These searches are not tested production detections. Confirm actual data, permissions, field types and collector-host semantics before use.

## 11. Analysis tasks and answer key

| Task | Minimum supported answer |
| --- | --- |
| What is directly observed on WS01? | E001–E003 show one actor's creation/query/connection; no supplied initial-compromise proof |
| What can be linked within FILE01 session 0x7a01? | E005–E007; identify the different native logon-ID fields |
| Did 4769 prove SMB file transfer? | No; ticket request is distinct from service use and content transfer |
| Did the task cause process B? | Candidate only; full run/trigger/action evidence absent |
| Was LSASS successfully dumped? | Unconfirmed; access, ASR action and filename are insufficient |
| Is process C another execution of B? | No; different GUID/lifetime despite reused PID |
| Did deleting the task complete containment? | No; E017 is scoped cleanup, isolation completes later in R004 |
| Does APP01 prove credential reuse from FILE01? | No; mechanism/source material and authorization remain unresolved |

A defensible working assessment is: **suspicious multi-host activity requiring response, with potential persistence and credential-access concerns; initial access, successful extraction and exfiltration remain unconfirmed**. Escalation can be justified without exaggerating the evidence.

Competing explanations include authorized support/deployment work, compromised use of a legitimate account and unrelated baseline activity. Check owner/change records, file provenance and original endpoint/authentication data to discriminate among them. Do not mark the case benign simply because one task has an approved change number.

## 12. Response decision log and scope

![From evidence assessment to containment and recovery gates]({{ '/assets/diagrams/windows-ir-decisions-en.svg' | relative_url }})

The action worksheet separates **requested, completed, pending and planned**. A request timestamp is not an enforcement timestamp. E019/E020 precede the 06:20 isolation acknowledgment, so they do not demonstrate post-isolation bypass.

| Decision | Required scope/check |
| --- | --- |
| Endpoint isolation | Confirm each endpoint, enforcement acknowledgment and permitted management paths |
| Evidence preservation | Source host, original artifacts, manifest, restricted access and collection gaps |
| Task cleanup | Full task path/host, definition backup, dependencies and independent process review |
| Identity response | Exposure window, actual material, trusted administration and sessions/tokens |
| Domain escalation | Evidence of domain/replication/CA scope; not every local LSASS alert |
| Reconnection | Approved recovery and monitoring gates, owner acceptance and rollback |

Do not kill LSASS, disable protections or perform domain-wide credential recovery as an improvised reaction. Rotate/revoke scoped material from a trusted environment with the identity owner. A password reset does not universally terminate sessions or revoke certificates.

The worksheet does not prove containment of APP01 or WS02, completed credential response, artifact content validation or restored telemetry. Those gaps must remain visible in the handoff.

## 13. Recovery, communication and closure

Before reconnecting affected hosts, document integrity/rebuild decisions, initial-access and persistence review, relevant identity/session actions, operational dependency tests and functioning monitoring. Resolve E018's error and verify representative benign activity end to end.

Use a short status format:

- **Observed:** evidence IDs, hosts, times and concrete behaviors.
- **Assessment:** working hypothesis, confidence and credible alternatives.
- **Actions:** requested versus completed, scope, owner and timestamps.
- **Unknowns:** impact, credential exposure, missing artifacts and data gaps.
- **Next decision:** who owns it, what evidence is needed and what permits recovery.

This exercise remains **open for investigation/recovery decisions** at the supplied endpoint. R005 is pending and R006 is planned. Do not write a closed-success report from these worksheets.

After-action review should produce owned improvements: audit/retention gaps, task execution visibility, reliable identity/host normalization, control applicability and response acknowledgment tracking. Do not measure success solely by alert count or task deletion.

## 14. Scoring and related learning

Score each of the five deliverables from 0–4, for **20 points** total: timeline traceability, correct correlation boundaries, fact/hypothesis separation, proportionate response decisions and honest recovery criteria. Full credit requires preserving unknowns and distinguishing requests from completed actions.

Review [Kerberos]({{ '/wiki/kerberos-authentication/' | relative_url }}), [NTLM]({{ '/wiki/ntlm-authentication/' | relative_url }}), [SMB]({{ '/wiki/smb-security/' | relative_url }}), [Windows logs]({{ '/wiki/windows-logs/' | relative_url }}), [persistence]({{ '/wiki/windows-persistence/' | relative_url }}), [Sysmon]({{ '/wiki/sysmon-investigation/' | relative_url }}) and [credential protection]({{ '/wiki/windows-credential-protection/' | relative_url }}). AD CS/LDAP concepts remain relevant where evidence indicates certificate or directory scope; this case supplies no such compromise evidence.

**Source review: 22 October 2026.** NIST supports the organizational response framing; Microsoft supports event/control interpretation. The environment, worksheet rows, actions, diagrams, questions and scoring are original synthetic teaching material. Publication checks validate consistency, query examples' stated schemas, syntax and delivery; no live incident, host containment, credential extraction or production SIEM execution occurred.
