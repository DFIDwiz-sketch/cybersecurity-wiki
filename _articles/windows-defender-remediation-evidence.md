---
title: "Microsoft Defender Antivirus · Detection and Remediation Evidence"
description: "Follow Windows Defender Operational events from detection to action and distinguish a product-reported outcome from incident closure."
category: blue-team
tags: [Microsoft Defender, Windows, Event Logs, Incident Response, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/windows-defender-remediation-evidence/
---

A collector receives a Defender Antivirus alert for a file on a Windows workstation. The first question is what the antivirus observed. The next is what happened to that resource and whether the endpoint still needs investigation. Keep these questions separate so that a single status does not close an incident prematurely.

## 1. Follow the detection and response

A **detection** is a product finding about a resource such as a file or script. The **action** is the operation the product reports for that resource, such as quarantine or blocking. **Remediation** here means a recorded clean, quarantine or removal of that resource, with the result and any follow-up checked separately. Quarantine restricts access to the resource. Removal deletes it. Endpoint **containment** limits further activity such as network communication and is a separate response decision.

Use the **Microsoft-Windows-Windows Defender/Operational** channel for the Windows Antivirus events in this chapter. **Threat ID** identifies the threat classification and can recur across multiple detections. Where the raw event exposes an instance identifier, preserve that **Detection ID** and pair it with a stable endpoint identifier. Keep resource and time as supporting evidence. An event record ID locates a row in an originating channel and log generation. It is useful for provenance rather than as a detection join key.

| Event in the Defender Operational channel | Question it helps answer | What to read next |
| --- | --- | --- |
| 1116 | What did the product detect? | Resource, detection source, product and intelligence version, available identity fields |
| 1117 | What action did the product record? | Action, status or error fields, and any follow-up requirement |
| 1118 | Did the action encounter a noncritical error? | Attempted action and error. Look for a later result for the same detection |
| 1119 | Did the action encounter a critical error? | Attempted action and error. Escalate and review other host evidence |

The action field matters. **Allow** or **No action** leaves cleanup unconfirmed. **Block** describes restricting the attempted execution or operation. It does not show that the file was removed. Even a successful **Quarantine** says something about the specific resource at that time. It leaves previous execution, other copies and the state of the rest of the host to be checked.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-defender-remediation-evidence-en.svg' | relative_url }}" alt="Start with detection event 1116. Correlate the endpoint and detection. Event 1117 supplies an action to interpret. Events 1118 or 1119 show a failed attempt, while an absent action leaves a collection or outcome question. Check other host evidence before closing the incident." style="max-width: 100%; height: auto;">
  <figcaption>Figure 1. Trace the resource and recorded action before making a host-level decision.</figcaption>
</figure>

## 2. Read a normal timeline

The following observations are fictional. At 10:00:00 UTC, workstation `LAB-01` reports 1116 for detection `D-01` on a file under its downloads folder. The source is real-time protection. At 10:00:05, the same endpoint and detection report 1117 with `Quarantine` and a successful result. The forwarded record arrives at 10:02:13. For incident ordering, use the source time and allow for clock skew. Use ingest time to investigate the delay.

Write the finding as “Defender reported successful quarantine of the detected resource.” If the host also has suspicious process activity before 10:00, pursue it using source-appropriate process creation telemetry. For example, Security 4688 requires process creation auditing, and Sysmon Event 1 requires Sysmon and coverage for the process. Join on endpoint and time with available path, hash, and process lineage. User or process names in an antivirus record can describe the scan context. Treat them as leads for corroboration.

## 3. Account for misuse and incomplete evidence

Repeated alerts may describe copies on different hosts, multiple resources with the same threat classification, or a retried action. Incorrectly joining on threat name or Threat ID can attach a successful cleanup to an unresolved detection. An attacker or unauthorized change to protection policy can reduce coverage, but a quiet log also has ordinary explanations such as rotation, forwarding delay, or a sensor running in a different mode. Check approved changes and the incident-time state where evidence exists. A present-day status snapshot describes the time you collected it.

A detection can be associated with scanning a download or inspecting script content. Avoid inferring that the associated process launched the detected code. Equally, an allowed action does not establish that the file ran. Document the difference between a label from the product and a verified behavior. When the raw record lacks a Detection ID, compare device, resource, Threat ID, source and a bounded source-time window. Keep multiple matching candidates open for review rather than silently assigning one.

## 4. Collect, detect and respond

1. **Collect source records.** On an authorized Windows endpoint with access to the channel, review the affected window in Event Viewer or use the read-only PowerShell example below. The last four hours are an example. Use the incident window and record its time zone. Preserve original EVTX through your collection process, source XML, and the corresponding collector records. Avoid publishing real resource paths or account data. The Defender cmdlets require the Defender module and access to local product data. The example reads a current mode snapshot and currently available detection history.

~~~powershell
$channel = 'Microsoft-Windows-Windows Defender/Operational'
$end = Get-Date
Get-WinEvent -FilterHashtable @{
  LogName = $channel
  Id = 1116, 1117, 1118, 1119
  StartTime = $end.AddHours(-4)
  EndTime = $end
} | ForEach-Object { $_.ToXml() }

Get-MpComputerStatus | Select-Object AMRunningMode
Get-MpThreatDetection
~~~

2. **Validate coverage before assigning a result.** Verify the operating mode, channel retention and forwarding subscription, endpoint identifiers, source clock, and preservation of XML event data. Inspect the structured fields for your build. Keep the normalized row and raw event linked. Compare local and central findings and allow for expected ingest delay. A missing 1117 alone leaves the action outcome unresolved. An unmatched 1117 or error event is evidence that the collector or query may lack the detection side.
3. **Triage by resource and outcome.** Track 1118/1119, allowed actions, and detections with no matched action after an approved delivery window. A failure followed by a reliable success for the same detection means there was a failed attempt and a later success. Keep both. For unresolved failures, capture action and error details, evaluate required actions such as an approved reboot if the product calls for one, check related resources, and consider containment based on correlated behavior and business impact.
4. **Verify the host separately.** Report action outcomes for each relevant resource. Check follow-up status and rerun the investigation for execution, recurrence and exposure across other devices. A new detection, later restoration, or other resource outside the sampled window can change the decision. Use the [Windows event analysis guide]({{ '/wiki/windows-logs/' | relative_url }}) for source selection and [endpoint isolation evidence]({{ '/wiki/endpoint-isolation-evidence/' | relative_url }}) for independent containment checks.

## 5. Authorized offline exercise

Save the <a href="{{ '/assets/labs/windows-defender-remediation-evidence.py' | relative_url }}" download>Python analyzer</a> and the <a href="{{ '/assets/labs/windows-defender-remediation-evidence.csv' | relative_url }}" download>fictional event CSV</a> in the same directory. In your own or approved environment, run the command below with Python 3. It reads the fixture only. The CSV is an illustrative normalization, not a Microsoft event schema. The fixture uses explicit UTC timestamps and a synthetic `reported_success` value. In a real parser, derive success only from validated action and result fields for your product version.

~~~bash
python3 windows-defender-remediation-evidence.py
~~~

| Fixture entries | Expected result |
| --- | --- |
| LAB-01 D-01 and LAB-02 D-01 | Reported quarantine on LAB-01. Detection only on LAB-02 despite the repeated ID |
| LAB-01 D-02 and D-03 | Allowed and blocked respectively. Neither demonstrates file cleanup |
| LAB-01 D-04 and D-05 | Failed attempt followed by successful removal for D-04. Critical action error for D-05 |
| LAB-01 D-06 and D-07 | Action without result confirmation for D-06. Action without a matched detection for D-07 |
| LAB-01 record 120 and LAB-01 D-08 | Unlinked event without an instance ID. Review of coincident conflicting outcomes for D-08 |

Expect ten output rows. As a negative control, make a copy of the CSV, replace `D-01` with `D-X` on the LAB-01 quarantine row only, and run the analyzer with that filename as its argument. LAB-01 D-01 should become `detection-only` and D-X should show `missing-detection`. If the baseline differs, check that the files match the same edition and that your editor preserved column names and UTC timestamps. The Python exercise was executed against synthetic data. The PowerShell and Defender workflow were reviewed against Microsoft documentation without a live Windows device.

## 6. Check your reasoning

1. **Why does 1117 alone leave cleanup uncertain?** The result depends on the recorded action and its status. Allow and Block have different implications from confirmed quarantine or removal.
2. **A critical failure belongs to one host. A second host reports quarantine for the same Threat ID. Is the first resolved?** Each endpoint and detection needs its own action evidence. The second host supplies no outcome for the first.
3. **Does scan context prove execution?** Check process creation and lineage, and note any coverage gap before concluding whether a resource ran.

**Completion criterion.** Reproduce the baseline and negative control, explain one safe event join, and write an incident note that distinguishes the resource outcome, uncertainty about execution, and the next source to collect.

## Official references

Reviewed 2026-11-26. Scope is current Microsoft documentation for Defender Antivirus on supported Windows endpoints and the cited PowerShell interfaces. This chapter focuses on the 1116–1119 family. Microsoft's event catalog also lists older or additional event families. Confirm the source channel, product mode and event payload in your environment.

- [Microsoft Defender Antivirus event IDs and error codes](https://learn.microsoft.com/en-us/defender-endpoint/troubleshoot-microsoft-defender-antivirus#event-id-1116)
- [Review Defender Antivirus scan results](https://learn.microsoft.com/en-us/defender-endpoint/review-scan-results-microsoft-defender-antivirus) and [Get-MpThreatDetection reference](https://learn.microsoft.com/en-us/powershell/module/defender/get-mpthreatdetection)
- [Microsoft Defender Antivirus for Windows and operating modes](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-antivirus-windows) and [Get-WinEvent reference](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.5)
- [Security 4688 and Audit Process Creation](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688) and [Sysmon process creation](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon#event-id-1-process-creation)

For rule decisions about behaviors, compare [Defender ASR audit, block and Warn evidence]({{ '/wiki/windows-asr-rule-evidence/' | relative_url }}).
