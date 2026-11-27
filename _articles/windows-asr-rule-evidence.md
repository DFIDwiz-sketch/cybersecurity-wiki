---
title: "Microsoft Defender ASR · Audit, Block and Warn Evidence"
description: "Trace an Attack Surface Reduction rule decision, check the effective setting, and corroborate whether the attempted child process started."
category: blue-team
tags: [ASR, Microsoft Defender, Windows, Event Logs, Blue Team, Detection Engineering]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/windows-asr-rule-evidence/
---

A help desk ticket says that Excel failed to open a reporting helper. The endpoint has a Defender event with ID 1121. The analyst needs to identify the matching rule, tie it to the reported attempt, then check whether any retry started a process. Those questions use different evidence.

## 1. Follow the rule from policy to endpoint

**Attack Surface Reduction (ASR)** rules in Microsoft Defender Antivirus evaluate selected risky behaviors on Windows, such as an Office application attempting to start a child process. Controlling a behavior can interrupt an attack even when the files involved are otherwise legitimate. An approved Office add-in may also start a helper, so a match needs business and security context.

A rule has a stable **GUID** (rule identifier) and an **action** (configured mode). A management service such as Intune assigns settings to devices. The endpoint evaluates activity using its effective rule settings, rule-specific prerequisites, and applicable exclusions. When investigating a past decision, keep both the historical policy evidence and the time of the local observation. An assigned policy or today's configuration alone gives limited evidence about yesterday's state.

<figure>
  <img src="{{ '/assets/diagrams/windows-asr-rule-evidence.svg' | relative_url }}" width="560" height="332" alt="Assigned policy and endpoint prerequisites lead to rule evaluation. Defender records the decision. Independent process telemetry answers whether a matching child started." />
  <figcaption>Read the policy, the Defender decision and process creation as separate observations.</figcaption>
</figure>

| Evidence in Defender Operational | What it supports | What remains to check |
| --- | --- | --- |
| **1122**, Audit (mode 2) | The activity matched a rule evaluated in Audit mode. ASR did not block this operation in Audit mode. | Whether the child started or another control intervened. |
| **1121**, Block (mode 1) | Defender recorded blocking an operation under an ASR rule. | Which rule and operation were blocked, and whether another attempt succeeded. |
| **1129**, Warn override (mode 6) | An override was recorded for a rule operating in Warn mode. | Whether the related retry started the child, and who approved the action if applicable. |
| **5007**, settings changed | A Defender configuration change was recorded. | Whether the old and new values concern the ASR rule in question. |
| No rule record in the collected window | The available source did not show a matching entry. | Effective settings, exclusions, sensor and forwarding health, time range and retention. |

**Current and historical Warn behavior.** For supported rules and versions, Microsoft documents temporary suppression for 24 hours with Warn. Administrator approval for selecting Unblock was introduced in Defender platform **4.18.26060**. Older deployment notes may describe a different approval experience. Check the platform that was running during the incident and the prerequisites for that rule. An override record is a separate event from the initial warning and subsequent process creation.

## 2. Reconstruct one attempt

In this fictional pilot, at 09:04 UTC the approved monthly report triggers the Office child-process rule on `LAB-REPORT-01`. Defender records 1122, and process telemetry records the approved helper starting under that Excel instance. At 10:15 UTC, after a controlled rollout switches the rule to Block, the same workflow gives 1121 and no matching child appears in complete test telemetry for that attempt. The application owner confirms the helper is an expected dependency. The team now has evidence of a compatibility regression and can review the workflow and policy with its owner.

The Office child-process rule has GUID `d4f940ab-401b-4efc-aadc-ad5f3c50688a`. The current Microsoft reference notes the rule's Office installation path requirement (`%ProgramFiles%` or `%ProgramFiles(x86)%`). For a suspicious Office document, the same behavioral match can be a lead to examine the file's provenance, parent process, target executable and nearby network or file activity. An unexpected policy change could also reduce coverage. Correlate changes against approved assignments, exclusions and administrator activity before attributing intent.

## 3. Collect, corroborate and respond

1. **Confirm scope and coverage.** Identify the device, UTC interval, and log source. Check Defender Antivirus Active mode as the primary antivirus, real-time protection, rule support, and applicable cloud requirements. Note the OS, Defender platform and engine, policy source and timing, exclusions, local retention and any gaps in forwarding. Different Defender features share the channel. Scope numeric IDs by provider and channel.
2. **Preserve the original evidence.** Export the relevant EVTX or raw XML with its source and collection window. Keep rule GUID and the raw paths, user, process and target details when present. For 5007, compare old and new values and correlate the management-side rollout. A 5007 row alone does not identify the actor or prove that a child process was allowed.
3. **Check execution independently.** On the same device, use an available process-start identifier or the parent PID **with its creation time**, and compare time, path, and session where available. Confirm the actual child and separate retries. For example, use Sysmon Event 1 only where Sysmon collects it or Security 4688 where Audit Process Creation is enabled. Command-line data for 4688 requires additional policy. A missing process event is inconclusive if coverage is incomplete.
4. **Act on the evidence.** For a validated business workflow, record the owner, rule, rollout ring and affected application before seeking a scoped, reviewed policy decision. For unexplained repeats, correlated suspicious process starts, or unexpected policy drift, preserve the related artifacts, verify the configuration source, and follow endpoint incident triage. Microsoft recommends Block for standard protection rules and initial Audit testing for other rules before enforcement.

For a Windows host with access to the local channel, this **read-only** example lists candidates from the last 24 hours. Inspect XML for the case record. No returned rows can also indicate a log or collection problem.

```powershell
$filter = @{
  LogName = 'Microsoft-Windows-Windows Defender/Operational'
  ProviderName = 'Microsoft-Windows-Windows Defender'
  Id = 1121, 1122, 1129, 5007
  StartTime = (Get-Date).AddHours(-24)
}
Get-WinEvent -FilterHashtable $filter |
  Select-Object TimeCreated, MachineName, Id, RecordId, Message
```

With permission to use Advanced Hunting and Defender for Endpoint onboarded and sending data, the following query lists the documented Audit and Block action types for this Office rule. Review Warn overrides in the local channel. Show `ReportId` with `DeviceName` and `Timestamp` for event identity. `ReportId` and the local `RecordId` belong to different sources.

```kusto
DeviceEvents
| where Timestamp >= ago(24h)
| where ActionType in ("AsrOfficeChildProcessAudited", "AsrOfficeChildProcessBlocked")
| project Timestamp, DeviceId, DeviceName, ReportId, ActionType,
    InitiatingProcessFileName, InitiatingProcessId, InitiatingProcessCreationTime,
    FileName, FolderPath
| order by Timestamp asc
```

## 4. Offline defense validation

Use only the attached fictional observations and Python 3. Run this example in your own or an explicitly approved workspace. It reads a CSV, makes no network calls, and does not touch a Windows policy. Download <a href="{{ '/assets/labs/windows-asr-rule-evidence/asr-cases.csv' | relative_url }}" download="asr-cases.csv">asr-cases.csv</a> beside a local `review_asr.py` containing the code below, then run `python3 review_asr.py`.

The fixture simplifies sources into labels. Its `attempt` value is a supplied match key for the exercise, not a native Windows field. A real investigation must justify the correlation from independent metadata.

```python
import csv
from collections import defaultdict

with open("asr-cases.csv", encoding="utf-8", newline="") as stream:
    cases = defaultdict(list)
    for row in csv.DictReader(stream):
        cases[row["case"]].append(row)

decision_names = {"1121": "blocked", "1122": "audited", "1129": "warn-override"}
expected = {
    "audit-and-start": ("audited", True),
    "block": ("blocked", False),
    "warn-only": ("warn-override", False),
    "warn-and-start": ("warn-override", True),
    "other-host": ("audited", False),
    "different-attempt": ("blocked", False),
    "config-only": ("config-only", False),
    "no-rule-evidence": ("no-rule-evidence", False),
}

def review(rows):
    defender = [row for row in rows if row["source"] == "defender-operational"]
    decisions = [row for row in defender if row["event_id"] in decision_names]
    if not decisions:
        changed = any(
            row["event_id"] == "5007" and row["detail"] == "confirmed-asr-setting"
            for row in defender
        )
        return ("config-only" if changed else "no-rule-evidence", False)
    if len(decisions) != 1:
        raise ValueError("Fixture cases must have at most one ASR decision")
    decision = decisions[0]
    started = any(
        row["source"] == "process"
        and row["detail"] == "child-start"
        and decision["attempt"]
        and (row["host"], row["attempt"]) == (decision["host"], decision["attempt"])
        for row in rows
    )
    return decision_names[decision["event_id"]], started

actual = {name: review(rows) for name, rows in cases.items()}
assert actual == expected, f"Expected {expected!r}, got {actual!r}"
for name, (decision, start_seen) in actual.items():
    print(f"{name}: {decision}, matched child start={start_seen}")
```

**Expected results.** Eight cases pass. Only the paired Audit and Warn cases have a matching child start. The other-host and different-attempt cases have a process record, but neither record can corroborate the relevant attempt. A rule-specific 5007 contributes configuration evidence only. A generic 5007 and an ID 1121 from another source establish no ASR decision.

**Failure checks.** Run from the folder containing both files and retain the UTF-8 header. As a negative control, edit a copy of the CSV by changing the host on the `warn-and-start` process row. That case should fail the assertion because the recorded process belongs to another host. Restore the original CSV before comparing again. The Python fixture was executed in the cloud. The Windows and Defender XDR examples were reviewed against product documentation.

## 5. Review and completion criteria

1. **Does 1129 establish that the child ran?** No. It establishes a recorded Warn override. Confirm the matching execution separately.
2. **Does a 5007 before 1121 explain the block?** Review the values and rule GUID first. A chronologically adjacent change can involve a different setting.
3. **Can an incident be closed with 1121 and no process event?** Check sensor coverage, retries and related activity. The block supports a decision about one operation.

Complete the chapter when you can name the rule and decision, cite the event source and time range, show which independent record supports execution, and explain what missing telemetry leaves unresolved.

## Official references

Reviewed **2026-11-27**. The product scope is Microsoft Defender ASR on supported Windows systems and Defender XDR telemetry where available. The Warn change is scoped to Defender platform 4.18.26060 and later.

- [Microsoft Learn · ASR overview, prerequisites and mode behavior](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview)
- [Microsoft Learn · Windows event channel and IDs](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-windows-events)
- [Microsoft Learn · ASR rule reference and Office rule details](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-reference)
- [Microsoft Learn · ASR deployment guide](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-deployment)
- [Microsoft Learn · Get-WinEvent filter parameters](https://learn.microsoft.com/en-us/powershell/scripting/samples/creating-get-winevent-queries-with-filterhashtable)
- [Microsoft Learn · Defender XDR DeviceEvents schema](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table)

- [Microsoft Learn · Security event 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [Microsoft Learn · Sysmon event 1](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

[Previous · Defender Antivirus detection and remediation]({{ '/wiki/windows-defender-remediation-evidence/' | relative_url }}) · [Next · Windows App Control audit and enforcement]({{ '/wiki/app-control-evidence/' | relative_url }}) · [Corroborate with process creation events]({{ '/wiki/windows-process-creation-evidence/' | relative_url }})
