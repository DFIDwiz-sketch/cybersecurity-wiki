---
title: "PowerShell Script Block Evidence · Reassemble Event 4104"
description: "Reassemble PowerShell script-block fragments, check source coverage and corroborate outcomes with independent evidence."
category: blue-team
tags: [PowerShell, Windows, Event Logs, Blue Team, DFIR, Detection Engineering]
level: Beginner
updated: "2026-11-23"
translation_url: /ko/wiki/powershell-script-block-evidence/
---

**Learning goal.** Reassemble Windows PowerShell script-block records in the right order. Explain what the recovered text establishes and what additional evidence you need to show execution effects.

## 1. What is a script block?

A **script block** is a unit of PowerShell code, such as a script body, a function body or a block written inside braces. An **event provider** is the component that emits events. A **channel** is the event log stream where those records are written. A **runspace** is an execution environment within a PowerShell host process. A process may host more than one runspace.

Script Block Logging records the content PowerShell processes. This can reveal the contents of a script file even when a process command line only names the file. It does not make every line, branch, invocation or downstream action an observed fact. Reusing a logged block can run code again without producing a fresh creation event for that block.

| Evidence | What to look for |
| --- | --- |
| Windows PowerShell 5.1, Event 4104 | `Microsoft-Windows-PowerShell/Operational`. Use the 5.1 policy and test in a new session. |
| PowerShell 7.6 on Windows, Event 4104 | `PowerShellCore/Operational`. Verify the provider is registered and the effective 7.x configuration is applied. |
| Security 4688 | Process start under Audit Process Creation. The command line needs a separate policy. Which fields exist depends on the event version. |
| Sysmon 1 | Process start and ProcessGuid if Sysmon is installed and capture rules include the process. |
| File, service or application evidence | Use telemetry covering the claimed effect and its timestamp. Select the source for the question you are answering. |

These Windows channels can coexist on one machine. A search that only covers 5.1 can miss PowerShell 7 activity. On Linux and macOS, PowerShell uses platform-specific logging, outside this Windows workflow.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/powershell-script-block-evidence-en.svg' | relative_url }}" alt="PowerShell can split the text of one script block into numbered 4104 records. Group them by source and block, verify the full numbered sequence and join the resulting text with process and outcome evidence.">
  <figcaption>Check the fragment sequence before interpreting the code. Check another evidence source before claiming an effect.</figcaption>
</figure>

## 2. Reconstruct one normal record

Imagine a scheduled inventory job uses a PowerShell script that reports a local software version. Its 4104 events arrive at your collector in order 2, 1, then 2 again. The first pass through the stream makes the text seem reversed or duplicated.

1. Keep the original event XML, including `System/Computer`, `Provider`, `Channel`, `TimeCreated`, `Execution/ProcessID` when present, and `EventRecordID`. Preserve the source channel across forwarding. The collector's receipt time can differ from the source event time.
2. In `EventData`, group by `ScriptBlockId` within the original host, provider, channel and verified process lifetime. For this exercise the window is bounded and the process IDs are known and unambiguous. In production, scope each source hostname to a stable host identity and verify PID reuse before joining. An empty `Path` alone does not settle where content came from.
3. Require one consistent `MessageTotal` and all `MessageNumber` values from 1 through that total. Compare the content of repeats. Identical repeated parts can be collapsed within a confirmed group for reconstruction. Preserve the original records. Disagreeing text at the same number leaves a conflict. Assemble `ScriptBlockText` in numerical order, without introducing spaces or line breaks.
4. Find the emitting process on the same source host and within its lifetime. For Security 4688, compare 4104's execution PID to `NewProcessId`, which can be represented in hexadecimal. Do not use the provider's own PID from the 4688 `System/Execution` element. With Sysmon 1, use its process ID and then retain its `ProcessGuid` for follow-on Sysmon joins. A matching inventory job log can show that the report actually succeeded.

Missing parts can reflect an overwritten local log, a narrow query window, an event filter or forwarding loss. Check the endpoint before interpreting a partial collector record. Do not fill a gap from a similar-looking block or concatenate events by arrival order.

## 3. Detect and investigate with context

Intrusions can misuse legitimate scripting to automate unwanted actions. The same interpreter is also used by inventory tools, management agents and administrators. A keyword, unusual parent, blank path or event level alone is weak attribution. A block that defines a function alone does not show the function was called. Treat a proposed effect, such as a changed file, as a separate fact to verify.

1. **Establish coverage.** Record OS and engine versions, local channel and provider, effective Script Block Logging policy, retention and collector subscription. Run an approved, distinctive benign control in a new session. Confirm its local record and the collected copy. Compare UTC timestamps and preserve any lag or gaps. Check read permissions before assuming a quiet channel.
2. **Build a scoped timeline.** Start from the original source host, user or service identity, scheduled time and process creation. Record the matching window and any competing process matches. Join forensic evidence of the claimed effect, such as an independently collected application result or file metadata. A hosted PowerShell process may have a name other than `powershell.exe` or `pwsh.exe`.
3. **Investigate exceptions.** Compare the text and process context with approved job definitions and known maintenance. Use coverage-aware signals such as a newly seen script combined with an unexpected launch path and matching endpoint changes. Measure the rate of incomplete or conflicting fragment groups separately from behavior alerts. Preserve originals and use your response process if the resulting evidence supports containment.
4. **Protect the records.** Script text and command lines can contain secrets. Limit access and redact copies used for training or tickets. Microsoft documents Protected Event Logging with CMS. Put the public encryption certificate on emitters and keep the private key in an authorized decryption environment. When protected fragments are present, retain the ciphertext and use approved decryption before interpreting or assembling plaintext. Do not deploy the decryption key to endpoints.

## 4. Verify an approved endpoint and practice offline

On a Windows lab you own or are authorized to use, open a new session of the engine under test with logging already configured. Use a distinctive benign command such as `Write-Output 'Wiki4104-Control'`. Read back the matching event. These queries are read-only. They require working channels and permission to read the local logs. Set the time window around your test and query the channel that corresponds to the engine you used. The XML output can contain sensitive code. Inspect it in the approved environment.

```powershell
$channel = 'Microsoft-Windows-PowerShell/Operational'
# For PowerShell 7 on Windows, use 'PowerShellCore/Operational'.
Get-WinEvent -FilterHashtable @{
    LogName   = $channel
    Id        = 4104
    StartTime = (Get-Date).AddMinutes(-10)
} -MaxEvents 50 | ForEach-Object { $_.ToXml() }
```

If the channel cannot be read, distinguish a missing provider from access denied. If no matching record exists, confirm the engine, effective policy, new session and time window. The limit of 50 is for a quiet lab and can truncate evidence on a busy host. An investigation export must cover all relevant records. The Windows command was reviewed against vendor documentation and was not run on Windows for this publication.

Save the <a href="{{ '/assets/labs/powershell-script-block-evidence.py' | relative_url }}" download="powershell-script-block-evidence.py">Python script</a> and <a href="{{ '/assets/labs/powershell-script-block-evidence-cases.json' | relative_url }}" download="powershell-script-block-evidence-cases.json">fictional, normalized records</a> in one folder. The script reads only this JSON shape. It groups fragments and verifies sequence integrity, with a supplied flag for protected content. It does not read EVTX, decrypt CMS, infer a process lifetime or execute script text. Its report omits the recovered text.

```bash
python3 powershell-script-block-evidence.py powershell-script-block-evidence-cases.json
```

```text
out_of_order: complete
missing_middle: incomplete
conflicting_copy: conflict
separate_sources: complete, incomplete
mixed_totals: conflict
protected_fragment: protected
invalid_index: invalid
```

If input fails, check the working directory and filenames. In `separate_sources`, the fixture deliberately reuses the same block identifier on two hosts. Their parts must not be mixed. A reconstructed block with an unconstrained or incomplete source lifetime is still unsafe to interpret as a single execution. Python was executed with these fictional records and the reconstructed order was checked.

## 5. Check your reasoning

- **A block has parts 1 and 3 of 3. Can you report the whole block?** Report the gap and check the source log for part 2.
- **Two 4104 records show the same part number with different text. Which should win?** Preserve both and verify the source and grouping. Do not pick by collector arrival time.
- **Does complete 4104 text prove all commands succeeded?** Use process and outcome evidence. A complete text is evidence about the content processed by the engine.

Finish when all seven lines match and you can identify the engine, the group key, any missing parts and one independent source for the claimed effect.

## Official references

Reviewed November 23, 2026. The Windows behavior is scoped to Windows PowerShell 5.1 and PowerShell 7.6. The source snapshot documents 7.6.0 specifically.

- Microsoft Learn on channels, policy and protected content. [Windows PowerShell 5.1 logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1) · [PowerShell 7.6 on Windows](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging_windows?view=powershell-7.6)
- PowerShell 7.6.0 field names and fragment-writing behavior. [Event manifest](https://github.com/PowerShell/PowerShell/blob/v7.6.0/src/PowerShell.Core.Instrumentation/PowerShell.Core.Instrumentation.man#L3875) · [Engine source](https://github.com/PowerShell/PowerShell/blob/v7.6.0/src/System.Management.Automation/engine/runtime/CompiledScriptBlock.cs#L1421)
- Microsoft Learn on event filtering and process evidence. [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.6) · [Windows Security 4688](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688) · [Sysmon events](https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/sysmon-events)

[Previous · Windows event logs]({{ '/wiki/windows-logs/' | relative_url }}) · [Next · Sysmon investigation]({{ '/wiki/sysmon-investigation/' | relative_url }}) · [Related · Windows Event Forwarding]({{ '/wiki/wef-delivery-evidence/' | relative_url }})
