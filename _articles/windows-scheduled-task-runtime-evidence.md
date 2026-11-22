---
title: "Windows Scheduled Task Runtime Evidence · From Registration to Effect"
description: "Trace a Windows scheduled task from definition to instance, action result and independently observed workload effect."
category: blue-team
tags: [Windows Security, Scheduled Tasks, Task Scheduler, Windows Logs, Sysmon, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/windows-scheduled-task-runtime-evidence/
---

A scheduled task can be registered, start an instance, launch an action and report a result. The requested effect can still be absent. This chapter shows how to establish each stage for a Windows task with an executable action.

## 1. Read the definition before the run

A **scheduled task** is a stored definition that Windows Task Scheduler can activate. The **trigger** defines when or under what condition the task can start, such as a daily time. The **action** defines what it does. For an executable action, read the command, arguments and working directory separately. The **principal** specifies the execution identity and context, including logon type and run level. The registration event’s **subject** is the account that requested the registration or change. The two identities can differ.

The definition also contains **settings** such as what to do when an earlier instance is still running. Depending on the setting, a new run can be ignored, queued, run in parallel or stop the existing instance. An elapsed schedule is a reason to inspect the settings, prerequisites and runtime history. A task **instance** represents one run. Multiple instances may share the same task path.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-scheduled-task-runtime-evidence-en.svg' | relative_url }}" alt="After definition and trigger evaluation, a task instance and its actions may start. The scheduler records an action result, while separate application or file evidence can corroborate the intended effect. A trigger alone can leave the start unobserved.">
  <figcaption>Registration, scheduler history and workload telemetry answer separate questions.</figcaption>
</figure>

## 2. Walk a normal run

Consider the fictional task `\Training\InventoryReport` on workstation `WK-01`. Its approved action creates a local inventory summary. An administrator updates the task at 08:00 UTC and Security 4702 records the new definition. At 08:30 UTC the scheduler records instance `run-a` and the action launch. A process creation record with the expected image and narrow time window supports execution. The schedule team confirms the process association from the available runtime fields. The action returns zero. The file system and the inventory application then independently show a newly written report for that run. Each observation adds evidence that the preceding observation alone could not provide.

| Question | Evidence and boundary |
| --- | --- |
| Was a definition created or changed? | Security 4698 or 4702. 4699 is deletion, 4700 is enablement and 4701 is disablement. These are configuration events. |
| Did an instance start or complete? | TaskScheduler Operational 100 or 102 respectively. Compare the host, full task path and instance ID. Task completion describes the scheduler instance. |
| Was an action started or completed? | Operational 200 or 201 respectively. Inspect the action name, task instance reference and return code where present. A task may have several actions. |
| Which process executed? | Security 4688 or Sysmon 1 when collected. Confirm process identity and parent context with source fields. |
| Did the intended effect occur? | Application logs, file metadata and contents or destination telemetry. Preserve the evidence needed to associate the effect with this run. |

The TaskScheduler provider commonly uses `InstanceId` for the instance start and `TaskInstanceId` for action events. Confirm the provider, channel, event version and XML on the installed build. A task path can be reused after deletion or on another workstation. For runtime grouping use source host, full task path and instance identifier, then confirm per-action identity and order. For repeated actions with the same executable, use additional ordinal or event context where available. Without it, multiple start/completion matches can remain ambiguous.

## 3. Explain suspicious changes and missing effects

A familiar task name can hide an unexpected change to arguments, identity, trigger or writable action path. Compare the latest logged definition with the last known approved definition. A patch deployment or maintenance ticket can also explain a new or changed task. Look for independent support from the deployment record, approved binaries and observed process activity. Preserve the task XML and referenced workload metadata before a response action.

A result of zero often means the executable reported success. A wrapper may return zero even if a child operation failed. A nonzero result needs the program’s documented code or the scheduler’s failure context. Record the raw value and its meaning separately. A completed run with no expected output calls for application logs, working directory, execution account, access rights and destination health. Missing 200/201 can reflect disabled history, retention or forwarding gaps, a trigger that did not run, or launch failure. Use the enabled state, conditions and error events to narrow these possibilities.

## 4. Collect and validate on an authorized host

1. Record the host, time window and time basis. Collect Security and TaskScheduler Operational from the origin host where possible, and preserve raw XML with channel, provider, event version and record ID. Security task changes need **Audit Other Object Access Events** success auditing. Operational history needs the channel enabled and retained. Confirm forwarding coverage separately.
2. For process correlation, collect Security 4688 with **Audit Process Creation** success auditing. Command-line coverage requires its own policy. Alternatively use Sysmon 1 when installed and included by its configuration. Convert hexadecimal process IDs as necessary, use the same host and process lifetime, and use Sysmon ProcessGuid for subsequent Sysmon records. A PID from a provider’s `System/Execution` section can be the event-writing process. Confirm the semantics of a field before using it as the launched process.
3. Compare full path, arguments, principal, trigger, settings and approved-change timing. Correlate scheduler events to the run, then follow the observed child process, application or resource evidence. Treat a match on time and image alone as a candidate.
4. For sustained unexpected task changes or action launches, check whether a known rollout accounts for them. Preserve configuration, relevant files and execution evidence, then coordinate containment with the host owner. After remediation, confirm both the approved task behavior and the evidence pipeline with a benign control in the approved scope.

For a local Windows host with event-log read permission and the ScheduledTasks module, the following checks query history and current runtime information. Change the fictional path and time to your approved investigation scope. The last run and result are a current snapshot and may have been replaced by a later execution.

```powershell
$channel = 'Microsoft-Windows-TaskScheduler/Operational'
(Get-WinEvent -ListLog $channel).IsEnabled
(Get-WinEvent -ListProvider 'Microsoft-Windows-TaskScheduler').Events |
  Where-Object { $_.Id -in 100,102,200,201 } |
  Select-Object Id, Version, Description
Get-WinEvent -FilterHashtable @{
  LogName = $channel
  Id = 100,102,200,201
  StartTime = (Get-Date).AddHours(-2)
} -MaxEvents 40 | ForEach-Object { $_.ToXml() }
Get-ScheduledTaskInfo -TaskPath '\Training\' -TaskName 'InventoryReport' |
  Select-Object LastRunTime, LastTaskResult
```

The history query samples up to 40 matching events across all tasks. Filter by the full task path in the XML for the investigation and adjust the window or limit if the known run falls outside the sample. An empty result also warrants checking permissions, channel state and retention. The PowerShell commands and event descriptions were reviewed against documentation. No live Windows host was used for execution.

## 5. Offline exercise · ten fictional runs

Download the <a href="{{ '/assets/labs/windows-scheduled-task-runtime-evidence.py' | relative_url }}" download="windows-scheduled-task-runtime-evidence.py">Python script</a> and <a href="{{ '/assets/labs/windows-scheduled-task-runtime-evidence-cases.json' | relative_url }}" download="windows-scheduled-task-runtime-evidence-cases.json">fictional JSON</a> into one folder. Run in your own approved workspace using Python 3. The records use teaching fields rather than native Windows XML. Each case targets one task and one specific runtime instance and assumes a single named action. A distinct normalized action reference is already available. Real data may not provide that reference directly.

```bash
python3 windows-scheduled-task-runtime-evidence.py windows-scheduled-task-runtime-evidence-cases.json
```

```text
normal: effect_observed
registration_only: run_unobserved
start_only: action_unobserved
launch_only: completion_unobserved
nonzero: nonzero_result
zero_only: zero_effect_unobserved
other_host: completion_unobserved
other_instance: completion_unobserved
early_effect: zero_effect_unobserved
duplicate_completion: ambiguous_completion
```

Explain the result before comparing with the output. This exercise prioritizes the first unresolved stage, then checks the effect for a zero-return case. A nonzero return can coexist with a partial effect in a real investigation. The exercise requires effect observations at or after the logged launch. A workload can write its file before exiting. If you get a file error, check your working directory and both filenames. For an unexpected match, inspect host, task path, runtime instance, action reference and event order. The offline analyzer was executed on these fixtures.

## 6. Check your understanding

- **4698 contains the expected executable. Did that executable run?** The event establishes registration. Look for an instance, the corresponding action and process evidence.
- **Two 201 events name the same task and executable. Can you pick the nearest timestamp?** First distinguish host, run instance and action occurrence. Deduplicate copies by origin metadata and leave genuine ambiguity open.
- **An action returned zero, but the expected file is missing. What comes next?** Check the application output, working directory, account permissions and file evidence. Review the program’s result semantics.

Complete the exercise when all ten lines match and you can identify the next evidence source for `registration_only`, `zero_only` and `duplicate_completion`.

## Official references and event research

Reviewed 2026-11-22. Microsoft’s Security event entries include historical Windows 10 examples. Verify the event schema and collection on the installed Windows build. The cmdlet reference is for Windows Server 2025 and the Sysmon reference is the edition published September 2026.

- Task definition, settings and diagnosis. [Microsoft Task Scheduler schema](https://learn.microsoft.com/en-us/windows/win32/taskschd/task-scheduler-schema) · [Troubleshoot Scheduled Tasks](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/troubleshoot-scheduled-tasks-not-running)
- Registration and update prerequisites. [Microsoft Audit Other Object Access Events](https://learn.microsoft.com/windows/security/threat-protection/auditing/audit-other-object-access-events) · [Event 4698](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4698) · [Event 4702](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4702)
- Installed-provider metadata and latest runtime results. [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent) · [Get-ScheduledTaskInfo](https://learn.microsoft.com/powershell/module/scheduledtasks/get-scheduledtaskinfo)
- Process evidence. [Microsoft Event 4688](https://learn.microsoft.com/windows/security/threat-protection/auditing/event-4688) · [Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- Operational event mapping, checked against independent research and for verification on the target build. [Splunk Security Content · Action Started](https://research.splunk.com/endpoint/b3632472-310b-11ec-9aab-acde48001122/) · [EVTX Parser · Task Started](https://www.evtxparser.com/en/events/task-scheduler/100) · [Action Completed](https://www.evtxparser.com/en/events/task-scheduler/201) · [Task Completed](https://www.evtxparser.com/en/events/task-scheduler/102)

[Previous · Windows persistence overview]({{ '/wiki/windows-persistence/' | relative_url }}) · [Next · Windows service runtime evidence]({{ '/wiki/windows-service-runtime-evidence/' | relative_url }})
