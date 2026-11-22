---
title: "Windows Service Runtime · Verify Startup, Process Identity and Health"
description: "Trace Windows service configuration, SCM state, process and module observations, and workload health through seven offline cases."
category: blue-team
tags: [Windows Security, Windows Services, Windows Logs, Sysmon, DFIR, Blue Team]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/windows-service-runtime-evidence/
---

Start here when an investigator has a service name or an installation event and needs to establish what happened at runtime. The [Windows persistence guide]({{ '/wiki/windows-persistence/' | relative_url }}) covers how registration fits alongside tasks, Run keys and WMI. This chapter focuses on Windows user-mode services and the evidence that separates registration, startup, module loading and useful work.

## 1. Configuration and observed state answer different questions

The **Service Control Manager (SCM)** maintains the installed service database and tracks status reported by services. A service has an internal **name** used for lookup and a **display name** intended for people. Start configuration describes when the service is eligible to run. A manual setting can coexist with a running service, and an automatic setting can coexist with a stopped service. Record configuration at collection time as a snapshot. Use period-appropriate audit or inventory records to establish changes.

A typical startup takes the service from `STOPPED` through `START_PENDING`. The service reports `RUNNING` once it is ready to receive service control requests. Pending states can carry a **checkpoint** showing progress and a **wait hint** estimating how long the current operation needs. A single pending snapshot and its wait hint are insufficient to establish a timeout. Query time, repeated observations and the raw error help distinguish normal initialization from a failure. SCM returns the latest status that it has received, so snapshots can lag a transition.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-service-runtime-en.svg' | relative_url }}" alt="Configuration leads to SCM state. Pending or failed states lead to error and collection checks. A running report leads to process or module correlation and then independent workload evidence.">
  <figcaption>Follow the branch supported by the collected state. On the running branch, process evidence and service health answer successive questions.</figcaption>
</figure>

| Evidence | Supports | Check next |
| --- | --- | --- |
| Service configuration or install record | The service was configured or installed in the observed scope | Whether a start was attempted |
| SCM pending, failure or running report | The corresponding state or failure was reported | Raw error, process association and observation time |
| Process creation or module load | A process instance started or loaded a module | Which service used it and whether work completed |
| Application health or transaction | A defined operation succeeded within the tested scope | What was tested, who initiated it, and its observed effect |

## 2. Walk a normal change and a failed start

Consider a fictional maintenance ticket to update the `DemoReport` reporting agent on host H1. At 09:00 UTC inventory records the approved service name, startup type and binary path. At 09:02 a process creation event records `report.exe`. An SCM snapshot at 09:02:03 shows the same PID in `RUNNING`. The agent then records one completed test report with the matching run ID. The ticket supports authorization. SCM and process records support startup. The test result supports functionality for that run.

On another host the process appeared, then the service stayed pending and SCM logged a startup timeout. Check the error details, dependency and account records, endpoint policy, application logs and first-seen time before deciding a cause. Windows Server's documentation discusses a specific timeout pattern involving events 7000 and 7011. Those IDs require the event's context and message to support that interpretation. A failure is compatible with a routine deployment problem and with unauthorized change.

For a shared-process service several services can occupy a single host such as `svchost.exe`. Its creation can predate the service start. A module load in that host narrows the claim to a specific module and process instance. To attribute activity to the service, compare its trusted configuration and the application's own event, transaction ID or measured output. One module can be used by multiple components.

## 3. Collect and correlate before containment

1. **Anchor the service.** Record host identity, boot interval, UTC time, internal and display names, configured account, binary command, dependencies, service type and owner. Save raw System and Security events with provider, channel, event version and record ID. Preserve the actual file metadata and hash through approved collection. A command line may contain arguments and is a different field from a resolved file path.
2. **Check event coverage.** Security 4697 is an installation event with the **Audit Security System Extension** success setting, log access and retention as prerequisites for investigating it. It captures installation-time configuration. In the System channel, inspect raw Service Control Manager events for the relevant time and name. Keep original error text and values. Check local evidence before treating an empty forwarded query as a negative finding. [Windows event analysis]({{ '/wiki/windows-logs/' | relative_url }}) covers the broader collection context.
3. **Join the right process.** Prefer a process-instance ID such as Sysmon `ProcessGuid` where available. Join using host and corroborating time, and check boot and process lifetime when using PID. `QueryServiceStatusEx` documents that a PID can be invalid in start/stop pending and is invalid in stopped. Do not associate a snapshot with a future process or continue a PID across restart. Sysmon event 1 records process creation if enabled and captured by the active filters. Event 7 records a module load only with appropriate ImageLoad collection, which is disabled by default. For shared hosts compare the complete module path and available hash, not just the basename used in the lab.
4. **Respond to the evidence.** Compare binary, module and account to the approved baseline and change record. An altered existing configuration or replacement binary can be important even without a new install event. Escalate unexplained changes to the service owner and incident lead, preserve records and assess dependent workloads before isolation or stopping a shared host. Corroborate effects with application evidence. Record which event channels, hosts and times are covered and which remain unknown.

When a detection flags installation or drift, confirm that observed old and new values come from the same service on the same host. Validate with a documented maintenance change and a fixture that includes the same service name on a second host. Use separate alert reasons for unexpected registration, an unexplained runtime image and unresolved collection. This preserves the distinctions an analyst needs to prioritize evidence.

## 4. Read-only inspection on an authorized Windows host

On a supported Windows client or server with PowerShell, local SCM/CIM read access and the Windows Event Log service installed, query by its internal name `EventLog`. Use `sc.exe` explicitly in PowerShell. These commands record the time and read current data.

```powershell
Get-Date -Format o
sc.exe qc EventLog
sc.exe queryex EventLog
Get-CimInstance Win32_Service -Filter "Name = 'EventLog'" |
  Select-Object Name, DisplayName, StartMode, State, ProcessId, StartName, PathName
```

Expect configuration and status observations sampled at slightly different times. Record the status, exit code and checkpoint if shown, and use a valid runtime PID before joining to process evidence. Repeat the observation with timestamps if the state changes between calls. Record access denied or service name errors as collection results. This example was reviewed against the product documentation. No Windows session was used to execute it.

## 5. Run the offline evidence exercise

Download both files into one folder. Use Python 3.10 or later and run from that folder. The exercise reads **fictional normalized JSONL**. Seconds and host, boot and process identifiers are illustrative. Collected product XML and vendor schemas require their own normalization. The script reads local synthetic files. The offline exercise was executed with Python 3.12.

<a href="{{ '/assets/labs/windows-service-runtime-review.py' | relative_url }}" download>windows-service-runtime-review.py</a> · <a href="{{ '/assets/labs/windows-service-runtime-cases.jsonl' | relative_url }}" download>windows-service-runtime-cases.jsonl</a>

```bash
python3 windows-service-runtime-review.py windows-service-runtime-cases.jsonl
```

```text
approved: dedicated_process_and_health
pending: pending
timeout: start_failure
shared_host: shared_host_only
module_observed: shared_module_observed
pid_reused: shared_host_only
registration_only: registration_only
```

The script anchors each case to its host, boot and observation time. The fixture uses module basenames and a known short time window for test health. Production joins need a stronger process identity, complete paths and a service-specific transaction or equivalent evidence. `shared_module_observed` means a matching module load was recorded in the identified host process. If that row is absent, check the Sysmon ImageLoad policy and collection before inferring what loaded. If the script cannot open a file, confirm the working directory and extension. If a classification differs, inspect the selected time and host/boot pair before trusting a same-PID event.

## 6. Check your conclusions

- **Does process creation plus a pending state prove successful service startup?** The process observation and pending report are both supported. A later running report, explicit failure or other lifecycle evidence is needed to finish the startup timeline.
- **Can the `pid_reused` case borrow the earlier module-load event?** No. The earlier process ended and its identity differs from the process associated with the current snapshot. The prior boot supplies a second mismatch.
- **Does an approved file prove this service performed its job?** File approval supports a configuration or provenance check. Look for the service's actual output, a matching health result or a transaction from the tested window.

Complete the exercise by reproducing all seven output lines, identifying the evidence supporting each claim in `approved`, and naming the next source needed for `pending`, `shared_host` and `registration_only`.

## Official references

Reviewed 2026-11-22. The Win32 API pages describe Windows service mechanics. Validate event schemas and coverage on the actual OS and Sysmon versions in use. The 4697 page contains a historical sample and the timeout article covers a specific Windows Server scenario.

- Win32 SCM and installed-service database. [Microsoft Learn · Service Control Manager](https://learn.microsoft.com/en-us/windows/win32/services/service-control-manager)
- Win32 service lifecycle. [Microsoft Learn · Service state transitions](https://learn.microsoft.com/en-us/windows/win32/services/service-status-transitions)
- Win32 snapshot and PID validity. [Microsoft Learn · QueryServiceStatusEx](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/nf-winsvc-queryservicestatusex)
- Win32 process types, checkpoint and wait hint. [Microsoft Learn · SERVICE_STATUS_PROCESS](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_status_process)
- CIM field definitions. [Microsoft Learn · Win32_Service and SC](https://learn.microsoft.com/en-us/windows/win32/cimwin32prov/win32-service)
- Windows SDK CLI. [Microsoft Learn · SC query commands](https://learn.microsoft.com/en-us/windows/win32/services/configuring-a-service-using-sc)
- Windows 10 reference and historical XML example. [Microsoft Learn · Security event 4697](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4697)
- documented timeout scenario for supported Windows Server versions. [Microsoft Learn · Windows Server events 7000 and 7011](https://learn.microsoft.com/en-us/troubleshoot/windows-server/system-management-components/service-not-start-events-7000-7011-time-out-error)
- Windows Sysmon event definitions and collection prerequisites. [Microsoft Learn · Sysmon events](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)

[Previous · Windows persistence]({{ '/wiki/windows-persistence/' | relative_url }}) · [Next · Sysmon investigation]({{ '/wiki/sysmon-investigation/' | relative_url }})

## Verify scheduled task execution

Use [Windows scheduled task runtime evidence]({{ '/wiki/windows-scheduled-task-runtime-evidence/' | relative_url }}) to track an executable action from the task definition to its scheduler instance, process and observed result.

## Investigate group managed service accounts

[Active Directory gMSA Evidence]({{ '/wiki/ad-gmsa-evidence/' | relative_url }}) connects retrieval eligibility to actual service logon and workload health.
