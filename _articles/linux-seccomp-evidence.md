---
title: "Linux seccomp Evidence · Explain a Denied System Call"
description: "Separate a loaded filter, a system-call result and an audit record, then verify one restrictive rule on a disposable Python process."
category: blue-team
tags: [Linux, seccomp, Linux Audit, Containers, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/linux-seccomp-evidence/
---

**Learning path** · [Linux capabilities]({{ '/wiki/linux-capability-evidence/' | relative_url }}) → seccomp decisions → [Linux Audit file access]({{ '/wiki/linux-audit-file-evidence/' | relative_url }}).

## 1. What a seccomp filter decides

A **system call** is a request a thread makes to the Linux kernel. Examples include opening a file or reading the parent process ID. The **application binary interface (ABI)** specifies how the program makes a call, including which number represents it. The same number can identify different calls on different ABIs.

**seccomp** reduces the set of kernel operations available to a thread. In filter mode, the kernel evaluates a filter against the call number, architecture and other call data. Classic seccomp BPF can inspect scalar argument values, including a pointer's numeric value, without following that pointer into memory. For example, a filter cannot read the path string passed through an `openat` pointer. File permissions, capabilities and Linux Security Modules remain separate controls. A filter's allow decision permits the kernel to proceed to its usual handling, where other checks can still deny the request.

## 2. Follow the request and its side effects

1. **Identify the caller.** Establish the host, boot, process and thread. A container's PID and the host PID may differ. Account for PID reuse and collect the thread's ABI before translating a raw system-call number.
2. **Find the effective filter state.** Read the calling thread's status. `Seccomp: 0` indicates disabled, `1` strict mode and `2` filter mode. `Seccomp_filters` counts attached filters on kernels that expose the field. `NoNewPrivs` describes a separate restriction on gaining privileges through execution. None of these fields reveals the rules.
3. **Interpret the action.** Multiple filters can apply, including inherited filters. The kernel uses the highest-precedence action returned. A permissive rule in one filter does not override a stricter decision in another.
4. **Check the observed result and audit coverage.** The application sees a return value or a signal. A separate kernel decision determines whether an audit message is emitted. The audit pipeline must also retain and deliver it.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/images/linux-seccomp-evidence-en.svg' | relative_url }}" alt="A thread submits a system call and the kernel evaluates attached seccomp filters. The selected action determines whether the kernel proceeds, returns an error or signals the thread. Audit export is separately conditional." width="540" height="370" style="max-width: 100%; height: auto">
  <figcaption>The filter action and the audit record answer different questions. Check each against the same thread and time window.</figcaption>
</figure>

| Filter action | Effect on the call | What the observer can infer |
|---|---|---|
| `ALLOW` | Continue into ordinary kernel handling | Later permission checks may still fail. seccomp does not audit an ALLOW action itself. |
| `LOG` | Request audit logging and continue into ordinary kernel handling | A resulting record can describe a call that continued. Logging settings and pipeline coverage still matter. |
| `ERRNO` | Skip executing the call and return the configured error | An application can receive the same error from other causes. Correlate the call and filter action. |
| `TRAP` | Do not execute the call and send `SIGSYS` to the calling thread | Where available, inspect signal details such as `SYS_SECCOMP`. The application may handle the signal. |
| `KILL_PROCESS` or `KILL_THREAD` | Do not execute the call and terminate the process or calling thread, respectively | Inspect wait status, worker restart and relevant audit evidence. |

## 3. Read a benign example and its alternatives

**Normal example.** A service starts with a reviewed filter that permits its normal file and network calls. It has `Seccomp: 2`. A request completes. This confirms that enough of the path worked for that request. It gives no complete inventory of permitted calls.

**Controlled contrast.** A disposable process first runs the harmless `getppid` call, then adds a filter that returns `EPERM` for that call. When the result changes and the attached-filter count grows by one, the intervention provides strong evidence within this experiment. In production, `EPERM` alone does not identify a filter. A changed image or runtime profile can introduce a compatibility problem, while an unexpected system call can also indicate an application path worth investigating.

A broad filter exposes more of the kernel's system-call interface to a compromised workload. A policy drift investigation should establish which image and profile changed and which controls actually applied. A denied call can equally reflect a benign compatibility issue.

In Kubernetes, `RuntimeDefault` refers to the runtime's default profile, which can vary by implementation and version. A manifest records the requested profile. Check the actual container, runtime and calling thread to confirm the state. A missing explicit profile must be interpreted with the node's configuration and applicable policy. If the profile is absent or unexpectedly broad, compare against the approved workload baseline before assigning cause.

## 4. Collect, detect and respond

On an approved Linux host, the following commands read status and audit data. Substitute the **host-visible** PID and TID for your case. Read access to the target's procfs entries may be restricted. The audit search needs audit userspace tools and access to the relevant audit log. `recent` in ausearch is a short relative window. Use the incident's recorded start and end for historical work.

~~~sh
pid=1234
tid=1234
grep -E '^(Name|Pid|Tgid|NSpid|NoNewPrivs|Seccomp|Seccomp_filters):' \
  "/proc/$pid/task/$tid/status"
cat /proc/sys/kernel/seccomp/actions_logged
sudo auditctl -s
sudo ausearch -m SECCOMP -ts recent
~~~

- **Collect.** Save the raw audit event and its timestamp and serial, architecture and call number, action when present, and the observed application error or signal. Capture executable identity, process start time, container and node, image and runtime version, and the effective or expected profile artifact. Record whether each observation came from the host or a container. Preserve file access and audit evidence with restricted access.
- **Detect.** Start with a baseline of expected actions by workload and version. Prioritize repeated denials immediately after a rollout or a new denied call on a stable workload. Check the raw action before counting events as blocks. Combine records from the same host and boot using the audit event identifier when present. Check the audit status, backlog or losses, routing and retention before treating missing records as a signal.
- **Respond.** First preserve the process and runtime evidence. Compare the deployed profile with the approved version and the change history. Correlate the denied action with a new request or failed worker. Work with the service owner to restore the reviewed configuration and rerun the legitimate workflow. An audit-only gap needs collection repair separately from a workload failure.

## 5. Authorized exercise · Restrict one call in one process

Use a disposable Linux workspace you own or are authorized to use. The script requires Python 3, `libseccomp.so.2` and procfs with `Seccomp_filters` (Linux 5.9 or a distribution backport). It runs without elevated privileges where the environment permits filter installation. The rule affects the Python process that runs it. Exiting that process ends the exercise. No service configuration or audit settings are changed.

- <a href="{{ '/assets/downloads/linux-seccomp-evidence/seccomp_getppid.py' | relative_url }}" download>Download the self-contained verification script</a>

~~~sh
python3 seccomp_getppid.py
~~~

The script resolves the call number through libseccomp for its running ABI and invokes the actual syscall through libc. Expect a nonnegative parent PID first. After loading the filter, expect `getppid=-1`, `errno=1` (`EPERM`), `Seccomp: 2`, one additional filter, and `PASS`. The parent PID and starting filter count vary. If the call was already denied, the library is missing, or the environment rejects filter installation, the script stops with the relevant diagnostic. Use a supported disposable environment for the exercise. An audit record is optional and the script does not check for one.

**Observed in execution on 2026-11-27.** Linux 6.18.57 x86-64, Python 3.12.14, libseccomp 2.6.0. The initial call returned 2, the filtered call returned -1 with errno 1, and the filter count rose from 1 to 2. A separate process could still call `getppid`. Production audit collection and Kubernetes runtime behavior were reviewed in documentation.

## 6. Check your understanding

- **Does `Seccomp: 2` prove that a particular syscall was blocked?** It proves a filter is active on the observed thread at collection time. Identify its rules or correlate the relevant syscall outcome and action for the separate claim.
- **Does a SECCOMP event always mean a denial?** No. `LOG` can allow the call to proceed. Read the action and compare the application result.
- **Why might two workers have the same `EPERM` with different causes?** A filter can return that errno, and kernel authorization or the application can expose the same error. Check caller, call, profile, other controls and audit coverage.

Finish when you can reproduce the one-call contrast, explain the filter count and name the extra evidence you would need to attribute a production failure.

## Official references

Reviewed **2026-11-27**. Linux documents seccomp filter mode from 3.5, configurable audit behavior described here from 4.14, and the procfs filter counter from 5.9. Validate deployed kernel and runtime versions and any distribution backports.

- [Linux kernel documentation · Seccomp BPF and action semantics](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [Linux man-pages · seccomp, filter stacking and audit logging](https://man7.org/linux/man-pages/man2/seccomp.2.html)
- [Linux man-pages · proc status fields](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html)
- Linux Audit userspace manuals · [ausearch](https://man7.org/linux/man-pages/man8/ausearch.8.html) and [auditctl](https://man7.org/linux/man-pages/man8/auditctl.8.html).
- libseccomp manuals · [profile initialization](https://man7.org/linux/man-pages/man3/seccomp_init.3.html), [rule addition](https://man7.org/linux/man-pages/man3/seccomp_rule_add.3.html) and [filter installation](https://man7.org/linux/man-pages/man3/seccomp_load.3.html).
- [Kubernetes v1.36 · Seccomp profiles and runtime defaults](https://v1-36.docs.kubernetes.io/docs/tutorials/security/seccomp/).
