---
title: "Linux Capabilities · From Executable Metadata to Thread Evidence"
description: "Read file and thread capabilities, explain exec-time policy, and distinguish a privilege grant from an observed operation."
category: blue-team
tags: [Linux, Linux Capabilities, File Permissions, Linux Audit, Blue Team, DFIR]
level: Intermediate
updated: "2026-11-26"
translation_url: /ko/wiki/linux-capability-evidence/
---

A service can run under a non-root UID and still perform a particular privileged operation. A second service can start from the same binary with fewer privileges because it was launched with different credentials or restrictions. Begin with [Linux file permissions]({{ '/wiki/linux-file-permissions-evidence/' | relative_url }}) for mode, ACL and path checks. Here the questions are which capability was available to which thread, how it became available, and whether an operation used it.

## 1. Read the file and thread separately

A Linux **capability** is a named unit of privilege that the kernel can check for certain operations. The kernel tracks capability sets per **thread**. A **file capability** is executable metadata in the `security.capability` extended attribute. It is one input to the capability calculation when a thread starts a new program image with `execve()`. A capability number is a bit index. Hexadecimal `0000000000000400` has bit 10 set, which maps to `CAP_NET_BIND_SERVICE`.

| Field in `/proc/<pid>/task/<tid>/status` | What it answers |
| --- | --- |
| `CapEff`, effective | Which capability bits can participate in the thread’s current kernel permission checks? The specific operation, namespace and other security checks still matter |
| `CapPrm`, permitted | Which bits can the thread make effective, subject to capability rules? An inactive permitted bit is still relevant |
| `CapInh`, inheritable | Which bits can contribute to permitted on a later exec when the file’s inheritable set agrees? |
| `CapBnd`, bounding | Which file-permitted bits survive the exec-time intersection? This does not erase current privileges or directly mask the inheritable branch |
| `CapAmb`, ambient | Which bits carry into permitted and effective on an ordinary, nonprivileged exec? Ambient bits must be both permitted and inheritable |
| `NoNewPrivs` | Can exec grant new privilege through mechanisms such as file capabilities or set-user-ID bits? `1` prevents such an exec-time gain and persists into descendants. It does not clear privileges already held |

In `getcap` output, `cap_net_bind_service=ep` means that the named bit is in the file’s permitted set and the file’s effective flag is set. That effective flag applies to the resulting permitted set as a whole in the ordinary transformation. It is not an independent per-capability file set. Read the thread’s actual `CapEff` to see the post-exec state.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/linux-capability-evidence-en.svg' | relative_url }}" alt="The executable capability attribute and launcher state enter exec-time calculation. Then inspect the target thread, and compare its state with the observed operation and outcome." style="max-width: 100%; height: auto;">
  <figcaption>Figure 1. Keep launch inputs, resulting thread state, and evidence of an operation separate.</figcaption>
</figure>

## 2. Follow a normal service launch

The following is fictional. An administrator starts a non-root HTTP service that must bind TCP port 443. The service’s network namespace has `net.ipv4.ip_unprivileged_port_start=1024`. The service manager is configured with `User=websvc`, `CapabilityBoundingSet=CAP_NET_BIND_SERVICE`, `AmbientCapabilities=CAP_NET_BIND_SERVICE` and `NoNewPrivileges=yes`. The expected binary has no file capability. This is an illustration of policy evidence, not a setup recipe.

1. The launch manager prepares the service credentials and ambient capability. systemd documents that adding an ambient capability also adds it to the inheritable set.
2. The service starts by executing an ordinary nonprivileged binary. The prepared ambient bit can carry through exec. `NoNewPrivs=1` is consistent with a bit the launcher already made available.
3. For the thread performing the bind, a snapshot at that time could show `CapInh`, `CapPrm`, `CapEff`, `CapBnd` and `CapAmb` all equal to `0000000000000400`. A different thread or a later snapshot can differ.
4. A successful bind record for the process, socket address and network namespace would establish the result. A listening socket alone does not establish the process called bind. The manager could have opened it and passed a descriptor. Check for socket activation and the relevant port threshold before asserting the capability was needed.

For a non-root exec in the ordinary case, the permitted result combines three sources: the intersection of thread and file inheritable sets, the intersection of the file permitted and thread bounding sets, and any surviving ambient bits. Executing a privileged file clears the ambient set. The file effective flag controls whether the resulting permitted set is immediately effective. Without it, the surviving ambient bits become effective. UID 0 rules, user namespace mappings, mount `nosuid`, tracing and no-new-privileges can change which rules or file grants apply. The kernel can also refuse exec with `EPERM` for a capability-unaware binary that would not receive all file-permitted capabilities. A missing bit in a snapshot is insufficient to reconstruct which condition applied.

## 3. Recognize an unexpected grant

An unauthorized change to executable metadata or service launch settings can give a program more privilege than its job requires. A legitimate package update, an approved listener change, or a container rollout can produce superficially similar evidence. A matching SHA-256 of executable contents does not establish that its extended attributes, owner or launcher are unchanged. A package replacement can also change the inode at the same path.

Treat a new or expanded `security.capability` attribute as a configuration finding. Look for a successful execution of that object and evidence of the operation before concluding that the new privilege was used. If a work item says “remove capabilities,” compare the old and new effective state and consider long-running processes. Changing disk metadata or a unit file does not itself change every running thread.

## 4. Blue-team collection and response

| Source | Capture and limitations |
| --- | --- |
| Executable and filesystem | Device, inode, numeric owner, mode, content hash, capability xattr and mount flags in the affected process’s view. With libcap tools, `getcap -n -v /path/to/binary` displays capabilities and a nonzero namespaced root ID when present. Run only against authorized objects, from the correct mount view |
| Running process | Read `/proc/<pid>/task/<tid>/status` for UID/GID and capability fields where procfs and access controls permit. Preserve boot ID, start time, PID/TID, executable identity, mount/user/network namespaces and UID mapping. `capsh --decode=0000000000000400` decodes the mask on a host with libcap tools |
| Service and change records | Active unit and drop-ins, invocation time, actual launcher and deployment approval. With systemd inspect `systemctl cat UNIT` and the active process separately. The unit on disk may differ from the effective configuration of a running invocation |
| Historical telemetry | Collect successful and failed execs and relevant operations where audit or EDR coverage exists. For metadata changes, verify your collection actually records relevant extended-attribute changes on the affected filesystem. Correlate host, boot, process lifetime, device/inode and time. A startup trace may not cover later capability changes |

Alert on a new file entitlement or expanded service capability outside an approved deployment. Inventory content and metadata separately. Prioritize sensitive workloads with both an unexpected entitlement and a recent matching execution. Use the specific operation’s outcome as another step in the investigation. Take a live snapshot before an approved restart or containment step when feasible. Restore the known-good executable metadata and launcher configuration, reconcile running services in the approved window, then verify their actual post-restart thread state and expected service function. Keep negative controls such as known-good package changes and authorized socket activation in the detection test set.

## 5. Authorized offline lab

<a href="{{ '/assets/labs/linux-capability-evidence.py' | relative_url }}" download>Download the Python lab</a> to a machine or container you own or are allowed to use. It reads its own procfs status, computes a simplified exec model over fabricated bit sets, and sets no-new-privileges in a child that then executes the Python interpreter again. It makes no network requests and changes no files, service settings or capability grants. Use Linux with procfs, libc with `prctl`, and Python 3. Run as a regular user.

```bash
python3 linux-capability-evidence.py
```

| Exercise | Expected result |
| --- | --- |
| File permitted bit admitted by the bounding set | With the file effective flag, the bit appears in both modeled output sets |
| Bounding denies that file-permitted bit | The reduced model outputs no grant through that branch. It does not predict whether a specific binary would start |
| File inheritable and thread inheritable match | Permitted can contain the bit even with a zero bounding set in the model. With no effective flag or ambient bit, it is inactive |
| Ambient survives ordinary exec, then compare a privileged file | Ambient carries to both sets in the first case. The ambient contribution disappears in the second |
| Actual child before and after re-exec | `NoNewPrivs=1` in both observations, even if the parent already had it |

Expect five model controls and one successful child inheritance check. The snapshot fields can vary. Missing procfs fields or a failed `prctl` indicate an incompatible or restricted environment. Keep the error separate from a failed model assertion. The reduced model omits root special cases, namespace and mount handling, `no_new_privs` file-grant decisions, and startup errors. The actual child test checks flag inheritance only. On Linux 6.18.57 and Python 3.12.14 the launcher already had the flag set, and the child retained it across exec. systemd behavior, service bind and audit collection were reviewed in documentation.

## 6. Check your understanding

1. **The file has `=ep` but the current worker has an empty effective set. What would you collect?** Confirm the executed inode, its file attribute, mount and namespace. Compare the launcher’s bounding and no-new-privileges settings and consider post-launch state changes.
2. **The worker has effective bit 10 but `getcap` shows no file attribute. What could explain it?** The launcher may have prepared an ambient bit that survived ordinary exec. Read the actual process and launcher state.
3. **Did a worker with bit 10 use it to obtain the listening socket?** Check the binding record, namespace threshold and descriptor provenance. A capability snapshot records available privilege at a time.

**Completion criterion.** Distinguish all five sets, reproduce the offline lab, and tell an investigator what would prove an actual operation. Next, use [Linux Audit file evidence]({{ '/wiki/linux-audit-file-evidence/' | relative_url }}) to interpret syscall records and [Linux socket scope]({{ '/wiki/linux-socket-scope-evidence/' | relative_url }}) to trace socket visibility.

## Official references

Reviewed 2026-11-26. The man-pages edition covers the Linux interfaces, the systemd source covers version 262, and the kernel page documents the flag available since Linux 3.5. Check your installed versions and service settings.

- Linux man-pages 6.19. [capabilities(7)](https://man7.org/linux/man-pages/man7/capabilities.7.html), [proc_pid_status(5)](https://man7.org/linux/man-pages/man5/proc_pid_status.5.html), [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html)
- Linux kernel user-space API. [No New Privileges Flag](https://docs.kernel.org/userspace-api/no_new_privs.html), [IP sysctl port threshold](https://docs.kernel.org/networking/ip-sysctl.html#ip-variables)
- libcap and systemd. [getcap(8)](https://man7.org/linux/man-pages/man8/getcap.8.html), [systemd.exec](https://www.freedesktop.org/software/systemd/man/262/systemd.exec.html)
