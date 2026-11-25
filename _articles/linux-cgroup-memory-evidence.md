---
title: "Linux cgroup Memory Evidence · Investigate Pressure and OOM Kills"
description: "Separate reclaim, limit pressure and process termination with cgroup v2 counters, logs and an offline lab."
category: dfir
tags: [Linux, cgroup v2, OOM, systemd, DFIR, Blue Team]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/linux-cgroup-memory-evidence/
---

**Learning goal.** When a workload slows down or disappears, explain what the memory counters support, determine which process and cgroup were involved, and distinguish an OOM kill from another source of termination.

## 1. What a memory cgroup measures

A **control group (cgroup)** puts processes into a resource-management hierarchy. In **cgroup v2**, a workload can have a leaf group inside a service or slice. Limits on ancestors can also constrain it. A process's memory charge belongs to the memory controller's accounting, which includes more than the process's private allocations. For example, charged page cache may contribute. **Reclaim** tries to free or reuse memory. **Pressure Stall Information (PSI)** records time lost to contention. **Out of memory (OOM)** describes a condition in which the kernel cannot satisfy certain allocations within the applicable constraints. The kernel can terminate a process to free memory.

| Evidence | What it supports | What to check next |
| --- | --- | --- |
| `memory.current`, `memory.stat` | Current usage and accounting breakdown | Compare historical samples and an appropriate baseline |
| `memory.high`, `high` event | Crossing this throttle boundary sends tasks into reclaim | Check impact with PSI and service latency. Crossing it alone does not call the kernel OOM killer. |
| `memory.max`, `max` event | An attempt to exceed the hard limit | Reclaim can succeed. Check `oom` and the actual termination evidence. |
| `oom`, `oom_kill` events | Allocation pressure near a limit and number of member processes killed by a kernel OOM killer, respectively | Identify the specific victim and whether a cgroup limit or another kernel OOM scope was involved. |
| `memory.pressure` | Time in which at least some tasks, or all non-idle tasks, were stalled on memory | Compare the time interval and sustained service impact. It does not count deaths. |

`memory.events` is hierarchical by default, so a parent can reflect events from its descendants. The `memory_localevents` mount option changes that behavior. `memory.events.local` reports the current group's own events. The counters are cumulative within the cgroup lifetime. Read only comparable samples from the same host, boot and cgroup instance. Select fields by key because kernels can add fields. A missing field or file leaves that observation unknown. In the PSI file, `some` means at least one task was stalled. `full` means all non-idle tasks were stalled at once. The averages cover 10, 60 and 300 seconds. The `total` is accumulated stall time in microseconds. Compare the same metric over similar windows.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/linux-cgroup-memory-en.svg' | relative_url }}" alt="A workload's memory usage can reach a throttle boundary or a hard limit. Counters and pressure show resource conditions. Kernel or service logs and process identity are needed to identify termination and its cause.">
  <figcaption>Link memory conditions to service impact and then to an independently identified termination.</figcaption>
</figure>

## 2. Follow a routine burst and a restart

Assume a fictional report worker in `report.slice` processes a larger-than-usual batch. Its group starts with a 256 MiB high boundary and a 384 MiB hard limit. A status file reports byte counts, with 1 MiB equal to 1,048,576 bytes. A limit displayed as `max` is unbounded at that group for that setting. Check the ancestors too.

1. During the batch, usage approaches 300 MiB. The leaf's `high` count rises from 5 to 18, its `oom_kill` stays at 0, and responses slow. PSI and service timing line up with memory stalls. Later usage falls and the same process continues. This supports throttling and reclaim during the window.
2. In a separate incident after a release, the parent and worker record an increase in `oom_kill`. The parent's local `oom_kill` stays unchanged. This can be a single victim reported in two files under the default hierarchy. Confirm which descendant was affected.
3. A matching kernel log identifies the killed host PID and the constrained group, and the workload records an exit and restart. Join by boot, process lifetime, cgroup instance and interval. The victim's cgroup alone does not tell you which ancestor enforced the limit. A restarted worker may have low current usage or a new cgroup instance. Its new counters describe that instance.

A supervisor can report that a process died from `SIGKILL`. A `137` status can also be consistent with the conventional `128 + 9` encoding. That evidence alone leaves the sender unresolved. Where enabled, `systemd-oomd` can select a cgroup and send `SIGKILL` from userspace based on pressure or swap policy. Correlate its own journal with the victim group. Treat it separately from a verified kernel OOM kill.

## 3. Collect, detect and respond

Unusual demand, a deployment regression or an over-tight limit can create the same pressure signal. Intentional demand on a resource-intensive service can also cause exhaustion. Use memory evidence to establish the mechanism and affected workload. Use request volume, workload changes and independent access evidence to investigate why the demand changed.

1. **Preserve the group before it disappears.** Record node identity, boot ID, UTC window, unit or container identity, cgroup path and a lifetime marker available in your inventory. Capture limits, usage, pressure and both local and hierarchical events for the leaf and relevant ancestors. Note where the files were read. A container's cgroup namespace can hide ancestors. Sample before and after within the same instance and keep the original text.
2. **Compare the whole chain.** A positive `high` delta and sustained PSI plus slower responses support pressure-related degradation. Repeated `oom_kill` deltas justify checking kernel logs even if the working set has dropped. Search kernel logs for the OOM record, its constraint and victim. Correlate the host PID and cgroup path with the process lifecycle and service restart. Preserve the boot and time filters and note gaps in local or central collection.
3. **Establish the source before changing policy.** A valid kernel victim record can distinguish a cgroup-constrained kill from a system-wide event when that scope is present. A matching oomd record supports a userspace policy decision. A status code with no matching logs leaves alternatives open, including a supervisor timeout or operator action. A container platform's termination summary is a useful lead. Check node-side records to learn which limit or pressure policy applied.
4. **Respond and compare with a control.** Work with the service and host owners to mitigate the affected component. Use the evidence to choose among correcting a deployment regression, reducing demand, or reviewing the resource budget. Preserve the pre-change state. Validate later latency, memory pressure, counters and expected restarts under comparable demand. Avoid counting a descendant event again at each ancestor.

### Read-only collection on a systemd host

Use the following in the authorized host context for an active unit. It assumes cgroup v2 mounted at `/sys/fs/cgroup`, the memory controller exposed for the selected non-root group, readable files and enough rights to view the relevant logs. Replace the unit and UTC incident window. Preserve the runtime's workload identifier separately when applicable.

```bash
date -u
cat /proc/sys/kernel/random/boot_id
systemctl show -p ControlGroup -p MainPID report-worker.service
wiki_cgroup=$(systemctl show -p ControlGroup --value report-worker.service)
if [ -n "$wiki_cgroup" ] && [ "$wiki_cgroup" != / ]; then
  for entry in memory.current memory.high memory.max memory.events memory.events.local memory.pressure; do
    printf '\n%s\n' "$entry"
    cat "/sys/fs/cgroup${wiki_cgroup}/$entry"
  done
fi
journalctl -k -b --since '2026-11-26 01:00:00 UTC' --until '2026-11-26 01:15:00 UTC' --utc
journalctl -b -u systemd-oomd.service --since '2026-11-26 01:00:00 UTC' --until '2026-11-26 01:15:00 UTC' --utc
```

Use the event's retained boot where applicable. A previous boot or removed cgroup might only be visible in retained logs and metrics. If a file cannot be read, record the error and check the mount mode, controller, namespace, group lifetime and permissions. Run a healthy read-only control in the same view before assessing a collection gap.

## 4. Practice with fictional snapshots

Save the <a href="{{ '/assets/labs/linux-cgroup-memory-evidence.py' | relative_url }}" download="linux-cgroup-memory-evidence.py">Python script</a> and <a href="{{ '/assets/labs/linux-cgroup-memory-cases.json' | relative_url }}" download="linux-cgroup-memory-cases.json">case file</a> to one directory in an authorized workspace. Use Python 3.9 or newer. The sample includes raw-style counter text and normalized summaries of already correlated logs, with fictional IDs. It reads only the selected file and creates no memory load or signals.

```bash
python3 linux-cgroup-memory-evidence.py linux-cgroup-memory-cases.json
```

| Case | Expected reading |
| --- | --- |
| `high_reclaim` | Throttling observed, kill attribution unresolved |
| `max_without_kill` | Limit pressure observed, kill attribution unresolved |
| `memcg_kill` | Matching kernel record identifies a cgroup-constrained kill |
| `system_oom_kill` | Matching kernel record identifies system-wide OOM, although the victim's group counter increased |
| `oomd_userspace` | Matching oomd record supports a userspace kill |
| `parent_only` | Aggregate kill count rose, with the child not identified |
| `instance_recreated` | Counter comparison unavailable across instances |
| `status_137_only` | Termination source unresolved without independent evidence |

Each result reports the comparable counter scope and deltas separately from attribution. All eight must print PASS. In a copy, change the `high 18` in `high_reclaim` to `high 5`. The original expectation should fail. Missing fields remain unknown. If a file cannot be opened, check both names and the working directory. If a result looks surprising, compare the two scope IDs and the file type before interpreting a delta.

The offline cases were executed in the cloud workspace. The collection commands and product behavior were reviewed against documentation. No real OOM, systemd-oomd event or Kubernetes workload was induced.

## 5. Check your reasoning

- **A parent aggregate increases by one and the leaf local count increases by one. How many kills?** The same victim can appear in both. Check the topology and correlated kernel records before counting.
- **A leaf shows an extra `oom_kill`. Was its own limit responsible?** A kernel OOM killer selected a member. Check the kernel's constraint and affected cgroup, including ancestors. System-wide OOM can also contribute.
- **A restart reports 137. What would distinguish an oomd kill from kernel OOM?** Match the workload instance and time to its oomd unit journal and kernel victim records. Keep the source unresolved if the necessary records were not retained.

Finish when all cases pass and you can describe a slowdown and a kill with separate evidence, limits and one corroborating source.

## Official references

Reviewed November 26, 2026. The chapter covers the current documented cgroup v2 ABI and kernel PSI. Check the deployed kernel, systemd version and runtime before transferring examples.

- Memory controller, limits and counters. [Linux kernel cgroup v2 documentation](https://docs.kernel.org/admin-guide/cgroup-v2.html#memory)
- Pressure measurement. [Linux kernel PSI documentation](https://docs.kernel.org/accounting/psi.html)
- Userspace memory policy and signals. [systemd-oomd](https://www.freedesktop.org/software/systemd/man/latest/systemd-oomd.service.html) · [systemd resource control](https://www.freedesktop.org/software/systemd/man/latest/systemd.resource-control.html)
- Journal boot and unit selection. [journalctl](https://www.freedesktop.org/software/systemd/man/latest/journalctl.html)
- Container memory requests, limits and status. [Kubernetes container resources](https://kubernetes.io/docs/concepts/configuration/manage-resources-containers/)

[Previous · Linux process identity]({{ '/wiki/linux-process-evidence/' | relative_url }}) · [Related · Linux journal coverage]({{ '/wiki/linux-journal-coverage/' | relative_url }})
