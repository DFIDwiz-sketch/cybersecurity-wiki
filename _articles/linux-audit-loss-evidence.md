---
title: "Linux Audit Loss · Trace the Kernel, auditd and Collector"
description: "Read Linux Audit counters in context and use a known event to locate a coverage gap between the kernel and the collector."
category: dfir
tags: [Linux, Linux Audit, Log Collection, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/linux-audit-loss-evidence/
---

A parser finds no Linux Audit event for a known operation. That could be a rule coverage gap, dropped records, a local log problem or missing delivery. The investigation starts by locating the last checkpoint with positive evidence for that operation, then checking which metrics apply to that host and time window.

## 1. Follow one audit record

Linux Audit can emit **records** about an operation under active audit rules and other audit sources. An **event** may contain multiple records such as `SYSCALL` and `PATH`. An event missing one record can still appear in a search. The kernel queues records for `auditd`, the userspace daemon. Where local logging is configured, auditd writes them to a log. An enabled audit plugin or a separate log shipper can forward the stream. Find the deployed path first. A plugin queue metric does not describe a shipper that tails a local file independently.

| Observation | What it measures | What it leaves open |
| --- | --- | --- |
| `auditctl -s` → `backlog` and `backlog_limit` | Current kernel queue occupancy and its configured limit | A high sample is pressure. It does not quantify drops |
| `auditctl -s` → `lost` | A kernel-reported count of lost audit records | Which specific record or event was lost |
| `auditctl -s` → `pid` | The receiving audit daemon's PID at sample time. Zero means none registered | Whether a previously observed daemon wrote to disk or forwarded successfully |
| auditd state → plugin queue and dropped metric, where available | The plugin delivery branch of the sampled daemon | Kernel loss count, completeness of the local file, or health of an independent shipper |
| Raw local log and collector | Whether records for the known event are present at each tested point | Completeness for all other events or hosts |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/linux-audit-loss-evidence-en.svg' | relative_url }}" alt="Kernel Audit queues records to auditd. A local log and an enabled plugin are separate outputs. A file shipper can forward from the local log, and a plugin can forward directly. Check the path that reaches your collector." style="max-width: 100%; height: auto;">
  <figcaption>Figure 1. A deployment can forward through the plugin branch or from the local file. Check the active route.</figcaption>
</figure>

## 2. Compare a normal interval with a gap

In a fictional Linux host, a known operation is covered by a rule, produces the expected local records, and reaches the collector inside the agreed 90-second delivery window. Two samples from the same boot 15 seconds apart show `lost` at 7 and 7, with backlog falling from 15 of 512 to 2 of 512. Seven is an accumulated value. Its measured change for this interval is zero. This supports successful delivery of the sampled operation and no observed increase in the kernel counter.

Later in that same boot, comparable samples show `lost` increasing from 7 to 12. The kernel reported five additional lost records. One event may contain several records, and the counter cannot attribute them to a specific rule or marker. Backlog occupancy can fall between a loss and the next sample. Investigate sustained queue pressure, bursty event sources, rate limits and resource constraints. The kernel can report losses for more than one reason.

A different interval shows a complete local event and no central match after the delivery window, with `lost` unchanged. Start with forwarding, parsing and query coverage for that event. If the delivery window is still open, log the incomplete observation and recheck at its end. When the local sink is intentionally disabled, use the first available checkpoint on the configured route and record the missing comparison.

## 3. Account for resets, blind spots and misuse

For the kernel counter, compare the same host and boot and record any known administrative reset. A decrease or a new boot invalidates a simple subtraction. Auditd itself can restart within a boot. A userspace plugin counter must be compared within the same daemon lifetime using process start evidence along with the PID. A stale state file or a missing field means coverage is unknown for that metric. Record the state timestamp before reading the numbers. Kernel and plugin metrics describe different stages and may have different units. Avoid adding them.

A maintenance burst, insufficient disk space, retention limits, an overly broad rule or a forwarding outage can create a gap. Deliberate changes to rules or collection can also reduce visibility. Correlate with approved changes, the incident timeline and surviving sources before assigning intent. A present rule list describes now, and a missing serial number alone is insufficient to quantify loss. A complete local event with a forwarding gap shows that event survived the kernel and local path. It does not clear the machine or forwarding channel for the full incident.

## 4. Collect, detect and respond

1. **Capture the source scope.** On an authorized Linux host with kernel Audit, audit userspace tools and the privileges needed to view state and rules, capture the following with the host identity. Run in the host's audit context and preserve UTC interval boundaries. Record the installed distribution, kernel and audit package version. Record active rule and key, local log path and retention, and the forwarding implementation. Protect raw logs and rule exports containing sensitive paths or subject information.

~~~bash
date -u
cat /proc/sys/kernel/random/boot_id
sudo auditctl -s
sudo auditctl -l
~~~

2. **Check auditd and the actual output route.** Inspect effective configuration for `write_logs`, `log_file`, disk actions and relevant plugins. A current state report can show logging suspended or plugin pressure. On a supported build and with authorization, `sudo auditctl --signal state` requests a diagnostic write. Upstream uses `/run/audit/auditd.state`; check your distribution's path and report timestamp. Periodic `report_interval` is documented upstream from audit-userspace 4.0.5. A state snapshot reports the sampled daemon. Inspect shipper queues and receiving-side parsing independently when applicable.
3. **Correlate one expected operation.** Use a benign approved action covered by a known rule, and record a unique test identifier where your rule and workflow support it. Preserve original local records and compare the same host, event identifier, rule key and source timestamp to the collector. Use a bounded window that includes delivery delay and clock uncertainty. Check rotated segments and whether all required records reached the parser. Keep absent, incomplete and uncollected data separate.
4. **Alert and verify recovery.** Track positive same-boot kernel loss changes, plugin losses within each daemon lifetime, and markers missing after the delivery objective. Baseline queue occupancy and monitor sustained pressure separately. Preserve evidence before a repair, check local disk and forwarding health, and compare an approved marker end to end after the correction. Do not close a visibility incident based on a single zero counter.

## 5. Authorized offline exercise

Save the <a href="{{ '/assets/labs/linux-audit-loss-evidence.py' | relative_url }}" download>Python checker</a> and <a href="{{ '/assets/labs/linux-audit-loss-evidence.json' | relative_url }}" download>fictional evidence</a> together. It runs with Python 3 in an owned or approved environment. The data normalizes two snapshots plus a known event at local and central checkpoints. The program reads only the fixture. It does not query or change the kernel, auditd or any collector.

~~~bash
python3 linux-audit-loss-evidence.py
~~~

| Cases | Expected observations |
| --- | --- |
| A–C | End-to-end delivery, added kernel losses without attributing them to the marker, and plugin losses alongside a local event |
| D–F | Missing central event after the window, an open delivery window, and a boot boundary |
| G–I | Same-boot counter decrease, new daemon lifetime, and an unavailable plugin metric |
| J | Some local records present, with the expected event incomplete |

Expect `10/10 cases matched.` For a negative control, change case D's `delivery.window_elapsed` to `false` in a copy without modifying the expected output. Pass that copy's filename to the script. D should move to `pending-window` and the script should exit 1. If the fixture fails unexpectedly, check that both downloads came from the same edition and are in the same directory. This Python exercise uses fictional data. The kernel and auditd commands were reviewed against upstream documentation without running an audit-enabled host or production pipeline.

## 6. Check your reasoning

1. **Lost rose by five. Did exactly five events disappear?** The count is in records. Events can span several records, and the metric does not identify them.
2. **The full local marker is present but its central copy is absent. What next?** Check the delivery objective, forwarding route, parser and query scope for that event.
3. **The daemon restarted while the boot ID stayed the same. What can be compared?** Do not subtract plugin counters across daemon lifetimes. Kernel comparison still needs a continuous same-boot kernel counter and reset context.
4. **Both counters are zero. Does a missing event prove the operation did not occur?** Check rule coverage, daemon and local state, retention and delivery. The counters do not measure every cause of silence.

**Completion criterion.** Reproduce the baseline and negative control. Given one missing marker, identify the last confirmed checkpoint, which metrics can be compared, and which source is needed next. Continue with [Linux file audit evidence]({{ '/wiki/linux-audit-file-evidence/' | relative_url }}) and [Linux journal coverage]({{ '/wiki/linux-journal-coverage/' | relative_url }}).

## Official references

Reviewed 2026-11-27. The examples target Linux kernel Audit and audit-userspace. Upstream audit-userspace 4.x documents plugin state reporting. Distribution backports, paths, options and report fields can differ. Use the installed package manuals when investigating a particular host.

- [Linux kernel · Audit implementation and record loss](https://github.com/torvalds/linux/blob/master/kernel/audit.c)
- [Linux Audit upstream · Performance and monitoring](https://github.com/linux-audit/audit-userspace#performance-and-monitoring) and [audit-userspace release history](https://github.com/linux-audit/audit-userspace/releases)
- [auditctl(8) · Status and rule listing](https://man7.org/linux/man-pages/man8/auditctl.8.html) and [auditd.conf(5) · Local logging, disk actions and queues](https://man7.org/linux/man-pages/man5/auditd.conf.5.html)
