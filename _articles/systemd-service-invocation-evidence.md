---
title: "systemd Service Invocation Evidence · Separate Restarts and Outcomes"
description: "Trace one Linux service invocation across journal records, distinguish manager messages from service output, and verify results with offline cases."
category: dfir
tags: [Linux, systemd, Journald, Service Investigation, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/systemd-service-invocation-evidence/
---

At 08:01 UTC a report service logged an error. At 08:02 the same unit logged that a report was sent. Before closing the incident, determine whether those messages came from the same run, what systemd actually observed, and whether the receiving system acknowledged the report.

## 1. Separate the unit, the invocation and the process

A **unit** is an object managed by systemd. A service unit describes what the manager starts and how it supervises the service. A system manager and separate per-user managers can each hold a service with the same name. A **service invocation** is one runtime cycle of a unit. Each new cycle has its own 128-bit invocation ID. Several processes may participate in one cycle. A **PID** identifies a process in a particular PID namespace and can be reused, while **MainPID** is a manager property for the currently tracked main process.

Think in stages. The manager loads settings and handles a start job. It evaluates startup success according to `Type=`. The service may then perform application work. A restart can start a new cycle under the same unit name. When you read a journal entry, first ask whether it came **from** the service or was written **about** it.

<figure>
  <img src="{{ '/assets/diagrams/systemd-service-invocation-evidence.svg' | relative_url }}" width="560" height="326" alt="One service name has invocation A and invocation B. Each cycle may contain manager messages and service output. Check the receiving system separately for the business result." />
  <figcaption>Keep each run together, then corroborate separately whether the expected work took effect.</figcaption>
</figure>

| Source or field | What it can support | Check before relying on it |
| --- | --- | --- |
| `_SYSTEMD_UNIT` and `_SYSTEMD_INVOCATION_ID` | The originating service context assigned by journald, when available. | Preserve the source, originating machine and boot. For a user service, also retain `_SYSTEMD_USER_UNIT` and `_SYSTEMD_OWNER_UID` when available. |
| `UNIT` or `USER_UNIT` with `INVOCATION_ID` or `USER_INVOCATION_ID` | Systemd can use these fields in messages about the target unit and run. | Verify the sender using the original journal and trusted metadata. Names without a leading underscore are also available to clients. |
| `OBJECT_SYSTEMD_INVOCATION_ID` | Additional context about a process referred to by the record. | Check the object unit and scope. This describes the subject of the message, distinct from its sender. |
| `systemctl show` and `systemctl cat` | A snapshot of the manager's properties and the contents of the current backing files, respectively. | Preserve the collection time. Disk changes and loaded settings can differ. Neither command reconstructs an old run on its own. |
| Application or receiving system | Work performed, receipt recorded, or a downstream state changed. | Match a transaction or artifact identifier and verify that the source covers the relevant interval. |

Systemd makes the invocation ID available to unit processes as the environment variable `$INVOCATION_ID`. Treat a copy in application text as a correlation lead. The underscore-prefixed fields have special provenance within a native journal maintained by journald. They are not cryptographic proof of integrity for arbitrary JSON in a collector, and stdout or stderr from a child can carry the stream owner's credentials. Preserve raw origin and transport. For forwarded data, verify that the collection chain preserved those original fields without conflating them with application fields.

## 2. Read what “started” meant

| Service type | What the manager waits for at startup | What still needs separate evidence |
| --- | --- | --- |
| `simple` | The main process is forked. The start step can succeed before the service binary is executed. | Whether the expected image ran and the application worked. |
| `exec` | The main binary is successfully executed. | Readiness and completion of work after execution. |
| `notify` | The manager receives the expected readiness notification. | Whether a later request or transfer completed. |
| `oneshot` | The configured start command or commands finish successfully under the service settings. | A business result outside the process, such as a receiver acknowledging a report. |

In a **fictional** normal recovery, `reports.service` fails with exit status 1 in invocation A after an upstream API timeout. The approved policy permits restart on failure. Invocation B starts at 08:02 UTC and writes the message “sent” for report reference R-417. The receiving system later records an acceptance with the same reference. The evidence supports a failed run followed by a separate successful delivery. With only the sender's “sent” message, the strongest statement would be that the application reported sending it. Likewise, a completed oneshot can be inactive at collection time.

Unexpected repetition matters when a unit changed outside approved maintenance. A new drop-in or unexpected process image can alter what a familiar unit runs. Repeated failures also fit a bad deployment or dependency outage. Compare the run's process and output with approved changes and trusted baselines before attributing intent.

## 3. Collect evidence for one run

1. **Scope the source.** Keep the originating asset identity, machine ID, boot ID, manager scope, unit and invocation ID. For user services, keep the owner UID and query the right user manager with authorized access. Use journal wall-clock time for cross-system comparison and monotonic time only within the same originating boot. Retain the raw records and note timezone, restarts, collection lag and retention limits.
2. **Compare manager and journal.** Snapshot loaded properties, backing files, metadata, and drop-ins. Compare the contents with approved deployment or package records. On a collector, check that filtering, forwarding, truncation or JSON normalization did not strip the invocation fields. Use source-validated manager messages to reconstruct startup and exit. A manager message and a service message have different evidentiary roles even when linked to the same run.
3. **Confirm effects and respond.** Use process and cgroup records, relevant application IDs, and a receiving-system record to test what happened. For repeated expected failures, give the owner the scoped run IDs and errors. For an unexplained configuration or executable change, preserve the effective state and artifacts before approved containment. Validate runtime evidence and downstream results on recovery.

On an authorized Linux host with a running systemd manager, readable journal data and a known unit, the following inspection commands make no changes. For a user unit, use the intended user's manager with `systemctl --user` and the journal's `--user-unit` selector with suitable access. Use an explicit boot and invocation ID when preserving evidence because relative selections can move as new runs arrive. The two invocation options were introduced in systemd 257. The broader invocation query can match sender, manager, or object fields, so inspect their provenance individually. The final field match deliberately omits manager-only and object-only records.

```bash
systemctl cat reports.service
systemctl show reports.service \
  -p Type -p InvocationID -p MainPID -p Result \
  -p ExecMainCode -p ExecMainStatus -p FragmentPath -p DropInPaths
journalctl --list-boots --no-pager

# Fictional sample IDs. Replace with the originating boot and run IDs.
boot=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
run=11111111111111111111111111111111

# systemd 257+ (check journalctl --version)
journalctl -b "$boot" -u reports.service --list-invocations --no-pager
journalctl -b "$boot" -u reports.service --invocation="$run" -o json --no-pager

# Direct field match for unit-origin records only, where the field exists
journalctl -b "$boot" -o json --no-pager \
  _SYSTEMD_UNIT=reports.service "_SYSTEMD_INVOCATION_ID=$run"
```

If access is denied or results are empty, check the user and manager scope, selected boot, local retention and central delivery, whether the unit sends output to the journal, and whether the installed version includes the fields and options. The presence of a start job in a manager log does not guarantee that the journal contains service output.

## 4. Offline defense validation

Use Python 3 in a directory you own or are explicitly approved to use. Download <a href="{{ '/assets/labs/systemd-service-invocation-evidence/invocation-cases.jsonl' | relative_url }}" download="invocation-cases.jsonl">invocation-cases.jsonl</a>, save the code beside it as `review_invocation.py` and run `python3 review_invocation.py`. No service or network is required.

This fictional dataset wraps each record in a test object. The exercise covers a system service. `manager_verified` stands in for sender validation done by an analyst. It is a fixture flag, not a systemd field or a security decision inferred from message text.

```python
import json

machine_id = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
boot_id = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
invocation_id = "11111111111111111111111111111111"
unit = "reports.service"

def classify(row):
    fields = row["fields"]
    if (fields.get("_MACHINE_ID"), fields.get("_BOOT_ID")) != (machine_id, boot_id):
        return "outside-scope"

    if fields.get("_SYSTEMD_UNIT") == unit and "_SYSTEMD_USER_UNIT" not in fields:
        invocation = fields.get("_SYSTEMD_INVOCATION_ID")
        if not invocation:
            return "id-missing"
        return "unit-member" if invocation == invocation_id else "other-invocation"

    if (fields.get("UNIT"), fields.get("INVOCATION_ID")) == (unit, invocation_id):
        return "manager-related" if row.get("manager_verified") is True else "unverified-related"

    if (fields.get("OBJECT_SYSTEMD_UNIT"), fields.get("OBJECT_SYSTEMD_INVOCATION_ID")) == (unit, invocation_id):
        if "OBJECT_SYSTEMD_USER_UNIT" not in fields:
            return "object-related"

    return "outside-scope"

with open("invocation-cases.jsonl", encoding="utf-8") as stream:
    cases = [json.loads(line) for line in stream if line.strip()]
for row in cases:
    actual = classify(row)
    assert actual == row["expected"], f"{row['case']}: expected {row['expected']}, got {actual}"
    print(f"{row['case']}: {actual}")
assert len(cases) == 9, f"Expected nine cases, got {len(cases)}"
```

**Expected result.** Nine cases pass. One matches the source unit's run. A manager record and an object record relate to the same run without becoming service output. A competing unverified manager claim stays unverified. A retry and records from another machine, boot or user scope do not join the target. A missing ID stays unresolved.

**Failure check.** In a copy of the fixture, change the `unit-record` invocation ID to the retry's ID and use that file as the input. The row must fail with `other-invocation`. Restore the original before repeating. If Python cannot open the file, check the working directory and filename. The offline cases were executed in the cloud. The service inspection examples were reviewed against systemd documentation.

## 5. Review and completion criteria

1. **A new invocation logs success after an older one fails. Was the older run successful?** The success record pertains to the new run. Use a receiver or equivalent outcome record for each work item.
2. **An `INVOCATION_ID` appears in an exported record. Can you identify its sender from that field?** It gives a lead. Review how the source and transport were verified.
3. **Why can `systemctl cat` show a change when the process still uses the old configuration?** The displayed files are the current backing files. Inspect both the running state and the time of configuration changes.

Complete the chapter when you can write a scoped run identity, separate manager and application observations, explain one evidence gap and cite what confirms the downstream result.

## Official references

Reviewed **2026-11-27** using the upstream systemd **261** documentation. The direct sender invocation field was introduced in **233** and the invocation query controls in **257**. Check your distribution's release and any backports.

- [systemd.journal-fields(7) · Field provenance and meanings](https://www.freedesktop.org/software/systemd/man/261/systemd.journal-fields.html)
- [systemd.service(5) · Startup types and restart semantics](https://www.freedesktop.org/software/systemd/man/261/systemd.service.html)
- [systemd.exec(5) · Service execution environment](https://www.freedesktop.org/software/systemd/man/261/systemd.exec.html)
- [journalctl(1) · Unit, boot and invocation filters](https://www.freedesktop.org/software/systemd/man/261/journalctl.html)
- [systemctl(1) · Runtime properties and backing files](https://www.freedesktop.org/software/systemd/man/261/systemctl.html)

[Previous · systemd timer evidence]({{ '/wiki/systemd-timer-evidence/' | relative_url }}) · [Next · Journal collection coverage]({{ '/wiki/linux-journal-coverage/' | relative_url }}) · [Corroborate process identity]({{ '/wiki/linux-process-evidence/' | relative_url }})
