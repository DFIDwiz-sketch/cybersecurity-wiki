---
title: "SELinux AVC Evidence · From File Labels to a Denied Operation"
description: "Read process and file labels, join AVC and syscall records, and distinguish enforcing denials from permissive observations."
category: blue-team
tags: [Linux, SELinux, Linux Audit, File Permissions, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /ko/wiki/selinux-avc-evidence/
---

A web service can read most of its site but reports “Permission denied” for a newly staged page. The file's mode is `0644`. Follow the exact request and check the security labels, the SELinux decision, and what the system call returned.

## 1. Two layers decide file access

**Discretionary access control (DAC)** includes the permissions associated with file ownership, mode bits and ACLs. Directory search rights and the process's credentials matter too. **Mandatory access control (MAC)** adds rules set by system policy. SELinux evaluates **contexts** (security labels) for the requesting process and the target object. A context contains a user, role, type and level or range where applicable. The process type is commonly called its **domain**. **Type enforcement** uses that domain, the target type, the object class and the requested permission, such as `httpd_t` reading a `file` labeled `httpd_sys_content_t`.

On the RHEL file path described here, ordinary DAC checks can reject a request before SELinux evaluates it. An **AVC** record reports a policy decision associated with the Access Vector Cache. A silent log may reflect a DAC rejection, a policy rule that suppresses auditing (`dontaudit`), or incomplete collection. It cannot by itself identify the failing layer.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/selinux-avc-evidence-en.svg' | relative_url }}" alt="A file access first encounters DAC. If that permits access, SELinux can evaluate the labels. Compare the AVC and same-event syscall outcome when both records are available.">
  <figcaption>Mode, labels, the policy decision and the syscall result answer different questions.</figcaption>
</figure>

| Evidence | What it tells you | What to verify separately |
| --- | --- | --- |
| Mode, ACL and process credentials | Whether the observed DAC inputs appear to permit the request | Parent directories, mount view and evidence at incident time |
| `scontext`, `tcontext` and `tclass` | Source label, target label and object class | Intended labels for that deployment |
| AVC `denied` with `permissive=0` | The recorded SELinux permission check was enforced | Same-event syscall result and user-visible effect |
| AVC `denied` with `permissive=1` | The policy would deny this check, which ran permissively | Actual syscall result, including failure for another reason |
| `SYSCALL success` and `exit` | Whether the audited syscall succeeded and its return value | Whether the application's larger task completed |

A system can be globally enforcing while an individual domain is permissive. For past activity, the per-record permissive flag, when present, is closer to the decision than today's `getenforce` output.

## 2. Follow a normal read and a label mismatch

In this fictional RHEL 9 example, a confined web worker in domain `httpd_t` serves a static page under `/var/www/html/`. Directory search and file read are permitted by DAC, and the regular file has the expected `httpd_sys_content_t` type. With a matching policy, a file open succeeds. A successful open is evidence of acquiring a file descriptor. An application response or another observation is needed to establish what was served.

After a deployment stages a new page, the actual file label is `user_home_t` while the active mapping for that path expects `httpd_sys_content_t`. A deployment method that preserves a source label can produce this discrepancy. In the following abbreviated synthetic audit records, `1730120000.010:101` identifies one event on one host and boot:

```text
type=AVC msg=audit(1730120000.010:101): avc: denied { read } for pid=420 comm="httpd" path="/var/www/html/guide.html" scontext=system_u:system_r:httpd_t:s0 tcontext=unconfined_u:object_r:user_home_t:s0 tclass=file permissive=0
type=SYSCALL msg=audit(1730120000.010:101): arch=c000003e syscall=257 success=no exit=-13 pid=420 comm="httpd"
```

On this synthetic x86-64 record, `257` is `openat` and `-13` is `EACCES`. Read syscall numbers against the recorded architecture. The AVC names a denied `read` under SELinux, and the paired syscall failed. Preserve the labels, process and event, then compare the expected label and deployment manifest. An analyst who saw only `exit=-13` would need more evidence to identify the cause.

## 3. Collect, detect and respond

1. **Locate the operation.** Record host, boot identity when available, UTC time, service unit and process, actual mount or container view, full audit timestamp and serial, and resolved object metadata where available. Keep all records in the event, including `PATH` and `CWD` when supplied. A PID can be reused. The same serial can appear on a different host.
2. **Check scope and coverage.** Capture the source and target labels, object class, denied permissions, permissive flag and syscall result. Record current security status and policy versions as timestamped observations. Confirm service and Audit coverage, retention, collection loss, and whether your central pipeline preserves associated records from the same event.
3. **Triage with context.** A repeated enforcing denial after a deployment can reflect a wrong label. Unexpected attempts from a web domain to read labels associated with private files can also indicate an application fault or suspicious activity. Compare the release window, service identity and paths, package or policy changes, and independently logged application outcomes. An AVC alone does not establish compromise, successful access or the identity of a human.
4. **Correct narrowly.** Preserve original logs and label evidence first. If a vendor-supported location has drifted from its expected label, coordinate a narrowly scoped correction with the owner. For a nonstandard path, review the intended durable file-context mapping with the policy owner. Broad permission changes or an automatically generated allow rule can expand access beyond the application requirement. Validate that an intended operation succeeds and a separate policy negative control stays blocked in the approved test environment.

On an approved RHEL 9 host with appropriate tools installed, replace `420` and the path with the observed values. `ausearch` requires read access to the local Linux Audit store. These examples inspect state and do not relabel files:

```bash
getenforce
ps -p 420 -o pid,label,comm
ls -Zd -- /var/www/html/guide.html
matchpathcon -V /var/www/html/guide.html
ausearch -m AVC,USER_AVC,SELINUX_ERR,USER_SELINUX_ERR -ts recent --raw
```

`matchpathcon -V` compares an existing object's context with the default lookup. It does not tell you whether the type is appropriate for the application or whether the process can read it. `recent` examines roughly the last ten minutes and is only an initial check. Widen the authorized time window for an earlier incident and examine original host logs if collector data is missing. The commands were reviewed against the documentation. The lab below reads fictional records and does not require SELinux or Audit on the host.

## 4. Offline lab

On an approved workstation with Python 3.8 or later, save the <a href="{{ '/assets/labs/selinux-avc-evidence.py' | relative_url }}" download="selinux-avc-evidence.py">event join script</a> and <a href="{{ '/assets/labs/selinux-avc-evidence.json' | relative_url }}" download="selinux-avc-evidence.json">synthetic records</a> to the same directory.

```bash
python3 selinux-avc-evidence.py selinux-avc-evidence.json
```

The JSON wraps abbreviated AVC and SYSCALL strings with fictional host and boot fields. The parser covers this fixture's exact forms. It groups by host, boot, and the full value inside `audit(...)`, then compares the permissive flag with the syscall result. It does not reconstruct policy or decode arbitrary audit records.

| Event | Expected result |
| --- | --- |
| `lab-a/boot-1/101` | Enforcing decision with failed syscall |
| `lab-b/boot-2/101` | Permissive decision with successful syscall, despite the same audit value as `lab-a` |
| `lab-a/boot-1/102` | Failed syscall with no paired AVC in the fixture |
| `lab-a/boot-1/103` | Recorded enforcing decision, syscall result unavailable |
| `lab-a/boot-1/104` | Permissive decision with a failed syscall |
| `lab-a/boot-1/105` | Successful syscall with no paired AVC in the fixture |
| `lab-a/boot-1/106` | Denial observed, enforcement unknown because its flag is absent |

If you cannot open the fixture, check the directory and both filenames. If an event is missing its pair, compare the host, boot, timestamp and serial before attributing the discrepancy to policy. In a copy, remove the syscall paired with event 101 on `lab-a`. The result should then say the syscall was unobserved. All published examples were executed on the synthetic data.

## 5. Check your understanding

1. **Why can mode `0644` coexist with an enforced denial?** It describes file DAC inputs. The process and target labels can still fail an SELinux rule.
2. **Does `permissive=1` prove the syscall succeeded?** It establishes that the recorded SELinux check ran permissively. Other checks can still fail the operation.
3. **Does a missing AVC prove DAC denied access?** No single cause follows from that absence. Audit coverage, suppression rules and whether SELinux saw the request all matter.
4. **What confirms a label mismatch was corrected safely?** Compare the intended mapping with the resulting label and replay a permitted and a prohibited action with the relevant service context. Confirm the service result as well as the audit result.

Complete the chapter when you can explain the matching event on each host, the difference between a permissive observation and a block, and which evidence is missing in the unpaired cases.

## Official references

Reviewed November 23, 2026. The product guidance covers RHEL 9. Match the tools and audit setup to your distribution and installed policy.

- [Red Hat · Getting started with SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/getting-started-with-selinux_using-selinux)
- [Red Hat · Troubleshooting SELinux](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/using_selinux/troubleshooting-problems-related-to-selinux_using-selinux)
- [Linux Audit · ausearch(8)](https://man7.org/linux/man-pages/man8/ausearch.8.html) and [SELinux Project · matchpathcon(8)](https://man7.org/linux/man-pages/man8/matchpathcon.8.html)

[Previous · Linux file permissions]({{ '/wiki/linux-file-permissions-evidence/' | relative_url }}) · [Next · Linux Audit file evidence]({{ '/wiki/linux-audit-file-evidence/' | relative_url }})
