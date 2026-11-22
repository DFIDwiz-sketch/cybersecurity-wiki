---
title: "Linux sudo Command Evidence · From Policy Decision to Observed Effect"
description: "Trace Linux sudo authentication context, command allow, process execution, exit status and independent effects through twelve fictional cases."
category: dfir
tags: [Linux, sudo, Authentication, Linux Audit, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/linux-sudo-command-evidence/
---

A sudo entry names a command and a target account. Before reporting that a privileged action happened, identify the stage the entry represents. A policy decision, a process launch, a command exit and a resulting state change can each require different evidence. Start with [Linux authentication evidence]({{ '/wiki/linux-auth-evidence/' | relative_url }}) if SSH or PAM session records are new to you.

## 1. What sudo decides

**sudo** lets an invoking user request an operation under a **target account**. The target can be root or a less privileged service account. The **policy plugin** decides what the caller may request. With the sudoers plugin, effective policy can depend on the caller's groups, host, target user or group, command, arguments and configuration source. The account permitted to authenticate for the request is also policy-dependent. Read the applied policy and identity context for that host and time.

**Authentication** checks the required credentials. Sudoers may reuse an authentication timestamp according to settings such as `timestamp_type` and `timestamp_timeout`. Some policy entries use the `NOPASSWD` tag. An absent password prompt can have ordinary causes, and does not distinguish a cached authentication from an exemption on its own. Neither observation establishes that any other command was authorized.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/linux-sudo-command-evidence-en.svg' | relative_url }}" alt="Identify the caller and target account, confirm authentication context, read the policy decision, correlate execution and exit, and verify the operation's effect.">
  <figcaption>Retain each stage independently. Stop the inference where the records stop.</figcaption>
</figure>

| Observation | What it supports | Evidence still needed |
| --- | --- | --- |
| Prompt, authentication failure or valid cached context | How authentication was handled in that context | Policy decision for the particular operation |
| Sudoers allow or reject | A recorded policy decision | Matched process execution or failure |
| Linux Audit syscall and process event | The recorded syscall outcome under the relevant audit coverage | Program exit or independent effect |
| sudo exit status or signal | How that invocation ended, if collected | The operation's effect in a file, service or application |
| Resource state or activity | What the observer actually saw | A defensible link to the correct process and change |

## 2. Follow a normal maintenance invocation

A fictional operator runs an approved service status command on `app-lab-01`. The sudo event records caller `alex`, target `root`, `TTY=pts/2`, working directory and `COMMAND=/usr/bin/systemctl is-active reports.service`. The operator had previously authenticated in an eligible context. Audit or endpoint telemetry supplies a matching process instance. A configured exit log records exit 0. For this read-only status example, capture what the command reported before claiming the service was healthy. No persistent state change is expected.

In a separate maintenance case, a similarly linked command creates an approved application change. Check the application's own record or versioned file state for that operation. The exit code cannot tell you which values changed. A launch failure can follow a policy allow. An application can also exit nonzero after a partial change. Record that possibility until you check the affected state.

## 3. Collect and correlate each source

1. **Record the policy and caller context.** Preserve host, boot interval, UTC time, invoking account, target account, TTY, working directory, arguments where authorized, policy plugin and version. Keep the relevant configuration history and identity or group records. Local policy files, includes and directory-backed rules can all matter. A later policy listing is current evidence. Reconstruct historical policy with preserved snapshots and approved change records.
2. **Link execution deliberately.** When Linux Audit or endpoint process telemetry covers the action, use host, boot, audit session or other reliable session evidence, and the actual process instance. Confirm process start time, executable, parent and effective identity. `auid` is the Audit login UID, when populated. `euid` is the effective UID. An elevated `euid` alone cannot identify sudo as the mechanism. `exit` on an Audit `SYSCALL` record describes the syscall result. It is a different field from the program's final exit code. See [Linux Audit file evidence]({{ '/wiki/linux-audit-file-evidence/' | relative_url }}) for multi-record reconstruction.
3. **Verify collection and outcome.** Sudoers logging can use syslog or a configured file and, with suitable configuration, other logging paths. The documented `log_exit_status` setting requires sudo 1.9.8 or later and is off by default in the upstream manual. Verify the installed package, log route, configured scope, retention and forwarder health. I/O recording and subcommand logging are separate controls with version, compatibility and privacy implications. An approved command can start other processes. Use approved process-lineage and resource evidence to scope descendants. Store logs with access controls because arguments and terminal output can contain secrets.

On an authorized test host with sudo installed, inspect your own current policy without running a target command. These commands may generate logs. `-n` disables interactive prompts. Effective listing policy or an authentication requirement can stop the second command. Interpret the message before deciding what failed. This product example was reviewed against the package manual.

```bash
sudo --version
sudo -n -l
```

## 4. Decide what needs investigation

An approved account may use more privilege than its job needs, or a compromised account may use an existing legitimate rule. A file or script on which a privileged rule depends can also change after approval. Assess the rule and referenced program's owner and integrity as part of the review. Rank discrepancies by unexpected caller or target, service purpose, unauthorized policy changes and actual effect. A failed command followed by an allowed one can be normal troubleshooting. Preserve the surrounding actions and approvals before assigning intent.

Escalate unexplained privileged actions to the system owner and incident lead. Preserve logs and current effective policy before coordinated containment where feasible. Compare the program, descendants, file and service effect. If evidence is missing, verify Audit rule scope, sensor backlog, journal retention and forwarded gaps. After remediation, verify expected allow and deny decisions on an approved disposable host using harmless commands and documented recovery. This chapter's downloadable lab uses fictional evidence only.

## 5. Offline exercise · twelve fictional observations

Download both files into one directory and run with Python 3.10 or later. The JSONL contains normalized teaching data, not vendor event formats. `invocation` is a teaching correlation key, not a universal sudo or Audit field. The lab requires host, boot, session and that key to agree. `at` is relative seconds. The fixtures have ordered times and the example expects strict order for separately recorded stages. Real evidence needs its own normalized keys and a clock uncertainty budget. The script reads local files and does not invoke sudo.

<a href="{{ '/assets/labs/linux-sudo-command-evidence.py' | relative_url }}" download="linux-sudo-command-evidence.py">linux-sudo-command-evidence.py</a> · <a href="{{ '/assets/labs/linux-sudo-command-evidence-cases.jsonl' | relative_url }}" download="linux-sudo-command-evidence-cases.jsonl">linux-sudo-command-evidence-cases.jsonl</a>

```bash
python3 linux-sudo-command-evidence.py linux-sudo-command-evidence-cases.jsonl
```

```text
status_read: zero_exit_effect_unknown
change_confirmed: effect_confirmed
allowed_only: allowed_execution_unknown
policy_denied: denied
auth_required: authentication_required
different_boot: execution_unlinked
missing_session: execution_unlinked
execution_rejected: exec_failed
exit_missing: started_exit_unknown
command_nonzero: command_nonzero
other_invocation: exit_unlinked
effect_before_start: zero_exit_effect_unlinked
```

In `status_read`, exit 0 gives no independent state evidence. In `effect_before_start`, an earlier observation cannot support an effect of the later command. If the command cannot open a file, check your directory and filenames. If a case unexpectedly fails to link, inspect the host, boot, session and correlation key before looking at exit code. Python 3.12 executed the offline exercise. No Linux sudo or Audit product behavior was executed in this lab.

## 6. Check your reasoning

- **There was no password prompt. Has policy been bypassed?** Check cached authentication and any applicable exception as well as the actual policy decision. The prompt observation alone is insufficient.
- **Audit shows `success=yes` on a recorded exec syscall. Did the program succeed?** The recorded syscall succeeded. Use an exit event and resource evidence for later outcomes.
- **Can an exit event with the same PID on another boot close the case?** Build identity with the correct boot, time and process instance. PID alone is reusable.

Complete the exercise by matching all twelve output lines and naming the next source for `allowed_only`, `exit_missing` and `effect_before_start`.

## Official references

Reviewed 2026-11-22. The Ubuntu references describe two LTS package lines and the Red Hat reference covers RHEL 9. The upstream manual describes feature conditions and defaults. Verify installed package behavior and local policy in your environment.

- Upstream policy and logging documentation. Compare against the installed release. [sudo project · sudoers manual source](https://github.com/sudo-project/sudo/blob/main/docs/sudoers.man.in)
- Policy matching, authentication and logging limits. log_exit_status requires 1.9.8 or later. [sudoers(5) · rendered upstream manual](https://man7.org/linux/man-pages/man5/sudoers.5.html)
- Noble package reference for cache records, including configured scope. [Ubuntu 24.04 LTS · sudoers_timestamp(5)](https://manpages.ubuntu.com/manpages/noble/man5/sudoers_timestamp.5.html)
- Jammy CLI documentation for listing, noninteractive mode and status. [Ubuntu 22.04 LTS · sudo(8)](https://manpages.ubuntu.com/manpages/jammy/man8/sudo.8.html)
- RHEL 9 audit field definitions for the login identity and system call result. [Red Hat Enterprise Linux 9 · Auditing](https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/epub/security_hardening/understanding-audit-log-files_auditing-the-system)

[Previous · Linux authentication evidence]({{ '/wiki/linux-auth-evidence/' | relative_url }}) · [Next · Linux Audit file evidence]({{ '/wiki/linux-audit-file-evidence/' | relative_url }}) · [Related · Linux process identity]({{ '/wiki/linux-process-evidence/' | relative_url }})
