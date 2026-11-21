---
title: "Active Directory Account Lockout · Trace the Failed Sign-ins"
description: "Start with Security event 4740, separate Kerberos and NTLM failures from locked-account rejections, and investigate the source across domain controllers and endpoints."
category: active-directory
tags: [Active Directory, Windows, Authentication, Kerberos, NTLM, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/ad-account-lockout-evidence/
---

**Learning goal.** Given an Active Directory Domain Services (AD DS) lockout alert, identify the account, explain why different systems recorded different events, and decide what evidence would distinguish an old saved password from unauthorized use. This chapter covers on-premises domain accounts. For cloud sign-in decisions, see [Entra sign-in evidence]({{ '/wiki/entra-signin-evidence/' | relative_url }}).

## 1. What does a lockout tell you?

A **domain controller (DC)** services authentication requests for a Windows domain. An **account lockout** is an account state that can temporarily block new authentication after qualifying failures. An ordinary failed sign-in describes one request. A locked-account rejection describes an attempt against an account that was already locked when the check occurred. To investigate, find the state change first, then reconstruct the requests around it.

Look up the affected account's **effective lockout policy** and record the values that applied at the incident time. The **threshold** specifies how many qualifying bad-password attempts trigger a lockout. The **observation window** governs when the counter can reset after time without another qualifying failure. The **duration** governs how long the lockout lasts before automatic recovery. A threshold of zero disables this threshold-based lockout. When lockout is enabled, a duration of zero requires an administrative unlock. A fine-grained password policy can give an individual user or a group different settings from the domain defaults. An authorized analyst with the ActiveDirectory module can check `Get-ADUserResultantPasswordPolicy` for the affected user and compare with `Get-ADDefaultDomainPasswordPolicy` when the default applies. Record the queried DC and collection time. Today's values may differ from the values in force during the incident.

<figure>
  <img src="{{ '/assets/diagrams/ad-account-lockout-en.svg' | relative_url }}" alt="One domain-account investigation has three views. The destination can record a 4625 logon failure. Domain controller records can show Kerberos 4771 or NTLM 4776, and 4740 anchors a transition to locked.">
  <figcaption>Use 4740 to anchor the timeline. A destination failure and a domain credential check can describe different stages of one request. After lockout, subsequent attempts can carry a locked-account status.</figcaption>
</figure>

## 2. Know which system saw which event

Collect the original Security event XML from the emitting host or from forwarding that preserves it. The table describes the AD DS password path. Check audit policy and log retention on each source before treating missing events as evidence.

| Security event | Collection prerequisite and location | Field and interpretation |
| --- | --- | --- |
| **4740** | Audit User Account Management **Success**, on DCs involved in the domain lockout. Local accounts have separate telemetry. | The target SID identifies the locked account. Caller Computer Name is a host clue. Success here refers to the audited lockout operation. |
| **4771** | Audit Kerberos Authentication Service **Failure**, on the KDC on a DC. | Failure Code `0x18` is invalid pre-authentication, commonly a password mismatch. Inspect Client Address. Accounts exempt from Kerberos pre-authentication do not generate this event. |
| **4776** | Audit Credential Validation **Failure** for rejects, on the authoritative DC for domain NTLM credentials. Collect **Success** separately if needed for related validation results. | `0xC000006A` indicates a bad password and `0xC0000234` a locked account. Source Workstation is a name and the destination is absent. |
| **4625** | Audit Logon / Audit Account Lockout **Failure** as applicable, on the Windows host processing the attempted logon. | Inspect Status, SubStatus, Logon Type and available source fields. `0xC0000234` indicates a locked account. A generic `0xC000006D` without a specific bad-password detail stays generic. |

Start with the **PDC emulator** role holder and also collect the relevant authenticating DCs, including the DC named in any earlier records. Microsoft documents PDC lockout processing and referral of bad-password failures from other DCs for a check. Field availability and coverage still vary across sources. The AD `badPwdCount` attribute is maintained separately on each DC and is not replicated. A later reading, or a sum across DCs, cannot reconstruct the number of attempts that caused a lockout.

**Read the XML in the context of the event ID.** In Microsoft's version 0 example for 4740, the raw `TargetDomainName` contains the rendered caller computer name. In other event types the same XML field name can describe a domain. Preserve the 4740 target SID, confirm its directory identity and use the caller only as a pivot. The event's Subject can be the DC's system context. It does not identify the person or process submitting the password.

## 3. Walk through a normal failure

In a fictional example, an approved reporting application stores credentials for `LAB/svc-reports`. The owner rotates the password at 08:55 UTC. At 09:03, 09:06 and 09:09, a worker still using the old secret retries from REPORT01. DC02 records NTLM validation failures and APP01 logs a destination-side failure at 09:03. At 09:09:01, DC01 records 4740 for that account. At 09:10, APP01 rejects another attempt because the account is locked. The job schedule, password change record, and the owner confirming the worker's configured account support the stale-credential explanation. A shared time and host clue alone leave the initiating process unconfirmed.

The same state change can follow repeated guessing against one account, a broader set of invalid sign-ins, or activity aimed at denying access. Investigate first. A caller name might identify an authenticating intermediary. Corroborate it with endpoint, gateway or application records before treating it as the original source.

| Pattern | Evidence to seek before acting |
| --- | --- |
| One known account, one managed host, recurring intervals after a rotation | Scheduled task or service ownership, run history, credential update timing and proof that retries stop after owner-led correction |
| Several accounts with failures near one reported address | Compare gateway, proxy, host and authentication logs. Determine if many clients share the address. Check later successful sign-ins and account scope. |
| 4740 and later locked-account rejects, with few preceding events | Check other DCs, audit policy, time offset, Security log retention and forwarding filters. Preserve the uncertainty if the gap remains. |

## 4. Build the timeline and respond

1. Record the target SID, original DC, provider, channel, source event record ID and UTC time from 4740. Resolve the SID to the directory account. When an earlier event has only a username, resolve its domain and account using case evidence. Keep ambiguous matches separate.
2. Search earlier and later records using the effective policy and any known clock offsets. Keep Kerberos, NTLM and destination events distinct. Remove exact duplicate exports using source host, channel, record ID and timestamp. Two different records may still describe one attempt. Keep same-time ordering uncertain unless other evidence establishes it.
3. Compare event patterns with maintenance windows, password changes, task or service logs and network mappings at the event time. Confirm the relevant audit subcategories and forwarding coverage. Use source timestamps for ordering and arrival timestamps to diagnose collection delays.
4. Preserve the evidence and coordinate with the account and application owners. For an approved service with outdated credentials, correct the configured secret and confirm its failed retries stop before arranging any unlock. For suspected unauthorized access, follow the incident plan to contain the affected source or account and review related sessions and successful sign-ins. Escalate promptly for privileged accounts or multiple affected identities.

The following read-only PowerShell example displays XML for recent matching events on **the host where it runs**. Run only on an owned or authorized Windows host with permission to read Security. Choose a time bound that includes the case. For central collection, confirm the matching channels on the originating hosts and account for forwarding filters.

```powershell
$filter = @{
    LogName = 'Security'
    Id = 4740, 4771, 4776, 4625
    StartTime = (Get-Date).AddMinutes(-30)
}
Get-WinEvent -FilterHashtable $filter -MaxEvents 200 |
    ForEach-Object { $_.ToXml() }
```

The 200-event cap is for previewing the XML. In a busy log, use bounded time slices or an approved export for the full investigation. Check access errors, event retention and collection health when results are empty. A later successful authorization or business operation requires its own supporting evidence.

## 5. Work through the synthetic evidence

Download [ad-lockout-review.py]({{ '/assets/labs/ad-lockout-review.py' | relative_url }}){: download="ad-lockout-review.py" } and [ad-lockout-cases.csv]({{ '/assets/labs/ad-lockout-cases.csv' | relative_url }}){: download="ad-lockout-cases.csv" } into the same directory in your own workspace. Run with Python 3.8 or later.

```sh
python3 ad-lockout-review.py
```

The CSV is a synthetic **projection**, not raw Windows XML. Account names have already been resolved as `DOMAIN/user`. The selected code represents the relevant status or substatus and `clue` represents an address or workstation field from the event family. The program removes one duplicate export and uses a fixed ten-minute window on each side of 4740 for illustration. It counts source records. AD policy timing and cross-source request identity are outside the model.

| Account | Expected prior bad-password records / later locked-account records | Evidence decision |
| --- | --- | --- |
| `LAB/svc-reports` | 4 / 2 | The DC and destination records at 09:03 may describe one attempt. Check the reporting job before attributing it. |
| `LAB/ari` | 2 / 1 | The generic failure, the older failure outside the window and the account in another domain do not enter the bad-password count. Compare the recurring address with the gateway and the nearby `LAB/lee` event. |
| `LAB/mira` | 0 / 1 | A lockout and a subsequent rejection are visible. The prior source remains undetermined. Record which DCs and time ranges you would collect next. |

Expect **17 unique records and 1 duplicate copy**, followed by the three cases. If the script raises a file error, check the two filenames and their directory. If counts differ, compare the header and timestamps against a fresh fixture. The offline run was verified with Python 3.12.14. The PowerShell and AD DS behavior were reviewed against documentation. Execution in a Windows domain was outside verification scope.

## 6. Check your reasoning

1. **A 4740 Success event shows a DC account under Subject. Did the DC account sign in as the user?** The subject describes the operation context. Use the target SID to identify the locked account and look elsewhere for the source of the failed authentication.
2. **A DC reports 4776 with a bad-password code and a server reports 4625 at the same instant. Were there two attempts?** The two records may be different views of one request. Inspect the host roles and keep them as two records unless further evidence determines the attempt count.
3. **You only see 4625 events with a locked-account status. What do you know?** The account was already locked when those requests were checked. Establish the transition time using 4740 or other authoritative evidence. Confirm DC coverage and search the incident window before assigning an origin or cause.

**Completion check.** Reproduce the three lab results and write one sentence per account naming the observed state, the leading hypothesis or evidence gap, and the next source you would check.

## Official references

Reviewed 2026-11-22. The Windows Security event pages are legacy schema references with historical examples. The Windows Server and PowerShell documentation covers policy and collection interfaces at review time. Validate field rendering and audit coverage on your deployed builds.

- Microsoft [4740 · account lockout](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4740) · [4771 · Kerberos](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4771) · [4776 · NTLM](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4776) · [4625 · failed logon](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4625)
- Microsoft [Lockout threshold](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-lockout-threshold) · [Lockout duration](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/account-lockout-duration) · [Counter reset window](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/security-policy-settings/reset-account-lockout-counter-after)
- Microsoft [PDC emulator role](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/fsmo-roles#pdc-emulator-fsmo-role) · [Bad-Pwd-Count schema attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-badpwdcount)
- Microsoft PowerShell [User resultant policy](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-aduserresultantpasswordpolicy?view=windowsserver2025-ps) · [Domain default policy](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-addefaultdomainpasswordpolicy?view=windowsserver2025-ps) · [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent?view=powershell-7.6)

[Previous · AD fundamentals]({{ '/wiki/active-directory-fundamentals/' | relative_url }}) · [Next · Windows log continuity]({{ '/wiki/windows-log-continuity/' | relative_url }})
