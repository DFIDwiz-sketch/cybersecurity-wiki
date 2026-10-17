---
title: "Kerberoasting: Attack Mechanics, Event 4769, Detection and Defense"
description: "A practical Active Directory guide to SPNs, TGS tickets, offline password guessing, RC4 and AES, Splunk detections, and the DFIR response workflow."
category: active-directory
tags: [Windows Security, Kerberoasting, Active Directory, Kerberos, Red Team, Blue Team, DFIR, Detection Engineering, Splunk, Credential Access, MITRE ATT&CK]
level: Intermediate
updated: "2026-10-17"
translation_url: /ko/wiki/kerberoasting/
---

> **Scope:** This tutorial explains attacker behavior for defensive understanding and authorized lab validation. Account names, hostnames, times, IPs and event examples are illustrative. Never test credentials against systems you do not own or have permission to assess.

## 1. What is Kerberoasting?

**Kerberoasting** is an Active Directory credential-access technique (MITRE ATT&CK **[T1558.003](https://attack.mitre.org/techniques/T1558/003/)**). An attacker with a valid domain authentication context obtains a **Kerberos service ticket (TGS)** for a Service Principal Name (SPN), extracts the service-key-encrypted portion, and attempts **offline password guessing** to recover the underlying service account password.

A regular domain user can request tickets for many services without having Domain Admin privileges. This does **not** mean the attacker is immediately able to access those services, or that every obtained ticket is crackable.

**Crucial distinction:** The attack does not require repeated online login attempts while the attacker tests guesses locally. Consequently, **the offline password-guessing phase itself does not increment Active Directory bad-password counters, create password-failure events on the DC or cause account lockout**. Ticket requests, subsequent authentication and other activity may still leave evidence.

### Kerberoasting versus other attacks

| Technique | Main objective | Core prerequisite |
| --- | --- | --- |
| Kerberoasting | Guess a password from encrypted **TGS service-ticket material** | A service SPN and a ticket obtained by an authenticated requester (or suitable captured traffic) |
| AS-REP Roasting | Guess a password from an **AS-REP** | Account configured without Kerberos pre-authentication |
| Password spraying | Try a small number of candidate passwords **online** against multiple users | Accessible authentication endpoint |
| Pass-the-Hash | Authenticate with an available NT hash | Already obtained NT hash; not a Kerberoasting ticket by itself |
| NTLM relay | Relay authentication to another service | A relayed authentication exchange and a vulnerable target |

## 2. Kerberos fundamentals: TGT, TGS, SPN and the service account

In a Windows domain, the Domain Controller (DC) normally runs the Key Distribution Center (KDC). Its Authentication Service issues a **Ticket Granting Ticket (TGT)** to a successfully authenticated client. The client then presents its TGT to the Ticket Granting Service to request a **service ticket (TGS)**.

An **SPN** is a service identifier, for example `MSSQLSvc/sql01.example.local:1433` or `HTTP/intranet.example.local`. SPNs map to AD principals: a dedicated user service account, a computer account, or a managed service account. A ticket's service-encrypted portion is protected with a key derived from that target principal's secret.

**Example:** User `john` requests access to SQL. The KDC returns a ticket for the service associated with `svc_sql`. The encrypted ticket material depends on `svc_sql`'s key, **not on John's password**. Attackers try to recover the *service account* password, not the requesting user's password.

## 3. How the attack unfolds, step by step

![Five stages of Kerberoasting, showing Event 4769 and offline guessing]({{ '/assets/diagrams/kerberoasting-attack-en.svg' | relative_url }})

1. **Establish an authenticated domain context.** An attacker controls a domain user session or another valid TGT. They do not generally require local administrator or domain administrator privileges for the basic ticket request.
2. **Identify SPN-bearing accounts.** They discover service principals through AD directory information and prioritize accounts with valuable privileges, human-chosen passwords or long-unrotated secrets. Defensive LDAP telemetry or endpoint process telemetry may show enumeration, but plain directory reads are common in normal operations.
3. **Request service tickets.** The client sends a **TGS-REQ** to the KDC. The DC issues a **TGS-REP** containing service-ticket material and normally records **Security Event ID 4769** when auditing is enabled. The ticket request is a legitimate Kerberos operation in isolation.
4. **Extract and test encrypted material offline.** Attack tools format the encrypted ticket portion for password-candidate testing on separate compute resources. Each candidate is checked against the encrypted material without repeatedly contacting the DC. This is why the cracking phase can be invisible to ordinary Windows authentication logs.
5. **Use recovered credentials if guessing succeeds.** The attacker may attempt authenticated access, lateral movement, privilege escalation, or persistence *only to the extent the compromised service account permits*. Later logons, service creation, remote execution and privilege use can produce separate evidence.

**Possible tooling:** Attackers and testers have used Rubeus, Impacket's GetUserSPNs and offline password-recovery utilities. Their presence or a filename alone is not proof of abuse. This guide focuses on detection and defensive validation rather than targeting production credentials.

### What exactly is being attacked?

Kerberoasting is sometimes simplified to “stealing a password hash.” More precisely, attackers work with **Kerberos service-ticket encrypted data**, commonly serialized into a format such as `$krb5tgs$23$...`. It is **not the same thing as directly dumping the account's NT hash** from LSASS or the directory database. If a password guess produces the expected cryptographic result, the attacker has recovered the password.

## 4. Ticket encryption: why RC4 (0x17) matters

| Event 4769 ticket encryption type | Algorithm | Defender interpretation |
| --- | --- | --- |
| `0x17` (decimal 23, etype 23) | RC4-HMAC | Less resistant to offline password guessing; useful risk signal |
| `0x11` (etype 17) | AES128-CTS-HMAC-SHA1-96 | Stronger; roasting remains conceptually possible |
| `0x12` (etype 18) | AES256-CTS-HMAC-SHA1-96 | Stronger; weak passwords still create risk |

RC4-HMAC uses a relatively cheap password-to-key derivation process, whereas Kerberos AES requires more expensive key derivation. An attacker therefore usually prefers RC4 ticket material for offline guessing. **However, RC4 is neither a necessary nor a sufficient condition for Kerberoasting.** A legitimate application might receive an RC4 ticket, and an attacker might target AES tickets.

**Do not confuse** the ticket's `TicketEncryptionType` with `SessionKeyEncryptionType`. A session key's encryption type is not the same field and should not be used as a substitute for the ticket encryption type when triaging RC4 Kerberoasting.

### Important 2026 RC4 change

Microsoft's **2026 Windows security update rollout** moved away from implicitly assuming RC4 support for service accounts that have no explicit `msDS-SupportedEncryptionTypes` setting. Microsoft describes enforcement beginning with the April 2026 updates and the final transition in July 2026. RC4 can still be issued where explicitly permitted by account configuration and applicable policy. The actual posture depends on patch level, service keys and directory settings.

**Practical consequence:** Modern networks might generate far fewer `0x17` events. Do not build a detection strategy that requires RC4; monitor unusual *AES* ticket requests too. Also investigate unexpected RC4 issuance and verify `ServiceSupportedEncryptionTypes`, `ServiceAvailableKeys` and `ClientAdvertizedEncryptionTypes` when available.

For current guidance, see [Microsoft's RC4 remediation documentation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos) and [Microsoft's 2026 RC4 change explanation](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/what-changed-in-rc4-with-the-january-2026-windows-update-and-why-it-is-important/4504732).

## 5. Event ID 4769: what the DC actually records

**4769** is logged in the **domain controller's Security log** when the KDC receives a Kerberos TGS request and the relevant auditing is enabled. Events can represent success or failure. It is **not** an event stating that a password was cracked.

| Security event / field | What to investigate |
| --- | --- |
| `4769` | TGS requested; inspect success/failure status |
| `TargetUserName` / Account Name | Account **requesting** the ticket |
| `ServiceName` / Service Name | AD account/computer **targeted** by the service ticket |
| `IpAddress` / Client Address | Requester's network address, sometimes `::ffff:IPv4` |
| `TicketEncryptionType` | Issued ticket's cipher, e.g. `0x17`, `0x12` |
| `Status` / Failure Code | `0x0` generally means success |
| `ServiceSid` | Target service principal's SID where present |
| `ServiceSupportedEncryptionTypes` | The target's advertised/supported encryption settings (newer event format) |
| `ServiceAvailableKeys` | Key types actually available for the target service (newer event format) |
| `ClientAdvertizedEncryptionTypes` | Crypto algorithms offered by the client (newer event format) |
| `SessionKeyEncryptionType` | Session-key algorithm; **not** the ticket encryption type |

**The distinction many tutorials miss:** `ServiceName` in a 4769 event commonly identifies the **account behind the service**, rather than always providing the full requested SPN. Counting distinct `ServiceName` values is counting distinct observed target *accounts*, not necessarily distinct SPN strings. Correlate with directory SPN mappings when the precise service instance matters.

Microsoft introduced additional 4769 fields on Windows Server 2016 and later with the **January 14, 2025** cumulative update. Older DCs and different SIEM parsers might lack or rename them. See [Microsoft's Event 4769 reference](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769).

## 6. Why many RC4 tickets from one identity are suspicious

Consider these **fabricated example events**, all recorded on the DC:

| Time | Requester | Source IP | Target service account | Ticket etype |
| --- | --- | --- | --- | --- |
| 10:00:01 | john | 172.16.2.4 | svc_sql | 0x17 |
| 10:00:02 | john | 172.16.2.4 | svc_backup | 0x17 |
| 10:00:03 | john | 172.16.2.4 | svc_web | 0x17 |
| 10:00:04 | john | 172.16.2.4 | svc_report | 0x17 |
| 10:00:05 | john | 172.16.2.4 | svc_exchange | 0x17 |

This is interesting because **one identity + one source + many different target service accounts + a short interval + RC4** is consistent with bulk ticket collection. Nonetheless, automated inventory systems, jump hosts, scheduled jobs, service dependencies and application startup can also trigger bursts. Five tickets in five seconds is **an investigative example**, not a universal threshold or proof of attack.

A quieter attacker might request **one ticket for a privileged service account**. A rule requiring large bursts would miss that activity. Detect both **bulk requests** and **rare or risky targets**; compare by user, host, service account, time of day and expected application behavior.

![Detection triage: Kerberos events, anomalies and correlated telemetry]({{ '/assets/diagrams/kerberoasting-detection-en.svg' | relative_url }})

## 7. Splunk: practical search and detection examples

The following queries are **templates**, not universally plug-and-play searches. First confirm your index, source, field extraction, time window and whether the DC's 4769 audit events are actually reaching Splunk. The exact field names differ among Windows Event Log, XML, JSON and TA-based parsing.

### A. Inspect available 4769 fields

```spl
index=* (EventCode=4769 OR EventID=4769)
| head 20
| table _time host sourcetype EventCode EventID TargetUserName Account_Name ServiceName Service_Name IpAddress Client_Address TicketEncryptionType Ticket_Encryption_Type Status
```

Set the search time range to cover the incident. Use the real AD index in place of `index=*` once identified.

### B. Review RC4 ticket requests

```spl
index=* (EventCode=4769 OR EventID=4769)
| eval requester=coalesce(TargetUserName,Account_Name,AccountName,user)
| eval target=coalesce(ServiceName,Service_Name,service)
| eval src=coalesce(IpAddress,Client_Address,src_ip)
| eval etype=lower(trim(coalesce(TicketEncryptionType,Ticket_Encryption_Type,ticket_encryption_type)))
| eval result=coalesce(Status,Failure_Code)
| where in(etype,"0x17","23") AND (isnull(result) OR in(lower(result),"0x0","0"))
| stats count as requests values(target) as targets by requester src etype
| sort - requests
```

The query recognizes either hexadecimal `0x17` or decimal `23` if your parser emits decimal values.

### C. Detect bursts across *all* ticket encryption types

```spl
index=* (EventCode=4769 OR EventID=4769)
| eval requester=coalesce(TargetUserName,Account_Name,AccountName,user)
| eval target=coalesce(ServiceName,Service_Name,service)
| eval src=coalesce(IpAddress,Client_Address,src_ip)
| eval etype=lower(trim(coalesce(TicketEncryptionType,Ticket_Encryption_Type,ticket_encryption_type)))
| eval result=coalesce(Status,Failure_Code)
| where isnotnull(requester) AND isnotnull(target) AND target!="krbtgt"
| where isnull(result) OR in(lower(result),"0x0","0")
| bin _time span=5m
| stats count as ticket_requests
        dc(target) as distinct_target_accounts
        count(eval(in(etype,"0x17","23"))) as rc4_requests
        values(target) as target_accounts
        values(etype) as encryption_types
        by _time requester src
| where ticket_requests>=10 AND distinct_target_accounts>=5
| sort - distinct_target_accounts - ticket_requests
```

Here `5 minutes`, `10 tickets` and `5 distinct target accounts` are **illustrative starting thresholds**. Tune to the environment and whitelist expected high-volume automation only after confirming its identity and behavior. Do not blindly exclude every account ending in `$`: this can hide managed service accounts.

### D. Examine an unusually sensitive *single* target

```spl
index=* (EventCode=4769 OR EventID=4769)
| eval requester=coalesce(TargetUserName,Account_Name,AccountName,user)
| eval target=coalesce(ServiceName,Service_Name,service)
| eval src=coalesce(IpAddress,Client_Address,src_ip)
| eval etype=coalesce(TicketEncryptionType,Ticket_Encryption_Type,ticket_encryption_type)
| search target="svc_backup"
| stats count as requests values(etype) as ticket_etypes min(_time) as first_seen max(_time) as last_seen by requester src
| convert ctime(first_seen) ctime(last_seen)
| sort - requests
```

Replace `svc_backup` with a real high-value service account. A rare requesting user or unrecognized source IP may warrant investigation **even if the ticket is AES and even if only one ticket was requested**.

## 8. DFIR investigation playbook

| Stage | Analyst question | Evidence |
| --- | --- | --- |
| Validate | Are these really DC Security 4769 events? | DC, audit configuration, ingestion delay, event field mapping |
| Scope | Who requested which target accounts, when and from where? | 4769, requester, service account, source IP, status and etype |
| Context | Is this normal for this user and application? | 7–30 day baseline, change windows, known jobs, SPN inventory |
| Endpoint | Was there suspicious enumeration or ticket collection? | Endpoint process telemetry (e.g. 4688, Sysmon 1), LDAP activity when logged |
| Follow-on | Did the service account authenticate in an unusual place? | 4624, 4648, 4672; remote logons, service/task creation, host and network evidence |
| Outcome | Is compromise confirmed, probable or only suspected? | Correlated activity and corroborating indicators; do not infer success from 4769 alone |
| Contain | Which accounts/hosts need isolation or secret rotation? | Account owner, service dependencies, approved incident response procedures |

**Logging caveats:** Windows event 4624 indicates a successful logon on the destination; 4648 indicates an explicit-credentials logon attempt; 4672 denotes special privileges assigned during a logon. None by itself proves a Kerberoasting crack. Correlation depends on auditing, log availability, and sometimes a matching Logon GUID.

**Network evidence:** A Kerberos exchange typically uses TCP/UDP 88. Zeek/network metadata can help localize TGS traffic when collected, but encrypted ticket exchange metadata alone cannot reveal successful offline guessing. Endpoint telemetry is especially useful to differentiate ordinary application ticket requests from suspicious collection tooling.

### Quick triage example

If `john` at `172.16.2.4` requests 18 distinct service accounts in five minutes, first check whether `172.16.2.4` is a standard workstation or an authorized management system. Then inspect targeted account privileges, ticket encryption, the user's normal service access, recent process and directory activity, and subsequent service-account logons. **Do not declare the password cracked on ticket volume alone.**

## 9. Hardening and prevention

1. **Prefer gMSAs where supported.** Windows manages strong, randomly generated gMSA passwords and regular rotation. The account can still have an SPN and receive tickets; the protection is that its secret is extremely resistant to guessing.
2. **For traditional user-based service accounts, use unique, randomly generated long secrets.** MITRE recommends **25+ characters**, with a password vault and safe rotation. Length alone is not enough if the string is predictable.
3. **Reduce/retire RC4 using Microsoft's phased guidance.** Audit legacy dependencies, available AES keys, `msDS-SupportedEncryptionTypes`, keytabs and service compatibility before changing policy.
4. **Least privilege.** Remove unnecessary Domain Admin / Enterprise Admin memberships, delegation and interactive sign-in rights from service accounts.
5. **Inventory SPNs and service accounts.** Identify owners, criticality, password age, encryption capabilities and service dependencies. Remove unused SPNs safely.
6. **Audit and alert.** Collect 4769 from all relevant DCs, correlate with identity and process telemetry, and test both burst and low-volume high-value-account detections.
7. **Respond safely.** When compromise is suspected, preserve evidence and coordinate service-account password rotation and service restarts with system owners to avoid outages.

### Defensive service-account inventory (authorized administrators)

On a management workstation with RSAT / the ActiveDirectory PowerShell module and suitable read permission:

```powershell
Get-ADUser -LDAPFilter '(servicePrincipalName=*)' -Properties ServicePrincipalName,PasswordLastSet,msDS-SupportedEncryptionTypes |
  Select-Object SamAccountName,Enabled,PasswordLastSet,ServicePrincipalName,
    @{Name='SupportedEtypes';Expression={$_.'msDS-SupportedEncryptionTypes'}}
```

This performs **inventory**, not password recovery. Also inspect SPNs on computer accounts and gMSAs for full coverage; user objects alone are not the complete service inventory.

## 10. Common misconceptions

- **“0x17 means Kerberoasting occurred.”** No. It is a ticket encryption choice, not attack attribution.
- **“No failed logons means nothing happened.”** No. Offline guessing does not generate DC login failures.
- **“The user requesting the ticket is the password being cracked.”** No. The key belongs to the targeted service principal.
- **“Event 4769 ServiceName is always the full SPN.”** No. It is often the backing service account/computer name.
- **“AES stops Kerberoasting entirely.”** No. It raises the cost of guessing; strong secrets remain essential.
- **“All suspicious activity must request dozens of tickets.”** No. Targeted, low-volume roasting exists.
- **“Disabling RC4 is risk-free.”** No. Legacy services and old key material must be validated before enforcement.

## 11. Further reading

- [MITRE ATT&CK T1558.003: Kerberoasting](https://attack.mitre.org/techniques/T1558/003/)
- [MITRE DET0157: Detect Kerberoasting Attempts](https://attack.mitre.org/detectionstrategies/DET0157/)
- [Microsoft: Event ID 4769 documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [Microsoft: Detect and remediate RC4 usage in Kerberos](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos)
- [Microsoft: RC4 changes in 2026](https://techcommunity.microsoft.com/blog/coreinfrastructureandsecurityblog/what-changed-in-rc4-with-the-january-2026-windows-update-and-why-it-is-important/4504732)
- [Microsoft: Secure group managed service accounts](https://learn.microsoft.com/en-us/entra/architecture/service-accounts-group-managed)
- [Related guide: WPAD Security]({{ '/wiki/wpad-security/' | relative_url }})
