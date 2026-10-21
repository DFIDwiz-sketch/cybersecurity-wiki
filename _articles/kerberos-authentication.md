---
title: "Kerberos Authentication: AS-REQ, TGT, TGS, SPN, PAC, Detection and Defense"
description: "A comprehensive Windows AD Kerberos V5 guide to ticket flows, keys, SPNs, PACs, delegation, Windows Events 4768/4769/4771, Splunk detection and troubleshooting."
category: active-directory
tags: [Windows Security, Active Directory, Kerberos, Authentication, TGT, TGS, SPN, PAC, NTLM, Kerberoasting, Blue Team, Red Team, DFIR, Splunk, Detection Engineering, MITRE ATT&CK]
level: Intermediate
updated: "2026-10-21"
translation_url: /ko/wiki/kerberos-authentication/
---

> **Prerequisite:** Start with [Active Directory Fundamentals]({{ '/wiki/active-directory-fundamentals/' | relative_url }}) for domains, DCs, DNS and access control. All account names and hostnames are illustrative. Use diagnostics only on systems that you administer or are authorized to assess.

## 1. What is Kerberos authentication?

**Kerberos V5** is a network authentication protocol built around a trusted **Key Distribution Center (KDC)**. Rather than transmitting a user's plaintext password to every application server, clients acquire and present cryptographically protected **tickets** to authenticate.

Windows Active Directory Domain Services uses Kerberos as a principal domain authentication mechanism. It supports **single sign-on (SSO)** and **mutual authentication**. When user `john` opens `\\fileserver\Finance`, the SMB server may validate a Kerberos service ticket for its own service identity.

**Authentication is not authorization:** a validated ticket establishes an identity; share permissions, NTFS ACLs and the application's authorization rules still determine allowed operations.

### Why use Kerberos?

- Avoid repeated password presentation to every service.
- Enable a service to validate many tickets without contacting the DC for every request, subject to policy/PAC validation.
- Support mutual authentication when implemented and requested.
- Use session keys, timestamps, ticket lifetimes and replay protections.
- Transport Windows-specific authorization metadata including the PAC.

## 2. Twelve essential terms

| Concept | Role |
| --- | --- |
| **Principal** | An identity such as a user, machine or service |
| **Realm** | Kerberos authentication domain; generally maps to an AD domain in Windows |
| **DC / KDC** | Domain controller performing Kerberos ticket issuance |
| **AS** | Authentication Service portion of the KDC; establishes initial credentials and a TGT |
| **TGS** | Ticket Granting Service portion of the KDC; issues service tickets |
| **TGT** | Ticket Granting Ticket used when requesting service tickets |
| **Service ticket** | Ticket presented to a specific service; informally called a TGS ticket |
| **SPN** | Service Principal Name such as `cifs/fileserver` |
| **PAC** | Privilege Attribute Certificate with Windows authorization information |
| **Session key** | Ephemeral shared cryptographic key associated with a Kerberos exchange |
| **Authenticator** | Timestamp-based proof that the presenter possesses the relevant session key |
| **krbtgt** | Important domain account whose key protects TGTs |

The **AS and TGS are KDC functions**, not necessarily separate servers. Both commonly run on the same domain controller.

## 3. The complete AS → TGS → AP exchange

![Kerberos AS-REQ AS-REP TGS-REQ TGS-REP AP-REQ AP-REP sequence]({{ '/assets/diagrams/kerberos-exchange-en.svg' | relative_url }})

| Phase | Typical messages | Purpose |
| --- | --- | --- |
| **AS exchange** | AS-REQ → AS-REP | Initial authentication and TGT acquisition |
| **TGS exchange** | TGS-REQ → TGS-REP | Service-specific ticket acquisition |
| **AP exchange** | AP-REQ → optionally AP-REP | Present the ticket to the actual service; mutual authentication if negotiated |

Kerberos communication with the KDC generally uses **TCP/UDP 88**. However, **AP-REQ travels within the application's authentication exchange**, such as SMB or HTTP, and does not necessarily traverse port 88.

This diagram shows **a fresh ticket exchange**. A cached valid TGT or service ticket can remove the need for some of these steps.

## 4. Step one: AS-REQ and AS-REP

Consider a new password-based sign-on (smart cards, certificates, Windows Hello for Business or cached credentials can change the actual exchange).

1. A workstation locates a KDC through DNS/DC Locator.
2. It sends an **AS-REQ**. A common password-based preauthentication method includes a timestamp protected using a key derived from the user's password.
3. The KDC checks account details, the proof of key possession, time and applicable policies.
4. The KDC responds with an **AS-REP**, containing a **TGT protected using the krbtgt key** and a client-readable encrypted portion that conveys the **client–TGS session key**.
5. The client caches the TGT and the related session key.

**Crucial distinction:** It is **incorrect** to say that the TGT itself is simply encrypted with the user's password. In ordinary AD, **the TGT is protected with the krbtgt account key**, while the user's key protects parts of the AS response the client needs to decrypt.

### Kerberos preauthentication and AS-REP Roasting

Preauthentication helps the KDC verify that an applicant possesses the expected key *before* sending a ticket response. Disabling **Do not require Kerberos preauthentication** may expose material that permits **AS-REP Roasting (T1558.004)**—offline password guessing against vulnerable accounts.

**Event 4768 with PreAuthType=0 is not conclusive proof of an attack.** Check the account's configuration, authentication mechanism and other telemetry.

## 5. Step two: TGS-REQ and TGS-REP

User `john` next accesses `\\fileserver\Finance`:

1. The client resolves the target service's SPN, such as `cifs/fileserver.corp.example.com`.
2. It sends a **TGS-REQ** containing evidence based on its cached **TGT and authenticator**.
3. The KDC checks the ticket, service identity and relevant policies.
4. The **TGS-REP** contains a **service ticket encrypted for the target service account** plus session key material usable by the client.
5. The client uses the service ticket to authenticate to the file server.

On the DC, **Windows Security Event 4769** is a major source of evidence for the ticket request.

**An application connection does not always cause a new Event 4769.** Cached service tickets can be reused within their valid lifetime.

## 6. Step three: AP-REQ and AP-REP

During an SMB or other service connection, the client presents the **AP-REQ**. The server uses its service key to decrypt/validate the ticket, derive the service session key and check the authenticator's time/replay requirements.

If mutual authentication is requested and supported, the server returns an **AP-REP**. It then determines **authorization** from its ACLs and application access rules.

Do not confuse the traffic to a KDC on port 88 with the **application exchange** on TCP 445, HTTPS or another application transport.

## 7. TGT versus service ticket: keys and contents

![TGT krbtgt key, service ticket service key and PAC concept]({{ '/assets/diagrams/kerberos-tickets-en.svg' | relative_url }})

| Property | TGT | Service ticket |
| --- | --- | --- |
| Issued during | AS exchange | TGS exchange |
| Presented to | KDC's TGS | Target application service |
| Principal ticket-protection key | **krbtgt account key** | **Target service/computer account key** |
| Purpose | Request further tickets | Authenticate to a particular service |
| Abuse examples | Golden Ticket, stolen TGT | Kerberoasting, Silver Ticket, stolen service ticket |

An **AS client–TGS session key** and **TGS client–service session key** are different from the account's long-term ticket-encryption key.

Likewise, **TicketEncryptionType**, **SessionKeyEncryptionType** and **PreAuthEncryptionType** are different fields in updated Windows logs. Do not interpret one as another.

## 8. SPNs: mapping service names to accounts

An **SPN (Service Principal Name)** identifies the service for which a ticket is requested. Windows maps that SPN to a user, computer account or managed service account.

| Service | Illustrative SPN |
| --- | --- |
| SMB | `cifs/fileserver.corp.example.com` |
| HTTP | `HTTP/intranet.corp.example.com` |
| SQL Server | `MSSQLSvc/sql01.corp.example.com:1433` |
| Host-based service | `HOST/server01.corp.example.com` |

If the SPN points to the **wrong account**, the real service may lack the key required to decrypt the ticket. Symptoms include **KRB_AP_ERR_MODIFIED**, service logon failure or unexpected NTLM use. Missing or duplicate SPNs can also break ticket issuance.

### Read-only SPN diagnostics

```cmd
setspn -L FILESERVER$
setspn -Q cifs/fileserver.corp.example.com
setspn -X
```

The last command is useful for checking duplicate SPNs. Accessing SMB by literal IP address (e.g. `\\192.0.2.10\share`) may disrupt the expected SPN choice, although explicitly configured IP-based SPNs can work in some environments. "Kerberos never works with IP addresses" is too absolute.

## 9. The PAC and authorization

The Windows **Privilege Attribute Certificate (PAC)** is Kerberos authorization-related information which can contain group SIDs and other account/authorization data.

A PAC is **not** a list of passwords and **does not by itself grant permission** to every resource. Ticket signatures, PAC validation behavior and the resource server's ACL/policy checks matter.

A stolen **krbtgt secret** can enable **Golden Ticket (T1558.001)** attacks involving forged TGTs. A stolen **service-account key** can enable **Silver Ticket (T1558.002)** attacks involving forged service tickets. Their privileges, dependencies and observable KDC events are not identical.

## 10. Encryption types and the 2026 RC4 changes

| Ticket etype | Algorithm | Security relevance |
| --- | --- | --- |
| **0x17** (decimal 23) | RC4-HMAC | Legacy; relatively cheap to attack with offline password guessing |
| **0x11** (decimal 17) | AES128-CTS-HMAC-SHA1-96 | Stronger than RC4, but weak account passwords remain a risk |
| **0x12** (decimal 18) | AES256-CTS-HMAC-SHA1-96 | Stronger than RC4, but account/key hygiene remains critical |
| 0x1 / 0x3 | DES | Obsolete, not appropriate for modern deployments |

Microsoft implemented Kerberos RC4 default-behavior updates with **January 2026 audit/preparation**, **April 2026 AES-oriented defaults**, and **July 2026 final enforcement** for changes associated with CVE-2026-20833.

On **July 2026-patched domain controllers**, the previous implicit assumption of RC4 support for service accounts with no explicit encryption-type configuration is no longer valid. Explicit RC4 configurations, actually available service-account keys, relevant policy and patch levels still matter.

**Detection implication in 2026:** Monitoring *only* tickets with `0x17` misses unusual AES ticket activity. Detect abnormal service-ticket request patterns across **all encryption types**, and separately investigate unexpected RC4 dependencies.

Official resources: [Microsoft Windows Release Health](https://learn.microsoft.com/en-us/windows/release-health/windows-message-center/) and [Detect and remediate RC4 usage](https://learn.microsoft.com/en-us/windows-server/security/kerberos/detect-remediate-rc4-kerberos).

## 11. Caching, lifetimes, clock skew and SSO

Clients store TGTs and service tickets in a **ticket cache**, enabling SSO without obtaining fresh credentials for every access.

Ticket lifetimes are controlled by domain and authentication policies. A common configuration permits approximately **five minutes of clock skew**, but the actual tolerance is policy dependent.

### Read-only diagnostic commands

```cmd
klist
klist tgt
w32tm /query /status
w32tm /query /source
```

`klist` displays tickets for the relevant visible logon session, not automatically all identities and all service sessions on the machine. Check DNS, KDC reachability and clock synchronization before clearing caches or changing service passwords.

## 12. Kerberos versus NTLM

| Attribute | Kerberos | NTLM |
| --- | --- | --- |
| Core mechanism | Tickets issued through a KDC | Challenge–response |
| Server identity | Supports mutual authentication | Not equivalent default mutual service authentication |
| Dependencies | DNS, SPNs, time, reachable KDC | NTLM settings and credential validation |
| Threats | Roasting, ticket theft/forgery | Relay, Pass-the-Hash, captured NetNTLM responses |
| Best practice | Prefer where supported | Reduce legacy dependency after compatibility testing |

An application might fall back from Kerberos to NTLM because of SPN errors, IP-based connection names or legacy service configuration. **Fallback is not universally supported or guaranteed**, especially if NTLM is restricted by security policy.

## 13. Delegation and the double-hop problem

Suppose a user signs into a front-end web app, which must access a back-end SQL service **as that user**.

- **Unconstrained delegation:** Broad delegation of authentication is high-risk if the front-end host is compromised.
- **Constrained delegation (KCD):** Limits which back-end services may receive delegated access.
- **Resource-based constrained delegation (RBCD):** The back-end resource specifies which front-end principals may delegate to it.
- **S4U2Self and S4U2Proxy:** Kerberos extensions supporting a service's user-context and backend-ticket scenarios.

Delegation requires careful review of both **delegation configuration and who can modify its AD objects**. RBCD can be misused if an attacker obtains inappropriate write access to a resource's account object.

## 14. Common Kerberos attack mechanisms

| Technique | Preconditions and core idea | MITRE |
| --- | --- | --- |
| **Kerberoasting** | Request a service ticket and attempt offline password recovery from service-key-protected material | [T1558.003](https://attack.mitre.org/techniques/T1558/003/) |
| **AS-REP Roasting** | Offline guessing using responses from accounts with preauthentication disabled | [T1558.004](https://attack.mitre.org/techniques/T1558/004/) |
| **Golden Ticket** | Forge a TGT after compromising the krbtgt key | [T1558.001](https://attack.mitre.org/techniques/T1558/001/) |
| **Silver Ticket** | Forge a service ticket after compromising the service account key | [T1558.002](https://attack.mitre.org/techniques/T1558/002/) |
| **Pass-the-Ticket** | Reuse a stolen valid ticket within another authentication context | [T1550.003](https://attack.mitre.org/techniques/T1550/003/) |

These are different techniques. **An Event 4769 proves a TGS request, not successful Kerberoasting or privilege escalation.** Offline password guesses do not produce ordinary DC password failure events. In some Silver Ticket scenarios, a forged service ticket can be presented without requesting a new one from the DC, so a new 4769 may be absent.

## 15. Important Windows events and fields

![Kerberos Windows Security 4768, 4769 and 4771 triage workflow]({{ '/assets/diagrams/kerberos-telemetry-en.svg' | relative_url }})

| Event | Typical location | Investigation value |
| --- | --- | --- |
| **4768** | DC Security | TGT requested |
| **4769** | DC Security | Service ticket requested |
| **4771** | DC Security | Kerberos preauthentication failed |
| **4772 / 4773** | DC Security | Other Kerberos ticket request failure telemetry, depending on configuration |
| **4624** | Target host Security | Successful logon; Type 3 is common for network access |
| **4625** | Target host Security | Failed logon |
| **4672** | Logon host | Special privileges assigned during logon |

| Field | Meaning |
| --- | --- |
| `TargetUserName` / Account Name | Requesting identity |
| `IpAddress` / Client Address | Requester's IP, sometimes `::ffff:192.0.2.10` |
| `ServiceName` | In 4769 often denotes the **underlying service account**, not always the full SPN string |
| `Status` / Failure Code | Outcome; `0x0` generally indicates success |
| `TicketEncryptionType` | Encryption of the issued **ticket** |
| `SessionKeyEncryptionType` | Encryption of the **session key**, a separate attribute |
| `PreAuthType` | Method of initial preauthentication |
| `ServiceSupportedEncryptionTypes` / `ServiceAvailableKeys` | Target account crypto settings and available keys (updated format) |
| `ClientAdvertizedEncryptionTypes` | Algorithms offered by client (updated format) |

**Windows updates from January 2025 onward expanded 4768/4769 encryption fields**. Missing fields may reflect the OS patch level or parsing/sourcetype differences rather than malicious evasion.

### Selected Kerberos errors

| Code | Meaning | Typical lead |
| --- | --- | --- |
| `0x0` | Success | Check actual ticket and later service activity |
| `0x6` | KDC_ERR_C_PRINCIPAL_UNKNOWN | Unknown client principal |
| `0x7` | KDC_ERR_S_PRINCIPAL_UNKNOWN | Unknown service/SPN |
| `0x18` | KDC_ERR_PREAUTH_FAILED | Bad secret or preauthentication failure |
| `0xE` | KDC_ERR_ETYPE_NOSUPP | Client/service/KDC crypto mismatch |
| `0x25` | KRB_AP_ERR_SKEW | Clock skew too large |
| `0x29` | KRB_AP_ERR_MODIFIED | Server could not decrypt/validate ticket; investigate SPN/service key |

These are **Kerberos protocol error codes**, not guaranteed entries in the same Windows event field. Some appear on service hosts or in protocol troubleshooting rather than the DC's Security log.

## 16. Splunk: build detection from actual events

These searches are **templates**, not production-ready detections. Confirm DC Security ingestion, index, sourcetype, field extraction, time range and expected ticket activity before setting alerts.

### A. Confirm KDC event availability

```spl
index=* (EventCode=4768 OR EventID=4768 OR EventCode=4769 OR EventID=4769 OR EventCode=4771 OR EventID=4771)
| stats count by host sourcetype EventCode EventID
| sort - count
```

### B. Examine source IPs producing preauthentication failures

```spl
index=* (EventCode=4771 OR EventID=4771)
| eval requester=coalesce(TargetUserName,Account_Name,user)
| eval src=coalesce(IpAddress,Client_Address,src_ip)
| eval code=coalesce(Status,Failure_Code)
| bin _time span=10m
| stats count as failures dc(requester) as users values(code) as codes
        by _time src
| sort - failures
```

Some failures arise from stale credentials, configuration or time problems rather than deliberate attacks.

### C. TGS collection burst across all encryption types

```spl
index=* (EventCode=4769 OR EventID=4769)
| eval requester=coalesce(TargetUserName,Account_Name,user)
| eval target=coalesce(ServiceName,Service_Name,service)
| eval src=coalesce(IpAddress,Client_Address,src_ip)
| eval etype=lower(tostring(coalesce(TicketEncryptionType,Ticket_Encryption_Type)))
| eval status=lower(tostring(coalesce(Status,Failure_Code)))
| where isnotnull(requester) AND isnotnull(target)
| where isnull(status) OR status="0x0" OR status="0"
| bin _time span=5m
| stats count as tickets dc(target) as distinct_target_accounts
        count(eval(etype="0x17" OR etype="23")) as rc4_tickets
        values(etype) as etypes values(target) as targets
        by _time requester src
| where tickets>=10 AND distinct_target_accounts>=5
| sort - distinct_target_accounts - tickets
```

**Important:** `dc(target)` usually counts distinct **backing service accounts**, not necessarily the count of SPN strings. **Five minutes, ten requests and five accounts are example thresholds**; tune to normal service operations and privileged targets.

### D. A single sensitive service account

```spl
index=* (EventCode=4769 OR EventID=4769)
| eval requester=coalesce(TargetUserName,Account_Name,user)
| eval target=coalesce(ServiceName,Service_Name,service)
| eval src=coalesce(IpAddress,Client_Address,src_ip)
| eval etype=coalesce(TicketEncryptionType,Ticket_Encryption_Type)
| search target="svc_sql"
| stats count as requests values(etype) as etypes
        min(_time) as first_seen max(_time) as last_seen
        by requester src
| convert ctime(first_seen) ctime(last_seen)
```

An attacker may request **only one ticket** for a valuable account. Do not rely only on broad request bursts, and do not automatically exclude AES tickets.

## 17. Read-only Windows and AD diagnostics

```cmd
whoami /all
klist
klist tgt
nltest /dsgetdc:corp.example.com
w32tm /query /status
setspn -X
```

```powershell
Resolve-DnsName -Type SRV "_kerberos._tcp.corp.example.com"

Get-ADUser -Identity "svc_sql" -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes |
  Select-Object SamAccountName,ServicePrincipalName
```

### Inventory accounts without Kerberos preauthentication

```powershell
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth |
  Select-Object SamAccountName,Enabled,DoesNotRequirePreAuth
```

AD queries need the **RSAT ActiveDirectory PowerShell module** and appropriate permissions. Avoid clearing caches or rotating secrets prematurely: changes may destroy useful evidence or disrupt production applications.

## 18. DFIR and troubleshooting playbook

**Fictional case:** `john` at `CLIENT01` requests tickets for 14 service accounts in five minutes, some using RC4.

1. **Validate:** Confirm the source is genuinely DC Security Event 4769 and distinguish successes from failures.
2. **Baseline:** Compare the identity, client IP and target mix to the previous week(s) and known management jobs.
3. **Map SPNs:** Identify the actual service account and applications behind the names; assess privilege and key age.
4. **Host evidence:** Inspect source endpoint process execution, directory lookups and authentication artifacts.
5. **Follow-on:** Correlate service-account logons (4624), privilege use (4672), SMB admin shares and remote services.
6. **Conclude precisely:** Separate **ticket issued**, **suspicious enumeration**, **possible password recovery**, and **confirmed misuse**.
7. **Respond:** Preserve evidence, investigate the source, coordinate service-account protection and compatible RC4 migration.

| Symptom | First checks |
| --- | --- |
| DC discovery fails | DNS SRV records, workstation resolver, DC Locator |
| Many 4771 events | Account/password/preauthentication source and clock |
| Kerberos falls back to NTLM | SPN, connection by IP, client/service policies |
| KRB_AP_ERR_MODIFIED | Duplicate/misplaced SPN, service account key mismatch |
| KDC_ERR_ETYPE_NOSUPP | AES key availability, 2026 RC4 policy, client compatibility |
| Ticket issued but share access denied | Resource/share/NTFS ACLs and application permissions |
| Service logon with no fresh 4769 | Cached ticket, DC visibility limits, service-side logging |

## 19. Practical hardening checklist

1. Use **gMSAs**, long random service-account secrets and least privilege.
2. Keep **Kerberos preauthentication** enabled except where compatibility is explicitly justified.
3. Prefer AES; audit and remediate outdated **RC4 dependencies** under current 2026 guidance.
4. Inventory SPNs, remove duplicates and fix incorrect service-account assignments.
5. Avoid **unconstrained delegation**. Review KCD/RBCD and directory-object write permissions.
6. Protect domain controllers and privileged accounts; apply credential protection where supported.
7. Centralize 4768, 4769 and 4771 and correlate with host/network activity.

### Quick knowledge checks

- Which account key encrypts an ordinary TGT? **krbtgt.**
- Which key protects a service ticket? **The target service or computer account's key.**
- Does 4769 prove a password was cracked? **No.**
- Does a missing new 4769 disprove a service connection? **No; the ticket might be cached.**
- Does `0x17` prove credential theft? **No; it is an RC4 ticket encryption type.**
- Is a valid ticket sufficient to read any file? **No; authorization is separate.**

## 20. Microsoft sources and related wiki articles

- [Microsoft: Kerberos Authentication Overview](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-authentication-overview)
- [Microsoft: Kerberos Subprotocols](https://learn.microsoft.com/en-us/windows/win32/secauthn/kerberos-subprotocols)
- [Microsoft: Authentication Service Exchange](https://learn.microsoft.com/en-us/windows/win32/secauthn/authentication-service-exchange)
- [Microsoft: Event 4768](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4768)
- [Microsoft: Event 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)
- [Microsoft: Kerberos troubleshooting](https://learn.microsoft.com/en-us/troubleshoot/windows-server/windows-security/kerberos-authentication-troubleshooting-guidance)
- [Microsoft: Kerberos constrained delegation](https://learn.microsoft.com/en-us/windows-server/security/kerberos/kerberos-constrained-delegation-overview)
- [Microsoft: Windows 2026 RC4 enforcement](https://learn.microsoft.com/en-us/windows/release-health/windows-message-center/)
- [MITRE ATT&CK: Kerberos ticket attacks](https://attack.mitre.org/techniques/T1558/)
- [Wiki: Active Directory Fundamentals]({{ '/wiki/active-directory-fundamentals/' | relative_url }})
- [Wiki: Kerberoasting deep dive]({{ '/wiki/kerberoasting/' | relative_url }})
- [Wiki: SMB security]({{ '/wiki/smb-security/' | relative_url }})

**Next suggested guide:** **NTLM Authentication and Attacks**—NTLMv1/v2, NetNTLM, NTLM Relay, Pass-the-Hash, Responder and Kerberos comparisons.
