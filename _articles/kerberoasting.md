---
title: "Understanding and Detecting Kerberoasting"
description: "Investigate Kerberos service tickets, Windows Event ID 4769, and the significance of RC4 encryption."
category: active-directory
tags: [Red Team, Blue Team, Active Directory, Kerberos, Detection Engineering]
level: Intermediate
updated: "2026-10-17"
translation_url: /ko/wiki/kerberoasting/
---
## What is Kerberoasting?
Kerberoasting is a technique in which an authenticated domain user requests a Kerberos service ticket for an account associated with a Service Principal Name (SPN). The encrypted ticket material may then be examined offline to attempt password recovery. **Requesting a ticket and attempting to recover a password are separate steps.**

## Key Windows telemetry
Windows Security **Event ID 4769**, logged by a domain controller when a service ticket is requested, is an important source of evidence.

| Field | Meaning |
| --- | --- |
| Ticket Encryption Type | A value of 0x17 represents RC4-HMAC |
| Account Name | Account requesting the service ticket |
| Service Name | Target service/account |
| Client Address | IP address of the requesting client |

## Investigation approach
If an account requests many service tickets over a short period, especially tickets using RC4, investigate whether the activity fits the account's usual behavior.

1. Compare the ticket request volume against a normal baseline.
2. Identify legitimate applications and legacy services that still use RC4.
3. Review the source IP, requesting identity, and targeted service accounts.
4. Correlate authentication, process execution, and network events.

**An RC4 ticket request alone does not prove Kerberoasting.**

## Prevention and response
Reduce RC4 where supported, use strong service account passwords, and consider group Managed Service Accounts (gMSAs) where applicable.

## References
- [MITRE ATT&CK: Kerberoasting (T1558.003)](https://attack.mitre.org/techniques/T1558/003/)
- [Microsoft: Event 4769](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4769)
