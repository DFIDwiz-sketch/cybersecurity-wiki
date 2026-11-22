---
title: "Introduction to Windows Security Event Analysis"
description: "Learn to correlate authentication and process events when investigating Windows security incidents."
category: dfir
tags: [DFIR, Blue Team, Windows, Event Logs]
level: Beginner
updated: "2026-10-17"
translation_url: /ko/wiki/windows-logs/
---
## Important event IDs
- **4624:** Successful logon
- **4625:** Failed logon
- **4688:** Process creation (requires the appropriate auditing policy)
- **4769:** Kerberos service ticket request

Whether an event is recorded depends on the system's audit policy. Avoid drawing conclusions from a single event without corroborating evidence.

## Linux authentication investigation

[SSH, PAM and sudo logs with an offline timeline]({{ '/wiki/linux-auth-evidence/' | relative_url }})

## Verify Windows Event Forwarding Delivery

[Distinguish source, subscription, collector and SIEM gaps]({{ '/wiki/wef-delivery-evidence/' | relative_url }})

## Investigate Windows Security Group Changes

[Compare membership, logon and resource evidence without joining unrelated hosts]({{ '/wiki/ad-group-membership-evidence/' | relative_url }})

## Distinguish Share Checks from NTFS File Evidence

[Use eight synthetic cases to distinguish the share check from the access right used.]({{ '/wiki/smb-file-audit-evidence/' | relative_url }})

## Investigate Windows App Control Events

[Distinguish audit decisions, enforced blocks and related signature records.]({{ '/wiki/app-control-evidence/' | relative_url }})

## Investigate missing Windows events

[Windows Security log gaps]({{ '/wiki/windows-log-continuity/' | relative_url }}) · Distinguish clearing, retention, policy changes and delivery gaps.

## Reconstruct an RDP Session

Follow [RDP session evidence]({{ '/wiki/rdp-session-evidence/' | relative_url }}) to distinguish a disconnect, reconnect and logoff.

## Investigate Active Directory Account Lockouts

[Trace account lockout evidence]({{ '/wiki/ad-account-lockout-evidence/' | relative_url }}) · Correlate 4740 with earlier authentication failures and later locked-account rejections.

## Verify Windows service runtime

Follow [Windows Service Runtime]({{ '/wiki/windows-service-runtime-evidence/' | relative_url }}) to distinguish installation, startup state, process evidence and workload health.

## Investigate PowerShell script blocks

[PowerShell Script Block Evidence]({{ '/wiki/powershell-script-block-evidence/' | relative_url }}) explains how to reconstruct 4104 fragments and connect the text to process and outcome evidence.
