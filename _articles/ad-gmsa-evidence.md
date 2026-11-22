---
title: "Active Directory gMSA Evidence · From Eligibility to Service Health"
description: "Distinguish managed-password eligibility, service logon, Kerberos ticket activity and workload evidence."
category: active-directory
tags: [Active Directory, gMSA, Service Accounts, Windows Logs, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /ko/wiki/ad-gmsa-evidence/
---

**Learning goal.** Follow a Windows service from Active Directory policy to host authentication and application health. Explain which evidence shows that a host became eligible to use a group Managed Service Account, and what would establish that it actually did.

## 1. Why use a managed service identity?

A **service account** is an identity used by a workload. A **group Managed Service Account (gMSA)** is a domain account whose password is managed by Active Directory and can be used by multiple approved hosts. This lets web or reporting servers share the intended service identity without operators distributing one manually managed password. The **Key Distribution Service (KDS)** supports password generation on domain controllers. The **retrieval policy** controls which principals can obtain the managed password. A **Service Principal Name (SPN)** maps a Kerberos service identity to its account where the application uses inbound Kerberos.

| Identity | Typical scope | Password responsibility |
| --- | --- | --- |
| Traditional domain account | As configured by the operator | Operator or external management system |
| Standalone MSA | One domain-joined server | AD-managed |
| Group MSA | Multiple approved domain-joined hosts | AD manages the password and authorized hosts retrieve it |

A gMSA does not grant access to the application's database or shares by itself. Its permissions and workload configuration must be reviewed separately. Confirm application support and deployment prerequisites for the specific Windows Server version. This chapter covers gMSA on supported Windows Server versions, with command references for Server 2025.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/ad-gmsa-evidence-en.svg' | relative_url }}" alt="Active Directory defines which principals are eligible. A target host records service logon and process evidence. Application or resource records confirm actual work.">
  <figcaption>Eligibility, service logon and completed work are separate conclusions.</figcaption>
</figure>

## 2. Follow a normal start

Two fictional servers, `REPORT01` and `REPORT02`, run a reporting service as `LAB\ReportSvc$`. Their computer accounts belong to a dedicated approved retrieval group. A configuration inventory lists both hosts and the service's intended account SID.

1. The administrator's recorded rollout associates the gMSA with the workload and grants retrieval permission to the dedicated group. Review direct principals and relevant nested membership. Verify the actual configuration using a timestamped directory view and the appropriate DC.
2. On `REPORT01`, the service requests a service logon. With success auditing enabled, Security event 4624, logon type 5, can show the gMSA's SID on that host. Confirm the service and matching process using its configured identity, process evidence and collection time. One identity can be shared by more than one service.
3. Independent application evidence shows the reporting service completed a known health operation. If a client also requests a Kerberos ticket to a service, DC event 4769 is evidence of the ticket request and its result. The requestor and target service are separate fields. A successful ticket request does not prove that the application ran or accepted the request.

## 3. Read changes and follow up

| Observation | What to verify next |
| --- | --- |
| Allowed principals changed on the gMSA | Check the object GUID, attribute, old and new state, actor, DC, time and change approval. Verify whether a new host became eligible. |
| A computer joined a retrieval group | Check the effective group path, approval and affected gMSAs. The gMSA's own retrieval attribute may remain unchanged. |
| Host passes `Test-ADServiceAccount` | The local readiness test succeeded at that time. Check actual service start, process owner and application health separately. |
| Unexpected 4624 type 5 | Verify the target SID, host, service configuration and process identity. Check maintenance and approved service migrations. |
| 4769 for the account's service | Confirm status and the target on the DC, and look for target-side evidence. The event is not a password retrieval audit. |

An overbroad retrieval group expands the number of systems that can use the identity. A compromised member or an unapproved change raises the risk of misuse. A change in membership is evidence about eligibility, not proof that anyone retrieved the secret. A normal rollout or stale inventory can also explain a new host. Separate temporary service failures caused by replication, host readiness, or configuration from actual use on an unexpected system.

1. **Scope the entitlement.** Record UTC time, object GUID and SID, relevant account and group IDs, the host inventory and the expected SPNs. Review the ACL that governs changes to the account and retrieval group. Do not collect managed password data.
2. **Check audit coverage.** On writable DCs, event 5136 can help investigate changes to `msDS-GroupMSAMembership` or `servicePrincipalName` when Audit Directory Service Changes and matching object SACLs are in place. Some attributes need different audit coverage. For changes to a domain security group's membership, collect Audit Security Group Management successes on DCs, such as 4728 for global or 4756 for universal group additions. Check the actual group scope. The absence of an event leaves coverage and retention questions open.
3. **Join the runtime evidence.** Collect 4624 from the target host with Audit Logon success enabled. Join the target SID, host, type, time and relevant process evidence. Collect DC 4769 only where Audit Kerberos Service Ticket Operations and the appropriate result coverage are configured. The 2025 security update changed the 4769 record on applicable servers, so verify fields from the collected XML before normalizing. Use service health, resource access or application records to confirm the effect you claim.
4. **Respond and verify.** For a confirmed unauthorized path, preserve approved snapshots and remove or contain access with the service owner under the incident change procedure. Check dependent services and coordinate credential recovery as appropriate. Verify effective eligibility and target workload health afterward. Do not assume a directory change immediately terminates existing sessions.

## 4. Read-only checks and offline lab

On an approved domain-joined Windows system with the ActiveDirectory PowerShell module, connectivity to an appropriate DC and delegated read rights, replace `ReportSvc` with your lab account. The first command queries directory metadata. Run the second only on the intended service host where the managed account has been configured. It tests local readiness without asserting that any service is running.

```powershell
Get-ADServiceAccount -Identity ReportSvc -Properties PrincipalsAllowedToRetrieveManagedPassword,ServicePrincipalNames |
    Select-Object Name,SID,PrincipalsAllowedToRetrieveManagedPassword,ServicePrincipalNames
Test-ADServiceAccount -Identity ReportSvc
```

If the query fails, check the module, identity, connected domain and read permissions. If the local test fails, verify local configuration, DC reachability and effective eligibility with the domain administrator. Use service and application evidence to diagnose a later startup failure. The Windows procedure was reviewed against documentation. It was not executed on a domain in this publication.

Download the <a href="{{ '/assets/labs/ad-gmsa-evidence.py' | relative_url }}" download="ad-gmsa-evidence.py">Python script</a> and <a href="{{ '/assets/labs/ad-gmsa-evidence-cases.json' | relative_url }}" download="ad-gmsa-evidence-cases.json">fictional cases</a> to an approved workspace. The fixture is normalized and already scoped to one account and observation. It models evidence decisions, not the Windows permission engine. The script reads only a local file.

```bash
python3 ad-gmsa-evidence.py ad-gmsa-evidence-cases.json
```

```text
healthy_service: service_outcome_confirmed
policy_change: eligibility_changed_usage_unproven
group_change: eligibility_changed_usage_unproven
readiness_only: readiness_only
ticket_only: ticket_activity_only
unexpected_logon: unexpected_host_logon
incomplete_join: service_logon_only
```

The seven cases were executed. If a file cannot be opened, check the directory and filenames. If a result differs, check the host and SID keys first. In the last case the service logon is observed, but the supplied health record belongs to a different process and cannot confirm the service result.

## 5. Check your reasoning

- **A machine was added to a nested retrieval group. Did it use the identity?** Verify effective eligibility and then obtain host or resource evidence of use.
- **The readiness test returned true. Did the report finish?** Look for service process evidence and an independent result tied to the same host, SID and process.
- **The DC issued a service ticket. Did the reporting host retrieve the password?** The event concerns Kerberos ticket activity. Investigate the separate entitlement and host evidence.

Finish when all seven outcomes match and you can name the evidence needed for eligibility, service logon and workload success.

## Official references

Reviewed November 23, 2026. Microsoft documents gMSA management for Windows Server 2016 through 2025. Interpret older audit examples according to the event versions and policies in the environment.

- [Microsoft gMSA management](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/group-managed-service-accounts/group-managed-service-accounts/manage-group-managed-service-accounts) · [gMSA membership attribute](https://learn.microsoft.com/en-us/windows/win32/adschema/a-msds-groupmsamembership)
- [Get-ADServiceAccount](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adserviceaccount?view=windowsserver2025-ps) · [Test-ADServiceAccount](https://learn.microsoft.com/en-us/powershell/module/activedirectory/test-adserviceaccount?view=windowsserver2025-ps)
- [Advanced audit policy](https://learn.microsoft.com/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration) · [Event 5136](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136) · [Event 4624](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4624) · [Event 4769](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769)

[Previous · Active Directory fundamentals]({{ '/wiki/active-directory-fundamentals/' | relative_url }}) · [Next · Windows service runtime]({{ '/wiki/windows-service-runtime-evidence/' | relative_url }}) · [Related · Kerberos authentication]({{ '/wiki/kerberos-authentication/' | relative_url }})
