---
title: "Active Directory Replication Evidence · Trace an Attribute Change"
description: "Compare an attribute’s value, version, origin, local USN and Security 5136 across domain controllers."
category: active-directory
tags: [Active Directory, AD DS, AD Replication, Domain Controller, Windows Logs, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/ad-replication-change-evidence/
---

Two domain controllers can report different values for the same directory object. Often they have seen different points in a legitimate change. Start by identifying exactly which object, attribute, server and time each source describes. This chapter investigates one ordinary replicated, single-valued AD DS attribute on writable DCs.

## 1. How a write becomes a replicated value

A **domain controller (DC)** hosts replicas of directory partitions. A **partition**, or naming context, is a portion of the directory replicated to the servers that host it. A write to a writable DC is an **originating update**. Other replicas can receive the change through their replication partners. **Convergence** means the relevant replicas have settled on the same state. It takes time, particularly across sites with different replication schedules.

A replicated attribute has **metadata** about its latest originating update. A **USN**, or update sequence number, comes from a DC’s local update sequence. The originating USN identifies the update in the originating database’s sequence. The **invocation ID** identifies that database incarnation and can change after supported recovery operations. The local USN records where the queried DC applied the update in its own sequence. Values such as 48,200 and 91,100 from different local sequences cannot rank replicas by freshness.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/ad-replication-change-evidence-en.svg' | relative_url }}" alt="An approved write on DC A can produce audit evidence and a new attribute stamp. DC B later receives the same originating stamp with its own local USN. Independently collect values and metadata from both DCs.">
  <figcaption>Audit evidence describes the write, while metadata and the value observed on each replica describe its current state.</figcaption>
</figure>

## 2. Follow a normal change

In this fictional example, an administrator updates the `description` of a training computer at 09:00 UTC. The write goes to `dc-a.ad.example`. Security 5136 on that DC records the change under the configured audit scope. An observed replacement can produce a Value Deleted and a Value Added event. At 09:01 DC A shows version 4, originating invocation `inv-a1` and originating USN 48,200. DC B still shows version 3. At 09:04 DC B reports the same version 4, originating time, invocation and originating USN as DC A. Its local USN is 91,100. The matching attribute value and originating fields support convergence for these two observations.

| Evidence | Use and limit |
| --- | --- |
| Object GUID and attribute LDAP display name | Link observations of the same object and field. A distinguished name gives location and can change after a move or rename. |
| Version and originating time | Identify a revision and the time assigned at its origin. Replication of that update does not increment its version or timestamp. |
| Origin invocation ID and USN | Distinguish the origin of updates with equal versions. Compare originating USNs only in the same invocation’s sequence. |
| Local USN | Helps describe the application of the change on the queried DC. Local USNs are scoped to that replica. |
| 5136 and the attribute value | An appropriately audited write and the value at collection are independent observations. The latest value can differ from an earlier logged write. |
| Inbound partner status | Operational replication evidence scoped to a DC, partner and partition. Check the object even when partner status indicates success. |

Equal version numbers alone are weak evidence. Parallel originating writes can have equal versions with different origins. AD uses an attribute stamp comparison, including version, originating time and invocation ID, to resolve conflicts. The latest observed stamp is no substitute for retained audit history. This chapter excludes per-value linked attributes such as group `member`. Gather linked-value metadata and group change evidence when investigating individual memberships.

## 3. Separate delay, collection error and unauthorized change

Check whether both observations point to the same object GUID and attribute, whether both DCs host the relevant partition, and whether they were queried close enough together. A failed or unauthorized read leaves the state unknown. A stale replica may follow ordinary intersite timing, a broken partner connection or a recent recovery. If the same origin fields appear alongside different captured values, repeat the read with timestamps and check normalization and whether a write occurred between the value and metadata queries.

An improperly delegated account can change attributes outside its intended role. Review the approved change and effective permissions on the object or OU, and preserve the actor recorded by the origin DC. When 5136 is present, group compatible records by source DC, correlation ID, object GUID and attribute to reconstruct a replacement. The same correlation ID can cover other modifications in the operation. The logged subject can be a service or automation account. Trace its initiating workflow with independent evidence before attributing the change to a person.

## 4. Collect and validate on authorized systems

1. Write down the forest, partition, object GUID, attribute, approved change window and relevant DCs. Use synchronized UTC times, and store the exact DC queried and whether each read succeeded.
2. Compare the value and metadata on the originating and another relevant writable DC. Preserve the original output. These reads are separate queries, so record their times and repeat if the state changes between them.
3. Collect original Security records from the appropriate DCs. Event 5136 requires successful **Audit Directory Service Changes** auditing and a matching write **SACL** on the object or attributes. Preserve object GUID, attribute, operation, subject, correlation ID, DC and event time. If missing, verify audit policies, SACLs, retention and forwarder coverage. The receiver of replication need not provide the original write’s audit history.
4. Check replication partner health for the same partition and DC. Correlate error text, affected sites, transport and the last successful replication with the collection window. Escalate persistent discrepancies to AD administrators. Preserve evidence before coordinated remediation and repeat the same scoped reads afterward.

On an approved Windows system with the ActiveDirectory PowerShell module, authorized read access and connectivity to the named DCs, these queries read the chosen non-sensitive attribute and its metadata. Substitute your own lab DCs and object GUID. The current value and metadata results are separate. The open specifications explain the originating and local fields represented in the output.

```powershell
$objectId = [guid]'11111111-2222-4333-8444-555555555555'
foreach ($dc in 'dc-a.ad.example', 'dc-b.ad.example') {
  $obj = Get-ADObject -Identity $objectId -Server $dc -Properties description -ErrorAction Stop
  [pscustomobject]@{
    DC = $dc
    ObservedUtc = [datetime]::UtcNow
    ObjectGUID = $obj.ObjectGUID
    Description = $obj.Description
  }
  Write-Output "Metadata read started UTC: $([datetime]::UtcNow.ToString('o'))"
  Get-ADReplicationAttributeMetadata -Object $obj -Server $dc -Properties description -ErrorAction Stop |
    Format-List *
}
```

If one query fails, save the error then check object scope, connectivity and permissions before repeating. For inbound partner status use `Get-ADReplicationPartnerMetadata` with the destination DC and relevant partition. The commands were reviewed against Microsoft documentation. Live AD DS and PowerShell execution were outside this exercise.

## 5. Offline exercise · compare eight fictional pairs

Save the <a href="{{ '/assets/labs/ad-replication-change-evidence.py' | relative_url }}" download="ad-replication-change-evidence.py">Python script</a> and <a href="{{ '/assets/labs/ad-replication-change-evidence-cases.json' | relative_url }}" download="ad-replication-change-evidence-cases.json">fictional JSON</a> in the same directory and run Python 3 in your own approved workspace. Each pair is pre-scoped to one training forest, and each record contains a replica, object, attribute and read outcome. The script checks scope, the originating fields and a fictional value reference. It neither queries AD nor simulates conflict resolution.

```bash
python3 ad-replication-change-evidence.py ad-replication-change-evidence-cases.json
```

```text
converged: same_update_and_value
pending: version_difference
competing_writes: same_version_different_origin
read_denied: observation_missing
other_object: scope_mismatch
other_attribute: scope_mismatch
same_stamp_different_value: recheck_value_capture
incomplete_stamp: metadata_missing
```

Two converged observations deliberately have different local USNs. A version difference alone gives no cause. A read failure should stay unknown. If you cannot open the file, check both filenames and the current folder. For an unexpected result compare object ID, attribute, observed fields and originating identity. Python execution was verified on the fictional data.

## 6. Check your understanding

- **DC B has the larger local USN. Is it newer?** Local USNs are meaningful in the local sequence. Compare the originating fields and actual value for the same object and attribute.
- **Both DCs have version 4. Can you call them converged?** Check originating metadata and the value. Two originating writes can have the same version.
- **The object was modified but no 5136 is available. Was there no change?** Check auditing, the SACL, which DC handled the write and retention. A metadata comparison can corroborate state without identifying the actor.

Finish when all eight results match and you can identify the next source for `pending`, `read_denied` and `same_stamp_different_value`.

## Official references

Reviewed 2026-11-22. The cmdlets referenced use the Windows Server 2025 view. The 5136 reference contains a historical Windows 10-format example. Verify coverage and fields on the DC builds you operate.

- Replicated attribute metadata and conflict ordering. [Microsoft MS-DRSR · AttributeStamp](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-drsr/2973bb80-c8ed-450d-a981-59639e09820b) · [Microsoft MS-ADTS · Attribute metadata blob](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/63fabec7-cb4b-47ed-ab45-9a20e4397d55)
- Audit requirements and correlation. [Microsoft Learn · Event 5136](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5136)
- Scoped object and metadata queries. [Get-ADObject](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adobject?view=windowsserver2025-ps) · [Get-ADReplicationAttributeMetadata](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationattributemetadata?view=windowsserver2025-ps)
- Partner metadata and replication failures. [Get-ADReplicationPartnerMetadata](https://learn.microsoft.com/en-us/powershell/module/activedirectory/get-adreplicationpartnermetadata?view=windowsserver2025-ps) · [Microsoft Learn · Diagnose AD replication failures](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/diagnose-replication-failures)

[Previous · Active Directory fundamentals]({{ '/wiki/active-directory-fundamentals/' | relative_url }}) · [Next · Group Policy application evidence]({{ '/wiki/gpo-application-evidence/' | relative_url }})

To scope the computer object and client attempt before reviewing replication, see [Active Directory domain join evidence]({{ '/wiki/ad-computer-domain-join-evidence/' | relative_url }}).
