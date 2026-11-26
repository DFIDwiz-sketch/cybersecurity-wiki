---
title: "BitLocker Recovery Evidence · Separate Key Read, Volume Unlock and Rotation"
description: "Correlate an Entra recovery read with Windows recovery evidence and confirm that a replacement protector was backed up."
category: blue-team
tags: [BitLocker, Windows, Microsoft Entra, Incident Response, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/windows-bitlocker-recovery-evidence/
---

A help desk opens a BitLocker recovery record for a laptop. Entra logs a read. The owner later reports that the laptop started. A defender needs three independent answers. Was a recovery secret disclosed? Was it used on the affected volume? Was the protector replaced and the replacement backed up?

## 1. Identify the volume, the protector and the record

**BitLocker** encrypts a Windows volume. A **key protector** controls how BitLocker's volume master key can be unlocked. A numerical recovery password is a 48-digit secret. The **recovery key ID** displayed for recovery is an identifier used to select the corresponding record. An ID alone cannot unlock the volume. Microsoft interfaces often use “recovery key” as the name of the record or secret. Record which meaning applies to each field.

A managed device can back up its recovery information to Microsoft Entra ID when configured. Other environments may use Active Directory Domain Services or a different approved backup method. Collect the source that actually holds the recovery information. A device display name can be reused, and device objects can change after re-enrollment. Link the tenant, stable device identity, volume and protector identifier before comparing evidence. A partial ID from a screen is a search aid until disambiguated.

| Source or action | What it supports | What to check next |
| --- | --- | --- |
| Recovery record metadata | A record with a particular ID exists in the queried store | Whether anyone accessed the secret and whether the protector is active |
| Successful Entra `Read BitLocker key` for that record | A successful recovery-key read was recorded | Whether the read was authorized, and outcome at the endpoint |
| Matching endpoint recovery evidence | Recovery of the observed volume under the recorded mechanism | Whether the old protector remains active and whether the replacement is backed up |
| Rotation action accepted | A management system accepted the action | Device execution, active replacement ID and backup confirmation |
| Old protector absent, replacement active, matching new backup | The tested device and backup store agree about the replacement | Other affected volumes or accounts and any residual risk |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/windows-bitlocker-recovery-evidence-en.svg' | relative_url }}" alt="Link the device, volume and protector identity. Check authorized backup-store access, endpoint recovery, and replacement and backup as separate evidence points." style="max-width: 100%; height: auto;">
  <figcaption>Figure 1. A read, a recovery and a verified replacement each require their own evidence.</figcaption>
</figure>

## 2. Follow a normal recovery

In a fictional organization, `LAB-WIN-01` prompts for recovery after a planned hardware service at 08:00 UTC. The help desk checks the owner, work order, device identity and recovery identifier. Entra logs an authorized, successful read of the matching record at 08:04. At 08:07 the endpoint investigation confirms that the expected volume recovered using that protector. If the source shows only that Windows booted, document “boot observed” and leave protector use uncertain.

After an approved rotation, the device reports an active replacement and the inventoried old protector is absent. The tenant holds the matching replacement record. A rotation request that is merely pending, or a new record with the old protector still present, is weaker evidence. Keep the old and new **identifiers** in authorized evidence. Do not attach passwords, recovery files, raw secret responses or screenshots showing the secret.

## 3. Distinguish support from misuse

If an unauthorized person obtains the recovery secret and also has access to the encrypted device or volume, they can use it for recovery. A successful read without a support record warrants investigation. Owner self-service, a documented help desk action or an authorized recovery test can produce the same access pattern. Review the initiating principal, role, ticket, device scope and timing. A read is useful even when there is no matching Windows event. Recovery could occur offline or outside retained logging. Conversely, a read alone establishes neither unlock nor file access.

Microsoft Graph v1.0 documents that a default BitLocker recovery object read excludes the secret property. A request selecting the actual secret triggers Entra auditing. The activity reference lists `Read BitLocker key` under `KeyManagement`. Treat successful secret read, failure to read, metadata-only observation and no collected audit as separate states. Do not infer exposure from generic inventory activity or expect this Entra activity for an on-premises-only backup path.

## 4. Collect, detect and respond

1. **Collect the administrative evidence.** In an authorized tenant with audit-reading access, filter Entra audit logs for `KeyManagement` and `Read BitLocker key`. Retain the UTC time, actor, target object or identifier, result, and relevant correlation details actually present. Use device inventory to map IDs rather than relying on names. Confirm audit retention and export scope before treating an event as absent. Correlate the account's sign-ins and authorization at that time with the support ticket. Repeated reads across unrelated devices or outside a support window are leads for review.
2. **Collect endpoint evidence separately.** On the authorized Windows device with the BitLocker PowerShell module and permission, the following command selects volume and protection status only. It describes the current state. For historical evidence, inspect retained BitLocker-API Management and Operational logs, boot or TPM records, and approved recovery notes. Match the device, volume, time and protector where the logs expose it. Local evidence may be unavailable during recovery. Keep that limitation in the case record.

~~~powershell
Get-BitLockerVolume |
  Select-Object MountPoint, VolumeStatus, ProtectionStatus
~~~

3. **Verify replacement securely.** Intune documents prerequisites for remote rotation, including supported Windows and managed policy. An accepted device action is an administrative checkpoint. Check the managed endpoint's protector inventory, the expected volume state, the old protector's absence and the matching replacement metadata in the backup store. Coordinate actions with the device owner and preserve access to the recorded recovery path.
4. **Respond according to the confirmed evidence.** If exposure is confirmed or suspected, preserve evidence and coordinate rotation and account or device response under the incident plan. If a device was actually recovered, collect separate endpoint or resource evidence for any claim about accessed data. Label missing telemetry rather than substituting assumptions.

## 5. Authorized offline exercise

Save the <a href="{{ '/assets/labs/windows-bitlocker-recovery-evidence.py' | relative_url }}" download>Python checker</a> and <a href="{{ '/assets/labs/windows-bitlocker-recovery-evidence.json' | relative_url }}" download>fictional cases</a> together. Run with Python 3 in an environment you own or are approved to use. The fixture has only synthetic protector and device labels plus normalized observations. It contains no secret values and the checker never contacts a tenant or device.

~~~bash
python3 windows-bitlocker-recovery-evidence.py
~~~

| Cases | Expected observations |
| --- | --- |
| A–C | Matched authorized read and recovery, metadata only, failed read |
| D–F | Successful read without confirmed recovery, mismatched device identity, and accepted rotation without confirmation |
| G–J | Verified replacement, wrong backup ID, old protector still recorded, and no backup evidence |

Expect `10/10 cases matched.` To run the negative control, use a copy of the JSON and change case G's `rotation.backup_id` from `new-lab-id` to `unrelated-id`. Keep the expected output, and pass the copy's filename. G should report `backup-id-mismatch` for rotation and the script should exit 1. If startup fails, verify both files are present and that the JSON is intact. The offline exercise was executed. Windows, Intune and Entra product behavior was reviewed in documentation.

## 6. Check your reasoning

1. **A record exists in Entra. Did an administrator read the secret?** An inventory record proves existence. Check the activity and result in the relevant audit source.
2. **A read succeeded. Did anyone unlock the disk?** Confirm the specific volume and recovery mechanism at the endpoint or in trusted support evidence.
3. **A rotation command was accepted. Can you close the exposure finding?** Confirm a replacement is active, the old protector is absent from the affected volume, and the backup store has the matching replacement.
4. **Two devices share a name. Which one matches the recovery?** Use the tenant's stable device identity, volume and recovery identifier. Treat the name as a search hint.

**Completion criterion.** Reproduce the ten cases and the negative control. Classify one support timeline into read, use and rotation evidence and identify what remains unverified. Continue with [Entra sign-in evidence]({{ '/wiki/entra-signin-evidence/' | relative_url }}) and [Key Vault read evidence]({{ '/wiki/azure-key-vault-read-evidence/' | relative_url }}).

## Official references

Reviewed 2026-11-27. Scope is managed Windows BitLocker recovery, Microsoft Graph v1.0, Entra audit and current Intune documentation. Compare the device's Windows version, join state, backup service and managed policy with the guidance before using the workflow.

- [Microsoft · BitLocker recovery overview](https://learn.microsoft.com/en-us/windows/security/operating-system-security/data-protection/bitlocker/recovery-overview)
- [Microsoft Graph v1.0 · BitLocker recovery object](https://learn.microsoft.com/en-us/graph/api/resources/bitlockerrecoverykey?view=graph-rest-1.0) and [read behavior](https://learn.microsoft.com/en-us/graph/api/bitlockerrecoverykey-get?view=graph-rest-1.0)
- [Microsoft Entra · Audit activity reference](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/reference-audit-activities) and [Intune BitLocker management and rotation](https://learn.microsoft.com/en-us/intune/intune-service/protect/encrypt-devices)
- [Windows · Troubleshoot BitLocker](https://learn.microsoft.com/en-us/troubleshoot/windows-client/windows-security/bitlocker-issues-troubleshooting) and [Get-BitLockerVolume](https://learn.microsoft.com/en-us/powershell/module/bitlocker/get-bitlockervolume)
