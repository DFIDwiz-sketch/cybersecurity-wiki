---
title: "Active Directory Domain Join · Computer Account Evidence"
description: "Distinguish computer account creation, existing-account reuse checks and a member's domain join result with nine offline evidence cases."
category: active-directory
tags: [Active Directory, Domain Join, Windows Logs, Domain Controller, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/ad-computer-domain-join-evidence/
---

A DC reports a new computer account named `LAB-PC07$`. The deployment queue still says the device failed to join. Before deciding which record is wrong, ask what the DC recorded, what the joining Windows client reported, and whether the device established its trust relationship later.

## 1. Separate the directory object from the device

A **computer account** is the AD DS object representing a machine identity. Its account name commonly ends in `$`. The object has a **SID** used for security decisions and an **objectGUID** used to identify the directory object. The **distinguished name** (DN) is its current directory path and can change after a move or rename. A **domain join** configures a Windows device to participate in the domain. The machine and domain maintain a trust relationship, which can be checked through the Netlogon **secure channel** on a domain member.

During a new online join, a DC may create a computer account as part of the request. Provisioning staff can instead create the object in advance, called **prestaging**. The endpoint then tries to reuse that object. Reuse security checks and AD write permissions are separate gates. After the join operation reports success, follow any required restart and verify the member's current trust. Changes in the directory, approval to reuse, a successful join operation and a working trust are separate observations.

<figure>
  <img src="{{ '/assets/diagrams/ad-computer-domain-join-evidence.svg' | relative_url }}" width="560" height="350" alt="The DC can create an object or find an existing one. Reuse can be allowed or blocked. The client reports the join result, and a member secure-channel check can corroborate current trust." />
  <figcaption>Collect directory events and client-side results separately, then connect the right object and attempt.</figcaption>
</figure>

| Source | What it supports | Collection and limits |
| --- | --- | --- |
| DC Security **4741 / 4742 / 4743** | Computer account created, changed or deleted. Read the subject and target SID separately. | Enable and collect successful **Audit Computer Account Management** on the relevant DCs. 4741 can be prestaging. 4742 can reflect ordinary password maintenance or an unlisted attribute. |
| DC Security **5137** | A directory object was created. For a computer, check `ObjectClass`, `ObjectGUID` and `ObjectDN`. | Requires **Audit Directory Service Changes** and matching creation auditing in the parent OU or container's **SACL**, which defines what to audit. It may record the same creation as 4741. |
| Joining client System, **Netjoin 4100 / 4101** | An existing account was found and reuse was allowed or blocked, respectively. Preserve the contacted DC, existing DN and error when present. | Confirm the provider and client. 4100 reports the reuse decision, even if a later join step fails. |
| Joining client `%windir%\debug\Netsetup.log` | The selected operation, intermediate steps and final status. Microsoft examples show `NetpDoDomainJoin` final status `0x0` for success and `0xaac` for blocked reuse. | Enabled by default. Match the attempt, domain and DC, and read the final operation status. An intermediate `0x0` does not establish overall success. |
| DC System, **Directory-Services-SAM 16998** | The DC rejected reuse during security validation. The event can supply the client, computer and owner SIDs. | Collect the DC's System channel on applicable hardened builds. Match it to client evidence. |
| After-join trust check | A successful test corroborates that this domain member has a working secure channel at test time. | Record host, domain, time and scope. It is a current check, separate from the historical join result. |

**Version context.** Microsoft began the account-reuse hardening with Windows updates dated **2022-10-11**. Later updates added a trusted-owner policy and updated DC validation. Microsoft removed support for the legacy `NetJoinLegacyAccountReuse` setting in updates from **2024-08-13**. Investigate applicable patch levels, object owner, permitted owner groups and the separate permissions on the target object. The documented owner policy names **trusted account owners**, and ordinary AD permissions are still evaluated. A policy designed for reuse does not govern creation of a new account.

## 2. Walk a normal sequence

In this fictional example, the deployment service creates `LAB-PC07$` in a staging OU at 08:45 UTC. DC-A records 4741 for the new SID. At 09:00 a technician joins the corresponding endpoint using the existing account. The client records Netjoin 4100 for the same DN and DC, then a final join status of `0x0`. A later secure-channel test succeeds on that member. The records support prestaging, permitted reuse, a successful join operation and later working trust, in that order.

Suppose a replacement device of the same name records 4101 and a final status of `0xaac`. This is evidence the security policy blocked reuse for that attempt. It can arise during approved reimaging when the owner or deployment identity differs from what the policy expects. In another case, 4100 followed by a nonzero final status means the reuse check allowed the operation to continue and a later step failed.

Computer account changes are security relevant because the directory makes decisions using machine identities. Broad creation rights or excessive control over existing accounts can allow unauthorized machine identities to enter an otherwise approved workflow. Unusual creation or changes outside the enrollment schedule are investigation leads. Routine management and automation can produce similar records.

## 3. Collect, correlate and respond

1. **Start with the client.** Export the System event and relevant `Netsetup.log` window before another retry. Record the managed asset identifier, host name, UTC time, target domain, contacted DC, existing DN and final status. Record whether the platform required a restart or was already joined. On an authorized **domain member** with connectivity and functioning Netlogon, `Test-ComputerSecureChannel -Verbose` is a diagnostic check without repair. Microsoft documents that this cmdlet can report false-positive errors on DCs. Document when it ran and whether it returned true.
2. **Establish the directory object's identity.** Export raw Security and optional System records from relevant DCs. Verify effective audit policy, SACLs where applicable, retention and forwarding. Match DC, time, subject SID and target SID, using `objectGUID` and DN from directory or 5137 evidence where available. Names can be reused after deletion or re-creation. Preserve target and subject separately even when their values match. A 4742 field of `-` does not rule out a change.
3. **Verify the approved workflow.** Compare the attempt with an approved enrollment ticket, asset identity, deployment server and operator records. Review both the domain's effective machine-account quota and who has delegated Create Computer Objects permission on relevant OUs. They are different avenues, and a tight quota alone leaves delegated rights intact. Microsoft recommends controlled, carefully delegated provisioning. For unexpected attributes or a different DC view, obtain authorized directory snapshots and inspect replication before concluding that a change is missing.
4. **Respond according to the finding.** For blocked but authorized deployment, send the owner the exact asset, DC, account identity, status and effective policy for remediation through change control. For unexplained machine identity changes, preserve the original events, object security information and tickets, then coordinate authorized containment. Verify the next approved join from client, DC and trust evidence. Treat a missing event as a coverage or unresolved evidence question until checked.

## 4. Offline defense validation

Use Python 3 in a directory you own or are explicitly authorized to use. Download <a href="{{ '/assets/labs/ad-computer-domain-join-evidence/ad-join-cases.csv' | relative_url }}" download="ad-join-cases.csv">ad-join-cases.csv</a>, save the code beside it as `review_join.py`, and run `python3 review_join.py`. The fixture uses invented rows. It makes no directory changes, creates no machine accounts and needs no network.

The fixture supplies `attempt` and `object_id` as keys already correlated by the exercise. They are not native event fields shared by all sources. The rows target `object-A` and the scoped client attempt is `LAB-PC07/run-1`. A real investigation must derive the match from independent records.

```python
import csv
from collections import defaultdict

expected = {
    "new-join": ("created", "unknown", "reported-success", False),
    "prestage": ("created", "unknown", "unknown", False),
    "reuse-ok": ("changed", "allowed", "reported-success", True),
    "reuse-blocked": ("unknown", "blocked", "reuse-policy-block", False),
    "allow-then-fail": ("unknown", "allowed", "other-failure", False),
    "routine-change": ("changed", "unknown", "unknown", False),
    "same-name-older-object": ("unknown", "unknown", "reported-success", False),
    "mismatched-client-and-retry": ("created", "unknown", "unknown", False),
    "removed": ("deleted", "unknown", "unknown", False),
}

def describe(rows):
    object_rows = [r for r in rows if r["object_id"] == "object-A"]
    directory = {r["event"] for r in object_rows if r["source"] == "dc-security"}
    dc_labels = {"4741": "created", "4742": "changed", "4743": "deleted"}
    directory_state = "+".join(dc_labels[e] for e in dc_labels if e in directory) or "unknown"

    member = [r for r in object_rows if (r["device"], r["attempt"]) == ("LAB-PC07", "run-1")]
    netjoin = {r["event"] for r in member if r["source"] == "client-system-netjoin"}
    reuse = {value for code, value in (("4100", "allowed"), ("4101", "blocked")) if code in netjoin}

    status = {r["value"].lower() for r in member
              if (r["source"], r["event"]) == ("client-netsetup", "final-status")}
    status_labels = {"0x0": "reported-success", "0xaac": "reuse-policy-block"}
    final = "unknown"
    if len(status) == 1:
        final = status_labels.get(next(iter(status)), "other-failure")
    elif len(status) > 1:
        final = "conflicting-status"
    channel = any((r["source"], r["event"], r["value"]) ==
                  ("post-join-check", "secure-channel", "true") for r in member)

    reuse_state = next(iter(reuse)) if len(reuse) == 1 else ("conflicting" if reuse else "unknown")
    return directory_state, reuse_state, final, channel

with open("ad-join-cases.csv", encoding="utf-8", newline="") as stream:
    cases = defaultdict(list)
    for row in csv.DictReader(stream):
        cases[row["case"]].append(row)

actual = {name: describe(rows) for name, rows in cases.items()}
assert actual == expected, f"Expected {expected!r}, got {actual!r}"
for name, result in actual.items():
    print(f"{name}: {result}")
```

**Expected results.** Nine cases pass. Creation alone does not establish a join. A permitted reuse can precede a failure, and a routine change does not establish reuse. A same-name older object and the wrong endpoint or retry do not supply matching evidence. The fourth result field means a matching positive secure-channel check was seen.

**Failure check.** In a copy of the CSV, change the `new-join` Netsetup row's device to `LAB-PC08`. The expected success for `LAB-PC07` becomes unknown, and the test must fail. Restore the original before rerunning. If Python cannot read the file, check the filename and working directory. The offline exercise and negative control were run in the cloud. Product events and the member diagnostic were reviewed against Microsoft documentation.

## 5. Check your understanding

1. **There is 4741 but no client record. Did the client join?** The DC recorded creation. It might have been prestaging. Find the client attempt and trust evidence.
2. **There is 4100 and the final status is nonzero. Which result is correct?** Both can be. Reuse was allowed and the overall operation failed at another point.
3. **The DN matches a 4743 from last month but the SID differs. Is it the same account?** A reused name or path does not identify the same object. Compare SID, GUID and creation chronology.

Complete the chapter when you can state the directory operation, reuse decision, exact client's final result and current trust finding, along with any unresolved evidence.

## Official references

Reviewed **2026-11-27** for supported Windows domain members and Windows Server AD DS. The hardening chronology is scoped to the Windows update dates in KB5020276. Older event reference pages document field layouts. Validate them against the XML from your own Windows builds.

- [Microsoft Support · KB5020276 Domain join hardening](https://support.microsoft.com/en-us/servicing/os/windows/2022/10/kb5020276-netjoin-domain-join-hardening-changes)
- [Microsoft Learn · AD domain join permissions](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/active-directory-domain-join-permissions)
- [Microsoft Learn · Domain join log analysis](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/domain-join-log-analysis)
- [Microsoft Learn · Advanced audit policy](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/plan/security-best-practices/advanced-audit-policy-configuration)
- [Microsoft Learn · Computer account event 4742](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4742)
- [Microsoft Learn · Directory creation event 5137](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-5137)
- [Microsoft Learn · Test-ComputerSecureChannel](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.management/test-computersecurechannel)

[Previous · Active Directory fundamentals]({{ '/wiki/active-directory-fundamentals/' | relative_url }}) · [Next · AD replication evidence]({{ '/wiki/ad-replication-change-evidence/' | relative_url }}) · [Compare group change and access evidence]({{ '/wiki/ad-group-membership-evidence/' | relative_url }})
