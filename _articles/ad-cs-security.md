---
title: "AD CS Security: Certificate Templates, ESC Risks, Strong Mapping, Detection and Defense"
description: "Understand certificate enrollment and authentication, AD CS template and CA permissions, selected ESC risks, modern mapping enforcement, audit evidence, Splunk searches and a synthetic investigation."
category: active-directory
tags: [Windows Security, Active Directory, AD CS, PKI, Certificates, Certificate Templates, NTLM Relay, Kerberos, Blue Team, DFIR, Splunk, Detection Engineering, MITRE ATT&CK]
level: Intermediate
updated: "2026-10-22"
translation_url: /ko/wiki/ad-cs-security/
---

> **AD security extension.** Read [AD Fundamentals]({{ '/wiki/active-directory-fundamentals/' | relative_url }}), [Kerberos]({{ '/wiki/kerberos-authentication/' | relative_url }}), [NTLM]({{ '/wiki/ntlm-authentication/' | relative_url }}), [LDAP & ACLs]({{ '/wiki/ldap-ad-enumeration/' | relative_url }}) and [Windows Lateral Movement]({{ '/wiki/windows-lateral-movement/' | relative_url }}). Examples use fictional systems and certificates. Assessment commands inspect configuration or metadata; they do not request impersonation certificates, export keys, relay authentication or change production policy.

## 1. Why AD CS is part of identity security

**Active Directory Certificate Services (AD CS)** is the Windows Server PKI role used to issue and manage certificates for users, devices and services. Organizations use certificates for authentication, TLS, signing and other purposes. An enterprise issuing CA can apply certificate templates stored in AD; a standalone CA is a different enrollment model. AD CS is not automatically installed on every DC. [Microsoft AD CS overview](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/active-directory-certificate-services-overview).

A certificate can become an authentication credential only when the target accepts its chain, purpose, identity binding and proof of private-key possession, under applicable policy. A bad template or enrollment endpoint can create an identity route that password-only monitoring misses. Conversely, an ordinary certificate issuance is not itself compromise.

**Keep four claims separate:** risky configuration, request received, certificate issued, and certificate actually used to authenticate or access a resource.

## 2. Certificate vocabulary without the common shortcuts

| Term | Meaning | Investigation caution |
| --- | --- | --- |
| Public certificate | Signed association of a public key and certificate information | Possession alone does not prove access to its private key |
| Private key | Secret used to prove possession or perform permitted cryptographic operations | Protect key files, stores, backups and access to signing operations |
| Subject / SAN | Subject and alternative names asserted in the certificate | A requested name is not proof the KDC mapped that identity |
| EKU | Extended Key Usage defining permitted purposes | A TLS-only certificate is not automatically an AD logon credential |
| Template | Enterprise enrollment policy and client settings | Display name, internal name and OID are different identifiers |
| Issuer + serial number | Identifies a certificate in its issuing context | Serial alone is not a global cross-CA key |
| Thumbprint | Fingerprint of a particular certificate | Not the same as a user SID, private key or request ID |
| CSR / enrollment request | Request containing public-key and enrollment information | Requested attributes can differ from the final issued certificate |
| CRL / OCSP | Revocation-status mechanisms | Publication, retrieval and relying-party enforcement are separate |

A `.cer` file commonly contains public certificate material; a `.pfx` can contain a private key as well. Inspect the actual content and protections rather than trusting the extension. A non-exportable key can still be misused through a compromised authorized process.

## 3. Normal enrollment and later authentication

![Enrollment, issuance, authentication and access are separate stages]({{ '/assets/diagrams/adcs-lifecycle-en.svg' | relative_url }})

1. A legitimate client creates or uses a key pair and selects an enrollment policy/template.
2. It authenticates to a reachable enrollment service and submits a request.
3. The CA evaluates its policy, published templates, enrollment permissions and required approval/signature conditions.
4. The request is issued, denied or held pending. The final certificate and its status must be checked.
5. In a **later, separate** operation, a client proves private-key possession to a relying service.
6. That service checks applicable trust, purpose, validity, revocation and identity-mapping policy; authorization still decides resource access.

For Kerberos certificate authentication, PKINIT participates in the initial ticket exchange; later access may use ordinary Kerberos tickets. TLS client-certificate authentication and other consumers have their own processing. Do not assume every issued certificate is used for PKINIT, or that issuance causes a new logon automatically.

An offline root and online issuing CA are a common hierarchy, not a statement that every deployment has that design. Record actual trust paths, authentication trust such as NTAuth where applicable, enrollment services and dependent applications.

## 4. Templates: enrollment rights versus control of policy

Enterprise templates are AD objects in the Configuration partition. Their settings govern subject construction, intended purposes, key requirements, approval and enrollment behavior. The CA must also be configured to issue the template. [Certificate template concepts](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/certificate-template-concepts).

| Control point | Question | Do not confuse it with |
| --- | --- | --- |
| Read / Enroll | Which principals can use this template, subject to CA policy? | Permission to edit the template |
| Autoenroll | Which eligible clients can enroll automatically? | Bypassing CA policy or gaining arbitrary identity |
| Subject/SAN construction | Does AD supply identity information or can the requester influence it? | Proof that every supplied name is accepted for authentication |
| Authentication-capable purposes | Which consumers and uses accept the certificate? | A guarantee of successful impersonation |
| Manager approval / authorized signatures | What independent authorization is required? | The same thing as network authentication |
| Template DACL / owner | Who can alter permissions or security-relevant attributes? | Ordinary enrollment rights |
| CA publication / CA permissions | Is the template available and is the requester permitted by the CA? | Mere presence of an AD template object |

Review effective ACLs including nested groups, object-specific ACEs and inheritance. Template administrators, CA administrators, certificate managers and enrollment agents have different responsibilities. An enrollment agent can be legitimately authorized to act for others; its scope must be constrained and audited.

## 5. Read selected ESC labels as hypotheses, not verdicts

**ESC** labels are practitioner classifications of AD CS abuse conditions, not Microsoft CVE numbers or an exhaustive checklist of current attacks. Tool versions and graph models may split or rename paths. A finding requires the configuration, an effective permission path and a reachable usable authentication route.

| Family | Risk to investigate | Defensive validation |
| --- | --- | --- |
| ESC1 | Enrollment with requester-controlled identity data on a template usable for authentication | Publication, effective enrollment, identity fields, approval/signatures and actual mapping behavior |
| ESC4 | Excessive control of a template that can permit dangerous policy changes | Current ACL/owner, exact writable attributes, approved baseline and available issuance path |
| ESC7 | Excessive CA administration or certificate-manager authority | Separate roles and validate approval/delegation scope |
| ESC8 | NTLM relay exposure on relevant IIS enrollment endpoints | Required EPA, HTTPS-only access, authentication providers and actual endpoint configuration |
| ESC11 | RPC enrollment without the required packet-privacy protection | Effective RPC interface flags, clients and compatible enforcement |

For template paths, see [SpecterOps ESC1](https://bloodhound.specterops.io/resources/edges/adcs-esc1) and [ESC4](https://bloodhound.specterops.io/resources/edges/adcs-esc4). For CA and interface assessments, see [Microsoft certificate security assessments](https://learn.microsoft.com/en-us/defender-for-identity/security-posture-assessments/certificates).

Broader SAN policy and suppressed SID-extension scenarios, often discussed under ESC6/ESC9/ESC16, are **mapping-dependent**. Do not treat one flag as proof of a working path, and do not assume current DC hardening removes every template, relay or CA-key risk. This guide focuses on defensive reasoning for selected families rather than promising coverage of every ESC variation.

## 6. Strong certificate mapping: the 2026 baseline

Older tutorials often describe account selection from a supplied UPN as though it were sufficient everywhere. Current Windows KDC protections require attention to **strong certificate-to-account binding**. An appropriate SID extension or explicit strong mapping can establish the required binding; subject/name-only mappings are not equivalent.

Under [KB5014754](https://support.microsoft.com/en-us/servicing/os/windows-server/2022/05/kb5014754-certificate-based-authentication-changes-on-windows-domain-controllers), February 2025 updates moved relevant DCs to enforcement by default. Updates from **9 September 2025** removed support for the old `StrongCertificateBindingEnforcement` compatibility override. For 2026 assessments, record actual patch levels and effective authentication configuration rather than proposing an obsolete compatibility-registry workaround.

This is a KDC mapping control, not a universal removal of certificate abuse. Evaluate the actual certificate, allowed name/SID inputs, CA/template processing, strong mappings, relying service and attacker control. Schannel/TLS clients, third-party CAs and enrollment platforms can have different dependencies. Test legitimate renewals and authentication while improving mapping; do not weaken validation to silence failures.

Kdcsvc System events described in the KB can explain mapping problems. Match provider, message, OS and certificate information; a bare event number 39 from an arbitrary provider is not a reliable AD CS indicator.

## 7. Enrollment relay: protect the destination protocol

A relay can forward a live authentication exchange to an enrollment service, potentially obtaining a certificate for the relayed identity under permitted enrollment rules. This does not first require recovering the password, and the identity can be a computer account.

For affected web enrollment/CES configurations, Microsoft recommends **EPA and disabling HTTP**, with Required EPA the stronger setting; HTTPS alone is not an assurance that NTLM relay is prevented. Validate each installed IIS endpoint and the applicable CES configuration, plus NTLM dependencies. RPC enrollment has its own packet-privacy requirement; securing web endpoints does not automatically secure RPC. [KB5005413](https://support.microsoft.com/en-us/servicing/os/windows-server/2021/07/kb5005413-mitigating-ntlm-relay-attacks-on-active-directory-certificate-services-ad-cs).

An IIS request or authentication event alone is not proof of relay or certificate issuance. Correlate source host, endpoint, authenticated identity, CA disposition and subsequent use. A reverse proxy, load balancer or TLS termination point can affect binding and source attribution, so test the deployed path. Remove unused enrollment surfaces through the normal dependency/change process.

## 8. Private-key theft and CA compromise

User or device certificate misuse typically requires the associated private key or access to an operation that uses it. Resetting the account password does not automatically revoke its certificates. Depending on policy and validity, a certificate can remain an authentication route. [MITRE T1649](https://attack.mitre.org/techniques/T1649/).

Compromise of an issuing CA private key is a **trust-infrastructure incident**, not just a single-user password problem. An attacker may create certificate material without a normal enrollment-database record. Therefore, absence of 4887 cannot rule out forgery involving a compromised CA key. Protect CA hosts, backups, recovery credentials and signing permissions; hardware-backed protection helps only alongside sound administration.

Separate certificate-key theft from template abuse and relay in the incident record. They require different evidence and containment. Do not publish internal certificate inventories, real PFX files, private keys or CA backups in this public wiki.

## 9. Evidence locations and audit prerequisites

| Source | Where to collect | What it can support |
| --- | --- | --- |
| 4886 / 4887 / 4888 | CA Security | Request received / certificate issued / request denied |
| 4870 / 4872 | CA Security | Certificate revoked / CRL published when audited |
| 4882 / 4885 / 4892 | CA Security | CA permission / audit-filter / property changes |
| CA database and issued certificate | Issuing CA / approved certificate inventory | Request disposition, issuer/serial, final extensions and enrollment context |
| 5136 and configured directory auditing | Relevant DCs | Audited template or mapping-attribute modifications; not every directory read |
| IIS logs and endpoint configuration | Enrollment web server | Requests, paths, identities where logged and EPA/authentication context |
| 4768 with relevant certificate fields | DC Security | Kerberos initial-authentication context; check raw fields/version |
| Kdcsvc System diagnostics | Relevant DCs | Certificate mapping failures under documented conditions |
| Destination logons and EDR | Resource / client hosts | Subsequent access, processes and key-use context |

CA operation auditing requires **both the CA audit filter and Audit Certification Services policy**. Forwarding alone enables neither. AD object auditing additionally depends on the relevant policy and matching SACLs. Confirm local generation before testing forwarding and retention. [CA administration and audit](https://learn.microsoft.com/en-us/windows-server/identity/ad-cs/secure-delegate-audit-certification-authority), [Audit Certification Services](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/audit-certification-services).

Raw CA event fields may not include the final SAN, serial, template or IP you need in every format. Enrich from the CA database/certificate and other records, while preserving provenance. A requester is not necessarily the final certificate subject, and neither automatically identifies the host holding the private key.

## 10. Correlate enrollment, mapping and actual access

![CA, directory, enrollment endpoint and destination evidence]({{ '/assets/diagrams/adcs-evidence-en.svg' | relative_url }})

1. Record CA name/instance, database context and host; scope the request ID to that CA. The same number on CA01 and CA02 is not the same request.
2. Compare request receipt with issued/denied disposition; a received or pending request is not an issued credential.
3. Obtain final certificate metadata: issuer, serial, validity, purpose and identity/security extensions. Do not infer it only from requested attributes.
4. Review template/CA policy and ACLs as they existed at issuance, including prior changes and replication/cache timing.
5. Correlate client/IIS/network identity and source; do not equate requester, certificate subject and mapped account.
6. Check later authentication using compatible certificate identifiers and raw event details. A nearby 4768 or 4624 alone is not a certificate-use join.
7. Track actual access/impact separately; preserve unknowns and alternative legitimate explanations.

Use CA instance + request ID within the relevant database lifetime for enrollment correlation, and issuer + serial for certificate identity. Normalize serial formatting and byte-order representations only according to the source documentation. Thumbprints and other identifiers are different keys; do not compare unlike values.

## 11. Splunk investigation templates

These examples require the real index, time range, source channel and parser. They are starting searches, not tested production detections or proof of an ESC exploit.

### A. Verify CA audit ingestion

```spl
index=* (EventCode IN (4870,4872,4882,4885,4886,4887,4888,4892)
      OR EventID IN (4870,4872,4882,4885,4886,4887,4888,4892))
| eval event_id=coalesce(EventCode,EventID)
| stats count by host sourcetype event_id
| sort - count
```

### B. Group request dispositions on a CA host

```spl
index=windows (EventCode IN (4886,4887,4888) OR EventID IN (4886,4887,4888))
| eval event_id=coalesce(EventCode,EventID)
| eval ca_host=coalesce(Computer,host)
| eval request_id=tostring(coalesce(RequestId,RequestID,Request_ID))
| where isnotnull(request_id)
| stats min(_time) AS first_seen max(_time) AS last_seen
    values(event_id) AS events values(Requester) AS requesters
    values(Attributes) AS request_attributes BY ca_host request_id
| convert ctime(first_seen) ctime(last_seen)
```

Map `RequestId`/`Requester`/`Attributes` to the actual source XML. This assumes one known CA/database context per normalized `ca_host` in the search window. If hosts, CA instances, aliases or restored databases can overlap, normalize a separate CA-instance/database identifier before grouping. The `where` clause intentionally excludes rows without a request ID; inspect those separately for parsing failures.

### C. Inspect audited template attribute changes

```spl
index=windows (EventCode=5136 OR EventID=5136)
| where like(lower(ObjectDN),"%cn=certificate templates,cn=public key services,%")
| table _time host SubjectUserName SubjectLogonId ObjectDN
    AttributeLDAPDisplayName OperationType AttributeValue OpCorrelationID
| sort 0 _time
```

This scopes to the conventional template container under Configuration. Validate the actual DN and attribute mapping. It does not calculate effective ACLs or prove that the change caused an issuance. Compare before/after permissions and the approved change record.

### D. Baseline issued records by requester and template

```spl
index=pki_lab sourcetype=certificate_issuance_normalized outcome=issued
| where isnotnull(ca_instance) AND isnotnull(requester) AND isnotnull(template)
| bin _time span=15m
| stats count AS issued dc(request_id) AS distinct_requests
    values(subject) AS subjects values(serial_number) AS serials
    BY _time ca_instance requester template
| sort - issued
```

The last search uses an **illustrative enriched schema**, not default Windows fields. `issued` counts records, potentially including duplicates; distinct requests are scoped to each CA and time bucket. Deduplicate and tune against renewal bursts, device provisioning and certificate-management systems before alerting. A single high-impact issuance can matter even without a volume burst.

## 12. Read-only configuration and certificate checks

On an authorized CA, with appropriate local permissions and installed tools:

```powershell
Get-Service -Name CertSvc
certutil -getreg CA\AuditFilter
certutil -getreg CA\InterfaceFlags
certutil -getreg policy\EditFlags
certutil -catemplates
```

These commands display service state, audit/interface/policy flags and templates available from the selected/default CA context. They do not enable auditing or change policy. Interpret bit fields against the installed version; a displayed flag alone is not a complete vulnerability finding. `certutil` availability/options vary and it is an administrator diagnostic tool, not a guaranteed application API. [certutil reference](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil).

```powershell
$since = (Get-Date).AddHours(-2)
Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4886,4887,4888,4870,4872; StartTime=$since} -MaxEvents 100 |
  Select-Object TimeCreated,Id,ProviderName,MachineName,Message
```

This returns a bounded sample, not a complete investigation export. A missing result can reflect audit setup, permissions, retention or timing. On a machine you administer, the following inspects only local certificate metadata:

```powershell
Get-ChildItem -Path Cert:\LocalMachine\My |
  Select-Object Subject,Issuer,Thumbprint,NotAfter,HasPrivateKey
```

`HasPrivateKey` indicates a key association, not that the reader can export/use the key. This command does not export certificates or private keys, validate the full chain, query every store or prove authentication. Use the appropriate user/machine store and application context for a real assessment.

## 13. Synthetic investigation exercise

[Download the 12-row synthetic CSV]({{ '/assets/labs/adcs-investigation-events.csv' | relative_url }}). It is a teaching worksheet, not native event XML or a ready-to-install lookup. Some CA rows are enriched from the fictional database; `detail` identifies uncertainty. No private-key material or real internal identities are included.

| UTC | Observation | Correct initial interpretation |
| --- | --- | --- |
| 02:00 | CA01 request 101 received and issued for DEVICE01$ | Verify approved device renewal |
| 02:10 | DC01 records a template attribute change | Resolve exact attribute/values, actor and authorization |
| 02:12 | CA01 request 102 from reader_lab issued as 10BB | Unusual requester/template pair; inspect final certificate |
| 02:13–14 | A DC ticket event and APP01 logon occur | Certificate linkage remains unconfirmed |
| 02:15 | CA01 request 103 is received then denied | Do not count it as an issuance |
| 02:16 | CA02 also has request ID 102 | Separate CA context; do not merge with CA01 |
| 02:20–21 | 10BB is revoked and a CRL is published | Verify distribution/consumer checks and existing sessions |

**Questions:** Which request was issued? Is the directory change related to the same template and effective at issuance? Who requested, who is named in the certificate, who holds the key and which account was mapped? Does the worksheet demonstrate certificate use? Does revocation end every existing session?

**Answer guide:** The first renewal can be legitimate. CA01/102 requires review because of the requester/template combination and nearby policy change; neither proves impersonation. CA01/103 is denied. CA02/102 is independent. The supplied 4768/4624 rows do not establish a join to 10BB, so certificate authentication and downstream misuse remain unconfirmed. The revocation actor can differ from the original requester. Publication alone does not prove every consumer has retrieved fresh status or that existing tickets/sessions ended.

Preserve original XML, CA database records, template/ACL snapshots, public certificate metadata, mapping settings, web logs and endpoint evidence. Handle any private-key evidence only through the approved protected process.

## 14. Remediation and containment without breaking PKI

| Priority | Action | Evidence of completion |
| --- | --- | --- |
| 1 | Assign owners to CAs, templates, enrollment endpoints and critical dependencies | Inventory and named approval responsibilities |
| 2 | Remove unnecessary template/CA control and broad enrollment; separate roles | Effective ACLs and legitimate enrollment tests |
| 3 | Correct unnecessary subject input/purposes and approval requirements | Final test certificates match intended identities and uses |
| 4 | Require compatible web EPA/HTTPS and RPC packet privacy; reduce NTLM | Tested endpoint paths and documented client dependencies |
| 5 | Maintain current mapping enforcement and patching | Legitimate certificate authentication succeeds without weak workarounds |
| 6 | Protect CA/device keys, backups and administrative access | Key custody, controlled signing permissions and recovery tests |
| 7 | Validate audit generation, forwarding and retention | Known request/issuance/denial and change events arrive as expected |

If an authentication certificate/key is compromised, identify its issuer/serial and other related issuances, revoke through the CA process, publish and validate revocation information, investigate key custody, and address affected accounts/tickets/sessions. Password rotation alone is not certificate revocation; revocation alone is not a universal immediate session kill.

CA-key compromise requires PKI/identity incident leadership to determine trust removal, CA recovery/rebuild and reissuance scope. Do not casually delete a CA, remove trusted roots or revoke a production hierarchy: the impact can include VPN, Wi-Fi, smart cards, TLS and device management. Preserve evidence and use a tested recovery plan.

## 15. MITRE mapping and common misconceptions

| Behavior | Relevant mapping | Evidence requirement |
| --- | --- | --- |
| Stealing/forging authentication certificates | [T1649](https://attack.mitre.org/techniques/T1649/) | Certificate/key misuse or forging evidence, not issuance alone |
| Live NTLM relay in a relevant scenario | [T1557](https://attack.mitre.org/techniques/T1557/) | An adversary-in-the-middle path with supporting authentication evidence |
| Later use of remote services | [T1021](https://attack.mitre.org/techniques/T1021/) | Actual remote access; choose the supported subtechnique |

- **AD CS installed means vulnerable:** no; validate specific conditions and effective rights.
- **Enroll equals edit-template permission:** no; using policy and changing policy are different capabilities.
- **A named SAN proves the mapped account:** no; evaluate final certificate and mapping/consumer policy.
- **HTTPS alone eliminates enrollment relay:** no; endpoint binding/authentication protections matter.
- **4887 proves certificate authentication:** no; it supports issuance.
- **No 4887 means no forged certificate:** no; CA-key forgery need not use the normal request path.
- **A password reset invalidates the certificate:** no automatic equivalence.
- **All numeric request IDs are globally unique:** no; retain CA/database context.

## 16. Completion checks and related learning

Explain public versus private key, enrollment versus authentication, template use versus control, and issuance versus access. Validate one effective enrollment path, interpret one audit prerequisite, correlate a request without merging CAs, and state what the synthetic case cannot prove.

Continue with [LDAP/ACL analysis]({{ '/wiki/ldap-ad-enumeration/' | relative_url }}), [NTLM relay protections]({{ '/wiki/ntlm-authentication/' | relative_url }}), [Kerberos authentication]({{ '/wiki/kerberos-authentication/' | relative_url }}) and [Windows lateral movement]({{ '/wiki/windows-lateral-movement/' | relative_url }}). Continue with [Windows Persistence]({{ '/wiki/windows-persistence/' | relative_url }}). The next planned extension is Sysmon.

**Source review: 22 October 2026.** Microsoft and SpecterOps references explain product behavior and selected risk models; MITRE supplies behavior classifications. Diagrams, queries and the lab are original synthetic teaching material. Field names, tools and exploit preconditions vary by version. No live certificate enrollment, key export, relay, production policy change or operational Splunk test was performed for this publication.
