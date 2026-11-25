---
title: "AD LDAP Signing and Channel Binding · Read the Evidence"
description: "Distinguish LDAP integrity, TLS and channel binding, then compare Directory Service audit signals with the actual bind outcome."
category: active-directory
tags: [Active Directory, LDAP, Channel Binding, Windows Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/ad-ldap-session-evidence/
---

**Learning goal.** A service reports an LDAP authentication error while several domain controllers log channel binding warnings. Identify the applicable protection, connect evidence to the actual client and controller, and determine what the logs establish.

## 1. Three protections answer different questions

**LDAP** is a protocol for accessing directory entries. An Active Directory **domain controller (DC)** hosts the directory service. A **bind** sets the authentication state for an LDAP connection. A simple bind with a name and password relies on its transport for protection. **SASL** connects LDAP to mechanisms such as Kerberos or Negotiate and can negotiate a security layer. A successful bind establishes an identity for later operations. An LDAP search or modify still gets its own authorization decision.

| Control | What it protects | What to verify |
| --- | --- | --- |
| SASL signing | LDAP message integrity after negotiation | The mechanism and negotiated protection. Signing alone does not encrypt the messages. |
| SASL sealing | LDAP message confidentiality and integrity through a negotiated security layer | The library and mechanism actually negotiated sealing. TLS is a separate way to protect the transport. |
| TLS | Confidentiality and integrity in transit. Certificate validation establishes trust in the server identity. | Whether TLS was established and the client validated the expected name and certificate chain. |
| Channel binding token (CBT) | Links supported TLS-based SASL authentication to the TLS channel | Whether CBT applies, what the DC's effective policy required and whether validation succeeded. |

**LDAPS** starts TLS immediately, commonly on TCP 636 for LDAP. **StartTLS** upgrades an existing LDAP connection, commonly on TCP 389, before sending protected credentials or queries. The port is a routing hint. Determine the actual transport and whether the client would stop if StartTLS failed. A simple bind over properly validated TLS can meet AD's server-side signing requirement through TLS protection. CBT does not apply to that simple-bind mode. A TLS handshake does not reveal which bind mode or channel binding result followed.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/ad-ldap-session-evidence-en.svg' | relative_url }}" alt="A client reaches a domain controller over LDAP or TLS and chooses a simple or SASL bind. TLS protects the transport, while CBT can bind TLS-based SASL authentication to the channel. A successful bind precedes a separate directory access decision." width="480" height="384">
  <figcaption>Collect transport, bind method and outcome as separate observations. Check operation authorization after authentication.</figcaption>
</figure>

## 2. Follow an approved bind

In a fictional rollout, `report-reader` connects to `dc-a` by name. The client validates the certificate and establishes TLS. Its SASL mechanism provides a valid CBT, and separate client diagnostics and DC evidence support acceptance. A subsequent search runs with the authenticated service identity and the directory's permissions. A second application uses a simple bind inside validated TLS. Its bind also succeeds. It has no CBT for this mode. The operator records these as two different valid observations.

If the client cannot trust the DC certificate, TLS can fail before any bind occurs. If the TLS session is established but the DC records a matching CBT validation failure, focus on the SASL compatibility, applied policy and TLS termination. If a bind succeeds and a search is denied, inspect the requested operation, authenticated identity, effective directory permissions and search scope.

## 3. Understand misuse and deployment defaults

An unprotected simple bind can expose a password to someone who can observe the traffic. Unsigned authentication or messages can leave systems exposed to interception, modification or relayed authentication, depending on the mechanism and protection in use. In relay, authentication intended for one connection is presented elsewhere. Signing requires negotiated integrity on applicable unprotected SASL connections, and CBT can expose an inconsistency between applicable TLS-based SASL authentication and the channel. A CBT failure also occurs during ordinary client or TLS configuration problems. It establishes neither intent nor who initiated the traffic. Investigate before attributing an event.

Microsoft documents signing enforcement by default for **new AD deployments on Windows Server 2025 or later**. The enforcement GPO takes precedence over the signing-level policy when enabled. Microsoft describes existing signing policies as preserved during upgrades and stricter default behavior in the absence of a server-side signing policy on Server 2025. New Server 2025 deployments default to **When supported** for CBT. In that mode, applicable clients capable of CBT must provide it, while clients without support can be accepted. **Always** requires a valid token for applicable clients. **Never** disables CBT validation. Confirm the effective DC policy and installed update, rather than inferring an individual result from the server version. The 2020–2024 servicing history documents separate audit additions and enablement changes. It does not imply one historical update turned on universal enforcement.

## 4. Collect and interpret Directory Service records

Read the **Directory Service** log on each relevant DC. Match provider `Microsoft-Windows-ActiveDirectory_DomainService`, event XML, computer, timestamp and local record ID. In forwarded data, preserve the originating channel and computer. Diagnostic logging and updated builds affect coverage. Microsoft documents **16 LDAP Interface Events** diagnostic level **2 (Basic)** for detailed per-client events such as 2889, 3039, 3074 and 3075. Keep any approved diagnostic change scoped and time-bound. Check DC clocks, retention, subscription filters and whether every relevant DC actually contributed data.

| Event | What it contributes | How to limit the conclusion |
| --- | --- | --- |
| 2886 | Reminder about permissive signing configuration | Configuration signal. No individual bind result. |
| 2887 / 2888 | 24-hour total of permitted unprotected binds or rejected unprotected binds, respectively | Site or DC trend. The summary alone does not identify the relevant process or connection. |
| 2889 | Client detail for unsigned SASL or clear-text simple binds, with diagnostic level 2 | Binding Type 0 is unsigned SASL and 1 is simple bind. Check effective policy and client outcome before labeling the attempt accepted or rejected. |
| 3039 | TLS LDAP channel binding validation failure with an applicable policy | Correlate to the same client and DC, then verify the bind outcome. Microsoft conditions this event on When supported or Always and detailed logging. |
| 3040 / 3041 | Completed unprotected TLS binds summarized over 24 hours, or a configuration reminder when CBT is Never | Use for baseline and policy review. No decision for a particular connection. |
| 3074 / 3075 | Compatibility audit for an invalid CBT or missing channel binding information | An audit observation about enforcement behavior. Use a separate result to establish what happened to the bind. Availability depends on policy, diagnostic level and updates. |

For 3074 and 3075 Microsoft specifies applicable Windows Server 2022 updates from August 2023 and Windows Server 2019 updates from October 2023, with later servicing changes to enablement. Confirm effective policy `When supported` or `Always`, diagnostic level and installed build. Missing events can reflect scope or collection gaps.

On an authorized DC with Windows PowerShell and rights to read the log, use this bounded query to enumerate candidate records. Review `ToXml()` for individual records if message text or event fields are missing. The example was reviewed against Microsoft documentation.

```powershell
$filter = @{
  LogName = 'Directory Service'
  ProviderName = 'Microsoft-Windows-ActiveDirectory_DomainService'
  Id = 2886,2887,2888,2889,3039,3040,3041,3074,3075
  StartTime = (Get-Date).AddHours(-24)
}
Get-WinEvent -FilterHashtable $filter |
  Select-Object TimeCreated, MachineName, Id, RecordId, Message
```

1. **Join by connection evidence.** Record UTC, selected DC, source address and port where available, client process or service owner, and the bind method and observed result. Time and IP alone may collide at a proxy, NAT or busy client. Check actual TLS termination. Encrypted network data usually leaves outcomes to application and DC diagnostics.
2. **Separate the controls.** RFC 4511 code 8 (`strongerAuthRequired`) indicates stronger authentication is required. In the context of an unprotected bind and corroborating DC telemetry, it supports a signing-policy diagnosis. Neither code 8 nor a generic authentication failure supplies all those details by itself.
3. **Scope response and validation.** Inventory affected clients and owners, distinguish baselines from changes and compare DC policy consistency. Test a compliant client and a compatibility control in a controlled, authorized directory. After approved library or configuration changes, check representative applications, expected rejections and the downstream directory operation. If misuse is suspected, preserve minimal evidence and trace subsequent operations with the appropriate directory auditing and service records. Avoid storing raw passwords or sensitive packet payloads in routine reports.

## 5. Offline evidence drill

Download <a href="{{ '/assets/labs/ad-ldap-session-evidence.py' | relative_url }}" download>the Python 3 checker</a> and <a href="{{ '/assets/labs/ad-ldap-session-evidence-cases.json' | relative_url }}" download>the fictional records</a> to the same folder. The tool reads only local JSON and requires no DC or credentials. The fixture's connection ID is hypothetical normalized metadata. Native DC records do not guarantee it. The join's five-second window is specific to this drill.

```sh
python3 ad-ldap-session-evidence.py
```

| Cases | Expected distinction |
| --- | --- |
| A, B, M | Clear simple accepted, signed SASL without TLS, and unsigned SASL accepted. |
| C, D, L | TLS simple, TLS with explicitly confirmed CBT, and TLS SASL acceptance with CBT unconfirmed. |
| E, I | Matched independent outcomes and events support CBT and signing rejections, respectively. |
| F, G | Audit plus independently observed acceptance, versus audit with no known result. |
| H, J, K | TLS failure before bind, only a summary, or rejected bind with no matching 3039. |

Expect `13/13 LDAP evidence cases matched.` For a negative control, change the event's DC from `dc-a` to `dc-b` in a copy of case E and pass that file as the argument. Expect E to change to `bind-rejected-cause-open`, 12 matches and exit status 1. If the fixture cannot open, check both filenames and JSON syntax. If E still matches, verify which DC field you changed and which file you passed. Both controls were executed in a cloud Python environment. The Windows policies, query and Event IDs were reviewed against documentation. The lab did not exercise an actual DC.

## 6. Check your understanding

1. **Does seeing port 389 establish clear text?** No. Check whether StartTLS completed or whether a SASL security layer was negotiated.
2. **What does a matched 3075 establish?** A CBT compatibility audit observation. Add client or DC evidence for the actual bind result.
3. **Should you expect CBT on a TLS-protected simple bind?** CBT is inapplicable to this mode. Verify TLS and certificate validation separately.
4. **Can 2888 identify the client that failed?** The summary counts rejections. Use per-client detail and independent session evidence to identify a connection.

**Completion.** Explain cases C, E, F, H and K, reproduce the original and altered results, and list the extra evidence needed to attribute a real failed bind to a policy.

## Official references

Reviewed 2026-11-26. The RFCs define protocol behavior. Current Microsoft documentation covers supported AD DS versions and distinguishes new Windows Server 2025 deployments from upgrades. The KB is the source for the 2020–2024 servicing timeline.

- LDAP bind, StartTLS and result codes. [RFC 4511, June 2006](https://www.rfc-editor.org/rfc/rfc4511.html) · [RFC 4513, June 2006](https://www.rfc-editor.org/rfc/rfc4513.html)
- Current Windows settings. [LDAP signing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-signing) · [LDAP channel binding](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/ldap-channel-binding) · [Session security guidance](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/ldap-session-security-settings-requirements-adv190023)
- Event evidence and collection. [Microsoft KB4520412](https://support.microsoft.com/en-us/servicing/os/windows/2020/02/2020-2023-and-2024-ldap-channel-binding-and-ldap-signing-requirements-for-windows-kb4520412) · [Enable LDAP signing](https://learn.microsoft.com/en-us/troubleshoot/windows-server/active-directory/enable-ldap-signing-in-windows-server) · [Get-WinEvent](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.diagnostics/get-winevent)

[Previous · Active Directory fundamentals]({{ '/wiki/active-directory-fundamentals/' | relative_url }}) · [Next · LDAP and AD enumeration]({{ '/wiki/ldap-ad-enumeration/' | relative_url }})
