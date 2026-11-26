---
title: "MTA-STS and TLS-RPT Evidence · SMTP Transport Policy and Failures"
description: "Distinguish MX policy, STARTTLS, certificate checks, policy cache and aggregate reporting on an SMTP hop."
category: network
tags: [SMTP, MTA-STS, TLS-RPT, TLS, Email Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/smtp-mta-sts-evidence/
---

A mail delivery delay can start before the receiving SMTP server ever sees the message. A sender applying MTA-STS may reject an MX, decline a TLS connection or queue the message for retry. TLS reports help locate those failures. This chapter covers direct delivery between mail servers, one SMTP hop at a time.

## 1. What each mechanism controls

An **MTA** is a mail transfer agent. A sending MTA looks up the recipient domain’s **MX** records to find candidate mail servers. With **STARTTLS**, an SMTP session can start in plaintext and upgrade to TLS after the server advertises the capability. On an opportunistic route, what happens if the upgrade is unavailable depends on the sender’s policy. A missing or altered advertisement can lead to a downgrade when plaintext remains allowed.

**MTA-STS** lets the recipient domain publish a policy telling supporting senders which MX hostnames are acceptable and whether matching, authenticated TLS is required. The DNS TXT record at `_mta-sts.<domain>` announces `STSv1` and an `id`. The policy body is fetched over HTTPS from `https://mta-sts.<domain>/.well-known/mta-sts.txt` and includes `version`, `mode`, MX patterns and `max_age`. The TXT ID signals a change. It does not contain the policy or replace HTTPS certificate verification. The HTTPS policy host and the selected SMTP MX are separate endpoints with separate certificate checks.

**TLS-RPT** is reporting. The recipient domain publishes a TXT record at `_smtp._tls.<domain>` with `v=TLSRPTv1` and a destination in `rua`. Participating sending MTAs submit aggregate observations. A report can surface a failure without showing the final disposition of any message. SPF, DKIM and DMARC address sender or message identity, and end-to-end message encryption protects content beyond one transport hop.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/smtp-mta-sts-evidence-en.svg' | relative_url }}" alt="The sender identifies the recipient’s MX and effective MTA-STS policy, checks the candidate MX, and negotiates STARTTLS with certificate validation. A passing check permits an SMTP attempt. A failure under enforce prevents delivery to that candidate. Participating senders report aggregate TLS results.">
  <figcaption>Policy checks control the SMTP hop. Reporting summarizes observed TLS outcomes on a separate path.</figcaption>
</figure>

## 2. Follow an ordinary delivery hop

Suppose the fictional domain `mail-lab.example` publishes MX records for `mx1.mail-lab.example` and `mx2.mail-lab.example`. The HTTPS policy contains `mode: enforce`, matching `mx` entries and `max_age: 86400`. The sender validates the HTTPS policy endpoint when fetching the file, selects an eligible MX, sees `STARTTLS`, and negotiates TLS. It checks the MX certificate’s trust chain, validity and DNS name in the Subject Alternative Name against the selected MX. SMTP capability discovery then starts again inside TLS with a fresh `EHLO`. A policy pattern like `*.mail-lab.example` matches only one leftmost label, as in `mx1.mail-lab.example`. The apex and `mx1.edge.mail-lab.example` fall outside that scope. The sender can then continue the SMTP transaction. A later `250` after the end of message data supports acceptance on that hop. Inspect the next gateway or delivery trace for onward handling.

| Effective policy | If the selected MX fails a policy check |
| --- | --- |
| Valid `enforce` | Do not deliver to that MX. Another eligible MX may pass. Treat unresolved failures as transient where appropriate and check for an updated policy before a permanent failure. |
| Valid `testing` | MTA-STS alone does not block the attempt. Participating senders can report the failure. Other transport controls still apply. |
| Valid `none` | No active MTA-STS requirement for this domain. Other controls may still require TLS. |
| No valid policy found or cached | Continue without MTA-STS enforcement. Investigate discovery or fetch errors and other policy sources. |

A policy fetched yesterday and still valid in the sender cache can remain effective today even if the DNS or HTTPS endpoint is temporarily unavailable. A current lookup from your workstation cannot establish what a particular MTA applied in the past. Obtain the sender-side policy mode, fetch/cache time and expiry if available. MTA-STS discovery depends on DNS and HTTPS, so initial discovery failure with no valid cache is a real gap. DANE uses DNSSEC-validated TLSA policy information and has different discovery and authentication requirements.

## 3. Separate negotiation, policy and queue outcomes

A sudden run of `starttls-not-supported` reports may reflect a server that stopped advertising the extension, an intervening gateway or a path-specific downgrade. Establish whether several independent senders see the same MX and time period. A `certificate-host-mismatch` may follow a mail-provider migration or inconsistent listener configuration. Compare the observed certificate on each affected MX with the expected DNS name and maintenance record. A successful HTTPS policy fetch does not validate any SMTP certificate.

| Evidence | What you can establish |
| --- | --- |
| Historical DNS, HTTPS policy and sender cache records | What was published, fetched or applied, depending on the source. Preserve timestamps and separate the three. |
| Sender SMTP and queue logs | Candidate MX, retry or final disposition of the specific recipient on the hop, where the product exposes it. |
| Receiver or downstream trace | Whether that gateway accepted, rejected or forwarded the message across later stages. |
| TLS-RPT JSON | Per-reporter, policy-domain and time-window aggregate TLS observations. Counters summarize sessions and can include repeated attempts for the same email. |

Read the reporter identity, `report-id`, UTC `date-range` and each policy entry before reviewing counts. `policy-type: sts` indicates an MTA-STS policy entry. `no-policy-found` indicates the reporter did not find an applicable DANE or MTA-STS policy for that entry. Reports normally cover a UTC day and may arrive later. Use `total-failure-session-count` for the policy’s summary. Several failure-detail categories may describe the same attempt, so adding details can overcount. No report can mean the sender did not participate, no report was generated, or delivery to the reporting endpoint failed. It is insufficient evidence of perfect TLS coverage.

## 4. Collect, detect and respond

1. Start with the affected domain, UTC window, direction and known queue or trace identifier. Obtain sender logs with MX, selected IP, policy status, TLS result and retry/acceptance fields where available. Track the recipient per hop. Restrict access to message identifiers and recipient data.
2. Compare approved DNS and policy history, sender cache and MX certificate changes. Check all active and backup MX hosts and any intervening gateway. Record policy mode and relevant TTL or cache lifetime rather than assuming an update was instantaneous.
3. Baseline report coverage by reporter and domain. Alert on sustained increases in policy failures or on a reporting gap from a previously consistent source. Verify reporter provenance and de-duplicate retransmitted reports within reporter and report ID. Treat report data as untrusted and keep parsing separated from any automatic containment action.
4. If mail is delayed, preserve queues, policy evidence and the affected logs, then coordinate repair with DNS, PKI and mail owners. After repair, confirm both a known delivery through an eligible MX and recovery in sender retry logs. Reports may lag behind the repair.

Microsoft documents that Exchange Online applies outbound MTA-STS for protected destinations and exposes aggregate outbound transit security data in the Exchange admin center. Confirm scope and role permissions before using the product report. It does not substitute for per-recipient message tracing or a sender-side policy record.

## 5. Offline exercise with fictional observations

Save the <a href="{{ '/assets/labs/smtp-mta-sts-evidence.py' | relative_url }}" download="smtp-mta-sts-evidence.py">Python script</a> and <a href="{{ '/assets/labs/smtp-mta-sts-evidence-cases.json' | relative_url }}" download="smtp-mta-sts-evidence-cases.json">fictional JSON</a> together. Run on your own approved workspace with Python 3. For each case the input supplies policy fetch or cache status and validation outcomes for one candidate. The exercise identifies what MTA-STS alone implies. It neither sends mail nor validates real certificates. The last line summarizes one synthetic TLS-RPT policy entry.

```bash
python3 smtp-mta-sts-evidence.py smtp-mta-sts-evidence-cases.json
```

```text
normal: live:eligible_for_smtp
backup_outside_policy: live:blocked_candidate
no_starttls: live:blocked_candidate
testing_bad_certificate: live:testing_failure
cache_outage: cache:blocked_candidate
expired_cache: no_policy:no_sts_enforcement
retired_policy: live:no_sts_enforcement
handshake_failed: cache:blocked_candidate
tls_report: failures=3 detail_sum=4
```

The report’s two failure types overlap in the fixture. Use three as the reported total. For a file error, check both filenames and the working directory. For an unexpected decision, check whether an unexpired cached policy was available and which validation failed. Python was run on these inputs. Mail server execution, HTTPS policy fetch and Exchange Online behavior were reviewed through documentation and require independent product testing.

## 6. Check your understanding

- **Does an enforce failure prove there was an attack?** Compare candidate MX, certificate, policy cache and change history for maintenance, configuration drift and path interference.
- **The DNS record has disappeared. Can senders still enforce?** Yes, an unexpired cached policy can still apply. Check the sender’s state.
- **A report counts three failed TLS sessions. Were three emails lost?** The number describes sessions. Examine message and queue evidence to determine final delivery.

Finish when you can explain the difference between `cache_outage` and `expired_cache`, match all nine output lines, and name the source needed to verify message acceptance.

## Official references

Reviewed 2026-11-22. RFC 3207 defines the SMTP extension, the 2018 standards define MTA-STS and TLS reporting, and the vendor docs describe the stated Exchange Online scope.

- SMTP upgrade and security considerations. [IETF RFC 3207 (2002)](https://www.rfc-editor.org/info/rfc3207/)
- Discovery, cache, modes, host validation and downgrade limits, sections 3–5 and 10. [IETF RFC 8461 (2018)](https://www.rfc-editor.org/info/rfc8461/)
- Reporting windows, aggregates and failure categories, section 4. [IETF RFC 8460 (2018)](https://www.rfc-editor.org/info/rfc8460/)
- DNSSEC/TLSA for SMTP. [IETF RFC 7672 (2015)](https://www.rfc-editor.org/info/rfc7672/)
- Inbound/outbound behavior and portal reporting. [Microsoft Learn · MTA-STS](https://learn.microsoft.com/en-us/exchange/security-and-compliance/enhance-mail-flow-using-strict-transport-security) · [Outbound transit security](https://learn.microsoft.com/en-us/exchange/monitoring/mail-flow-reports/outbound-messages-in-transit-security-report)

[Previous · SMTP delivery evidence]({{ '/wiki/smtp-delivery-evidence/' | relative_url }}) · [Next · TLS handshake evidence]({{ '/wiki/tls-handshake-evidence/' | relative_url }})

## SMTP DANE and TLSA

Compare the sending resolver’s DNSSEC result with the MX certificate association in [SMTP DANE and TLSA]({{ '/wiki/smtp-dane-evidence/' | relative_url }}).
