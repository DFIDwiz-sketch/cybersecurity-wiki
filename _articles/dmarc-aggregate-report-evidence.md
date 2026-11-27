---
title: "DMARC Aggregate Reports · Read Alignment, Volume, and Policy Overrides"
description: "Read DMARC aggregate XML, compare authentication and alignment, and investigate unexpected sender routes without double-counting reports."
category: network
tags: [Email Security, DMARC, DMARC Reporting, SPF, DKIM, DNS, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/dmarc-aggregate-report-evidence/
---

An email team sees a spike in DMARC failures after moving its billing platform. A receiver's daily report shows SPF passing on part of that traffic. Before changing DNS, check which domain passed SPF, which domain customers saw, and what the receiver did. An aggregate report helps you distinguish an unaligned vendor, an expected forwarding path, and traffic that needs an incident investigation.

## 1. What the report measures

DMARC checks whether a validated identity from SPF or DKIM **aligns** with the domain in the visible `From` header. For ordinary mail with a nonempty SMTP reverse-path, SPF evaluates the envelope sender domain against the IP that connected to the receiver. DKIM validates a signature associated with the signature’s `d=` domain. Strict alignment requires the same domain. Relaxed alignment permits identities with the same Organizational Domain, as determined by the discovery rules the receiver uses. Either aligned pass can satisfy DMARC.

A **Mail Receiver** is the service that evaluates incoming messages and may send aggregate feedback. A **Domain Owner** can request that feedback via `rua` in its DMARC DNS record. The **Author Domain** is the visible From domain. The **Policy Domain** is where the receiver found the DMARC policy it used and may be a parent of the Author Domain. A report summarizes observations for one Policy Domain and can contain several From domains under that policy.

<figure>
  <img src="{{ '/assets/diagrams/dmarc-aggregate-report-evidence.svg' | relative_url }}" width="560" height="338" alt="SPF and DKIM produce authentication results. The receiver checks alignment with the visible From domain, applies DMARC and local policy, then groups observations in XML. Delivery evidence is collected separately.">
  <figcaption>Read the two levels of evaluation in the XML. Investigate delivery separately using the receiver’s message trace.</figcaption>
</figure>

## 2. Open one report in the right order

1. Identify the reporting service and check the report ID and UTC window in `report_metadata`. `date_range.begin` and `date_range.end` are Unix seconds and describe the reporting interval. They cannot place an individual message at an exact time.
2. Read `policy_published` for the policy observed by that receiver. Record the Policy Domain and relevant `p`, `sp`, alignment modes, and testing status if present. Compare those values with the change record and DNS answers from the incident window. A TXT lookup today answers a different question.
3. Read each `record`. Its `row.count` reports how many messages the row represents, and `row.source_ip` is the connecting mail server as seen by this receiver. Repeat appearances of one IP can represent different From domains or outcomes.
4. Compare the identifiers and authentication results, then read the receiver’s alignment and disposition. Use the supplied alignment fields for report analysis. Reconstructing historical alignment independently also requires the receiver's discovery rules and the DNS evidence from that time.

| XML field | What it tells you | Where to look next |
| --- | --- | --- |
| `identifiers.header_from` | Visible From domain under evaluation | Domain and subdomain inventory |
| `auth_results.spf` and `auth_results.dkim` | Domains and underlying validation results before DMARC interpretation. DKIM can list multiple signatures. | Envelope sender and DKIM signing domain or selector in the vendor configuration |
| `row.policy_evaluated.spf` and `.dkim` | The receiver’s two DMARC alignment outcomes | Check whether either method supplied an aligned pass |
| `row.policy_evaluated.disposition` and `.reason` | Reported DMARC treatment and the override reason when supplied | Receiver-side message trace for SMTP acceptance, filtering, or placement |
| `row.source_ip` and `.count` | Connecting mail server and volume for this row | Approved sender inventory, relay logs, and known forwarding paths |

## 3. Work through a normal report and a suspicious row

The downloadable fictional report covers one receiver during 2026-11-26 UTC. Its policy domain is `example.com`, its Author Domain is `orders.example.com`, and it reports `p=reject`.

| Connecting IP | Count | Raw evidence | Alignment and reported treatment |
| --- | ---: | --- | --- |
| `192.0.2.10` | 240 | Vendor SPF passes for `bounce.vendor.example.net`. DKIM passes for `orders.example.com`. | SPF fails alignment. DKIM passes alignment. DMARC passes. |
| `198.51.100.20` | 12 | Forwarder SPF passes for `forward.example.org`. Original DKIM fails. | Neither aligns successfully. Disposition `none`, reason `mailing_list`. |
| `203.0.113.30` | 5 | An unrelated envelope domain passes SPF and an unrelated DKIM signature also passes. | Both fail alignment with `orders.example.com`. Disposition `reject`. |
| `192.0.2.11` | 3 | SPF passes for `orders.example.com`. DKIM fails. | SPF provides the aligned pass. DMARC passes. |

The aligned-pass share is **243 / 260 = 93.46%** for this report. The 12 and 5 count toward the 17 without an aligned pass. Only 5 carry the reported DMARC disposition `reject`. The row of 12 can be consistent with a mailing-list override. A receiving system's reason is evidence of its reported decision and leaves the exact ARC and delivery evidence to that system.

The row of 5 merits review. A sender can validate its own unrelated identity while putting your domain in the visible From field. Misconfigured legitimate services can also produce this pattern. An already authorized sender or a visually similar domain can send harmful mail that passes DMARC for the domain actually evaluated. Validate the business request and inspect trusted message evidence before concluding impersonation or compromise.

## 4. Collect, detect, and respond

- **Collect through an approved `rua` route.** Confirm that participating receivers can deliver to the mailbox or report service. When the destination is outside the policy domain’s organization, verify external destination authorization as described in RFC 9990 §4. Monitor receipt, parsing failures, and missing windows by reporter. Apply size limits to compressed and decompressed material, use a parser with external resources and document type declarations disabled, and restrict access to XML and sender-infrastructure metadata. Validate claimed reporter provenance against trusted inbound mail evidence before using an unexpected report in policy decisions.
- **Normalize without inflating counts.** Preserve reporter, the report ID, domain, window, and a file fingerprint. Deduplicate a retransmitted report in the context of its verified reporter and Policy Domain. Hold conflicting copies and overlapping windows for that same scope until reviewed. Keep separate receiver series separate during triage. Sum `count`, not XML row totals, and label report coverage and the denominator when quoting a percentage.
- **Investigate a change in the expected routes.** Compare failure volume and rate against a baseline for the same reporter and From domain. Break down by connecting server, signing domain or selector, and override reason. Correlate a new IP or selector with onboarding and DNS change tickets, relay logs, and a sample of trusted `Authentication-Results`. Shared provider IPs and missing reports each limit the inference. A missing report may reflect an opted-out receiver, late delivery, a DNS authorization problem, or an ingestion failure.
- **Respond proportionally.** If a legitimate vendor passes only with its own domain, work with the mail owner to enable aligned DKIM or an aligned envelope domain supported by the provider. If evidence points to unauthorized use, preserve representative messages and receiver decisions and coordinate with the mail abuse team. Track affected legitimate senders and delivery before and after any policy change. A single report is insufficient reason to change the entire domain’s policy.

RFC 9989 (May 2026) replaces the RFC 7489 scheme and removes `pct`. Its `t` tag expresses testing status and is not a percentage. RFC 9990 specifies a namespaced XML format and permits a `discovery_method` field, including `psl` or `treewalk`. Expect mixed formats during receiver migration and check the observed report and provider behavior before relying on new tags. For example, Gmail’s published sender guidance recommends aggregate reports for monitoring and permits a DMARC policy of `none` to meet the DMARC policy component of its bulk-sender requirement. This is provider guidance, with separate authentication and delivery requirements.

## 5. Offline exercise · Count and verify

Use Python 3.9 or later in a directory you control. Save these files with their listed names. All inputs are fictional. The script reads plain UTF-8 XML fixtures and makes no DNS or SMTP requests. It accepts the RFC 9990 namespace and one unnamespaced legacy format and checks the fields used in this lesson. It does not validate the full schema or authenticate incoming mail.

- <a href="{{ '/assets/labs/dmarc-aggregate-report-evidence/review.py' | relative_url }}" download="review.py">Download review.py</a>
- <a href="{{ '/assets/labs/dmarc-aggregate-report-evidence/daily.xml' | relative_url }}" download="daily.xml">Download daily.xml</a>
- <a href="{{ '/assets/labs/dmarc-aggregate-report-evidence/legacy.xml' | relative_url }}" download="legacy.xml">Download legacy.xml</a>

```sh
python3 review.py daily.xml daily.xml legacy.xml
```

Expect 260 messages, 243 with an aligned pass, 17 without one, and 5 reported rejects in `daily.xml`. Two rows lack an aligned pass despite at least one raw pass. The exact duplicate contributes no second total. The separate legacy report shows 20 aligned passes and zero rejects. As a check, copy the daily XML to `changed.xml`, substitute `241` for the count `240`, and run `python3 review.py daily.xml changed.xml`. The script should report a conflict and exit 1. Try again after also changing its report ID. It should hold the overlapping window. If the original run fails, confirm that your downloads are plain XML with the expected namespace and that all three files are in the current directory.

The cloud run exercised the fixtures, duplicate handling, conflicting copies, and overlapping windows. Provider behavior was checked against published documentation.

## 6. Check your understanding

1. **SPF passes for the vendor but SPF alignment fails. Can DMARC pass?** Yes, when a verified DKIM signature aligns. The fictional report has 240 such messages.
2. **A row has 12 failures and disposition `none`. Did 12 messages arrive in inboxes?** The row reports no DMARC disposition action for those messages. Check message traces for acceptance and final placement.
3. **An unfamiliar IP reports several rejects. Is it the original sender or the person behind the mail?** It is the connecting mail server seen by the reporter. Establish its role from logs and investigate any individual message with trusted headers and traces.

You are done when you can reproduce the counts, explain the denominator, identify what a duplicate would inflate, and write separate conclusions about authentication, alignment, policy treatment, and delivery. Aggregate `rua` reports cover grouped observations. Optional `ruf` failure reports have different privacy implications and may be unavailable even when requested.

## Official references

Reviewed 2026-11-27. Standards scope is the May 2026 DMARC suite, with legacy report context from March 2015. Provider scope is the sender guidance published for personal Gmail accounts as of the review date.

- IETF [RFC 9989 §4.4 · Alignment](https://www.rfc-editor.org/rfc/rfc9989.html#section-4.4) and [Appendix A.6 · Replacement of percentage-based testing](https://www.rfc-editor.org/rfc/rfc9989.html#appendix-A.6).
- IETF [RFC 9990 · Aggregate report fields, identifiers, external destinations and security](https://www.rfc-editor.org/rfc/rfc9990.html) and [RFC 9991 · Failure reporting](https://www.rfc-editor.org/rfc/rfc9991.html).
- IETF [RFC 7489 · Historical DMARC reporting format](https://www.rfc-editor.org/rfc/rfc7489.html#appendix-C).
- Google [Gmail sender guidelines · Authentication and DMARC](https://support.google.com/mail/answer/81126).

[Previous · Sender authentication and message headers]({{ '/wiki/mail-auth-evidence/' | relative_url }}) · [Next · ARC and forwarded mail]({{ '/wiki/arc-forwarding-evidence/' | relative_url }}) · [Trace delivery for an individual recipient]({{ '/wiki/smtp-delivery-evidence/' | relative_url }})
