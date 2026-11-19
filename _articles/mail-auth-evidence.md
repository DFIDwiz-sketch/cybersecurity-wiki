---
title: "Email Sender Authentication and Phishing Investigation"
description: "Interpret SPF, DKIM, DMARC and alignment through five synthetic receiver cases."
category: network
tags: [Email Security, DNS, Blue Team, DFIR, SPF, DKIM, DMARC]
level: Beginner
updated: "2026-11-19"
translation_url: /ko/wiki/mail-auth-evidence/
---

## A message carries several sender identities

The SMTP envelope contains MAIL FROM for bounce handling and RCPT TO for requested delivery. The visible From is a message header. Reply-To directs replies. An order notification provider may use its bounce domain while retaining a customer’s visible author domain. SMTP acceptance, mailbox delivery and a recipient following a link are separate events.

![SMTP envelope and message → Receiver · SPF / DKIM → DMARC · From alignment → Receiver · deliver / quarantine / reject]({{ '/assets/diagrams/mail-auth-en.svg' | relative_url }})

## Read SPF, DKIM and DMARC

| Check | What it evaluates | Identity to record |
| --- | --- | --- |
| SPF | Whether the connecting IP is authorized by the SMTP sender policy | MAIL FROM domain. A null reverse path uses the HELO identity |
| DKIM | Whether the signed header and body scope validates | Signing domain d= and DNS key selector s= |
| DMARC | Whether at least one passing SPF or DKIM identity aligns with From | Author domain, passing mechanism and aligned domain |

**Alignment** compares an authenticated identity to the visible From domain. Strict alignment requires equality. Relaxed alignment compares Organizational Domains discovered under the applicable standard. SPF and DKIM can each pass without either identity aligning. Aligned DKIM can yield a DMARC pass even when SPF fails.

For ordinary outsourced notifications, assume From is orders.example.test and SPF passes for mailer.example.test. Strict SPF alignment fails. A passing DKIM signature from orders.example.test aligns. Reading DNS later gives current policy. Preserve receiver results and configuration history to establish the policy at receipt.

**Current standard:** RFC 9989 (May 2026) supersedes RFCs 7489 and 9091 and defines DNS Tree Walk for policy and Organizational Domain discovery. Verify deployed behavior when interpreting older public-suffix-list guidance. The p=none, quarantine and reject values signal the domain owner’s preferences. Verify actual delivery, quarantine or rejection in receiver evidence.

## Compare misuse hypotheses with ordinary explanations

| Observation | Possible cause | Evidence to check |
| --- | --- | --- |
| SPF fails after forwarding | Forwarder IP falls outside original policy | Trusted Received hops and forwarding path |
| DKIM fails after a mailing list | Covered subject or body changed | Relay evidence and signature coverage |
| DMARC fails | Spoofing candidate or misconfigured legitimate service | Approved sender list and alignment results |
| DMARC passes for a familiar-looking From | Lookalike authenticates as its own domain | Exact From domain and sending authorization |
| Risky link from a legitimate domain | Account or sending service may be abused | Session, mail audit and click evidence |

The domain 0rders.example.test resembles orders.example.test and can pass authentication for its own identity. Confirm payment or bank changes using an established contact channel. Preserve link text and actual destination separately.

## Blue-team investigation

1. Acquire the original message and headers through approved mailbox or gateway access. Record UTC, internal trace ID, Message-ID, recipient and disposition. Corroborate Message-ID using time, recipient and internal trace ID.
2. Find Authentication-Results written by the trusted receiving boundary. Check the authorized authentication service identifier and header handling. Separate external copies of the header from trusted output. Read Received from a known receiver boundary.
3. Check provider-specific fields and confirm generation and ingestion with an ordinary message. Compare increased failures for protected domains against a baseline and approved forwarding or vendor changes.
4. When evidence supports phishing, use trace records to scope mailboxes and quarantine under local policy. Check proxy, endpoint and account sessions where a click or credential entry is indicated. Protect original messages and any private information.

## Offline exercise and answer key

[mail-auth.csv]({{ '/assets/labs/mail-auth.csv' | relative_url }}) · [mail-auth.py]({{ '/assets/labs/mail-auth.py' | relative_url }})

Keep the files together and run using Python 3. Use precomputed synthetic checks to compare strict alignment.

```bash
python3 mail-auth.py
```

| Case | Expected result |
| --- | --- |
| A | Aligned SPF passes |
| B | Both checks pass but strict alignment fails |
| C | Aligned DKIM passes despite SPF failure |
| D | A separate lookalike aligns through both checks |
| E | A transient error leaves the worksheet unresolved |

Expect PASS and printed receiver dispositions. Check filenames and folder if loading fails. Assess relaxed alignment in B using the applicable Organizational Domain calculation. For E, check the retry and disposition in receiver logs. This run verified the offline CSV exercise. Live DNS, signature verification and vendor logging require separate validation.

**Completion criteria:** Record the envelope, header and signing identities. Explain the results in B and D and document the lookalike concern separately. In an authorized environment, match one ordinary test message’s trusted authentication header to mailbox trace evidence.

[DNS]({{ '/wiki/dns-investigation/' | relative_url }}) · [Previous · HTTP logs]({{ '/wiki/http-evidence/' | relative_url }})

## Official references

Reviewed 19 November 2026. Verify behavior in the deployed receiver.

- [SMTP · RFC 5321, 2008](https://www.rfc-editor.org/rfc/rfc5321.html)
- [SPF · RFC 7208, 2014](https://www.rfc-editor.org/rfc/rfc7208.html)
- [DKIM · RFC 6376, 2011](https://www.rfc-editor.org/rfc/rfc6376.html)
- [DMARC · RFC 9989, 2026](https://www.rfc-editor.org/rfc/rfc9989.html)
- [Authentication-Results · RFC 8601, 2019](https://www.rfc-editor.org/rfc/rfc8601.html)
