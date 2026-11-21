---
title: "ARC and Forwarded Mail · Verify the Chain and the Receiver's Decision"
description: "Distinguish direct DMARC, the ARC chain, trusted sealer policy and final message delivery with eight offline cases."
category: network
tags: [Email Security, ARC, DMARC, SMTP, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/arc-forwarding-evidence/
---

**Learning goal.** Given an indirectly delivered message, explain what the final gateway verified, which earlier assessment it considered, and whether that assessment influenced actual handling. Start with [SPF, DKIM and DMARC evidence]({{ '/wiki/mail-auth-evidence/' | relative_url }}) to review alignment.

## 1. Why forwarding changes authentication evidence

A **forwarder** receives mail and sends it onward. A **mailing list** can also alter the message, for example by adding a footer. At the next receiver, SPF checks the relay that actually made the SMTP connection against the applicable envelope identity. The original sender's SPF result may therefore fail or the passing envelope domain may be unaligned. When a list changes content covered by the original DKIM signature, that signature can fail. If the final receiver finds neither an aligned SPF nor an aligned DKIM pass, direct DMARC evaluation can fail even though the previous receiver found a pass.

**Authenticated Received Chain (ARC)** lets participating handlers attach signed records of earlier authentication assessments and handling. A **sealer** is the handler that adds a set. Each set has a shared instance number `i=`. The numbers describe the order of ARC sets. Mail can pass through other systems that add no set. A receiver evaluates the received chain cryptographically and separately decides whether the recorded assessment is trustworthy and relevant to its policy.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/arc-forwarding-en.svg' | relative_url }}" alt="An origin sends to a forwarder, which records its earlier checks and seals the forwarded message. The final receiver evaluates local DMARC and validates the ARC chain separately, then checks sealer trust and records an action.">
  <figcaption>Read the forwarding record and the final receiver's direct checks as separate observations. Trust and delivery are decisions made at the receiving system.</figcaption>
</figure>

## 2. Read the three ARC headers

| Header | What it records | What to check |
| --- | --- | --- |
| `ARC-Authentication-Results` (AAR) | The participating handler's recorded assessment, such as SPF, DKIM and DMARC on arrival | Instance number, authentication service, tested identifiers and their relation to the visible From |
| `ARC-Message-Signature` (AMS) | A DKIM-like signature over covered headers and body of the message the handler seals | Which instance and signing domain appear, plus the verifier's outcome |
| `ARC-Seal` (AS) | A signature binding the ARC set and, for a passing sequence, previous sets. It carries the sealer domain and `cv=`, the sealer's chain assessment. | Verify the chain and the sealer's identity at the receiving boundary |

In a valid sequence the first set has `cv=none` because there was no preceding chain. Later seals can report `cv=pass` for the chain they processed. Treat that text as a claim from the sealer. The final receiver's own validation result is a separate observation. RFC 8617's verifier checks the set structure, the most recent AMS and the ARC seals. A prior AMS can no longer match a legitimately modified message, so a current chain pass does not require every older AMS to match the final bytes. Chain validation says which cryptographic checks succeeded. Trust in the handler's assessment and its operational controls is a local policy decision.

## 3. Follow a normal mailing list case

In a fictional example a bill notice from `billing.example.test` arrives at an approved relay with aligned DKIM and DMARC pass. The relay records that assessment, adds a list footer and seals its outgoing version. On the onward hop the relay uses its own envelope domain. At the final mailbox provider, SPF passes for that domain but is unaligned with the visible From. The old DKIM body signature fails. Direct DMARC reports fail. The provider validates ARC, recognizes the approved sealer, records use of the earlier pass under its own policy and delivers the message. Record all four facts. Delivery alone does not identify which policy was applied.

| Observation at the final receiver | Supported interpretation | Next evidence |
| --- | --- | --- |
| Direct DMARC fail and ARC pass from a trusted sealer | Valid chain and local trust may make prior results relevant | Check the prior identifiers, explicit receiver decision reason and trace action |
| Direct DMARC fail and ARC pass from an unrecognized sealer | Signatures can be valid while trust in the assessment is unresolved | Verify the connector and approved provider records |
| ARC fail after forwarding | Received chain could not be validated | Check modifications, incomplete export, structure, DNS/key lookup or verifier diagnostics |
| An email contains `Authentication-Results` that claims pass | Text in the message alone cannot identify who wrote it | Confirm the service within the recipient's trust boundary |
| Final trace says delivered | The trace recorded delivery at that stage | Check whether an ARC override or another policy applied, and where the message ended up |

An untrusted signer may attach a structurally valid chain containing claims the final receiver should not adopt. Body changes or lost headers can also break a legitimate chain. A valid chain does not validate a URL, attachment, sender display name or payment request. Use [SMTP delivery evidence]({{ '/wiki/smtp-delivery-evidence/' | relative_url }}) to confirm queue, handoff and recipient disposition independently.

## 4. Collect, distinguish and respond

1. Export the complete original held by an approved gateway or mailbox, preserving raw headers and bytes. Avoid pasting sensitive headers or message bodies into third-party analyzers. Record the recipient, UTC interval, route and gateway trace ID. Scope the message ID to the source and interval when correlating.
2. Identify the recipient-side service that stamped the trusted `Authentication-Results`. Compare its reported author domain and passing identities with the original From on that segment. Separate upstream claims from receiver assessment. An ordinary `Authentication-Results` header is reliable only when its producer and the boundary treatment are established.
3. Record the chain result from the verifier, the reviewed sealer policy, the prior assessment and whether the receiver explicitly recorded its use. If review happens later, note that DNS keys may change and an exported or redacted copy may not reproduce validation on receipt. Compare gateway and connector logs at the original time.
4. In Microsoft 365, Microsoft documents `arc=pass` with `oda=1` in its latest AAR as evidence of a verified, trusted prior sealer. In the provider-stamped Authentication-Results, `compauth=pass` with `reason=130` is its documented indicator that trusted ARC was used for an override. These are product-specific indicators. Check the stamped provenance and the tenant configuration, and confirm delivery with the message trace.
5. If a trusted path unexpectedly fails, isolate the affected connector and test an authorized benign message through each hop. Compare the full headers on both sides. Where a trusted intermediary is implicated in a compromise, involve the mail and security owners to correct trust and scope affected mail. Review URLs and attachments under the normal investigation policy before changing disposition.

## 5. Practice with eight fictional receiver records

Save [arc-forwarding-review.py]({{ '/assets/labs/arc-forwarding-review.py' | relative_url }}){: download="arc-forwarding-review.py" } and [arc-forwarding-cases.jsonl]({{ '/assets/labs/arc-forwarding-cases.jsonl' | relative_url }}){: download="arc-forwarding-cases.jsonl" } in the same directory in your own workspace. Use Python 3.12.

```sh
python3 arc-forwarding-review.py
```

The JSONL is a fictional analyst export using a reduced evidence model. `prior_aligned` records whether a prior aligned pass has been established in that model. A null value records missing information. `evidence_source` distinguishes receiver records from a claim found in the message. The script consumes pre-labeled outcomes. It performs no DNS lookups, cryptographic chain validation or policy changes.

| Case | Expected finding |
| --- | --- |
| A | Local DMARC fail, recorded trusted ARC override and delivery |
| B | Chain pass, sealer trust unconfirmed and quarantine |
| C | Chain fail, no supported override and rejection |
| D | Message-supplied claim. Receiver assessment and disposition remain unknown |
| E | Trusted prior pass and delivery. Override reason remains unconfirmed |
| F | Local DMARC pass without ARC. Disposition remains unknown |
| G | Trusted passing chain lacking an established prior aligned pass. Quarantine recorded |
| H | Recorded override conflicts with a failing chain. Recheck the evidence sources |

Expect eight lines. If the fixture is missing, check that both files are in the same directory. Preserve one complete JSON record per line. In a real investigation, an inconsistency like case H requires examination of timestamps, independent sources and producer identities before concluding anything about policy. We ran all eight cases with Python 3.12.14 and checked the exact outputs. ARC cryptography, Exchange Online and other mail gateway runtime behavior were outside the execution scope.

## 6. Check your understanding

1. **The final receiver reports ARC pass and direct DMARC fail. Which result is wrong?** Both can be correct. They describe different checks. Find the authenticated prior assessment, sealer policy and precise decision reason.
2. **The first seal says `cv=none`. Is the chain broken?** The first set has no preceding chain to validate. Look at the recipient's verification result for the received message.
3. **A message from an unfamiliar route was delivered. Was ARC used?** Delivery alone leaves the policy reason unknown. Correlate the trusted receiver verdict and message trace.

**Completion check.** Reproduce the eight results. For cases A and E, write the direct authentication result, chain validation result, sealer trust and decision reason separately. Explain which additional receiver evidence would resolve E.

## Official references

Reviewed 2026-11-22. RFC 8617 is an Experimental specification from July 2019. RFC 7960 describes historical forwarding interoperability under the older DMARC spec. RFC 9989, published May 2026, supersedes RFC 7489 and RFC 9091. Product indicators refer to Microsoft Learn as updated 2026-08-07.

- IETF [RFC 8617 · ARC sets, chain validation and local trust](https://www.rfc-editor.org/rfc/rfc8617.html) · [RFC 8601 · Authentication-Results trust boundary, May 2019](https://www.rfc-editor.org/rfc/rfc8601.html)
- IETF [RFC 7960 · Indirect email and DMARC interoperability, September 2016](https://www.rfc-editor.org/rfc/rfc7960.html) · [RFC 9989 · DMARC, May 2026](https://www.rfc-editor.org/rfc/rfc9989.html)
- [Microsoft Learn · Validate a trusted ARC sealer](https://learn.microsoft.com/en-us/defender-office-365/email-authentication-arc-configure#validate-a-trusted-arc-sealer)

[Previous · Mail authentication evidence]({{ '/wiki/mail-auth-evidence/' | relative_url }}) · [Next · SMTP delivery evidence]({{ '/wiki/smtp-delivery-evidence/' | relative_url }})
