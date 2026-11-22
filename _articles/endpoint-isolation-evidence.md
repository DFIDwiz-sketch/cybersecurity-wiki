---
title: "Endpoint Isolation Evidence · Verify Containment on the Tested Path"
description: "Distinguish an isolation request, product confirmation and independently observed enforcement with ten fictional incident-response cases."
category: dfir
tags: [Incident Response, Endpoint Isolation, DFIR, Blue Team, EDR, Microsoft Defender]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/endpoint-isolation-evidence/
---

An analyst sees **Succeeded** in a response console while a firewall entry seems to show the device is still communicating. Which evidence should drive the next action? This chapter presents a way to establish when the action completed, what it was meant to cover, and what the network actually observed. The [Windows incident response exercise]({{ '/wiki/windows-incident-response-lab/' | relative_url }}) provides a wider case timeline.

## 1. What network isolation controls

**Endpoint isolation** applies a product policy intended to restrict network communications for a named device. **Containment** is broader. An investigation might also need account, session or network controls and separate evidence of their effects. Isolation is commonly designed to retain a management path. The flows permitted and the dependencies required to keep management online vary by product, scope and configuration.

An **action record** belongs to the management plane. It records a request and its status. An independent **network observation** can show what actually traversed a monitored path or arrived at a destination. A test result is scoped to its device, time, path, protocol, direction and observer. Record these fields before you generalize.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/endpoint-isolation-evidence-en.svg' | relative_url }}" alt="Start with the request and correct device. For pending or failed status, check device reachability and action details. After success, compare the network path and event time and state the tested scope and gaps.">
  <figcaption>A confirmed action opens the next question about enforcement. Keep the control record and the network evidence together.</figcaption>
</figure>

| Evidence | What you can say | What you still need |
| --- | --- | --- |
| Request ID and request time | Management accepted or recorded a request | Current status for that action and device |
| Product status `Succeeded` | The product reports completion for that scope | An aligned test or observation of the path |
| Matching firewall deny or endpoint block | The named observer recorded a deny or block | Correct source, direction, rule and destination |
| Fresh transaction at the destination | The matching operation reached that point | Attribution, scope or exception, and what ultimately completed |
| Quiet console or absent flow | The selected view returned no matching evidence | Observer health, coverage and an independent check |

## 2. Follow a clean isolation timeline

Fictional laptop `D-17` completes an approved test transaction at 14:00 UTC against an owned lab service. At 14:02 a responder submits isolation and saves the action ID. The management console reports `Succeeded` at 14:04. At 14:05 a fresh transaction to the same expected-block destination is denied. The investigator matches the deny to the device and expected policy, confirms the destination's logging still works through a separate control host, and records a fresh endpoint management heartbeat. The resulting statement is bounded. Isolation was reported applied, the tested transaction was blocked, and the management path remained available at the observed time.

A flow generated at 14:03 and received by the collector at 14:07 is earlier than the 14:04 confirmation, even though it appears in the dashboard later. Save both times as well as the timezone and estimated clock error. When clocks or sampling intervals overlap the boundary, report uncertain order. Flow records can summarize intervals and previously established sessions. A fresh application-level transaction with a unique correlation ID provides stronger evidence of new activity than an isolated packet or an aggregate counter.

## 3. Read Microsoft Defender action records

For Microsoft Defender for Endpoint, the isolate API documents HTTP **201 Created** plus a `MachineAction` response. Check that record's `id`, `machineId`, `type`, `scope`, `status`, `creationDateTimeUtc` and `lastUpdateDateTimeUtc`. The last field describes a status update. Use the action history and device evidence to refine enforcement timing when available. `Pending` and `InProgress` need follow-up. `Failed`, `TimeOut` and `Cancelled` require investigation and a new decision before reporting completion.

Microsoft documents retries for up to three days when a device is inactive or offline at submission. Use current device connectivity and action history to distinguish queued work from completion. Check the actual applied scope and exclusions, when supported, in Action center history. Compare a later release action or other product lifecycle event to the traffic time. Platform, agent and VPN configuration can affect reachability. Use the deployed platform and policy to interpret management traffic. No Defender API calls or tenant actions are needed for this chapter's lab.

## 4. Collect, verify and respond

1. **Define the expected boundary.** Record stable device ID, inventory history, host and incident owner, intended scope, allowed management dependencies and an owned test destination. Normalize event time, status-update time and ingest time separately. DNS name and IP address can be reused. Check lease, NAT, interface or inventory evidence before attributing a network observation.
2. **Check the observers.** Preserve the action timeline and source records. On the network side, collect connection time, interface or segment, direction, protocol, endpoint tuple, rule decision and observer coverage. On the receiving side, use logs or a small approved transaction whose fresh ID is visible at the destination. Prove that the logging path is healthy with a separate permitted control, and record gaps as unknown. See [endpoint collection evidence]({{ '/wiki/endpoint-collection-evidence/' | relative_url }}) for checking whether observations arrived.
3. **Triage unexpected activity.** Classify a completed transaction on an expected-block path after reliable confirmation as a containment gap to investigate. First rule out stale records, incorrect device mapping, approved exceptions, and a scope change or subsequent release. A genuine gap is possible even while the product reports success. A mismatch alone gives no reliable attribution of cause or intent.
4. **Record the next decision.** Preserve evidence, notify the incident lead and coordinate any additional approved containment with the device and network owners. Check the separately scoped identity or session controls if relevant. Before reconnecting, obtain the recovery decision, verify the release action and define a monitoring window for renewed activity. Preserve the timeline even when a dashboard status changes.

For joint defender and validation exercises, use only an owned, isolated environment and a benign destination within the written scope. Document baseline success, expected blocked transaction, expected permitted management signal, and control-observer success. Agree on a recovery path and an owner capable of restoring the disposable test device before applying any approved controls. The downloadable exercise below is entirely offline.

## 5. Offline exercise · ten fictional observations

Download both files into one folder and run the listed command with Python 3.10 or later. The JSONL contains **synthetic normalized summaries**, not a product export. `match` represents an already verified device-and-path association. `observer_ok` represents usable coverage for the precise observation. `action_updated` is the time of the success confirmation in the fixture, while `observed_at` is the source event time. All numeric times are relative seconds. The script reads local files and performs no network or endpoint actions.

<a href="{{ '/assets/labs/endpoint-isolation-evidence.py' | relative_url }}" download="endpoint-isolation-evidence.py">endpoint-isolation-evidence.py</a> · <a href="{{ '/assets/labs/endpoint-isolation-evidence-cases.jsonl' | relative_url }}" download="endpoint-isolation-evidence-cases.jsonl">endpoint-isolation-evidence-cases.jsonl</a>

```bash
python3 endpoint-isolation-evidence.py endpoint-isolation-evidence-cases.jsonl
```

```text
blocked_in_scope: blocked_in_test_scope
offline_pending: await_enforcement_evidence
timed_out: inspect_action_failure
permitted_management: expected_exception
late_ingest: before_confirmation
other_device: wrong_device_or_path
unexpected_success: investigate_unexpected_success
observer_blind: insufficient_observation
time_boundary: time_order_uncertain
release_afterward: after_release
```

In `late_ingest`, the result is based on source event time, even though `received_at` is later. In `time_boundary`, the times have the same precision so the event order is unresolved. If the command fails, check the working folder and filenames. If an exercise result differs from your expectation, check the association, observer health and action chronology before interpreting the outcome. The fixture was executed with Python 3.12. Defender behavior was reviewed against official documentation.

## 6. Check your reasoning

- **Does a 201 response prove the network path was cut?** It records creation of the response action. Check action status and a path-level observation.
- **Why can a management heartbeat be expected after isolation?** The applied policy can preserve a service-management path. Confirm it belongs to the verified device and authorized policy scope.
- **Does an empty sensor response verify a block?** It gives no result from that view. Check that the observer could see the relevant traffic and compare with a destination or an explicit deny.

Complete the exercise when all ten outputs match and you can name the next evidence source for `observer_blind` and `unexpected_success`. Write a one-sentence conclusion for `blocked_in_scope` that names the device, path, period and any remaining limitation.

## Official references

Reviewed 2026-11-22. Microsoft references apply to the documented Defender plans, versions and features. Verify the operating platform and policy on the affected device.

- April 2025, incident response in CSF 2.0. Supersedes Rev. 2. [NIST SP 800-61 Rev. 3](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- November 2025 API reference for the HTTP response and action scope. [Microsoft Learn · Isolate machine API](https://learn.microsoft.com/en-us/defender-endpoint/api/isolate-machine)
- Defender action resource schema and status values. [Microsoft Learn · MachineAction](https://learn.microsoft.com/en-us/defender-endpoint/api/machineaction)
- 2026 product guidance for isolation, offline endpoints and platform prerequisites. [Microsoft Learn · Device response actions](https://learn.microsoft.com/en-us/defender-endpoint/respond-machine-alerts)
- Defender selective isolation exclusions and applied policy history. [Microsoft Learn · Network isolation exclusions](https://learn.microsoft.com/en-us/defender-endpoint/network-isolation-exclusions)

[Previous · Windows incident response]({{ '/wiki/windows-incident-response-lab/' | relative_url }}) · [Related · Endpoint collection]({{ '/wiki/endpoint-collection-evidence/' | relative_url }}) · [Related · Detection validation]({{ '/wiki/detection-validation/' | relative_url }})
