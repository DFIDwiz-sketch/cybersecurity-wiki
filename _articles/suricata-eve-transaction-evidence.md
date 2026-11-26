---
title: "Suricata EVE · From a Rule Alert to the Right HTTP Transaction"
description: "Correlate EVE flow and transaction IDs, interpret per-rule actions and packet verdicts, and confirm outcomes with evidence beyond the alert."
category: network
tags: [Suricata, HTTP, Network Monitoring, Detection Engineering, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/suricata-eve-transaction-evidence/
---

**Learning goal.** Start with a Suricata rule alert, identify the HTTP transaction when the evidence supports it, and explain what the sensor and the application can each establish. Read [the Zeek, Suricata and Arkime comparison]({{ '/wiki/network-monitoring/' | relative_url }}) for the roles of the three tools.

## 1. Identify the flow and then the transaction

**EVE** is Suricata's JSON event output. A regular `eve.json` can mix event types such as `alert`, `http`, and `flow`. A **flow** is the sensor's tracked conversation. A **transaction** is an application exchange, such as an HTTP request and its associated response as the parser saw them. An HTTP/1.1 persistent connection can carry several requests. A connection match therefore gives you a set of candidates. In the HTTP/1.1 records used here, a shared top-level `tx_id`, when available, can select the transaction within that flow. `0` is a valid value.

Carry a stable **sensor and engine instance or replay dataset identifier** with each record. In this guide the collection metadata is called `sensor` and `run`, and the lab adds it outside the EVE object. Those names are examples, not mandatory EVE fields. Scope `flow_id` by the actual source and run used by your pipeline. Preserve exact integer IDs before storing them as text for correlation. A parser that rounds JSON numbers as binary64 can collapse neighboring large IDs. For other sensors, see [Community ID correlation]({{ '/wiki/community-id-evidence/' | relative_url }}) and verify observation point, tuple, replay scope and time before joining.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/suricata-eve-transaction-en.svg' | relative_url }}" alt="Start with an EVE alert scoped to sensor, run and flow ID. An available matching transaction ID identifies the HTTP record. Without it the flow supplies candidates only. Proxy or application evidence can establish the request outcome.">
  <figcaption>Scope the flow before comparing transaction IDs. Check the eventual outcome at the system that handled the request or enforced policy.</figcaption>
</figure>

## 2. Follow an ordinary connection

At 10:00 UTC an approved test client opens a persistent HTTP/1.1 connection to a demo portal. A benign marker rule fires near `GET /catalog`. The fictional alert and the `http` row have the same sensor, run, flow ID and `tx_id=0`. Suricata records status 200 on that HTTP row. Later on the same connection it records `GET /account`, `tx_id=1`, status 403. Reporting 403 as the marked request's response would pair the alert with the wrong transaction. An application request log can confirm how the portal processed the matching `/catalog` request. The HTTP status records an observed response on one hop.

| Source | Collect | Read it as |
| --- | --- | --- |
| EVE alert | `gid`, `signature_id`, `rev`, rule set, time, flow and optional transaction ID | Which rule condition matched in the observed direction |
| EVE HTTP | Same scoped flow, `tx_id` when emitted, method, host, path and response status if present | The exchange visible to the HTTP parser, within logging coverage |
| EVE flow | Start, end, direction counts, state and reason where present | Conversation context and direction. Read `flow.end` as the last observed packet time, which can precede the event's log time. |
| Proxy or application | Explicit hop, time, trusted request reference and response or state change | What that component handled and whether it can attest to an application outcome |

In an alert the outer packet endpoints can reflect the matching packet's direction. Use flow direction and the rule's conditions before assigning client and server roles. An HTTP row, alert metadata and a flow summary can describe overlapping observations, so three rows may represent one exchange rather than three requests.

## 3. Read the rule action and packet verdict separately

Suricata 8.0.8 distinguishes the alert's `alert.action` from the optional `verdict.action`. The first describes the action associated with that matching rule. The verdict describes the sensor's final decision for the packet, based on the applicable rules and conditions. An inline IPS can log `alert.action=allowed` for one signature and `verdict.action=drop` for that packet because another condition caused the drop. A passive IDS receives a copy of traffic. Record the deployment mode, actual path and rules before describing enforcement.

| Observation | Supported conclusion | Additional evidence |
| --- | --- | --- |
| `alert.action=allowed`; verdict absent | This alert reports allowed under that rule. Overall packet disposition is unobserved here. | Verify sensor configuration, other alerts or inline verdict records and path evidence. |
| `alert.action=allowed`; `verdict.action=drop` on inline IPS | The sensor reports dropping that packet. | Corroborate on the relevant path. Whether the application saw an earlier attempt or retry is a separate check. |
| Alert and HTTP 2xx on the same transaction | A rule matched and the sensor saw a successful class of HTTP response. | Inspect rule scope, proxy provenance, application logs and host evidence for any claimed compromise. |
| Alert with neither HTTP row nor clear enforcement | The matched pattern is visible. The HTTP outcome is unknown. | Verify logging, parser coverage and capture integrity. |

A generic marker in user-controlled HTTP data can match in legitimate testing or in an intrusion. An attacker can also submit ordinary-looking strings. Preserve the actual rule ID and revision, match direction and packet or request reference. Use the rule and the full request context to check for benign explanations. Signature text, user-agent strings and port numbers carry limited attribution on their own.

## 4. Collect enough evidence to make a decision

1. Identify the sensor, interface or capture, engine version, ruleset revision, run and UTC range. Preserve raw EVE alongside the parsed fields. Document restart boundaries and expected clock error before correlating.
2. Check that `alert`, `http` and `flow` event types are enabled on the relevant EVE outputs, and inspect all files if threaded or multiple outputs are in use. Suricata 8.0.8 documents `extended: yes` under the EVE `http` type and `verdict: yes` under `alert`. Confirm the deployed build and settings. Minimize collection of headers and payloads that could contain credentials or personal data. Check source and ingest coverage before treating missing fields as meaningful. End-of-flow reporting can appear after the alert and after the final observed packet.
3. Confirm that capture sees both directions where relevant, that the HTTP parser sees the traffic, and that a sensor outside TLS termination has appropriate visibility. Review capture loss, stream or application parser gaps, file rotation and delivery. For authorized PCAP replay, `pcap_cnt` when present identifies a packet in that exact input file. It can be absent from internal events, and packet numbers from a different export refer to a different packet sequence.
4. Pivot to the proxy or application using time, service, method and path, plus a verified request identifier if available. Check NAT and proxy boundaries before assuming endpoints are the same. Use downstream capture or enforcement telemetry to confirm what an inline decision affected. Preserve evidence and escalate to the service owner before containment decisions.

## 5. Review six synthetic alerts offline

Save [suricata-eve-review.py]({{ '/assets/labs/suricata-eve-review.py' | relative_url }}){: download="suricata-eve-review.py" } and [suricata-eve-cases.jsonl]({{ '/assets/labs/suricata-eve-cases.jsonl' | relative_url }}){: download="suricata-eve-cases.jsonl" } in the same directory in your own workspace. Run the following with Python 3.12. The dataset is fictional. The script reads it without installing Suricata or opening a network connection.

```sh
python3 suricata-eve-review.py
```

| Synthetic ID | Expected result |
| --- | --- |
| 7001 | `tx=0`, `GET /catalog`, status 200. Same IDs on other sensors or runs are excluded, as is the neighboring large flow ID. |
| 7002 | Two candidates in the flow. Transaction attribution is unresolved. |
| 7003 | Transaction ID is present but no matching HTTP record is available. |
| 7004 | `alert=allowed` and `verdict=drop`. There is no matching HTTP row. |
| 7005 | Two records share the scoped transaction key. Check for duplicated ingestion or conflicting evidence before choosing. |
| 7006 | No flow ID. The script leaves attribution unknown. |

Expect six output lines. If the file is missing or malformed, check that both original downloads are in the same directory and JSON objects remain one per line. If a run of this logic in another tool misattributes 7001, check precision and the sensor/run boundary. The script deliberately avoids resolving duplicate transaction rows and does not infer application state. All six outputs were compared against the expected results with Python 3.12.14. Suricata engine replay and a live inline network were outside the verification scope.

## 6. Check your reasoning

1. **The flow has both 200 and 403. Which belongs to the alert?** Use the transaction ID in the correct sensor and run. If it is unavailable, retain both as candidates and seek request-level evidence.
2. **The IPS alert says allowed and the same event's verdict says drop. What do you report?** State the action for the rule and the final packet verdict from the sensor. Seek application evidence before claiming what was prevented.
3. **A nearby HTTP row from another sensor has the same flow and transaction IDs. Can you join it?** Keep native identifiers within their source scope. For cross-sensor evidence establish an independent relationship using the observation points, timestamps and flow metadata.

**Completion check.** Reproduce the six outputs. For two cases, record the observation point, which result is attributable and the one next source you would query.

## Official references

Reviewed 2026-11-22. The field examples and deployment behavior below refer to OISF's Suricata 8.0.8 documentation. The release page dates 8.0.8 to 2026-10-29. Confirm field presence on your deployed version and configuration.

- OISF [Suricata releases](https://suricata.io/download/) · [Suricata 8.0.8 EVE JSON format](https://docs.suricata.io/en/suricata-8.0.8/output/eve/eve-json-format.html)
- OISF [Suricata 8.0.8 EVE output configuration](https://docs.suricata.io/en/suricata-8.0.8/output/eve/eve-json-output.html) · [Suricata 8.0.8 IPS concept](https://docs.suricata.io/en/suricata-8.0.8/ips/ips-concept.html)
- IETF [RFC 8259 §6 · JSON numeric precision, December 2017](https://www.rfc-editor.org/rfc/rfc8259.html#section-6)

[Previous · Network monitoring tools]({{ '/wiki/network-monitoring/' | relative_url }}) · [Next · Community ID correlation]({{ '/wiki/community-id-evidence/' | relative_url }})

## Find missing evidence on a Suricata sensor

[Suricata sensor health]({{ '/wiki/suricata-sensor-health-evidence/' | relative_url }}) traces capture drops, TCP reassembly gaps, and missing events between local EVE and the collector.
