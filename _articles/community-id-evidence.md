---
title: "Community ID: Correlating Suricata Alerts and Zeek Connections"
description: "Use Community ID, network scope and event time to review eight synthetic flow records without confusing a shared tuple with a shared session."
category: network
tags: [Community ID, Zeek, Suricata, Network Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-20"
translation_url: /ko/wiki/community-id-evidence/
---

**Learning goal.** Start from an IDS alert, find plausible network flow records, and explain which observations make a candidate stronger or weaker.

## 1. What problem does Community ID solve?

An IDS alert can tell you which rule matched. A connection log can tell you the connection's duration, endpoints and observed traffic. Suricata and Zeek use their own native identifiers, so an analyst needs a shared reference when the same traffic appears in both. **Community ID** is a published algorithm that makes a reproducible identifier from network flow metadata. It narrows a search without requiring the two tools to coordinate their own identifiers.

For TCP and UDP, a **five-tuple** is the IP protocol and the two IP address/port pairs. The algorithm orders the two endpoints so the tuple gives the same result when its direction is reversed. Community ID v1 also incorporates a 16-bit **seed**, normally zero unless configured differently. It hashes the binary values with SHA-1 and normally encodes the result in Base64 with a `1:` prefix. This is a correlation value. It adds no authentication, confidentiality or payload fingerprint. It does not identify the initiator, time, asset or tenant. Use the original records for those questions.

| Identifier | Where to use it | What to keep in mind |
| --- | --- | --- |
| Zeek `uid` | Follow a Zeek connection into related Zeek logs when they carry that UID | Preserve the originating dataset and sensor. |
| Suricata `flow_id` | Relate EVE events that refer to the same flow within the source | Preserve sensor and run or dataset context. |
| `community_id` | Find cross-tool candidates that describe the same observed tuple | Check version, encoding, seed, network scope and event time. |
| Packet or translation evidence | Confirm which network instance or NAT mapping fits | Requires visibility and preserved acquisition context. |

## 2. Follow a normal investigation

![Comparison flow. Preserve the alert and flow identifiers, check the common ID and tuple, confirm network scope and time, then corroborate any candidate.]({{ '/assets/diagrams/community-id-review-en.svg' | relative_url }})

Imagine a lab sensor detects a rule match at 12:00:04 UTC involving TCP from `192.0.2.24:51000` to `198.51.100.20:443`. Zeek sees the same network leg and records the endpoints in the opposite order. With v1 and seed 0, that tuple produces `1:crL5jj4ZGIYJPT6Db5ghbtwA+DI=` in either direction. Zeek's interval covers the alert time. The two observations support a candidate connection. Confirm the association with packet evidence, supported native log pivots or another independent clue before attributing the alert to a single session. A rule match alone does not establish that a host was compromised.

1. **Keep the raw lead.** Record sensor name, interface or VLAN, capture or dataset ID, alert timestamp, rule metadata, original packet fields and native IDs. Separate event time from ingestion time.
2. **Compare equivalent observations.** Confirm the same algorithm version, encoding and seed. Compare the original address/port pairs and transport protocol. Normalize direction for the comparison, while keeping originator/responder roles in the raw source.
3. **Scope the result.** Verify the network view, such as site, tenant, VRF, VLAN and pre/post-NAT leg as appropriate. Compare the alert event time with the flow interval after considering clock error and visibility. Use a measured tolerance, not an arbitrary broad interval.
4. **Corroborate.** A reused tuple can produce the same hash on different connections. Multiple matches in the admissible interval require additional evidence. A matching handshake or sequence in authorized packet data can help. In Zeek use the selected UID to pivot to `ssl.log`, `http.log` or another relevant log when that analyzer generated records. For a host-action claim, check separately collected endpoint evidence.

| Situation | How to interpret it |
| --- | --- |
| Same ID and reverse orientation | Expected for the bidirectional TCP/UDP comparison. Use raw fields to resolve direction. |
| Same ID at a different time or in another tenant | Common input values can reappear. Do not assign the record without matching scope and time. |
| Different ID across NAT | The tuple changed. Use timestamped original and translated endpoint mappings to bridge the views. |
| Same ID but a different raw tuple | Check field mapping, truncation, proxy address handling or rare collisions. Keep the discrepancy. |
| No ID in one log | Check logger configuration, event type and collected fields. A packet or native-ID pivot may still be possible. |

A proxy may terminate one transport connection and create another. A matching destination service name does not make those connections the same. Identical values from mirrored sensors may also be duplicate observations rather than additional sessions. Repeated suspicious-looking tuples, shared proxy addresses and unexpected bursts of candidate matches deserve investigation, but none alone proves intent. Preserve the original records and packet references, verify both visibility and clock corrections, and carry unresolved candidates into the case. For authorized defense validation, compare a known benign flow followed by an unrelated flow in a separate time window.

## 3. Configure and collect comparable fields

| Product | What to verify |
| --- | --- |
| Zeek | The policy `policy/protocols/conn/community-id-logging.zeek` is loaded. The optional `community_id` field is present in `conn.log` for the record. Check `CommunityID::seed` and Base64 output. `ts` is first packet time, and elapsed duration can be absent. |
| Suricata | The relevant EVE logger instance enables `community-id`, with a compatible `community-id-seed`. Preserve `community_id`, native `flow_id`, relevant `event_type`, capture/sensor context and timestamp. Where available, an EVE flow event's `flow.start` and `flow.end` represent its interval. |
| SIEM or export | Preserve case, prefix and Base64 padding. Verify how original tuple, time, sensor, tenant or zone, and native IDs are indexed. Unify field names only after confirming they have matching meanings. |

On matching tool builds in an authorized lab, process a previously saved benign capture with both analyzers. Use a fresh output directory, known matching seeds, and the same capture and link-layer view. Zeek can load the policy at invocation using `zeek -r approved.pcap policy/protocols/conn/community-id-logging`. In Suricata review the chosen `eve-log` settings, then compare a TCP or UDP EVE flow record with the Zeek connection. An ordinary capture does not need to trigger an IDS alert to test the shared ID. Product steps were reviewed against official manuals. No live or PCAP replay with Zeek or Suricata was performed for this publication.

## 4. Offline exercise · eight flow records

Save [the fictional data]({{ '/assets/labs/community-id-cases.json' | relative_url }}) and [the Python reviewer]({{ '/assets/labs/community-id-review.py' | relative_url }}) to the same folder. Use Python 3.8 or newer:

```sh
python3 community-id-review.py
```

These are normalized fictional records with documentation addresses and UTC timestamps from 2030. The code recomputes v1 IDs for IPv4 TCP and UDP only, checks the input tuples and tests the candidates against the alert's inclusive one-second window on either side. One second is a fixture assumption. The exercise is not a full Community ID library. IPv6, ICMP and other protocols use their documented handling in production tools.

| Row | Expected result | Reason |
| --- | --- | --- |
| Z01 | Candidate | Reversed tuple, same scope and interval covers the alert. |
| Z02 | Outside window | Same tuple and ID at 11:45. |
| Z03 | Scope mismatch | Same ID in a different network segment. |
| Z04 | Different tuple | Translated address and port. Look for mapping evidence. |
| Z05 | Different seed | Same inputs apart from the sensor seeds. |
| Z06 | Missing ID | No logged value to compare in this exercise. |
| Z07 | Candidate | Interval starts a second later than the alert and touches the tolerance boundary. |
| Z08 | Inconsistent ID | The advertised ID fails recomputation for its original fields. |

Expect `Candidates: Z01, Z07` and an ambiguity message. A unique link requires more evidence. If the files do not open, check their names and directory. If a value changes unexpectedly, check IP family, protocol, unsigned port, seed and UTC offsets, then compare how the sensors saw NAT. The lab was executed with synthetic records, and its hash calculation was checked against the specification publisher's IPv4 TCP/UDP baseline for seeds 0 and 1. This validates the calculations and the exercise logic within that scope.

## 5. Check your understanding

1. **Which endpoint initiated the connection?** Read the packet sequence or supported originator metadata. The common ID intentionally ignores orientation for TCP/UDP.
2. **Why is Z02 excluded with a valid ID?** It has the same tuple at a time that cannot explain the alert under this fixture's tolerance.
3. **Why is Z04 a possible upstream/downstream lead?** NAT can change the tuple and hash. Correlate by the recorded translation and time before drawing a conclusion.
4. **What evidence would resolve Z01 versus Z07?** Compare a reliable packet reference or a sensor-native record anchored to the same traffic instance. Retain both candidates if that evidence is unavailable.

Finish by writing a scoped conclusion for Z01, Z02 and Z07 with native IDs, event time, observation point and the remaining uncertainty.

[Previous · Network monitoring]({{ '/wiki/network-monitoring/' | relative_url }}) · [Next lesson · Firewall and NAT evidence]({{ '/wiki/firewall-nat-evidence/' | relative_url }}) · [Related · Endpoint collection]({{ '/wiki/endpoint-collection-evidence/' | relative_url }})

## Official references

Reviewed November 20, 2026. The baseline is the Community ID v1 public reference. Vendor examples use ISO-style UTC in this lab, independent of each product's native timestamp representation.

- Community ID v1, design, seed and binary layout. [Corelight specification](https://github.com/corelight/community-id-spec) · [Reference baselines](https://github.com/corelight/community-id-spec/tree/master/baseline)
- Zeek 9.0.1 online documentation at review. [Community ID policy](https://docs.zeek.org/en/current/scripts/policy/protocols/conn/community-id-logging.zeek.html) · [Connection log fields](https://docs.zeek.org/en/current/scripts/base/protocols/conn/main.zeek.html)
- Suricata 8.0.2 reference, with the EVE settings also checked in the online development manual. [EVE JSON · Community Flow ID](https://docs.suricata.io/en/suricata-8.0.2/output/eve/eve-json-output.html#community-flow-id)
