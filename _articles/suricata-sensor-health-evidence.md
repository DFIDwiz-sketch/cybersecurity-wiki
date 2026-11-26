---
title: "Suricata Sensor Health · Capture Drops, Reassembly Gaps and Missing Logs"
description: "Compute defensible counter changes and trace an expected EVE event from a passive sensor to the collector."
category: network
tags: [Suricata, EVE, Network Monitoring, Packet Capture, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/suricata-sensor-health-evidence/
---

A network analyst sees no Suricata alert for a known test request. The application log shows the request succeeded. Before interpreting the silence, determine whether the sensor received the traffic, could reconstruct it, emitted a local record and delivered the event to the collector. This chapter focuses on a passive Linux sensor and separates sensor observations from what happened on the live network.

## 1. Follow the packet copy and the log

A **TAP** or a switch mirror supplies a copy of traffic. The sensor’s network interface and capture backend deliver that copy to Suricata. Suricata decodes packets and can reassemble TCP before applying detection or parsing application transactions. **EVE** is Suricata’s structured event output. A forwarder can ship these records to a separate analysis system.

**Counters** count occurrences over a defined lifetime. **Gauges**, such as current memory use, describe a value at the sample time and may legitimately decrease. Compare like cumulative counters across adjacent samples. Identify the sensor, instance start, capture mode, interface scope and total or per-thread series before subtracting. In the EVE logger configuration, the `totals` option for the `stats` event type selects an aggregate across threads. EVE event JSON contains the resulting counters inside `stats`.

| Observation | What it measures | What it cannot establish |
| --- | --- | --- |
| TAP or mirror configuration and port counters | Traffic was eligible to be copied. A relevant port counter can show load or drops at that point | The sensor saw every packet or saw both directions |
| `capture.kernel_drops` | Discards reported by a capture backend. Confirm the mode and the counter’s semantics | Path loss at the endpoints or loss before the capture backend |
| `tcp.reassembly_gap` | Suricata encountered missing TCP stream data during reassembly | Which interface, packet, flow or cause produced the aggregate gap |
| `detect.alert_queue_overflow` | Alerts discarded because the per-packet alert queue was full | A forwarding failure, a specific missing signature, or a universal rate of lost alerts |
| Local EVE and collector arrival | Evidence that an event exists at source or arrived downstream | Why a local event failed to appear without checking coverage, timestamps and delivery |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/suricata-sensor-health-evidence-en.svg' | relative_url }}" alt="Traffic copies pass from TAP or mirror through the network interface and capture backend to the Suricata decoder and TCP reassembly. Local EVE travels through the shipper to the collector. Each step has different evidence." style="max-width: 100%; height: auto;">
  <figcaption>Figure 1. Packet visibility and log delivery have different checkpoints.</figcaption>
</figure>

## 2. Read a normal interval, then compare a gap

In a fictional 10-second interval, the same process and total series reports a kernel-drop count of `200` at 10:00:00 UTC and `200` at 10:00:10, while the decoder packet counter rises by `10,000`. The reassembly-gap counter stays at `15`. One expected, harmless test event appears in local EVE and later in the collector. These observations support delivery of that event and no increase in those two instrumented counters.

In the next fictional interval, kernel drops increase from `200` to `320` and reassembly gaps from `15` to `21`. The increases are `120` and `6`. Investigate capture pressure and stream visibility together. These units are different. Six gaps are not six dropped packets, and the counters cannot establish that one problem caused the other or that the target request was affected. Check the interface and mirror port and compare with another authorized vantage point.

To estimate a rate, divide a confirmed delta by the measured time between samples. Treat the packet denominator separately. Suricata documents different `capture.kernel_packets` meanings for AF_PACKET and PF_RING. Do not apply a single packet-drop percentage formula to all backends. A zero delta covers only the named metric and time interval. Missing fields and no traffic require their own handling.

## 3. Locate the missing evidence

A mirror can omit a VLAN or one direction. Capture load can exceed a port or queue’s capacity. A gap can also reflect checksum handling or stream resource limits. An unusually high load during an incident can degrade visibility, but ordinary backups, bursts or maintenance can create similar symptoms. A growing count does not establish deliberate activity.

A sensor might also observe encrypted traffic that a plaintext application rule cannot inspect, or use a different ruleset, application output or threshold. If an expected event exists locally, compare with the input filter, shipper checkpoint, queue status, parsing errors, index timestamps and collector permissions. When the local record is absent, verify the traffic and alert preconditions first. The packet-alert queue overflow counter measures local alert handling, even if the collector has spare capacity.

A process restart or series change invalidates the baseline. Record a process start marker in addition to a host boot ID. Validate the elapsed time and uptime, and flag non-monotonic cumulative values for investigation. A missing row can mean collection gaps, filters or rotation rather than a quiet network. Wait the expected delivery interval and search the event time as well as the ingest time.

## 4. Collect, detect and respond

1. **Identify the scope.** Preserve sensor, interface, traffic direction, capture mode, Suricata version, process start, EVE path(s), loaded rules/version and configuration. `suricata --build-info` reports compile-time support. Confirm the **active** capture backend and mode with the running service and its startup records.
2. **Collect the same interval at each layer.** Preserve mirror and NIC counters plus corresponding Suricata records. On an authorized Linux sensor, `ethtool -S INTERFACE` requires ethtool and driver support. Field names and meanings depend on driver and interface. If EVE is threaded or rotated, account for every relevant file and forwarding coverage.
3. **Compare source and collector.** Select a benign expected transaction in an authorized environment. Match local and forwarded events using sensor, event type, event time and available flow or transaction IDs. For local extraction, the read-only command below requires `jq` and access to a saved EVE JSON Lines sample with the `stats` event type and totals enabled. Use the cumulative fields, not exported deltas or thread rows. Missing fields remain `null`.

```bash
jq -c 'select(.event_type=="stats") | {
  timestamp, uptime:.stats.uptime, decoder_packets:.stats.decoder.pkts,
  kernel_drops:.stats.capture.kernel_drops, gaps:.stats.tcp.reassembly_gap,
  alert_overflow:.stats.detect.alert_queue_overflow
}' eve-snapshot.jsonl
```

4. **Use scoped detection and confirm recovery.** Alert on sustained positive changes on comparable series with adequate traffic, or when an expected local event misses the collector delivery objective. Watch for monitoring loss separately from suspicious traffic. For capture issues, validate mirror capacity, NIC errors and active capture settings before tuning. For forwarding issues, verify routing, backlog and rotation. Recover against an approved known event, checking both the sensor source and the downstream view.

## 5. Authorized offline exercise

Download <a href="{{ '/assets/labs/suricata-sensor-health-evidence.py' | relative_url }}" download>the Python checker</a> and <a href="{{ '/assets/labs/suricata-sensor-health-cases.json' | relative_url }}" download>the fictional cases</a> into the same directory. Run with Python 3 in an environment you own or are authorized to use. It reads only the local fixture and calculates interval changes or interprets a local/collector observation. It does not generate packets or query Suricata. Instance identifiers and delivery facts are synthetic collector metadata.

```bash
python3 suricata-sensor-health-evidence.py
```

| Compare | Expected result |
| --- | --- |
| Stable counters with traffic, stable counters without traffic, and absent counters | Separate no observed increment, idle interval and unknown telemetry |
| Kernel drops, reassembly gaps and alert queue overflow | Preserve each positive delta as a different observation |
| Changed instance or decreasing counter, and a long sampling gap | Reject the invalid baseline or report insufficient continuity. The fixture flags a gap above twice the requested interval |
| Event missing downstream and event missing locally | A known local emission gives a different starting point for investigation |

Expect `12/12 evidence cases matched.` If the untouched fixture fails, check that both files came from the same edition and inspect the case ID. In case B change `after.capture_drops` from `320` to `200` while keeping its expected result. The fixture should no longer show a drop increment, and the checker should exit with code 1. This proves the offline rule distinguishes the two readings. Suricata, NIC counters and forwarder behavior were reviewed in documentation. No live sensor or collector ran for this exercise.

## 6. Check your reasoning

1. **Drops stay at zero but TCP gaps increase. Did the network lose packets?** That conclusion needs another observation point, interface evidence and checks for asymmetric capture, checksums and stream limits.
2. **The drop count went from 320 to 10 overnight. Did the sensor improve by 310 packets?** Check instance start, counter continuity and scope. A decrease between supposedly comparable cumulative samples invalidates that delta.
3. **A known event is in local EVE but not in the collector after the expected interval. Where do you look?** Follow the source file, forwarder and destination, and confirm the query scope and time basis.

**Completion criterion.** Reproduce all results and the negative control. Given one missing test event, name the last layer you can establish and the evidence you need next. Continue with [paired captures and visibility]({{ '/wiki/capture-visibility/' | relative_url }}) and [Suricata transaction evidence]({{ '/wiki/suricata-eve-transaction-evidence/' | relative_url }}).

## Official references

Reviewed 2026-11-26. Statistics and configuration use the Suricata 8.0.8 stable documentation, released 2026-10-29. The EVE logging options below use the 8.0.5 reference for the same release line. Check your installed version and effective configuration.

- [Suricata downloads and release dates](https://suricata.io/download/)
- [Suricata 8.0.8 statistics and capture modes](https://docs.suricata.io/en/suricata-8.0.8/performance/statistics.html) and [8.0.8 YAML configuration and alert queue](https://docs.suricata.io/en/suricata-8.0.8/configuration/suricata-yaml.html)
- [Suricata 8.0.5 EVE output configuration](https://docs.suricata.io/en/suricata-8.0.5/output/eve/eve-json-output.html) and [8.0.8 command-line options](https://docs.suricata.io/en/suricata-8.0.8/command-line-options.html)
