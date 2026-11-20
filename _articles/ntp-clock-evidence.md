---
title: "NTP and Clock Evidence · How Far Off Was the Host?"
description: "Calculate NTP offset from four timestamps, check Linux and Windows time sources, and decide when a reading can support an investigation."
category: network
tags: [NTP, NTS, Network Security, Blue Team, DFIR, Timeline, Linux, Windows Logs]
level: Beginner
updated: "2026-11-20"
translation_url: /ko/wiki/ntp-clock-evidence/
---

**Learning goal.** Explain why a clock can be reachable and still be unreliable, calculate an NTP sample by hand, and document whether it supports a clock correction for a particular host and time window.

## 1. Which clock does the log trust?

Imagine that a server records a sign-in at 12:00:06 UTC and a gateway records the same request at 12:00:02 UTC. Four seconds could be processing time, clock error, or part of both. UTC standardizes how we express the time. It leaves each underlying host clock free to be fast or slow. A useful timestamp needs both a defined event stage and evidence about the clock that wrote it.

| Term | Meaning | Evidence to look for |
| --- | --- | --- |
| Wall clock | The host's estimate of the calendar date and time | Original timestamp, zone or UTC offset, and event field definition |
| Offset | The difference between two clocks at a particular time | Which clock, which reference, sign convention, units and measurement time |
| Frequency error | The rate at which a clock would gain or lose time without correction | A time series of estimates, often expressed in parts per million |
| Delay | In a single NTP exchange, estimated round-trip network time after subtracting server processing | A complete exchange and the vantage point of each timestamp |
| Stratum | Level of a time source in the synchronization hierarchy | Selected source and its upstream chain. A low number by itself does not establish accuracy |
| Step and slew | A discrete clock adjustment and a gradual correction by changing the clock's rate, respectively | Time-service records and boot or VM lifecycle evidence |

A sign-in, certificate validity check, and log pipeline can all depend on the wall clock. In an investigation, preserve the exact timestamp first. Keep an estimated correction and its uncertainty as separate fields.

## 2. Follow a request through four timestamps

Ordinary client/server NTP uses a request to the server on UDP port 123. The client records **T1** when it sends. The server adds **T2** when it receives the request and **T3** when it sends the reply. The reply carries the originating request timestamp for matching. The client records **T4** when it receives the reply. T1 and T4 use the client clock, while T2 and T3 use the server clock. In particular, T4 is a local receive measurement. A capture on a switch or separate network sensor timestamps packets with that sensor's own clock and cannot directly supply the client's T4.

![NTP exchange. The client sends at T1 and receives at T4. The server receives at T2 and sends at T3.]({{ '/assets/diagrams/ntp-exchange-en.svg' | relative_url }})

*The arrows show message direction. Vertical position shows order within the exchange. The diagram does not give a distance or a clock offset.*

~~~text
offset (server minus client) = ((T2 - T1) + (T3 - T4)) / 2
network round-trip delay     = (T4 - T1) - (T3 - T2)
~~~

**Fictional normal exchange.** With timestamps **0, 21, 23, 12 ms** on their respective clocks, the client measures 12 ms elapsed and the server measures 2 ms of handling time. The estimated round trip is **10 ms**. The inferred offset is **+16 ms**. With approximately equal one-way delays and an accurate server, the client clock is about 16 ms behind. Adding 16 ms to a contemporaneous client reading estimates server time. In the [timeline lesson]({{ '/wiki/incident-timeline-evidence/' | relative_url }}), the correction field instead measures how far **ahead the client is**, so the same estimate would be saved as **−16 ms** in that field. A numeric T3 greater than T4 is plausible because the two timestamps are from different clocks.

A single sample is the input to synchronization, not the host's final clock state. The daemon can collect multiple samples, filter them, choose among time sources, and adjust the clock. A measurement taken after a reboot or adjustment needs separate justification before it can describe an earlier incident.

## 3. How can synchronization evidence mislead?

NTP infers offset from mean path timing. If the outward path takes longer than the return path, the estimated server-minus-client offset is biased upward by half the difference. For example, one-way delays of 25 and 5 ms give a **+10 ms** bias even if both clocks are correct. Congestion and queueing can produce asymmetric delays. A party on the path can also bias an estimate by delaying already valid messages.

Plain unauthenticated NTP lacks cryptographic proof of the replying server. **Network Time Security (NTS)** adds a TLS-based key establishment phase and authentication for subsequent NTP client/server traffic. It helps establish that the response came from the intended server and was intact. Accurate server time and network delivery remain separate questions. RFC 8915 §8.6 discusses the remaining risk from delay. In an environment with accuracy requirements, the IETF recommends maintained implementations and at least four independent and diverse time sources where practical. Check the real upstream references and paths. Four addresses backed by one reference can fail together.

## 4. Collect first, then diagnose

**1. Record clock provenance.** Save host identity, boot or VM lifecycle evidence, software and version, policy, configured and selected sources, and time of the last update. If possible, record when you took the snapshot using an independent approved clock. Keep the original output with the case.
**2. Read the daemon's own state.** Collect the snapshot and recent time-service logs. On Linux with a running chrony daemon and local access, run the first two lines below. On supported Windows with W32Time running, use an elevated prompt for the last two. A domain-managed Windows host normally follows the AD domain hierarchy. Compare it to its expected source for its role, including the forest-root PDC emulator where relevant.

~~~text
chronyc tracking
chronyc sources -v
w32tm /query /source
w32tm /query /status /verbose
~~~

**3. Compare the right signals.** In chrony, check `Ref time` and `Leap status` alongside the selected source. In `sources -v`, `*` marks the selected reference and `Reach 377` is octal for replies or samples on all eight recent polls. A reachable source may still fail selection. The `Last sample` sign convention is **local minus source**, the opposite of the worksheet. In Windows, review last successful synchronization and source details. Where the supported `Microsoft-Windows-Time-Service/Operational` channel is available, inspect service starts, clock adjustments and source changes with the right time window and local retention. If using WEF, confirm the subscription actually collects that channel.
**4. Assess whether the value can support an incident finding.** In chrony 4.9, if the upstream stratum-1 clock is accurate, the documentation describes a clock error bound as the absolute `System time` offset plus `Root dispersion` plus half `Root delay`. With 2 ms, 3 ms and 20 ms respectively, the example gives **15 ms** at the snapshot. Those last two fields describe the upstream chain. Substituting the latest single packet's delay changes the meaning. This bound also cannot prove accuracy after a source change, an unobserved clock step or a long gap. Note the period the evidence supports and mark unknown periods explicitly.

| Observation | What to collect next | How to respond |
| --- | --- | --- |
| Current source changed from expected policy | Effective configuration, DHCP or domain policy where applicable, change record and daemon logs | Confirm an authorized change. If unexpected, preserve evidence and scope affected hosts along the dependency chain |
| Delay grows and multiple independent sources disagree | Source-specific offset and delay history, route or congestion data and an independent reference | Escalate if persistent and outside the service's timing budget. Corroborate before attributing the cause |
| Clock moves backward or the host starts without sync | Time-service and boot records, VM suspend or resume, platform time and the collector's unaffected copy | Split the comparison window and preserve timestamps on both sides. Coordinate any production adjustment with the service owner |
| Endpoint looks healthy but SIEM timing is wrong | Raw timestamp, parser format and zone, ingest time, forwarding state and an independent record | Test timestamp parsing and delivery on a known event before changing clock configuration |

Use a threshold tied to the service and investigation, such as the maximum uncertainty acceptable when ordering events hundreds of milliseconds apart. Combine sustained offset, sample age and source changes with other evidence. A single deviation is compatible with a routine failover or a poor path. A normal dashboard snapshot taken today does not certify yesterday's local events.

## 5. Offline exercise · Eight fictional exchanges

Download [ntp-exchanges.csv]({{ '/assets/labs/ntp-exchanges.csv' | relative_url }}) and the [Python worksheet checker]({{ '/assets/labs/ntp-exchanges.py' | relative_url }}). The file uses invented millisecond readings rather than binary NTP timestamps. Read the header, calculate N01 and N04 by hand, then run the checker from a folder containing both files with Python 3. The checker only reads the local CSV.

~~~bash
python3 ntp-exchanges.py
~~~

| Case | Expected offset and round-trip delay | Interpretation to practice |
| --- | --- | --- |
| N01 | +16 ms, 10 ms | The reference is estimated to be ahead of the client |
| N02 | −11 ms, 12 ms | The client is estimated to be ahead of the reference |
| N03 | 0 ms, 10 ms | The estimated difference is zero. Both clocks could share an error |
| N04 / N05 | +10 / −10 ms, 30 ms each | In the exercise, the clocks are correct and the directional delays are 25/5 and 5/25 ms. The worksheet alone cannot recover those paths |
| N06 | Incomplete | T4 is missing. Leave the sample unresolved |
| N07 | +0.5 ms, 13 ms | Preserve fractional precision before comparing results |
| N08 | +5 ms, 80 ms | A small estimated offset can accompany high delay. Compare it with other samples and the baseline |

If the checker cannot find the file, check that both downloads share the same directory and base name. A sign error usually means you reversed whose clock is ahead. If the delay is off by two or three milliseconds, check whether you subtracted the server's handling time. The checker rejects negative delay or reversed same-clock timestamps in these controlled inputs. Real NTP software applies its protocol and clock filters, and production captures have additional timing and timestamp-format constraints.

**Optional approved self-lab.** On an owned test VM already using chrony or W32Time, capture two read-only status snapshots on different poll cycles. Record observation UTC from an approved reference, selected source, last update and whether the source is the one expected by policy. Compare the reported status with the approved reference or time-system inventory. If the update has not advanced, check the expected poll interval and access to the configured source. Keep clock settings and network paths unchanged. The eight worksheet cases were executed in Python. The daemon commands and channel behavior were reviewed against official documentation.

## 6. Check your understanding

- **The packet capture has a reply, but no client T4. Can you recover the exact client offset?** No. You are missing a client-clock measurement. The capture time belongs to the sensor, and a substituted value would describe a different timing comparison.
- **NTS authentication passes and the selected source responds to every poll. Does that prove the clocks agree?** Authentication supports origin and integrity, and reachability supports delivery. Check the source chain, repeated offsets and delay before drawing a conclusion about time accuracy.
- **The only status record is after a reboot. Can you correct a log recorded before it?** Obtain evidence tied to the earlier time window. If that evidence is missing, preserve the log and document the clock uncertainty.

Finish by explaining the sign in N01 and the contrary estimates in N04 and N05. Then write one case note with the original timestamp, source identity, evidence interval, estimate or uncertainty, and the next check needed for higher confidence.

[Continue · Compare incident timelines]({{ '/wiki/incident-timeline-evidence/' | relative_url }}) · [Related · Network monitoring]({{ '/wiki/network-monitoring/' | relative_url }}) · [Related · Windows Event Forwarding]({{ '/wiki/wef-delivery-evidence/' | relative_url }})

## Official references

Reviewed 20 November 2026. For operational checks, match the version installed on the host and the time source the host was using at the relevant time.

- [IETF RFC 5905 §8 · NTPv4 timestamp exchange and arithmetic, June 2010](https://www.rfc-editor.org/rfc/rfc5905.html#section-8)
- [IETF RFC 8633 · NTP Best Current Practices, July 2019](https://www.rfc-editor.org/rfc/rfc8633.html)
- [IETF RFC 8915 §8 · Network Time Security and its limits, September 2020](https://www.rfc-editor.org/rfc/rfc8915.html#section-8)
- [chrony · chronyc 4.9 manual, August 2026 release](https://chrony-project.org/doc/4.9/chronyc.html)
- [Microsoft · Windows Time service tools and settings, updated September 2025](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-service-tools-and-settings)
- [Microsoft · Windows Time for Traceability, updated November 2021](https://learn.microsoft.com/en-us/windows-server/networking/windows-time-service/windows-time-for-traceability)
