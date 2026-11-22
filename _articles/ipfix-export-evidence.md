---
title: "IPFIX Export Evidence · Where Flow Records Go Missing"
description: "Trace observation scope, IPFIX sequence gaps, missing templates and collector indexing with ten fictional examples."
category: network
tags: [IPFIX, NetFlow, Network Monitoring, Network Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/ipfix-export-evidence/
---

A quiet flow dashboard can mean the monitored network was quiet. It can also mean packets were outside the observation scope, flow records were not exported, or the collector received records it could not decode. This chapter follows IPFIX version 10 over UDP from the observation point to the searchable index.

## 1. From live packets to exported flow records

**IP Flow Information Export (IPFIX)** carries structured measurements between an exporter and a collector. An **observation point** is where traffic is seen, such as an interface in one direction. An **observation domain** groups observation points under the metering process. Its numeric ID is local to the exporting process. Record the exporter identity alongside the domain in every investigation.

The **metering process** groups observed packets by configured characteristics. A familiar key is the directional five-tuple of source and destination addresses, source and destination ports, and transport protocol. Inspect the actual key, sampling and interface settings before interpreting a record. Cache expiry can split traffic with the same tuple across several records. The **exporting process** sends messages containing templates, Data Records, or both. A **Template** maps fields by describing their order, types and lengths on the wire. Its numeric ID identifies that schema within the relevant scope. A **collector** decodes Data Sets with the matching template and passes fields to storage or search. In an Options Template, some fields also identify the scope of the data being reported, such as an observation domain or metering process.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/ipfix-export-evidence-en.svg' | relative_url }}" alt="Packets at an observation point feed the meter and cache. The exporter sends templates and data over UDP. The collector either decodes data for the index or waits or discards it when the matching template is unavailable.">
  <figcaption>Inspect the meter, export transport, decoder and search index as separate sources of evidence.</figcaption>
</figure>

## 2. Read one normal export

In a fictional branch, an interface sees a client request to an approved server. The exporter meters the flow, then emits a record with the addresses and byte count selected by the template. Collector-side capture shows a message at sequence 100 containing Template 256 and four Data Records of that type for Observation Domain 7. The next message in the same session and domain starts at 104. Later, a template-only refresh begins at 108, and the next data message also starts at 108. Reusing the template-only sequence is expected. Track records after decoding rather than counting capture frames or Sets.

| Item | What the value tells you |
| --- | --- |
| IPFIX sequence number | Position in the counter of Data Records already exported by this exporter in this stream and Observation Domain. Includes data carried under Options Templates. |
| Template or Options Template Record | Schema. These records add zero to the counter. |
| NetFlow v9 sequence | Counter of export packets in the applicable exporter/domain scope. Use the v9 rules for version 9. |
| Export Time | When the IPFIX message leaves the exporter. Compare with flow start/end fields and collector receipt time separately. |
| Indexed rows | What made it through decoding, normalization and indexing. Collector filters or data model changes can alter the result. |

Within a stable scope, calculate the next expected sequence as `(previous sequence + previous Data Record count) modulo 2^32`. If 100 contained four records and the next start is 107, the apparent forward gap is three Data Records. That number includes any missing Options Data Records and provides no count of original network packets, unique connections or export datagrams. The wrap case `4294967294 + 2 → 0` is consistent.

## 3. Recognize gaps and misleading signals

- **UDP delivery and arrival order.** UDP can lose, duplicate or reorder datagrams. Compare short-lived gaps with a bounded reordering window and the late arrivals around them. Check for exporter restarts and session changes before interpreting backward jumps. For UDP, keep exporter identity, source port, collector address and destination port, and Observation Domain together. Identify any NAT or relay that changes the visible tuple. For TCP track connections, and for SCTP track the relevant stream as well as the transport session.
- **Template loss and restart.** A collector joining midstream or restarting can see a Data Set before receiving the right template. The wire header may be available while the Data Record count is unknown. Expect periodic template retransmission on UDP. Verify matching scope, template receipt and decoder outcome. A lost template-only message does not itself create a record-sequence gap.
- **Sampling, cache pressure and configuration drift.** A sampled-out packet or a flow never exported may leave no gap in the export sequence. Check whether counters are sampled or scaled and verify metering and export settings before comparing them with a packet capture. A template change may also remove fields that saved searches depended on.
- **Untrusted or incorrect telemetry.** Unexpected exporters, mismatched schemas and inconsistent sequences can contaminate an index. Tag sources by approved identities and collection paths, restrict collector access and compare configuration against inventory. Where supported, select a protected transport appropriate for the deployment. Use several evidence sources to assess why a discrepancy occurred.

## 4. Collect, detect and respond

| Collection point | Evidence to retain |
| --- | --- |
| Meter and exporter | Interface/direction, observation domain, sample and timeout configuration, software and boot/change window, cache/queue/export deltas where available |
| Export path and collector ingress | UTC timestamps, scoped transport tuple, message version, sequence, domain, template IDs and receiver socket or capture drops. Capture only where authorized. |
| Decoder and search pipeline | Unknown-template and decode counters, restart and parser changes, indexed-row counts, lag and rejected events |

Start with one exporter, observation domain and UTC window. Verify the expected interface and transport path. Check whether the exporter reports the same discontinuity, whether the message arrived in a collector-side capture, and whether the decoder knew the template then. With authorized captures on both sides, compare timestamps and message identity after accounting for export duplication, NAT and capture drops. Report the strongest localization that the independent observations support. Feed parser and ingestion failures into the same incident timeline.

Alert on sustained gaps or unknown-template bursts by scope and compare them with baseline rates and maintenance. If sequence continuity looks normal but indexed rows fall, inspect sampling, cache behavior, decoder and ingest backpressure first. Preserve snapshots and capture evidence before restarting the collector. After a fix, verify a fresh template and a known flow through decoding and search. On supported Prisma SD-WAN ION devices with IPFIX configured, the vendor documents `inspect ipfix exporter-stats` for Super and Read Only roles from release 5.5.1. Check the installed release and counter definitions. This command was reviewed from documentation.

## 5. Offline exercise with ten fictional pairs

Download the <a href="{{ '/assets/labs/ipfix-export-evidence.py' | relative_url }}" download="ipfix-export-evidence.py">Python script</a> and the <a href="{{ '/assets/labs/ipfix-export-evidence-cases.csv' | relative_url }}" download="ipfix-export-evidence-cases.csv">fictional CSV</a> into the same folder. In your own approved workspace, run Python 3. The CSV represents two already normalized observations per case. Scope values stand in for the full session and domain. A blank record count means the previous message could not be counted. A zero count marks a decoded message with no Data Records. In `options_data`, the previous message’s three records represent two flow records and one Options Data Record. In `restart`, the epoch change has already been corroborated in the exercise. A sequence jump alone would be insufficient to assign a new epoch. This exercise reads local input only.

```bash
python3 ipfix-export-evidence.py ipfix-export-evidence-cases.csv
```

```text
normal: consistent
template_only: consistent
gap: forward_gap:3
wrap: consistent
unknown_count: count_unknown
other_domain: scope_changed
restart: scope_changed
older_arrival: ambiguous_order
options_data: consistent
netflow_v9: unsupported_version
```

Try explaining each result before you run the script. It treats a modular difference of half the range or more as ambiguous, an assumption for these nearby pairs. It does not reorder captures or determine the cause of a gap. If the file cannot be opened, check the filename and working directory. For an unexpected gap, verify the count includes Options Data Records and excludes template records. Python execution was verified on these fixtures. No IPFIX appliance, collector or Wireshark installation was exercised.

## 6. Check your understanding

- **A gap of three means three client packets were dropped?** Three is the apparent export Data Record difference for that pair. You need separate packet evidence to evaluate client traffic.
- **The capture shows Data Sets but the collector has no parsed fields. What comes next?** Verify the matching template in the same scope and check decoder errors, startup and refresh timing.
- **Every sequence is consistent but searches went quiet. Is capture complete?** Check observation scope, sampling, exporter cache, decoding and ingest health. The sequence validates only a bounded part of the export path.

Finish when all ten results match and you can name separate evidence that would distinguish a lost export datagram from a missing template and a search pipeline failure.

## Official references

Reviewed 2026-11-22. The IPFIX standard and NetFlow v9 specification describe different versions. The vendor references apply to the documented Prisma SD-WAN feature and release. Validate local transport, exporter and collector behavior before applying the examples to production.

- Headers, template management, UDP export and collector handling, sections 3.1, 8, 9.3 and 10.3. [IETF RFC 7011 (2013)](https://www.rfc-editor.org/info/rfc7011/)
- Version 9 export packet counter, section 5.1. [IETF RFC 3954 (2004)](https://www.rfc-editor.org/info/rfc3954/)
- IPFIX profile and template configuration. [Palo Alto Networks · Prisma SD-WAN IPFIX](https://docs.paloaltonetworks.com/prisma-sd-wan/administration/prisma-sd-wan-sites-and-devices/use-external-services-for-monitoring/configure-ipfix-profiles)
- ION CLI feature, release and roles. [Palo Alto Networks · Exporter statistics](https://docs.paloaltonetworks.com/prisma-sd-wan/ion-cli-reference/use-cli-commands/inspect-commands/inspect-ipfix-exporter-stats)

[Previous · Network monitoring]({{ '/wiki/network-monitoring/' | relative_url }}) · [Next · Packet capture visibility]({{ '/wiki/capture-visibility/' | relative_url }})
