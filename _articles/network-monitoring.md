---
title: "Comparing Zeek, Suricata, and Arkime"
description: "Understand the complementary roles of network metadata, intrusion detection alerts, and packet session analysis."
category: network
tags: [Blue Team, Network Security, Zeek, Suricata, Arkime, DFIR]
level: Beginner
updated: "2026-10-22"
translation_url: /ko/wiki/network-monitoring/
---
## 1. Three tools, three views of the same traffic

Zeek, Suricata and Arkime complement each other. **Zeek describes activity, Suricata evaluates detection rules and protocol behavior, and Arkime helps find sessions and retained packets.** None alone establishes that a host is compromised.

| Tool | Primary output | Useful question | Important limitation |
| --- | --- | --- | --- |
| Zeek | Connection and protocol logs; scripts can also generate notices | Who communicated, using which protocol, and with what metadata? | Logs are not a full packet archive; enabled analyzers and visibility matter |
| Suricata | EVE JSON alerts, flows and enabled protocol/file events; IDS/IPS depending on deployment | Did an observed pattern match a rule or protocol condition? | An alert does not establish exploitation; no alert does not establish safety |
| Arkime | Indexed sessions and references to retained PCAP | Which session and packets support this hypothesis? | Packet availability depends on capture, filters, storage and retention |

Suricata provides more than signatures alone, and Zeek provides more than connection counts. Start with the investigation question rather than expecting any one tool to replace the others.

## 2. Establish visibility before interpreting a result

A TAP or SPAN/mirror source feeds sensors. Confirm which traffic directions and segments are covered, including internal east-west traffic. A perimeter-only sensor may never observe an internal workstation accessing a file server.

- Record sensor location, interface, software/rule versions and enabled outputs.
- Confirm both directions are visible and monitor packet loss, capture filters and storage health.
- Normalize time to UTC; retain original timestamps and measure sensor clock offsets.
- Record whether addresses are observed before or after NAT, a proxy, VPN or load balancer.
- Set metadata and PCAP retention independently; indexed sessions may outlive their packets.
- Restrict access to packet exports: unencrypted traffic can contain credentials and personal data.

Do not interpret `missed_bytes=0` in one Zeek connection as proof that every packet reached the whole monitoring system. Check capture and sensor-level health too.

## 3. Representative logs and fields

| Source | Fields to inspect | Meaning and scope |
| --- | --- | --- |
| Zeek `conn.log` | `ts`, `uid`, `id.orig_h/p`, `id.resp_h/p`, `proto`, `service`, `duration`, byte counts, `conn_state` | Connection metadata; originator/responder roles need context |
| Zeek `dns.log` / `http.log` | `uid`, query/answer or HTTP host/URI fields where available | Link related protocol records within the Zeek observation |
| Suricata `eve.json` | `timestamp`, `event_type`, `flow_id`, source/destination IPs and ports, `proto` | Multiple event types can describe one flow |
| Suricata alert | `alert.signature_id`, `alert.signature`, `alert.action`, `alert.severity` | Rule context; severity and action are not an incident verdict |
| Arkime session / PCAP | Session identifier, time range, endpoints, protocol, packet availability | Find retained traffic; a session index is not proof that PCAP still exists |

Zeek `uid`, Suricata `flow_id` and Arkime session IDs are **different identifiers**. Scope them to the originating sensor and dataset; do not join tools by equating these values. Across tools, start with protocol, endpoint addresses and ports (the five-tuple), overlapping times and sensor location. Account for reversed direction, port reuse and NAT. If compatible Community ID support is explicitly enabled, it can help correlate flows, but it does not replace time and vantage-point checks.

References: [Zeek connection fields](https://docs.zeek.org/en/current/reference/logs/conn.html), [Suricata EVE format](https://docs.suricata.io/en/suricata-8.0.1/output/eve/eve-json-format.html), [Arkime FAQ and packet retention](https://arkime.com/faq).

## 4. Synthetic examples: read the evidence before concluding

All addresses, IDs, alert text and events below are **fabricated learning data**. The documentation address ranges are not real indicators of compromise. JSON excerpts illustrate selected native field names; they are not complete exports or results from live sensors.

### Zeek connection excerpt

```json
{
  "ts": 1792630800,
  "uid": "CLabExample001",
  "id.orig_h": "192.0.2.10",
  "id.orig_p": 51514,
  "id.resp_h": "203.0.113.20",
  "id.resp_p": 80,
  "proto": "tcp",
  "service": "http",
  "duration": 2.4,
  "orig_bytes": 220,
  "resp_bytes": 640,
  "conn_state": "SF",
  "missed_bytes": 0
}
```

This records a short TCP conversation classified as HTTP. `SF` reflects Zeek connection-state interpretation, not a determination that the application was harmless or that an attack succeeded. Byte counts do not by themselves establish data theft.

### Suricata EVE alert excerpt

```json
{
  "timestamp": "2026-10-22T01:00:01.000000+0000",
  "flow_id": 1000001,
  "event_type": "alert",
  "src_ip": "192.0.2.10",
  "src_port": 51514,
  "dest_ip": "203.0.113.20",
  "dest_port": 80,
  "proto": "TCP",
  "app_proto": "http",
  "alert": {
    "action": "allowed",
    "signature_id": 1000001,
    "signature": "LAB example HTTP request - synthetic",
    "severity": 3
  }
}
```

The lab alert shares the example connection endpoints. `allowed` must not be read as “safe.” In an IDS deployment, alerting generally does not block traffic; in IPS, review effective rules, action and enforcement. Severity 3 is an assigned rule priority, not proof of low business impact. This fictional signature is not an installed production rule.

### Arkime investigation worksheet

| Search constraint | Example |
| --- | --- |
| Time window | 2026-10-22 00:59:50–01:00:15 UTC |
| Protocol | TCP |
| Endpoints | 192.0.2.10:51514 ↔ 203.0.113.20:80 |
| Expected observation | Session overlapping the Zeek connection and EVE alert |
| Packet check | Confirm PCAP is retained and export only the relevant authorized session |

This table is a search worksheet, not Arkime query syntax or an assertion that a matching session exists. Use the installed viewer field help and expand the time window for measured clock differences.

## 5. Investigation: alert → connection → protocol → packets

1. **Validate the alert:** record the sensor, timestamp, signature ID/revision where available, action, endpoints and deployment mode.
2. **Find connection context:** locate the matching Zeek five-tuple/time interval; compare direction, duration and traffic volume. One EVE flow can generate several alerts, so alert count is not connection count.
3. **Inspect protocol records:** follow the Zeek `uid` to relevant HTTP or DNS records when collected. Do not assume encrypted HTTP content is visible.
4. **Review retained packets:** find the corresponding Arkime session, verify coverage and examine the relevant request and response. Preserve the original export and collection context.
5. **Check endpoint evidence:** identify the process, user and approved software; use endpoint or proxy records when network evidence is incomplete.
6. **Test alternatives:** compare an approved health check, software updater, authorized scan and malicious access as competing explanations.
7. **State the result:** distinguish a rule match, a completed network exchange, an application operation and confirmed compromise.

**Exercise:** The fictional alert fires on an HTTP `/health.txt` request. What changes the conclusion? An approved inventory agent and expected response can explain the activity; an unknown process and unauthorized file delivery justify deeper investigation. The provided excerpts contain neither the URI nor the process, so their correct initial conclusion is **investigate, outcome unconfirmed**.

## 6. Optional Splunk starting point

Use only after a parser has normalized each input into `src_ip`, `src_port`, `dest_ip`, `dest_port`, `transport`, `sensor` and `data_source`, with `_time` correctly parsed. These are **illustrative normalized fields**, not default field names shared by all tools.

```spl
index=network_lab src_ip="192.0.2.10" dest_ip="203.0.113.20"
  src_port=51514 dest_port=80 transport=tcp
| table _time data_source sensor src_ip src_port dest_ip dest_port transport
    event_type zeek_uid suricata_flow_id arkime_session_id
| sort 0 _time
```

Set the search time picker to the lab interval. The query lists observations; it does not perform a reliable automatic cross-tool join. Preserve original IDs under separate fields, and search the reverse tuple if the source normalizer has not standardized direction. Zero results require checks of time, index, extraction, sensor coverage and NAT before any security conclusion.

## 7. Encryption and common false conclusions

| Observation | What it does not establish | Next evidence |
| --- | --- | --- |
| TLS connection | That the payload is benign or visible | Endpoint process, available TLS metadata, authorized proxy records |
| SMB over QUIC / UDP 443 | Ordinary web browsing or visible SMB file operations | Protocol identification, server audit and endpoint evidence |
| No Suricata alert | No attack occurred | Rules enabled, visibility, packet loss and endpoint findings |
| Zeek protocol metadata | Complete packet capture | Capture coverage and original PCAP |
| Arkime session found | Its packets are still retained | PCAP availability and storage/retention state |
| Many records | Many distinct attacks or connections | Event type, flow IDs, sensor duplication and time |

For encrypted traffic, recorded packets can still help establish timing and transport behavior, but they do not automatically expose application content. Decryption needs additional authorized capabilities and compatible key material.

## 8. Preserve and report defensible evidence

Record the question, UTC window, clock offsets, sensor location, original IDs, five-tuple, rule context, collection gaps and retention status. Hash preserved PCAP exports, retain originals under access control and document any filtering. Network addresses alone do not reliably identify a human user.

**Completion check:** Explain the three tools; correlate one synthetic flow without equating IDs; identify a visibility gap; distinguish an alert from confirmed impact; and document what additional evidence is needed.

## 9. References and related learning

- [Zeek: conn.log](https://docs.zeek.org/en/current/reference/logs/conn.html)
- [Suricata: EVE JSON format, version 8.0.1](https://docs.suricata.io/en/suricata-8.0.1/output/eve/eve-json-format.html)
- [Arkime: FAQ](https://arkime.com/faq)
- [SMB security]({{ '/wiki/smb-security/' | relative_url }})
- [WPAD investigation]({{ '/wiki/wpad-security/' | relative_url }})

**Review date: 22 October 2026.** Product references describe behavior; examples and the exercise are original synthetic material. Verify fields and capabilities against deployed versions. No live traffic collection or live Splunk search was performed for this publication.
