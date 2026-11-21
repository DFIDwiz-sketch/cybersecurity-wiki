---
title: "ARP and IPv4 Address Conflicts · From Packets to Switch Ports"
description: "Read normal ARP exchanges, distinguish address probes from competing claims, and cross-check link-local evidence with switch and DHCP records."
category: network
tags: [ARP, IPv4, Network Security, Wireshark, Blue Team, DFIR]
level: Beginner
updated: "2026-11-21"
translation_url: /ko/wiki/arp-address-evidence/
---

**Learning goal.** When an IPv4 address appears with two MAC addresses, work out whether you saw a normal address check, two claims on the same link, or an observation that needs more evidence. Start with [DHCPv4 leases]({{ '/wiki/dhcp-lease-evidence/' | relative_url }}) if you are new to address assignment.

## 1. Why a host needs ARP

An **IPv4 address** identifies a network-layer destination. A **MAC address** identifies the source or destination of an Ethernet frame on a local link. A **frame** is the unit carried on that link. A host first consults its routing table. If the IPv4 destination is on-link, the next hop is the destination itself. For a route via a gateway, the next hop is the gateway. **Address Resolution Protocol (ARP)** finds the Ethernet MAC address for that next-hop IPv4 address. The remote destination remains in the IP header while the next-hop MAC goes in the Ethernet header.

A **neighbor cache** holds mappings so a machine can send consecutive frames without asking every time. A switch uses a different table, often called a **MAC address table** or **forwarding database (FDB)**. It learns where to forward frames from source MAC addresses and ingress ports within its switching context. A **VLAN** defines a logical Layer 2 segment. Two networks can reuse the same IPv4 address without sharing a link. A meaningful comparison needs the capture segment and time as well as the IP and MAC. ARP has no TCP or UDP ports. IPv6 uses Neighbor Discovery instead.

## 2. Read a normal exchange

<figure style="margin-inline: 0">
<img src="{{ '/assets/diagrams/arp-address-evidence-en.svg' | relative_url }}" alt="A route chooses an on-link destination or gateway. Its IPv4 address leads to a cached MAC or an ARP exchange, then to the Ethernet destination.">
<figcaption>ARP resolves the next hop chosen by routing. The remote IP address stays in the IP packet.</figcaption>
</figure>

In a fictional VLAN 20, workstation `192.0.2.10` opens a connection to `198.51.100.25` through gateway `192.0.2.1`. With no usable mapping cached, it sends an ARP request as a broadcast frame. The request's sender protocol and hardware fields carry the workstation's IPv4 and MAC. The target protocol field is `192.0.2.1`. The gateway answers, normally with a unicast frame to the workstation, identifying itself in the sender fields as `192.0.2.1` at `02:00:00:00:20:01`. The workstation can now send a frame to that MAC carrying a packet destined for `198.51.100.25`. If the workstation already has a usable entry, a capture of the connection may contain no ARP exchange at all.

| Message | Typical fields | What you can say |
| --- | --- | --- |
| Ordinary request | Opcode 1. Nonzero sender IP. Target IP is the next hop being queried. | The sender asked about that target and advertised its own sender pair. |
| Ordinary reply | Opcode 2. Sender IP and MAC answer the query in a normal exchange. | A frame claimed the sender mapping. Check the request and capture context before calling it solicited. |
| IPv4 address probe | RFC 5227 broadcast request. Sender IP `0.0.0.0`, target IP is the candidate. | A device is checking a candidate address. Keep it out of the owner list, but investigate concurrent probes if diagnosing address conflict detection. |
| IPv4 address announcement | RFC 5227 broadcast request. Sender and target IP are the same nonzero address. | The sender announces its address. Some products use other forms of gratuitous ARP, so inspect the fields and device role. |

Ethernet source and ARP sender hardware address are distinct fields. Retain both when available. A mismatch deserves context from the capture and network equipment. An address shown in an ARP payload is a claim, and capturing the claim does not show that another host adopted it.

## 3. Distinguish a conflict from a planned change

ARP does not authenticate the claimed mapping. A false claim can make a receiver that accepts it send local frames to the wrong MAC. That can cause interruption or put traffic on an unintended path. Even a confirmed path change leaves TLS identity checks and the confidentiality of correctly protected traffic as separate questions.

| Observation | Ordinary explanation to check | Evidence that raises priority |
| --- | --- | --- |
| One announcement | Interface startup or a planned failover | Unexpected sender MAC and switch ingress port for a protected gateway |
| One IP, two MACs on the same link | Replacement, duplicate static assignment or overlapping configuration | Repeated competing claims in the same short interval, switching of endpoint cache mappings or simultaneous service impact |
| Same virtual MAC on a different switch port | Gateway failover, teaming or convergence | Unexpected access port, no corresponding change in redundancy telemetry, or repeated moves outside the expected path |
| One MAC replies about multiple IPs | Configured Proxy ARP or device role | Claims that do not match the documented proxy scope or segment |

A VRRP failover can preserve the virtual MAC and move that MAC's physical location. Check the expected virtual MAC and port history separately. A MAC vendor prefix, a lone announcement or one Wireshark diagnostic flag is thin evidence for attribution. Conversely, a real duplicate assignment can break connectivity without anyone attempting an attack.

## 4. Collect, correlate and respond

1. **Find the affected link.** Record IP, subnet, gateway, VLAN or bridge, interface, time (UTC), clock offset and impact. Verify the sensor is fed from the relevant segment, including traffic between local ports if needed. A routed-only vantage or an IP-only capture filter can miss ARP. An untagged capture may still come from a known VLAN. Document how you learned its scope.
2. **Preserve the evidence.** Retain the relevant original capture, switch logs and endpoint snapshots with capture location, filter and loss information. Record opcode, both Ethernet addresses, the ARP sender/target pairs, and capture time. A Linux endpoint with iproute2 can display IPv4 entries using `ip -4 neigh show` from the affected network namespace. Record interface, state and time. An empty or stale cache is a current observation with limited historical value.
3. **Compare independent records.** Start with a baseline of gateway IP, virtual/physical MAC and expected ports. Compare sender claims by site and VLAN and a bounded time window. Check DHCP snooping or lease history for dynamic addresses, static records for gateways, and the switch FDB or port logs for location. A current FDB snapshot may have aged out or relearned. A trunk locates a path onward. A DHCP binding records assignment and does not establish ownership of every observed frame.
4. **Contain with the network owner.** A deliberate or accidental competing claim is an operational concern when it changes forwarding or causes service impact. Preserve the records before cache or switch changes. Trace through uplinks to the actual edge port, check its role and maintenance history, then coordinate isolation of the confirmed source or correction of the duplicate assignment. Verify the affected hosts recover the expected mapping and service. Record the observations and any remaining uncertainty.
5. **Validate the control.** Dynamic ARP Inspection (DAI) on supported switches can check ingress ARP against DHCP snooping bindings or configured ARP ACLs for static systems. Validate coverage, static entries and trust boundaries in an approved test environment. Confirm expected traffic passes and violations are visible in vendor-specific logs or counters. A drop records a policy decision and may reflect a stale binding or incomplete configuration. Do not treat the absence of DAI alerts as evidence of coverage.

For already collected Ethernet packets in Wireshark, use the display filter `arp && (arp.src.proto_ipv4 == 192.0.2.1 || arp.dst.proto_ipv4 == 192.0.2.1)` to review claims and queries for the sample address. Add `arp.opcode == 1` or `arp.opcode == 2` when isolating a message type. These are display filters. They cannot recover packets omitted at capture. Use `eth.src` and `arp.src.hw_mac` to inspect Ethernet and ARP sender fields separately.

## 5. Offline lab · scope the claims

Download the <a href="{{ '/assets/labs/arp-observations.csv' | relative_url }}" download>synthetic ARP rows</a> and open them as UTF-8 CSV. The timestamps and packet fields are fictional teaching data. The worksheet scope column identifies the original segment, which could come from sensor configuration rather than an on-wire tag. No packet transmission, privileges, or real log collection is needed. Work with the supplied file or authorised, already collected records.

1. Locate frame 1 and frame 2. Identify the request target and the reply sender. The answer to the request is found in the reply's **sender** pair.
2. On segment `lab-vlan20`, find every row mentioning `192.0.2.1`. Separate the rows that **claim** it in `sender_ip` from rows that have it only as `target_ip`. Group the claims by `sender_mac`.
3. Compare early rows 2–3 with later rows 6–8. Assume the written baseline expects MAC ending in `20:01` for this VLAN. Which new MAC made the same claim? Which earlier row is only a probe, and which other-segment claim should stay out of the comparison?
4. Write a ticket with one observation, one uncertainty and a collection request. Then compare with the result below.

Expected result. Two sender MACs claim the gateway on VLAN 20. `02:00:00:00:20:01` appears in frames 2, 3 and 7. `02:00:00:00:20:77` appears in frames 6 and 8. Frame 4 is a probe with sender `0.0.0.0`. Frame 5 belongs to VLAN 30. A useful ticket records competing claims within one link and asks for endpoint cache snapshots, switch port history and gateway maintenance records before concluding a traffic path changed.

If there are three MACs in your result, check the segment filter. If a probe is counted as ownership, recheck the distinction between sender and target. If a workbook imports MACs or timestamps in a different format, use a plain text editor or import both columns as text. The worksheet and expected groupings were checked in a cloud runtime. Wireshark and vendor guidance were reviewed from official documentation.

## 6. Check your reasoning

1. **The packet's IP destination is on another network. Which MAC should appear at the first Ethernet hop?** The MAC of the next-hop gateway selected by routing. The packet's destination IP stays remote.
2. **A capture shows one announcement after a scheduled gateway switchover. What next?** Compare its IP/MAC with the expected virtual mapping, then correlate the role change and switch-port history. That can support a planned change.
3. **A sensor saw a competing claim. What would strengthen a traffic redirection finding?** A matching endpoint neighbor entry change near the claim and frames sent to the unexpected MAC, supported by switch location and timestamps. An application-level outcome requires more evidence.

**Completion criteria.** Explain routing versus local delivery, separate probes from sender claims, identify exactly two candidate MACs from the worksheet, and name two independent sources needed to judge impact.

Next, read [capture visibility]({{ '/wiki/capture-visibility/' | relative_url }}) to check whether your sensor could have observed the exchange.

## Official references

Reviewed 2026-11-21. The early ARP specification describes Ethernet resolution. The later documents cover address conflict detection, virtual router behavior, or current tool and switch interpretation.

- [RFC 826, Ethernet Address Resolution Protocol](https://www.rfc-editor.org/rfc/rfc826.html) (November 1982).
- [RFC 5227, IPv4 Address Conflict Detection](https://www.rfc-editor.org/rfc/rfc5227.html) (July 2008, especially §§1.1 and 2).
- [RFC 9568, VRRPv3](https://www.rfc-editor.org/rfc/rfc9568.html#section-8.1.2) (April 2024, IPv4 ARP behavior, supersedes RFC 5798).
- [Wireshark ARP display fields](https://www.wireshark.org/docs/dfref/a/arp.html) (reference through Wireshark 4.6.10).
- [iproute2 neighbor table manual](https://man7.org/linux/man-pages/man8/ip-neighbour.8.html) (Linux `ip neigh` commands and states).
- [Cisco Catalyst 9000 Dynamic ARP Inspection](https://www.cisco.com/c/en/us/td/docs/switches/lan/c9000/sec-crypto/fhs-sisf/fhs-and-sisf-configuration-guide/dynamic-arp-inspection.html) (IOS XE 17 family).
