---
title: "IPv6 Neighbor Discovery · Investigate Addresses and Reachability"
description: "Read Neighbor Solicitations, Advertisements and Duplicate Address Detection alongside endpoint cache evidence."
category: network
tags: [IPv6, ICMPv6, Neighbor Discovery, Wireshark, Blue Team]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/ipv6-neighbor-discovery-evidence/
---

**Learning goal.** Decide what an IPv6 neighbor message asks or claims, whether a specific endpoint changed its cache or address state, and what remains unresolved when a capture has gaps.

## 1. The next hop needs a link-layer address

An IPv6 packet names a network-layer destination. On Ethernet, the frame carrying it also needs a destination MAC. The host consults its route to decide which **next hop** to reach on the local link. That may be the destination itself or an on-link router. For a remote destination, the IP destination remains remote even though the frame goes to the router's MAC. The host uses **Neighbor Discovery (ND)** to resolve the local next hop and caches the result. Track the link, interface and IPv6 address together. A link-local address can be reused on separate links.

| Message or state | Meaning | Evidence to compare |
| --- | --- | --- |
| Router Advertisement (RA, type 134) | Announces router and configuration information | Routing, prefix and DNS state |
| Neighbor Solicitation (NS, type 135) | Asks about a target for resolution, reachability or Duplicate Address Detection (DAD) | Source, destination, target, link and local state |
| Neighbor Advertisement (NA, type 136) | Supplies information about its target | Target, flags, link-layer option and receiving host's cache |
| Neighbor Unreachability Detection (NUD) | Checks an existing neighbor's reachability | Cache state, probes and upper-layer progress |
| Duplicate Address Detection (DAD) | Tests a tentative address before using it | Tentative address state, same-link messages and host result |

## 2. Trace a normal exchange

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/ipv6-neighbor-discovery-en.svg' | relative_url }}" alt="Route selection identifies the local next hop. A host with no cached MAC sends a Neighbor Solicitation. A Neighbor Advertisement conveys a target binding. A sensor records what it sees, while a separate endpoint snapshot shows which binding the host actually has.">
  <figcaption>Follow the next hop from route selection to neighbor resolution. Compare what the sensor saw with the endpoint's own state.</figcaption>
</figure>

In this fictional IPv6 Ethernet example, a workstation in VLAN 20 needs to reach an off-link destination through router `fe80::1`.

1. The route points to `fe80::1` on the workstation's Ethernet interface. With resolution pending, the neighbor entry can be `INCOMPLETE`.
2. The workstation sends an NS (Hop Limit 255). Its IP destination is the target's solicited-node multicast group, `ff02::1:ff00:1` in this example. This group is based on the final 24 bits of the target and can be shared by several addresses. Read the full **Target Address** in the ICMPv6 message to identify the address queried.
3. The router returns a solicited unicast NA for the target, including its Target Link-Layer Address option in this multicast-resolution exchange. The workstation can use the learned MAC. Its cache can show `REACHABLE` after successful solicited resolution. Confirm the actual Ethernet destination in a subsequent frame if the question is where that host sent traffic.
4. An older mapping can become `STALE` and still be usable. When it is next used, NUD can proceed through `DELAY` and then `PROBE` if reachability is not otherwise confirmed. A probe for an existing mapping can be unicast. Upper-layer reachability confirmation can make a probe unnecessary. Linux `FAILED` means a neighbor check or resolution failed after probing, with the cause still to be investigated.

The three NA flags describe processing context. **S** is Solicited, **O** is Override, and **R** is Router. O affects whether a receiver may replace an existing binding and is evaluated with cache state and the option supplied. R conveys router status. A flag is protocol data and does not authenticate the sender. A conforming NA with a multicast IPv6 destination has S clear. Certain updates can be unsolicited during normal operation. RFC 9131 describes a case in which a first-hop router can proactively create a cache entry from a gratuitous NA. Verify support and configuration before assuming that behavior in a particular deployment.

### A DAD probe asks a different question

Before assigning a tentative address, a host performing DAD uses an NS with source `::`, the tentative address as Target Address, and the target's solicited-node multicast destination. It omits the Source Link-Layer Address option. The Ethernet source can still be present in the frame. This NS tests whether the address is already in use. A current owner may answer with an NA to all nodes, with S clear. Two hosts testing the same tentative address can also detect each other by receiving solicitations. One outbound DAD probe alone shows an attempt. The endpoint's eventual address state establishes whether it assigned the address or detected a conflict.

## 3. Investigate an unexpected mapping

A false local claim can affect where a host sends frames if the host updates its cache. An address conflict can also prevent assignment, while a flood of unresolved entries can consume router resources. Ordinary causes include a planned failover, a moved VM, an ND proxy or missing sensor coverage. Use those possibilities to choose corroborating evidence before attributing a cause.

1. **Collect from the correct link.** Record endpoint and sensor clock, interface, VLAN or equivalent segment, capture direction, dropped-packet counters and whether a mirror or offload changed what you see. Preserve NS and NA type, source, destination, target, Hop Limit, Code, flags, Ethernet MACs and source/target link-layer options when present. Keep Ethernet source and the advertised option in separate fields. Missing VLAN tags on a copy do not identify its original link.
2. **Check message validity before interpreting a claim.** RFC 4861 receiver checks include Hop Limit 255, valid checksum, Code 0, minimum ICMP length, non-multicast target and valid option lengths. An NS from `::` requires a solicited-node destination and no source link-layer option. A multicast-destination NA has S clear. RFC 6980 additionally requires recipients to ignore NS/NA carried with a Fragment Header. Validate disputed checksums at a suitable capture point because transmit offload can affect what a sender-side capture displays. A message passing structural checks still leaves the identity and authorization of the sender open.
3. **Check adoption at the endpoint.** Preserve route, neighbor and address snapshots before making changes. Compare the same target and interface across time. An NA on a mirror shows that the sensor observed an advertisement. A before-and-after MAC change in the affected host's cache gives stronger evidence of adoption, and an outgoing frame can show use. A cache change and a nearby NA alone do not establish causation. Correlate switch forwarding records, VLAN, approved router identities, inventory and change records. A switch trunk or proxy-facing port can aggregate many devices.
4. **Scope and respond.** Group anomalies by link and target. Prioritize a changed gateway binding with corroborated traffic redirection, or repeated DAD failures independently tied to new endpoint setup. For a suspected resolution outage, compare endpoint status, switch telemetry and a healthy control before attributing missing replies to network loss. With the network owner, correct mistaken configuration or contain a confirmed unauthorized port or workload. Verify that legitimate resolution and DAD still work after the change. Keep the before-and-after evidence.

### Read-only collection examples

On an authorized Linux host with IPv6 and iproute2, replace `eth0` with the affected interface in the correct network namespace. Capture the UTC time separately. These commands read route, cache and address state. `route get` performs a local route lookup. Save the snapshots while the incident is active. A single output is a point-in-time view and does not preserve previous mappings.

```bash
ip -6 route get 2001:db8:42::80
ip -6 neigh show dev eth0
ip -6 addr show dev eth0
```

In Wireshark, open a capture from that link and apply this display filter. It keeps both directions for one target. Substitute the IPv6 address of the next hop or tentative address as appropriate. Inspect destination and source separately, and use an unfiltered view when checking for fragment headers or missing context. A display filter cannot restore traffic that was never captured.

```text
icmpv6.nd.ns.target_address == fe80::1 || icmpv6.nd.na.target_address == fe80::1
```

## 4. Practice with synthetic evidence

Download the <a href="{{ '/assets/labs/ipv6-neighbor-evidence.py' | relative_url }}" download="ipv6-neighbor-evidence.py">Python script</a> and <a href="{{ '/assets/labs/ipv6-neighbor-evidence-cases.json' | relative_url }}" download="ipv6-neighbor-evidence-cases.json">case file</a> to the same directory in your own or authorized workspace. Use Python 3.9 or newer. The fixture contains pre-decoded observations from fictional links and endpoint snapshots. The script reads JSON and sends no traffic. Its checks cover a few teaching conditions and do not replace a packet decoder or protocol implementation.

```bash
python3 ipv6-neighbor-evidence.py ipv6-neighbor-evidence-cases.json
```

| Case | What the evidence supports |
| --- | --- |
| `normal_resolution` | Solicitation and advertisement observed. Endpoint learned a reachable mapping. |
| `normal_dad` | DAD probe observed. Endpoint snapshot shows address assigned. |
| `dad_conflict` | DAD probe and same-link claim observed. Endpoint recorded DAD failure. |
| `wrong_hop_limit` | Advertisement fails a header check. Endpoint binding stayed the same. |
| `capture_only` | An advertisement was observed. Endpoint state is unknown. |
| `separate_link` | A competing-looking advertisement came from another link. |
| `changed_binding` | Endpoint MAC changed. The cause remains to be investigated. |
| `failed_without_reply` | Endpoint neighbor check failed. The sensor sample showed a solicitation and no matching advertisement. |

Each case reports what was seen on the link and what was recorded at the endpoint. All rows should print PASS. Change the NA Hop Limit in a copy of `wrong_hop_limit` to 255. The original expected rejection should fail, while the endpoint binding remains unchanged. If the script cannot open the case file, check the working directory and both names. If an unexpected row fails, compare the link first, then the full target, the message fields and the two endpoint snapshots.

The Python cases were executed in the cloud workspace. The Linux command behavior and Wireshark fields were reviewed against documentation. No packet exchange, switch policy or Wireshark instance was exercised in this lab.

## 5. Check your reasoning

- **Why does a remote IPv6 destination stay in the packet while the frame goes to a local router?** The IP destination identifies the end destination. Ethernet delivers this one hop to the router.
- **An NS came from `::` and the endpoint later assigned its address. Was the probe evidence of a conflict?** The probe shows that the host checked. The endpoint's later state shows assignment. A conflict claim requires additional evidence.
- **An NA on a mirror had O set and an unfamiliar MAC. Did the host adopt it?** Examine the receiving endpoint's cache for the same link and target. Adoption and attribution require separate evidence.
- **A single entry is `STALE`. Is the neighbor offline?** The mapping lacks recent reachability confirmation. Check subsequent state and traffic before judging reachability.

Finish when all eight cases pass and you can write one finding that distinguishes the observed message, endpoint outcome, likely cause, and the next record needed to confirm it.

## Official references

Reviewed November 26, 2026. The primary standards are from 2007–2021. Use the updates when assessing current behavior.

- ND message validation, cache rules and NUD. [RFC 4861 §§7.1–7.3](https://www.rfc-editor.org/rfc/rfc4861.html#section-7)
- Tentative addresses and DAD outcomes. [RFC 4862 §5.4](https://www.rfc-editor.org/rfc/rfc4862.html#section-5.4)
- Fragment Header handling and gratuitous first-hop updates. [RFC 6980 §5](https://www.rfc-editor.org/rfc/rfc6980.html#section-5) · [RFC 9131](https://www.rfc-editor.org/rfc/rfc9131.html)
- Operational security, Linux states and Wireshark fields. [RFC 9099](https://www.rfc-editor.org/rfc/rfc9099.html) · [ip-neighbour(8)](https://man7.org/linux/man-pages/man8/ip-neighbour.8.html) · [Wireshark ICMPv6 display fields](https://www.wireshark.org/docs/dfref/i/icmpv6.html)

[Previous · IPv6 router advertisements]({{ '/wiki/ipv6-router-advertisement-evidence/' | relative_url }}) · [Compare · ARP and IPv4 conflicts]({{ '/wiki/arp-address-evidence/' | relative_url }}) · [Related · VLAN capture evidence]({{ '/wiki/vlan-capture-evidence/' | relative_url }})
