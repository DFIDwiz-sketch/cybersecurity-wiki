---
title: "Investigate VLAN Tags and Sensor Visibility"
description: "Trace single and stacked Ethernet tags across capture points with two synthetic PCAPs."
category: network
tags: [VLAN, Ethernet, Packet Capture, Wireshark, Network Security, Blue Team]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/vlan-capture-evidence/
---

A switch inventory places a workstation in VLAN 20, but the sensor's packet has no VLAN tag. Start by separating the segment used for forwarding, the tags on the observed link, and the bytes delivered to the collector. Each is a different piece of evidence.

## 1. Read the tag in the context of the port

A **VLAN** is a logical Layer 2 forwarding domain. A switch associates incoming Ethernet frames with one of these domains according to port configuration and any tags. An **access port** commonly carries one data VLAN with untagged frames on the host-facing link. A **trunk** commonly carries several VLANs and uses tags to distinguish them. A trunk can also carry an untagged VLAN when configured to do so. **PVID** is the port VLAN identifier used in classification, for example when an admitted frame arrives untagged. Vendor terminology and ingress and egress policies vary. Confirm both ends of the link.

An 802.1Q tag inserts four bytes between the source MAC address and the next type or length field. The first two bytes are the **Tag Protocol Identifier** (TPID). The next two are **Tag Control Information** (TCI). Read TCI in network byte order. Its upper three bits contain priority (PCP), the next bit is drop eligibility (DEI), and the low twelve bits are the VLAN identifier (VID). `0x8100` identifies the common C-tag; `0x88a8` identifies an S-tag. Each additional tag shifts the next type field by four bytes. In a typical provider stack, read the outer service tag and then the inner customer tag. Record the order, even when the two IDs look familiar.

| Captured evidence | What you can say | What you still need |
| --- | --- | --- |
| No tag header visible | This stored frame contains no visible tag | Source port, mirror, driver and capture context |
| C-tag VID 20 | The stored frame carries VID 20 at that tag layer | Site, switch and policy that give the number meaning |
| VID 0, PCP 5 | The tag carries priority and no specific VLAN association | Ingress classification and port configuration |
| Outer VID 200, inner VID 20 | Two tag layers are present, in that order | Which domain each tag names on this link |
| Capture ends inside the header | This record has insufficient bytes to finish decoding | Stored and original lengths, snaplen and an independent sample |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/vlan-capture-evidence-en.svg' | relative_url }}" alt="Untagged ingress is classified as VLAN 20. A tagged trunk view and a sensor copy can differ.">
  <figcaption>Compare the trunk observation and the sensor copy before inferring where a tag changed.</figcaption>
</figure>

## 2. Follow one normal request

At 09:10 UTC in a fictional site, a workstation sends a frame toward `198.51.100.20`. Its host-facing access link carries the frame untagged. The switch classifies it into VLAN 20 from the ingress configuration. An uplink carries tagged VLAN 20 traffic, and the switch inserts the C-tag for that egress link. A TAP on that uplink can observe the tag if the capture path preserves it. A local SPAN session copying the same uplink may emit a copy with tags removed. For example, Cisco documents untagged output by default on the cited Catalyst 9300 local SPAN release and original encapsulation preservation when configured. Verify your own platform and session rather than generalizing that behavior.

At 09:10:01 a second frame at the same sensor has the same IP addresses and ports but carries VID 30. In an overlapping address plan, the network tuple can legitimately repeat. Correlate both captures using the timestamp and complete frame or available higher-layer transaction evidence plus sensor and segment. Inspect routing or translation separately when the observations are on opposite sides of a Layer 3 boundary. A VLAN ID identifies context on a link and does not travel as a global flow ID.

## 3. Investigate changes and capture gaps

1. **Record the topology and point of observation.** Record site, switch and port, access or trunk role, configured PVID or native VLAN, allowed VLANs, time window, mirror source and destination, and direction. At the sensor preserve the interface, link-layer type, collector version, snaplen, filters, packet drop counters and original file. Record whether you captured a physical link, logical VLAN interface or a normalized copy. NIC, driver and capture-stack behavior can strip or reconstruct tags. A sensor with a logical VLAN input may preserve segment metadata even when the stored packet has no tag header.
2. **Compare an independent observation.** Use a benign test message with an approved endpoint and distinct transaction marker on each expected segment. Compare a suitable upstream TAP or verified mirror with the capture file and decoded logs. Document any tag rewriting and distinguish an absent frame from a present frame with fewer headers. When using Wireshark, inspect the Packet Details and raw bytes. Display filters such as `vlan.id == 20` and `ieee8021ad.id == 200` target specific dissector fields. Check the protocol tree on stacked tags and your installed version. A display filter cannot recover packets removed by a capture filter. In libpcap syntax each `vlan` qualifier shifts subsequent decode offsets by four bytes. Test proposed filters against representative untagged, single-tagged and stacked captures before using them for collection.
3. **Separate policy errors from misuse.** Unexpected segment crossings may follow an incorrect trunk allow-list, inconsistent untagged VLAN handling, intentional service tagging, or unauthorized changes. An unexpected tag alone does not show that forwarding occurred. Review interface and switch configuration history, MAC learning by VLAN, allowed inter-VLAN flows and firewall logs. Confirm when the switch observed the configuration and whether the frame actually reached another segment.
4. **Validate detection and recovery within scope.** Group unusual segment pairs by site, interface, direction and both tag roles. Keep absent tags and unresolved segment mappings explicit. Alert on changes relative to verified inventory, and review approved exceptions. After a fix, test an allowed path and a policy-denied path with harmless application traffic in your authorized test segment. Compare forwarding outcomes, logs and sensor counters. A working capture does not by itself validate the segmentation policy.

## 4. Offline evidence lab · two synthetic captures

<a href="{{ '/assets/labs/vlan-capture-lab.py' | relative_url }}" download="vlan-capture-lab.py">Download the Python capture lab</a>

Use Python 3 in an empty working directory. The script writes two small Ethernet PCAP files into a new folder named `vlan-lab`, then decodes its own fixtures. It uses deterministic documentation IP addresses, synthetic locally administered MAC addresses, and fixed payload markers. No packet is transmitted. The capture files have no Ethernet frame-check sequence. The capture-copy transformations illustrate possible outcomes and do not emulate a particular switch or NIC.

~~~bash
python3 vlan-capture-lab.py
~~~

| Marker | Link view | Sensor copy |
| --- | --- | --- |
| A | Untagged | Untagged |
| B | C-tag VID 20 | Same test message with no visible tag |
| C | C-tag VID 30 | C-tag VID 30, same IP tuple as B |
| D | Outer S-tag 200, inner C-tag 20 | Inner C-tag 20 remains |
| E | Priority tag VID 0, PCP 5 | Same priority tag |
| F | Complete C-tag VID 40 | Frame 6 has only 15 captured bytes, too short to decode TCI |

Expect six PASS lines. Open the generated files in a local Wireshark viewer if installed. Match the synthetic payload marker for complete frames. For frame 6, compare frame number and the recorded length fields because the saved bytes contain no marker. Read the Ethernet protocol tree, then optionally use the display fields above. If the script refuses to create the folder, use a fresh working directory. If a viewer cannot decode the file, verify Ethernet PCAP support and that the generated file was transferred intact. The Python writer and decoder were run locally in the cloud; the Wireshark filters were reviewed against its reference.

## 5. Check your reasoning

1. **A sensor copy has no VLAN tag. Was the packet forwarded in the native VLAN?** The copy lacks a tag. Verify the original port, mirror encapsulation and capture path before assigning the segment.
2. **Do frames B and C belong to one flow because their tuples match?** The fixture reuses the tuple on different tagged segments. Keep segment identity in the key and confirm the application marker.
3. **Does VID 0 name VLAN zero?** It is a priority tag with no explicit VLAN membership. The port configuration supplies classification.
4. **Does a short frame in a PCAP prove the wire frame was malformed?** Compare captured length with original length. A truncated record does not expose all wire bytes.

Finish when you can reproduce the six observations and write one note documenting link versus sensor evidence, tag order or absence, and the implementation or configuration you would check next.

## Official references and next reading

Reviewed **2026-11-26**. The base IEEE standard cited here was published in 2022. The Cisco example is specific to IOS XE 17.15.x on Catalyst 9300. The Wireshark display reference spans versions through 4.6.10 at review. Live switch forwarding and NIC behavior were reviewed from documentation.

- Bridged networks and tag protocol identifiers. [IEEE 802.1Q-2022](https://standards.ieee.org/ieee/802.1q/10323/) · [IANA IEEE 802 Numbers](https://www.iana.org/assignments/ieee-802-numbers/)
- Platform-specific mirror behavior and capture visibility. [Cisco Catalyst 9300 SPAN / RSPAN](https://www.cisco.com/c/en/us/td/docs/switches/lan/catalyst9300/software/release/17-15/configuration_guide/nmgmt/b_1715_nmgmt_9300_cg/configuring_span_and_rspan.html) · [Wireshark VLAN capture setup](https://wiki.wireshark.org/CaptureSetup/VLAN)
- Display and capture filter semantics. [Wireshark 802.1Q fields](https://www.wireshark.org/docs/dfref/v/vlan.html) · [Wireshark 802.1ad fields](https://www.wireshark.org/docs/dfref/i/ieee8021ad.html) · [pcap-filter(7)](https://man7.org/linux/man-pages/man7/pcap-filter.7.html)

Previous · [Capture visibility]({{ '/wiki/capture-visibility/' | relative_url }})  
Next · [ARP evidence]({{ '/wiki/arp-address-evidence/' | relative_url }}) · [Firewall and NAT evidence]({{ '/wiki/firewall-nat-evidence/' | relative_url }})
