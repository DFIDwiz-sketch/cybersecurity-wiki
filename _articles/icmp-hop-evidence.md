---
title: "Traceroute and ICMP Evidence · Match the Quoted Probe"
description: "Read TTL expiry, distinguish path observations from destination replies, and correlate IPv4 and IPv6 errors in an offline PCAP."
category: network
tags: [ICMP, ICMPv6, Traceroute, Wireshark, Network Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/icmp-hop-evidence/
---

**Learning goal.** A traceroute shows a silent hop, and a packet capture contains an ICMP error from a router. Learn to identify which probe the error describes and how much of the path that single observation can establish.

## 1. Why a hop sends an error

The IPv4 **Time to Live (TTL)** and IPv6 **Hop Limit** fields place a bound on forwarding. IPv4 routers decrement TTL by at least one when forwarding. IPv6 forwarding nodes decrement Hop Limit by one. A node that discards a packet because the limit expires normally reports an **ICMP Time Exceeded** error, subject to ICMP generation rules, policy and rate limits. Traceroute sends separate **probes** with increasing starting limits so different forwarding nodes can expose themselves by reporting expiry.

An ICMP error has two perspectives. The **outer IP header** gives the source and destination of the error itself. The **quote** inside the error contains a prefix of the packet that triggered it. That inner header and any visible transport fields are the starting point for correlation. The responding IP can be a different interface from the one that received the probe. A quote can be short by design or capture truncation. The original IPv4 ICMP specification includes the original IP header and first eight bytes after it. Later router guidance recommends a larger quote when possible. ICMPv6 includes as much as fits within its minimum-MTU size limit.

| Meaning | IPv4 ICMP type/code | IPv6 ICMP type/code | Interpretation |
| --- | --- | --- | --- |
| Forwarding limit expired | 11/0 | 3/0 | A forwarder reports expiry for the quoted packet. |
| Fragment reassembly timed out | 11/1 | 3/1 | Reassembly failed to finish. This code supplies no traceroute hop on its own. |
| Destination UDP port unreachable | 3/3 | 1/4 | For a matching UDP probe, an endpoint reports an unreachable port. A policy device can also produce this signal. Check its origin. |
| Packet too large to forward | 3/4, fragmentation needed | 2/0, Packet Too Big | Investigate size and path MTU using the quoted packet and reported limit. |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/icmp-hop-evidence-en.svg' | relative_url }}" alt="A sender and destination are connected through a router. A probe with TTL 1 expires at the router. The returned ICMP error encloses a quote of the original probe. Compare the quoted addresses and UDP ports with the probe." width="480" height="360">
  <figcaption>The outer addresses describe the reply endpoints visible to the observer. The quoted packet identifies the traffic the error describes.</figcaption>
</figure>

## 2. Walk a normal trace

In the fictional capture below, the client is `192.0.2.10` and the target is `203.0.113.80`. In frame 1 the client sends a UDP probe with TTL 1, source port 40010 and destination port 33434. Frame 2 arrives from `192.0.2.1` and reports 11/0. Open the quote. It contains the original client and target addresses, UDP protocol and both matching ports. Together with the capture order and time, that supports a first-probe match.

The next probe is frame 3, with TTL 2 and different ports. Frame 4 comes from a plausible router but quotes destination port 33499. The actual probe used 33435, so frame 4 remains unmatched in this view. Frame 5 has a matching quote. Later, the target returns a matching 3/3 (frame 7), a conventional terminal result for this UDP method. The sequence shows how the probes were treated at the observation point. A separate service-health request would be needed to establish that an application is working.

Traceroute implementations support different methods. A UDP-based method commonly expects a port-unreachable error at the destination. ICMP Echo uses an Echo Reply as the expected terminal response. A TCP-based method can end with a TCP reply such as SYN-ACK or RST, depending on the implementation and target state. Limit and response interpretation belong to the method. A policy-generated response or reply from a load balancer may affect attribution.

## 3. Evidence that changes the interpretation

| Observation | Plausible explanation | What to compare |
| --- | --- | --- |
| One hop is silent, later probes get replies | Control-plane limiting, filtering, loss or a change of path | Match later probes, compare counter or packet observations if available, and check whether the traffic actually arrived. |
| Several addresses appear at the same hop number | Equal-cost paths or different reply-source interfaces | Probe fields, path or route telemetry, same-vantage times and the tool's probe method. Some devices hash flow fields. |
| A matched message has a surprising outer address | An alternate return interface, forwarded policy response or untrustworthy report | Compare the quote, capture point and route context. ICMP source information is unauthenticated. |
| The quote is missing ports or uses a translated tuple | Capture truncation, short quotation, fragmentation, tunnelling or NAT | Captured versus on-wire length, inner protocol, correct boundary and NAT state if available. |
| Same tuple maps to two recent probes | Reused ports, retried probes or duplicate capture | Use timing and additional validated evidence where present. Preserve ambiguity if they fail to separate candidates. |

Hops that respond can differ between probe methods, direction, time and flows. Round-trip times include the return path and control-plane work. Subtracting adjacent hop round-trip times cannot reliably locate a slow link. A silent hop alone cannot distinguish packet loss from an unreturned ICMP message. Spoofed or unrelated errors can mislead an analyst or endpoint. Treat useful ICMP feedback as operational evidence and compare it with a known local flow and observations from the relevant boundary.

## 4. Collect, detect and respond

1. **Fix the scope.** Record UTC and clock offset, capture interface, VLAN or tunnel context, IP family, capture length and NAT side. Preserve the original capture and its approved digest. Record which trace method and request created the probes. Captures can include sensitive quoted data, so keep originals in the authorized evidence store.
2. **Join to an original observation.** Record frame number and time, outer ICMP type/code and sender, quoted addresses, protocol and visible ports. For Echo, record the appropriate identifier and sequence instead of UDP ports. Correlate within a justified window and on the same translation side. For another vantage, match through a timestamped NAT mapping or use coordinated captures. Treat missing transport fields and repeated identifiers as reduced confidence.
3. **Test the detection.** Report rates by sensor, IP family, type and code. Separate matching errors from ambiguous and unmatched traffic. Compare with the baseline for expected diagnostics, routing changes and ICMP policy. A spike in matched forwarding-expiry errors deserves comparison with route changes and multi-point evidence. A spike in unmatched errors can indicate a visibility gap or unexpected input. A single type, address or silent hop cannot attribute malicious intent.
4. **Verify the impact.** Compare endpoint or service observations and approved network counters. Escalate a routing-loop hypothesis with repeated matching evidence from relevant points rather than a single trace row. Review filtering, rate limits or NAT only with the responsible owner and verify reachability and error handling after changes.

With an authorized offline capture and TShark, this display filter finds candidate Time Exceeded frames in either family. It does not join anything. Inspect the dissection tree for the outer ICMP fields and the separately nested quote. Verify the installed version exposes these fields.

```sh
tshark -n -r icmp-hop-evidence.pcap \
  -Y 'icmp.type == 11 || icmpv6.type == 3' -V
```

## 5. Offline PCAP drill

Download <a href="{{ '/assets/labs/icmp-hop-evidence.pcap' | relative_url }}" download>the fictional Ethernet PCAP</a> and <a href="{{ '/assets/labs/icmp-hop-evidence.py' | relative_url }}" download>the Python 3 correlator</a> to a directory you control. The dataset contains 19 serialized frames built for the exercise using documentation IP addresses. It was never transmitted. Open the capture in a packet viewer if available. Start by predicting the result of each highlighted frame, then run:

```sh
python3 icmp-hop-evidence.py
```

| Frame | Expected outcome and why |
| --- | --- |
| 2, 5, 9 | A match to frames 1, 3 and 8 respectively, based on the quoted UDP tuple and time. |
| 4 | Unmatched because the quoted destination port differs. |
| 7, 13 | Port-unreachable terminal candidates matching frames 6 and 12. |
| 11 | Quote incomplete. The captured length cuts the quoted UDP header short, even though the original frame's recorded length was larger. |
| 14 | Fragment reassembly expiry, separate from forwarding-limit expiry. |
| 17 | Two recent candidates, frames 15 and 16. The simplified lab join leaves it ambiguous. |
| 18, 19 | Unmatched. The first falls outside the exercise's one-second window. The second shows a translated tuple without a matching probe on that side. |

Use a fresh copy if the checker reports a PCAP format error. It expects the supplied classic little-endian Ethernet PCAP with microsecond timestamps, direct IPv4 or IPv6 headers and UDP. The simplified parser has no IPv6 extension, VLAN, NAT reconstruction or checksum-validation support, and the one-second window is specific to this fixture. A production analysis should account for those details and use validated packet tooling. As a defensive control, inspect frame 4 and explain why a router address match alone would make it a false hit. For frame 17, examine additional fields with a packet viewer before deciding whether real evidence would resolve the ambiguity.

The cloud run decoded the actual supplied binary, verified both families, compared the expected per-frame outcomes and reran a copy with frame 1 removed. On the copy, the first remaining error was unmatched. TShark syntax and traceroute behavior were reviewed against documentation. No active trace or production equipment was used.

## 6. Check your understanding

1. **What identifies which probe expired?** Match the quoted original addresses and protocol, compatible transport fields and a defensible time window. Treat the outer sender as the source claim for the error.
2. **Hop 2 shows a star and hop 3 responds. What can you conclude?** Some later probe received a response. The second hop may have forwarded traffic without an observable ICMP reply. The original traffic outcome needs separate evidence.
3. **Why is IPv6 3/1 a poor hop signal?** Code 1 reports fragment reassembly timeout. Forwarding Hop Limit expiry uses code 0.
4. **Why may a correct quote fail to join across a boundary?** NAT may translate addresses and ports, and a tunnel may quote a different header layer. Align capture points or obtain the mapping before joining.

**Completion.** Identify the quote in frames 2 and 11, explain the different outcomes in frames 4, 14 and 17, and reproduce the expected outcomes. Describe one additional source you would use before claiming a routing fault.

## Official references

Reviewed 2026-11-26. The foundational ICMP standards are older and remain useful for wire semantics. Receiver, translation and tool behavior should be checked for the deployed environment.

- IPv4 errors and router practices. [RFC 792, September 1981](https://www.rfc-editor.org/rfc/rfc792.html) · [RFC 1812, June 1995](https://www.rfc-editor.org/rfc/rfc1812.html)
- IPv6 ICMP and forwarding behavior. [RFC 4443, March 2006](https://www.rfc-editor.org/rfc/rfc4443.html) · [RFC 8200, July 2017](https://www.rfc-editor.org/rfc/rfc8200.html)
- Translation and path selection. [RFC 5508, April 2009](https://www.rfc-editor.org/rfc/rfc5508.html) · [RFC 2992, November 2000](https://www.rfc-editor.org/rfc/rfc2992.html)
- Tool methods and display syntax. [Linux traceroute(8)](https://man7.org/linux/man-pages/man8/traceroute.8.html) · [TShark](https://www.wireshark.org/docs/man-pages/tshark.html) · [ICMP fields](https://www.wireshark.org/docs/dfref/i/icmp.html) · [ICMPv6 fields](https://www.wireshark.org/docs/dfref/i/icmpv6.html)

[Previous · UDP datagram evidence]({{ '/wiki/udp-datagram-evidence/' | relative_url }}) · [Next · Path MTU and ICMP]({{ '/wiki/pmtu-icmp-evidence/' | relative_url }})
