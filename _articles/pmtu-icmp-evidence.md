---
title: "Path MTU and ICMP · When Small Requests Work but Transfers Stall"
description: "Read IPv4 and IPv6 size feedback, correlate quoted packets with the affected flow, and investigate eight synthetic cases offline."
category: network
tags: [PMTU, ICMP, IPv6, TCP, Network Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-20"
translation_url: /ko/wiki/pmtu-icmp-evidence/
---

**Learning goal.** Explain why a connection can start normally and then stall on larger packets. Use packet size, ICMP feedback, capture location and TCP acknowledgments to distinguish a size-related failure from an observation gap.

## 1. Which size is too large?

A **link MTU**, or maximum transmission unit, limits the size of an IP packet that a particular link can carry. A **path MTU (PMTU)** is the smallest link MTU along a direction of travel. The return path can differ. The size includes the IP header. Ethernet headers and trailers use a different measurement. **TCP MSS** is the limit a TCP endpoint advertises for TCP data per segment. TCP and IP headers, options and any tunnel encapsulation still occupy space. A peer's MSS does not measure the forward path.

| Value | Where it comes from | What it tells you |
| --- | --- | --- |
| Interface MTU | One interface's configuration | One local limit. A later hop or tunnel may have a lower limit |
| Reported next-hop MTU | ICMP error from a forwarding node | The limit claimed for the relevant hop. Check the quoted packet and whether that layer is inner or outer |
| PMTU estimate | Sender's discovery or packetization behavior | What the sender believes it can deliver on the path. A route change can invalidate it |
| TCP MSS | Option in the SYN or SYN-ACK | The advertising peer's receive limit for TCP data. Path and header limits still apply |

For a 1,400-byte IP limit and minimal headers, IPv4 can carry up to 1,360 bytes of TCP data (20-byte IPv4 and 20-byte TCP headers). For ordinary IPv6 with no extension headers and the same TCP header size, the limit is 1,340 bytes. Options, extension headers and encapsulation change the calculation. A tunnel's outer MTU and a capture of its inner packet must be interpreted separately.

## 2. Follow a normal size adjustment

In a fictional IPv6 flow, the sender emits a **1,500-byte IP packet**. A router's next link carries at most **1,400 bytes**. The router drops that packet and sends an ICMPv6 **Packet Too Big** message with the link's MTU. The message quotes part of the invoking packet. If the sender receives and accepts the feedback, it can reduce its packet size. In this example, a smaller TCP retransmission is then acknowledged. The data sequence and acknowledgment tie the retry to the original data.

![A bottleneck router returns ICMP size feedback after a 1,500-byte packet. A smaller retry passes through the 1,400-byte link.]({{ '/assets/diagrams/pmtu-feedback-en.svg' | relative_url }})

*The arrows show a simplified IPv6 case. The upper right label is the next-link limit. The large packet is dropped rather than forwarded along that link. Receiving feedback and observing a successful retry are distinct observations.*

| IP version | Relevant feedback | Fragmentation behavior |
| --- | --- | --- |
| IPv4, Don't Fragment (DF) set | ICMP Destination Unreachable, Type 3 Code 4. A legacy sender of the ICMP error may report zero for the next-hop MTU | A forwarding router cannot fragment a DF packet |
| IPv6 | ICMPv6 Packet Too Big, Type 2 Code 0. Standards-based IPv6 PMTUD discards reports below the 1,280-byte minimum link MTU | Only the source can add a Fragment header. Forwarding routers do not fragment IPv6 packets |

Classical PMTUD uses ICMP feedback. Packetization-layer approaches can probe delivery with transport feedback. RFC 8899 describes a method for datagram transports. Product behavior depends on the host and protocol. An absence of ICMP does not rule out size adjustment through another mechanism.

## 3. Recognize a possible black hole

A **PMTU black hole** can occur when a large packet does not pass and its sender never receives usable size feedback. Small pings and TCP handshake packets may fit while bulk data stalls. Retransmissions can also result from congestion, a packet filter, a receiver problem, or an incomplete capture. A size-dependent failure is a hypothesis until you compare the same flow at the right points.

A misleading ICMP report can describe an unrelated flow or claim the wrong size. An unauthorized party can attempt to disrupt transport by sending false feedback. Compare the quoted IP addresses and transport identifiers where captured, sequence numbers when available, and the direction and timing of the original traffic. A router's source address alone is weak evidence. NAT, tunneling, truncated quotes, and reused ports can complicate the comparison. Corroborate with trusted gateway or endpoint records before attributing intent.

## 4. Collect, detect and respond

**Label the observation points.** Preserve timestamps, interfaces, direction, capture length and drop counters where available. Useful points include the sender side, the bottleneck's relevant interface and the receiver side. Capture inside an approved environment. Keep enough quoted data to connect errors to the original flow while limiting access to captured content. Record NAT zones and the inner or outer layer at each point.

**Read the same layer.** In Wireshark, IPv4 Total Length includes the IPv4 header. For an ordinary IPv6 packet, add the 40-byte base header to Payload Length. Treat jumbograms separately. Keep IP length apart from the captured frame length. Host-side segmentation offload can make a capture show packets larger than those sent on the wire. Corroborate with an approved on-wire observation or documented collection behavior before using that length as path evidence.

**Find feedback and verify the quote.** The following is a Wireshark display filter for an existing authorized capture with IPv4 or IPv6 decoded. It locates candidates. Look at `icmp.mtu` or `icmpv6.mtu` and expand the quoted packet. Match the original flow before concluding that a message explains the stall. A display filter cannot recover packets that were never captured. The field names were reviewed in Wireshark's 4.6.10 reference.

~~~text
(icmp.type == 3 && icmp.code == 4) || (icmpv6.type == 2 && icmpv6.code == 0)
~~~

**Compare progress, then investigate policy.** Check whether the receiver acknowledged the large TCP byte range and whether a smaller retry led to progress. Repeated large retries without ACK progress and matching feedback visible at the router but absent near the sender make the feedback path worth examining. Confirm the captures cover the same path and window. Compare firewall decisions, policy, tunnel MTU and network changes. If you confirm a policy or configuration fault, coordinate the narrow correction with the owner and validate again using approved tests. Baseline packet and ACK behavior before and after any change.

## 5. Offline exercise · Eight synthetic observations

Download [pmtu-cases.csv]({{ '/assets/labs/pmtu-cases.csv' | relative_url }}) and [pmtu-review.py]({{ '/assets/labs/pmtu-review.py' | relative_url }}) into one folder. Read the observations before running the checker. The CSV represents simplified analyst notes after reviewing fictional captures. `matched_quote` records an already-checked association, while `coverage=both` means the fictional sender and router observation points were both covered. `large_ack` means a later cumulative TCP ACK covered the data attributed to the large packet. It does not specify exactly which packet carried those bytes. Unknown observations stay unknown. The checker only reads this worksheet.

~~~bash
python3 pmtu-review.py
~~~

| Case | Expected finding |
| --- | --- |
| P01 / P02 | Matching IPv4 / IPv6 feedback reached the sender. Smaller retry ACKs support recovery |
| P03 | Router-side feedback matches, but is absent at the sender-side point. Investigate a feedback path gap |
| P04 | Sender-side evidence only. The absence of feedback does not locate a drop |
| P05 | A Type 3 Code 4 report exists, but the quoted packet is unrelated |
| P06 | The large data range was acknowledged. Reassess the original stall hypothesis |
| P07 | The IPv4 report matches, but zero leaves the next-hop MTU unspecified |
| P08 | Matching feedback arrived. The observations do not establish recovery |

Expect `Reviewed: 8 synthetic cases`. If the file cannot be opened, keep the original filenames together and retry. If results differ, check that the CSV has its original headers and that missing values were not converted to zero. For an optional exercise in an owned or approved lab, compare existing captures of a normal transfer at both ends and document how you would correlate a quote. The Python worksheet was executed. The Wireshark filter and protocol behavior were checked against documentation. No live tunnel, injected ICMP traffic, or vendor firewall was tested.

## 6. Check your understanding

- **A ping and TCP handshake work, but the file upload times out. Does that prove a PMTU problem?** Small packets can pass despite a bottleneck. Look for size dependence, matching feedback, ACK progress and confirmed capture coverage.
- **A router reports 1,400 bytes, but the quoted flow has different endpoints. Can you assign that limit to your flow?** First resolve capture layer and any translation. Without a supported association, keep the report separate.
- **Matching ICMP was captured near the sender. Did the application recover?** Check whether the endpoint accepted the feedback and whether resized transmissions, ACKs and application logs show progress.

Finish by explaining P03, P04 and P08 differently. Write one finding with capture point, packet layer and size, quote match or gap, observed acknowledgments and the next source you would check.

[Previous · TCP connections and packet evidence]({{ '/wiki/tcp-evidence/' | relative_url }}) · [Related · Network monitoring]({{ '/wiki/network-monitoring/' | relative_url }})

## Official references

Reviewed 20 November 2026. RFC 2923 documents historical failure patterns. Use the version-specific protocol and product references when applying them today.

- [RFC 1191 · IPv4 Path MTU Discovery, November 1990](https://www.rfc-editor.org/rfc/rfc1191.html) · [RFC 2923 · TCP black hole examples, September 2000](https://www.rfc-editor.org/rfc/rfc2923.html)
- [RFC 4443 §3.2 · ICMPv6 Packet Too Big, March 2006](https://www.rfc-editor.org/rfc/rfc4443.html#section-3.2) · [RFC 8201 · IPv6 PMTUD, July 2017](https://www.rfc-editor.org/rfc/rfc8201.html)
- [RFC 8200 §5 · IPv6 packet size, July 2017](https://www.rfc-editor.org/rfc/rfc8200.html#section-5) · [RFC 9293 §3.7 · TCP segmentation, August 2022](https://www.rfc-editor.org/rfc/rfc9293.html#section-3.7)
- [RFC 8899 · Datagram packetization-layer PMTU discovery, September 2020](https://www.rfc-editor.org/rfc/rfc8899.html)
- [Wireshark 4.6.10 reference · ICMP](https://www.wireshark.org/docs/dfref/i/icmp.html) · [ICMPv6](https://www.wireshark.org/docs/dfref/i/icmpv6.html) · [Capture offloading](https://wiki.wireshark.org/CaptureSetup/Offloading)

## Investigate IPv6 Router Advertisements

[Compare the advertised route, prefix and DNS settings with endpoint evidence.]({{ '/wiki/ipv6-router-advertisement-evidence/' | relative_url }})

## Separate hop expiry from packet size feedback

Use [Traceroute and ICMP evidence]({{ '/wiki/icmp-hop-evidence/' | relative_url }}) to distinguish forwarding expiry and fragment reassembly timeout from size-related ICMP messages.
