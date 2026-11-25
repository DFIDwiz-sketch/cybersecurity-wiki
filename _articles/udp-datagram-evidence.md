---
title: "UDP Datagram Evidence · From Send to Application Receipt"
description: "Distinguish UDP sends, capture observations, receiver truncation and application outcomes with a Linux loopback lab."
category: network
tags: [UDP, Network Security, Linux, Packet Capture, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /ko/wiki/udp-datagram-evidence/
---

A client says it sent a message, a capture shows a UDP packet, and the receiver says the message was truncated. All three can be accurate. This chapter follows a datagram from the sending call to what the receiving application can prove.

## 1. Read a datagram at the right layer

**UDP (User Datagram Protocol)** carries discrete messages over IP. A **datagram** is one message with a UDP header and payload. The header has source port, destination port, length and checksum fields. A **port** identifies a transport endpoint on a host. In ordinary UDP, the length counts the eight-byte header plus the payload, so a length of 28 describes 20 bytes of payload. A checksum detects certain transmission errors. It provides no cryptographic sender authentication.

UDP itself neither performs a connection-establishing handshake nor guarantees delivery, ordering or duplicate suppression. It is useful when the application wants message boundaries or implements its own transport features. For example, ordinary DNS can send a query and response over UDP, while QUIC implements its own acknowledgments and loss recovery over UDP. A local UDP socket API can use `connect()` to set a default peer without sending a UDP handshake.

| Evidence | What it establishes | What to check next |
| --- | --- | --- |
| Successful `sendto()` | Local sending call accepted the bytes | Capture or receiver evidence |
| UDP observed at a sensor | Packet visible at that point | Coverage, direction and other hops |
| Matched ICMP error | Network or endpoint reported a problem with the quoted datagram | Original tuple, ICMP type/code, NAT and path |
| Receiver reports `MSG_TRUNC` on Linux | A datagram arrived at the socket, but the receive buffer supplied to that call was too small | Original length, the app's buffer and parser behavior |
| Application receipt and result | The message and processing outcome the app recorded | Trusted transaction identifier and success semantics |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/udp-datagram-evidence-en.svg' | relative_url }}" alt="A UDP send enters the network. A sensor can observe the packet along the path. A receiving socket can deliver a whole message or truncate it for a small buffer. Application results are separate evidence.">
  <figcaption>Follow the message through the network and into the receiving program. Each observation covers one part of the path.</figcaption>
</figure>

## 2. Follow a routine request and its alternatives

Suppose a training client at `192.0.2.10:53000` sends a fictional 20-byte request to `192.0.2.20:9000`. It assigns application request ID `A17`. The sender capture shows a UDP length of 28. The receiving application records `A17` and queues the intended work. It then sends an acknowledgment defined by this application. Join the acknowledgment and job log to determine whether the operation finished. A generic UDP flow record cannot tell you the application result. These addresses and observations are fictional. The runnable lab below uses loopback.

If the receive call supplies an eight-byte buffer, Linux can deliver only the first eight bytes and set `MSG_TRUNC`. The remainder of that datagram is discarded by the receive operation. The next receive reads the next queued datagram, if any. A capture cut short by its snapshot length is a separate observation problem. Check captured length against original frame length and keep packet truncation separate from application truncation. The DNS `TC` bit is a third, protocol-level signal. It does not indicate a short socket buffer.

A destination or intermediate device can return an ICMP error. For example, IPv4 Destination Unreachable with code 3 reports an unreachable UDP port in the usual case. Match the quoted original packet to the transaction before attributing the error. Firewalls and rate limits can suppress replies. A timeout can also follow a dropped datagram, a missing listener, queue pressure or an application that did not respond. Silence alone does not establish a port state.

## 3. Collect and investigate defensively

1. **Anchor the transaction.** Record UTC time, direction, transport protocol, addresses and ports, sensor location, interface or namespace, and the application ID when available. Compare sender and receiver views and account for NAT. Five-tuple matching alone can join unrelated traffic if a tuple is reused.
2. **Check capture and host limits.** Preserve original capture lengths, snapshot length and capture drop counters. Consider capture location, hardware offload and fragmentation when interpreting header and length observations. On a Linux receiver, compare the specific app's received length and flags with queue or drop telemetry. Application receive-buffer size for one read and the socket receive-queue capacity are different controls.
3. **Compare legitimate and suspicious activity.** An application that replies much larger than it receives may be abused for reflection when a forged source sends traffic toward the service. Check service exposure, expected request and reply sizes, direction and application logs. Volume or a port number alone does not identify an attack. Large legitimate responses, product changes and measurement gaps can look similar.
4. **Act on the point of failure.** Preserve packet and application evidence. Check expected socket binding, firewall and service health for delivery failures. If receiving flags demonstrate truncation, review buffer and message-size handling with the owner. For suspected reflection, confirm the affected service and scope with the network owner before changing exposure or rate limits. Retest routine requests and confirm independent receiver outcomes.

## 4. Verify on Linux loopback

Run the <a href="{{ '/assets/labs/udp-datagram-evidence.py' | relative_url }}" download="udp-datagram-evidence.py">loopback script</a> with Python 3.8 or later on Linux in an approved training environment. It uses ephemeral ports and binds both sockets to `127.0.0.1`. There are no external targets, capture permissions or third-party packages. Download the <a href="{{ '/assets/labs/udp-datagram-worksheet.csv' | relative_url }}" download="udp-datagram-worksheet.csv">fictional evidence worksheet</a> for the separate interpretation exercise.

```bash
python3 udp-datagram-evidence.py
```

| Output | What to verify |
| --- | --- |
| `separate_datagrams: 3, 4 bytes` | Both datagrams keep their own boundaries |
| `truncation: sent=12 copied=5 flag=True` | Five bytes reach the receive program from a twelve-byte payload |
| `next_datagram: OK` | The discarded tail does not appear as a second message |
| `empty_datagram: 0 bytes` | A zero-length datagram is a received message |

If sockets cannot bind, verify loopback is available and the environment permits local UDP. If `recvmsg()` or `MSG_TRUNC` is unavailable, use a Linux training host that provides them. A receive timeout is a failed test. The four results were observed on IPv4 loopback with Linux 6.18.57 and Python 3.12.14. The worksheet is fictional and covers captures, missing evidence and one quoted network error. Read the observations before uncovering the interpretation column. No external routing, firewall or application protocol was exercised.

## 5. Check your understanding

1. **Is a UDP length of 28 the application payload size?** Subtract the eight-byte header. In the ordinary example, 20 bytes remain.
2. **Can a single sensor prove the receiver read the message?** It establishes visibility at its capture point. Use receiver and application records to establish delivery to the program and processing.
3. **Does a timeout show that no service is listening?** Several causes produce the same observation. Check sender, path, receiver and ICMP context.
4. **What distinguishes a five-byte truncated receive from a genuine empty datagram?** Linux can return `MSG_TRUNC` for the short buffer. A genuine empty datagram can be received without that flag. Neither implies an end-of-stream condition.

Complete the chapter when you can explain the four loopback observations and tell which evidence is missing between sender, sensor, receiving socket and application.

## Official references and next steps

Reviewed November 23, 2026. RFC 768 defines the wire header (1980). RFC 8085 provides usage guidance (2017). The socket references describe Linux and Python behavior as documented at review time.

- [IETF · RFC 768](https://www.rfc-editor.org/rfc/rfc768.html) and [RFC 8085](https://www.rfc-editor.org/rfc/rfc8085.html)
- [IETF · RFC 792, ICMP (1981)](https://www.rfc-editor.org/rfc/rfc792.html) and [RFC 9002, QUIC (2021)](https://www.rfc-editor.org/rfc/rfc9002.html)
- [Linux · udp(7)](https://man7.org/linux/man-pages/man7/udp.7.html) and [Python socket.recvmsg](https://docs.python.org/3/library/socket.html#socket.socket.recvmsg)

[Previous · TCP connections and packet evidence]({{ '/wiki/tcp-evidence/' | relative_url }}) · [Next · QUIC and HTTP/3 evidence]({{ '/wiki/quic-http3-evidence/' | relative_url }})

## Follow a DNS retry over TCP

[Investigate DNS Truncation and TCP Fallback]({{ '/wiki/dns-tcp-fallback-evidence/' | relative_url }}) traces a truncation signal through the TCP exchange to the caller's result.
