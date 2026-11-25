---
title: "Investigate DNS Truncation and TCP Fallback"
description: "Read DNS TC and EDNS fields, reassemble TCP messages and distinguish four transport outcomes on loopback."
category: network
tags: [DNS, EDNS, TCP, UDP, Network Security, Packet Capture, Blue Team]
level: Beginner
updated: "2026-11-25"
translation_url: /ko/wiki/dns-tcp-fallback-evidence/
---

A resolver records a UDP response with `TC=1`. The application still reports that the name could not be resolved. To explain the failure, follow the query to the next transport and locate the last step you can prove. This chapter covers conventional DNS between one requester and one server. A stub-to-recursive exchange and a recursive-to-authoritative exchange are separate, even when they concern the same name.

## 1. What truncation signals

A DNS question consists of a name (QNAME), type (QTYPE) and class (QCLASS). The header includes a 16-bit transaction ID, a query/response bit (`QR`), a truncation bit (`TC`) and a response code (`RCODE`). A valid matching `TC=1` response says the sender marked the DNS message as truncated. The response can include some records. Use a complete follow-up response to interpret the answer. A truncated referral can also be missing required glue, the addresses that help an iterative resolver contact delegated name servers.

Without EDNS, the original DNS limit for a message sent over UDP is 512 octets. EDNS(0) lets a requester advertise how much UDP **DNS payload** it can receive in the OPT pseudo-record. That value excludes UDP and IP headers and does not measure the path MTU. The responder can apply a smaller limit. A path with tunnels or lost fragments can fail to deliver a response that fits the advertised value. A size such as 1232 octets is an operational starting point discussed in RFC 9715, with assumptions about the available MTU and header overhead. It does not guarantee delivery on every path.

| Evidence | Question it answers | What to verify next |
| --- | --- | --- |
| Valid UDP response, `TC=1` | Did this peer signal truncation? | Follow the requester for a retry |
| EDNS OPT size in the query | What UDP DNS payload size did the requester advertise? | Check the sender's limit and actual path |
| TCP handshake or existing stream | Is there a TCP connection? | Reassemble the stream and look for the DNS question |
| Matched TCP response, `TC=0` | Did this peer return an untruncated DNS message? | Inspect RCODE, answer, validation and the caller's result |
| Capture reports fewer bytes than wire length | Did the sensor save only part of the frame? | Review capture snaplen and drop counters |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/dns-tcp-fallback-evidence-en.svg' | relative_url }}" alt="Follow the UDP question and OPT size to TC, the framed DNS exchange over TCP, and the lookup result.">
  <figcaption>A successful retry after truncation in conventional DNS. Other lookups can start over TCP.</figcaption>
</figure>

## 2. Reconstruct one routine lookup

Fictional example: a recursive resolver at `192.0.2.20` asks an authoritative server at `198.51.100.53` for an illustrative large TXT answer in `example.test.`. These addresses are for documentation. All times are UTC.

1. At 14:02:01.110 the resolver sends UDP from port 53010 to port 53. The question is `notes.example.test. IN TXT`. It advertises EDNS size 1232. The server limits the UDP reply and sends `QR=1, TC=1` at 14:02:01.112.
2. At 14:02:01.113 the resolver opens a TCP connection to port 53 from a different ephemeral port. An implementation may also reuse an existing TCP connection. Correlate server and requester, question, timing, and resolver trace ID if available. Do not require the UDP port or transaction ID to carry across the transport change.
3. In the TCP byte stream, each DNS message starts with two bytes in network byte order giving the DNS message length, excluding the prefix. A read can end in the middle of the prefix or message, or contain bytes from multiple messages. Reassemble in stream order and respect the declared length. For multiple outstanding queries, match IDs and question context on that connection. Replies need not arrive in query order.
4. At 14:02:01.119 the full TCP response has `TC=0`, `NOERROR` and the expected TXT records. The upstream hop completed. To establish the application's result, check what the recursive resolver validated and returned to the stub, then what the caller recorded.

DNS can start over TCP for operational reasons, so a valid TCP exchange may have no preceding UDP response. A UDP timeout differs from a received truncation signal. Retry behavior after silence varies by implementation and policy. DNS over TLS and HTTPS require telemetry at an authorized point where DNS is decoded. A conventional port-53 capture alone has limited coverage for those paths.

## 3. Investigate failure, misuse and gaps

**Collect both transports on the same hop.** Record the time zone, clocks, interfaces, capture direction, snaplen, drop counters and retention. On each feasible side of a suspected boundary, collect UDP and TCP between the same endpoints, including the TCP open, resets, and application exchange if available. DNS names can be sensitive. Restrict capture and retention to the authorized scope. Preserve resolver or authoritative logs with question, transport, result, and request ID where configured. Many query logs omit flags or responses, so check the actual schema.

**Locate the stopping point.** If one sensor sees `TC=1` but no subsequent TCP question, first ask whether it sees that requester, route and existing streams. Compare resolver policy and request timeout. If SYNs leave the requester but do not arrive at the server, compare firewall or ACL decisions and routes. If a SYN reaches the server and a reset returns, check listener state and any device that can generate a reset. If the handshake succeeds but no decodable answer appears, check stream reassembly, capture gaps, server logs and the client's deadline. If UDP goes silent without TC, compare advertised payload, response sizes, path MTU and fragment visibility. Filters limited to ports can miss non-initial fragments whose UDP header is absent.

**Compare a baseline before escalating.** More truncation can follow a legitimate DNSSEC or record change, a lower UDP limit, or a different query mix. Sustained repeated truncated responses with no completion can degrade service. An unexpected responder or a response incompatible with the outstanding question can suggest interference, but duplicate names, translated addresses, asymmetric capture, or an authorized secondary can explain apparent mismatches. Corroborate with endpoint, resolver and policy evidence before attributing the cause.

**Validate recovery on the approved path.** Measure matched truncation events with observed TCP completion over the same observation scope. Keep timeout, reset, negative DNS answer and visibility gap as separate outcomes. Compare by resolver, upstream, QTYPE and interval. Confirm both UDP and TCP availability for the authorized endpoints, then check an independent application lookup. Avoid globally opening TCP/53 or increasing UDP payload limits merely in response to a timeout.

## 4. Loopback lab · four observable outcomes

<a href="{{ '/assets/labs/dns-tcp-fallback-lab.py' | relative_url }}" download="dns-tcp-fallback-lab.py">Download the Python loopback lab</a>

Use Python 3 on a machine you own or are authorized to test. Save the script and run it without elevated privileges. It uses only `127.0.0.1`, binds ephemeral ports, and sends one fixed question for `service.test. IN A`. The replies are synthetic. The socket operations are real but the script is a teaching model, with no recursion, EDNS processing, DNSSEC or external targets. A deliberately set TC flag isolates fallback behavior from payload size.

~~~bash
python3 dns-tcp-fallback-lab.py
~~~

| Case | Expected trace | What the case demonstrates |
| --- | --- | --- |
| UDP complete | UDP `TC=0`, answer present | No fallback is needed |
| UDP to TCP | UDP `TC=1`, then TCP `TC=0` | A second exchange supplies the answer |
| No TCP listener | UDP `TC=1`, then TCP connection refused | UDP reachability and TCP availability differ |
| TCP first | Only a framed TCP question and reply | TCP can be the initial transport |

Expect four PASS lines. In the fallback case, the TCP reader reconstructs the length prefix and then the message in small reads. Read boundaries are an intentional exercise constraint, not evidence of TCP segment boundaries. The missing-listener case keeps the local TCP port bound without calling listen. There is no firewall change. If binding fails, verify the runtime permits IPv4 loopback. If a check fails, inspect the exact socket or framing error before changing the script. Local output is neither a capture of production traffic nor proof of resolver-specific retry behavior.

## 5. Knowledge check and completion

1. **A UDP packet shows `TC=1` and the matching TCP flow shows only a completed handshake. What can you report?** The UDP peer signaled truncation, and TCP established. DNS completion requires a matched DNS response or corroborating endpoint evidence.
2. **Why might a 1232-byte advertised payload still fail?** A local receive limit does not establish the effective MTU or fragment delivery. Encapsulation or path behavior can change what arrives.
3. **Two queries use the same ID. Are they the same lookup?** Compare transport connection or datagram tuple, question, time and endpoint evidence. The ID is scoped and can be reused.
4. **A TCP response has `TC=0` and `SERVFAIL`. Did lookup succeed?** The exchange delivered a complete DNS error response. Continue with resolver context and validation evidence to explain the failure.

Complete the chapter by reproducing all four results and writing a short note for the failed case. State the observation point, last verified event, conclusion and one source that could resolve the remaining uncertainty.

## Official references and related reading

Reviewed **2026-11-25**. The dates below describe the cited publications. The loopback exercise verifies the supplied teaching code. Production resolver behavior and network policy were reviewed against the documents.

- Base message layout and length framing, November 1987. [RFC 1035 §§4.1–4.2](https://www.rfc-editor.org/rfc/rfc1035.html#section-4)
- UDP payload advertisement, April 2013. [RFC 6891 §6.2](https://www.rfc-editor.org/rfc/rfc6891.html#section-6.2)
- TCP support, reuse and framing, March 2016. [RFC 7766 §§5–8](https://www.rfc-editor.org/rfc/rfc7766.html#section-5)
- DNS response failures, operational guidance from September 2020. [RFC 8906](https://www.rfc-editor.org/rfc/rfc8906.html)
- Glue in referrals, September 2023. [RFC 9471 §3](https://www.rfc-editor.org/rfc/rfc9471.html#section-3)
- Fragmentation avoidance, informational publication from January 2025. [RFC 9715](https://www.rfc-editor.org/rfc/rfc9715.html)

Previous · [DNS investigation]({{ '/wiki/dns-investigation/' | relative_url }})  
Next · [TCP connection evidence]({{ '/wiki/tcp-evidence/' | relative_url }}) · [Path MTU and ICMP]({{ '/wiki/pmtu-icmp-evidence/' | relative_url }})
