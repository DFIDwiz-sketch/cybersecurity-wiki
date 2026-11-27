---
title: "DHCPv6 Lease Evidence · Correlate Address, Prefix, and Client"
description: "Read DHCPv6 client and association identifiers, distinguish host addresses from delegated prefixes, and scope a lease match by network and time."
category: network
tags: [IPv6, DHCPv6, DHCP, Network Security, Blue Team, DFIR]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/dhcpv6-lease-evidence/
---

A resolver log shows an IPv6 source address at 14:22 UTC. A DHCPv6 export contains that address and a request from an edge router for a prefix. What do the records let you say about the source? A DHCPv6 binding can establish a server’s assignment in a particular scope and time. Identifying the endpoint that used an address takes additional evidence.

## 1. Read the configuration and identifiers separately

DHCPv6 provides IPv6 addresses, delegated prefixes, or other settings such as DNS resolvers. A client can use more than one configuration mechanism at once. On an ordinary IPv6 host, look to Router Advertisements (RAs) or explicit host configuration for the default route. Stateless Address Autoconfiguration (SLAAC) can produce additional addresses, including temporary ones, while DHCPv6 is in use.

| Field or exchange | What it describes | Scope to retain |
| --- | --- | --- |
| Client or server **DUID** | DHCP Unique Identifier of the corresponding endpoint, carried in its identifier option where present. | Store the full value. A DUID can contain a link-layer address for some types. It cannot be assumed to be the current interface MAC or a person's identity. |
| **IAID** | Client-chosen identifier for an Identity Association, a group of assignments. | Compare it with the client DUID and **IA type**. The same numeric IAID can occur in one client's IA_NA and IA_PD. |
| **IA_NA** | An association for non-temporary addresses. Its IA Address options can carry assigned IPv6 addresses and lifetimes. | Match the full IPv6 address, link scope, and time. Non-temporary addresses still have lifetimes. |
| **IA_PD** | An association for Prefix Delegation. A requesting router can use delegated space for its downstream network. | Keep the prefix length and the requesting router's scope. Membership in the prefix does not establish which downstream device used an address. |
| **Information-request / Reply** | A stateless exchange for settings without an address or prefix assignment in that exchange. | Match the exchange and compare the host's effective settings. No address binding is expected from this exchange. |

<figure>
  <img src="{{ '/assets/diagrams/dhcpv6-lease-evidence.svg' | relative_url }}" width="560" height="340" alt="A client reaches a DHCPv6 server directly or through a relay. An IA_NA provides an assigned address, an IA_PD provides a prefix for a router, and an Information-request exchange can provide settings without a lease. Router Advertisements supply separate router evidence.">
  <figcaption>Choose the observation to match the question. An address, delegated prefix, and default route come from different evidence.</figcaption>
</figure>

## 2. Follow an ordinary relayed lease

1. A client on the training link sends **Solicit**. Servers can answer with **Advertise**, indicating availability. The client selects a server and sends **Request**, and the server sends **Reply**. The two-message Rapid Commit procedure instead uses Solicit and Reply with Rapid Commit when supported and used by both parties. An Advertise alone does not establish a committed binding.
2. A relay can wrap the client message in **Relay-forward** and return the inner server response from **Relay-reply**. In a server-side capture, inspect the inner DHCP message for the transaction ID and client/server identifiers. Use the relay chain, `link-address` and, where present, Interface-Id or locally verified circuit mapping for link scope. A nested or zero link-address needs relay context. The outer source address and the peer address have different meanings.
3. A successful Reply may carry both an IA_NA and an IA_PD. Inspect status at the applicable level, and confirm the actual address or prefix and lifetimes in each association. A message named Reply can also report an error, contain options only, or answer a release. Check the server’s committed history for an assignment.
4. **T1** and **T2** are renewal and rebinding timers for the association. Preferred and valid lifetimes apply to each address or prefix. At T1 the client tries to renew with the assigning server. At T2 it can try to rebind through an available server. For an address, preferred expiry marks it deprecated while a remaining valid lifetime can allow continued use, notably for an existing communication. An expired valid lifetime ends the authorization to use that assignment under the protocol.

**Fictional example.** At 14:00 UTC a server commits `2001:db8:10::25` on link `training-a` for a client with IA_NA IAID 7. The client receives a preferred lifetime of 1,200 seconds and a valid lifetime of 1,800 seconds. Without renewal or early release, 14:20 UTC is the start of deprecation and 14:30 UTC is the validity boundary in this example. A flow at 14:22 UTC remains compatible with the server's recorded assignment. Confirm the endpoint and actual use with independent host or edge evidence. A delegated prefix such as `2001:db8:2200::/56` is a separate binding, including when the same router used IAID 7 for that delegation.

## 3. Collect enough evidence to make a scoped claim

| Source | What to collect, when available | What it can support |
| --- | --- | --- |
| DHCP server or history export | Server identity and scope, DUID, IA type and IAID, committed address or prefix, valid interval, renewal, release, expiry or reassignment | Which lease record covers the resource and time. A current lease dump alone misses historical states. |
| Packet capture or relay journal | On the affected link or approved relay/server vantage, collect direction, inner message type and transaction ID, identifiers, relevant status and relay context | Which exchange was observed and where. Transaction IDs are scoped to exchanges and are unsuitable as long-lived keys. |
| Endpoint and access network | Interface addresses, routes and resolvers, access-port or client-session evidence, switch/router neighbor data and UTC clocks | Which device likely used an address and which configuration actually applied. Neighbor and flow entries can be stale or scoped to one vantage. |

RFC 9915 uses UDP destination 546 for client delivery and ordinarily 547 for server or relay delivery. The source ports are recommendations and relay extensions can affect port behavior. Build capture filters against the documented deployment and verify both direct and relayed paths with authorized observations. Missing packets from one vantage are weak negative evidence.

Start with the original timestamp, IPv6 source, site and routing/link context. Look for the exact address in active IA_NA history. Where the routing context supports it, independently check whether it is in a delegated prefix and record the router binding. Use the original record, not the latest state, if the address was reused. Check time sync and keep overlapping, inconsistent bindings unresolved until corroborated. If there is no match, investigate SLAAC, static configuration, logging coverage, and the correct relay path before treating the result as suspicious.

A reply from an unexpected server or relay can introduce incorrect addresses or resolver settings. Misconfiguration and approved failover can also cause new responders. Compare against an approved server and relay inventory and check whether the endpoint actually installed the reported configuration. Repeated DUIDs across unrelated ports are a lead that also fits machine cloning or stale records. Preserve the original observations, scope affected client settings, and coordinate with network operations to contain unauthorized service and restore approved configuration. Evaluate DHCPv6-Shield where supported, using the approved server/relay topology. It addresses unauthorized DHCPv6 server traffic. Review RA controls separately.

ISC Kea 3.2.1 documents DHCPv6 lease activity in its optional Legal Logging hook. If enabled, its entries can include address or prefix, duration, DUID, and available relay information. Confirm actual hook and subnet settings, log retention and time format. The default record layout does not promise an IAID field. Use available lease metadata or packet evidence when the join needs it.

## 4. Offline exercise · Compare eight observations

Use Python 3.9 or later in a directory you control. The JSON models previously normalized historical assignments and flow observations. The script tests IPv6 equality, prefix membership, link scope and finite UTC validity intervals. A prefix match uses a binding scope already resolved from routing evidence in the fixture. It does not look up real leases, parse packets, or send network traffic.

- <a href="{{ '/assets/labs/dhcpv6-lease-evidence/review_leases.py' | relative_url }}" download="review_leases.py">Download review_leases.py</a>
- <a href="{{ '/assets/labs/dhcpv6-lease-evidence/cases.json' | relative_url }}" download="cases.json">Download fictional observations</a>

```sh
python3 review_leases.py cases.json
```

| Cases | Expected finding |
| --- | --- |
| On-time lease, deprecated lease | An exact binding remains within its valid interval in both cases. The latter is past preferred expiry. |
| Reassigned address | Only the later binding covers the recorded time. |
| Delegated prefix | One prefix matches, and no exact address assignment is asserted for the downstream source. |
| Advertise-only, wrong link, valid interval ended | No scoped active binding can be established from those rows. |
| Overlapping assignments | Two exact candidates remain unresolved. |

Expect eight passes. As a negative control, copy the JSON and change the first binding's `link` without changing the flow's `binding_link`. The expected first match fails and the script exits 1. If the original exercise fails, check the paired downloads, ISO timestamps with offsets, and that all values are IPv6. The offline comparisons ran in the cloud. Kea and the protocol were reviewed from official material.

## 5. Check your understanding

1. **A Reply contains a DNS resolver and no address. Did the server fail to allocate an address?** Check which exchange the Reply answered. An Information-request seeks configuration and does not request an address binding.
2. **An address is inside the customer's delegated prefix. Which device used it?** You have a prefix association and a possible routing scope. Check downstream address assignment and endpoint or access-network evidence to identify a device.
3. **The address matches two records at different times. Which one is relevant?** Compare the observation time with the original validity and link scope, then check early release, renewal, clock offsets and independent evidence.

**Completion criteria.** Reproduce eight cases and the scope negative control. Write separate conclusions for assignment, observed address use, and remaining endpoint identity uncertainty.

## Official references

Reviewed 2026-11-27. RFC 9915 is the January 2026 Internet Standard that supersedes RFC 8415. It obsoletes IA_TA and the Server Unicast option. SLAAC temporary addresses remain a separate mechanism. The product example refers to ISC Kea 3.2.1.

- IETF [RFC 9915 · DHCPv6](https://datatracker.ietf.org/doc/html/rfc9915), especially §§7, 9, 12, 18, 19 and 21.
- IETF [RFC 4861 · IPv6 Neighbor Discovery and router discovery](https://www.rfc-editor.org/rfc/rfc4861.html), [RFC 8981 · SLAAC temporary addresses](https://datatracker.ietf.org/doc/html/rfc8981), and [RFC 7610 · DHCPv6-Shield](https://datatracker.ietf.org/doc/html/rfc7610).
- ISC [Kea 3.2.1 · DHCPv6 legal log entries](https://kea.readthedocs.io/en/kea-3.2.1/arm/hooks.html#dhcpv6-log-entries).

[Previous · IPv4 DHCP lease evidence]({{ '/wiki/dhcp-lease-evidence/' | relative_url }}) · [Next · IPv6 Router Advertisements]({{ '/wiki/ipv6-router-advertisement-evidence/' | relative_url }}) · [Corroborate with Neighbor Discovery]({{ '/wiki/ipv6-neighbor-discovery-evidence/' | relative_url }})
