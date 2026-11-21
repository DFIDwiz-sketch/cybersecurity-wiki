---
title: "Linux Socket Evidence · Map a Connection to a Process"
description: "Separate network namespace visibility from process file descriptors and verify a socket holder with an actual loopback exchange."
category: dfir
tags: [Linux, Containers, Network Monitoring, Incident Response, Blue Team, DFIR]
level: Beginner
updated: "2026-11-22"
translation_url: /ko/wiki/linux-socket-scope-evidence/
---

**Learning goal.** Start with a Linux network connection or listening port and identify which process held the socket at collection time. Explain what changes when collection occurs inside a container, and what historical evidence would support a stronger attribution.

## 1. Read three views of the same system

A **socket** is a kernel communication endpoint. A **file descriptor** (FD) is a number in a process that refers to an open object, which can be a socket. A Linux procfs link such as `/proc/842/fd/7 → socket:[31810]` reports that PID 842 currently has descriptor 7 referencing socket inode 31810, provided the collector can read that link. A **PID** is a process ID within a PID namespace. It can be reused, so record the process start time and the scope in which the PID was read.

A **network namespace** isolates the network stack view, including interfaces, routes and port/socket tables. `/proc/net` normally points to `/proc/self/net`. `/proc/842/net/tcp` shows the IPv4 TCP table for PID 842's network namespace. It can include sockets held by other processes in that namespace. The `/proc/842/fd` directory is the process-specific view. A process may hold several descriptors to the same socket. Multiple processes may hold a reference through inheritance or descriptor passing.

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/linux-socket-scope-en.svg' | relative_url }}" alt="Two processes share a network namespace and see the same TCP listener. Only the service process holds the listener's socket inode in its file descriptor table.">
  <figcaption>A socket row tells you where the socket was visible. A matching descriptor ties that socket to a process at collection time.</figcaption>
</figure>

## 2. Follow a normal TCP connection

In a fictional snapshot, a service listens on `127.0.0.1:41802`, and its PID 842 holds the listening socket at FD 7. A diagnostic process, PID 1090, sees the listener in its own `/proc/1090/net/tcp` because both processes share a network namespace. None of PID 1090's descriptors refers to the listening inode. When it connects as a client, the service accepts the connection. The listener remains in LISTEN, and the client socket and the newly accepted server socket each have their own inode and local/peer endpoints. On loopback both ends appear in the same namespace's table.

| Evidence | Shows | Still to check |
| --- | --- | --- |
| `ss` local and peer addresses, ports and state | Sockets visible in the selected network namespace at collection time | Which PID information was readable and which tuple applies to the incident |
| `ss -e` inode and `/proc/<pid>/fd/<n>` link | Same inode in two views supports current descriptor ownership | Collection timing, process start time and possible shared ownership |
| `/proc/<pid>/net/tcp` | IPv4 TCP sockets visible in that PID's network namespace | Which process actually holds the descriptor |
| Proxy, network or endpoint history | Observations retained for the incident interval | Clock alignment, NAT, connection direction and coverage |

Linux kernel documentation describes the `/proc/net/tcp` and `tcp6` interfaces as deprecated in favor of the socket diagnostics interface. Use `ss` for routine socket listings and procfs links to cross-check a holder. The lab reads the legacy table to show exactly what that scope means. The IPv4 and IPv6 procfs tables are separate. TCP state and direction labels do not imply which process first initiated an exchange when earlier evidence is missing.

## 3. Collect a bounded snapshot

Use an approved collector with the necessary host, PID and network namespace visibility. Record the UTC timestamp, asset, collection location, namespace link values, relevant local and peer addresses and numeric ports, state, socket inode, PID, start time, and paths needed for the investigation. The process identification rules are covered in [Linux process evidence]({{ '/wiki/linux-process-evidence/' | relative_url }}). Pair PID with start time from process metadata, such as `/proc/<pid>/stat` field 22, expressed in clock ticks since boot on modern Linux. Preserve a boot identifier when available. Capture related fields close together, since socket and FD listings are separate observations and can race a process exit or reuse.

On a Linux host with iproute2, set `PORT` to the relevant numeric port, `PID` to a visible process ID, and `FD` to a candidate descriptor number. These read-only commands are for the collector's current network namespace. The quoted filters match either local or peer port only where shown. `-n` prevents service name resolution, `-p` requests process data, and `-e` requests details such as the inode.

```sh
ss -Hltnep "sport = :$PORT"
ss -Htnpe state established "( sport = :$PORT or dport = :$PORT )"
readlink "/proc/$PID/ns/net"
readlink "/proc/$PID/ns/pid"
readlink "/proc/$PID/fd/$FD"
```

| Symptom | Check before interpreting it |
| --- | --- |
| `/proc/net` absent or inaccessible | Check the procfs mount, namespace, collection restrictions and error. Use an approved host or workload collector with visibility of the intended scope. |
| Socket appears but `ss -p` has no process details | Check PID visibility, ptrace/access policy, process exit and socket state. Some kernel-maintained TCP states can outlast a user-space descriptor. |
| Host and container show different IP/port or PID | Compare network namespace, PID namespace and collection location. Resolve translation or proxying at the right time. |
| Several PIDs or descriptors share an inode | Record the observed holders. Check service supervisors, inheritance and workload design before choosing an initiating process. |

## 4. Investigate an unexpected connection

An outbound connection can be a normal agent heartbeat, a proxy forwarding another workload's request, or communication initiated by an unauthorized process. A local listener can be a sidecar, an approved service or an unwanted access point. A listener state alone does not establish that a remote peer reached it. Compare the tuple and time with network logs. Confirm the listener's expected bind addresses, deployment, process parentage and executable identity, then seek request, endpoint or workload history to explain the behavior. Use [endpoint collection evidence]({{ '/wiki/endpoint-collection-evidence/' | relative_url }}) to scope any follow-up. Preserve the known observations and share relevant gaps with the service owner or incident lead before choosing containment.

A sensor can observe a tuple after NAT or at another proxy hop, while a current process snapshot shows an internal tuple at a later time. A matching IP and port alone leaves the process and action uncertain. A PID-to-inode association shows a descriptor holder at that time. It cannot establish who originally opened the socket, which request used it or what a closed historical connection carried. Avoid collecting command line arguments, environment variables or payloads beyond what is approved for the case.

## 5. Reproduce socket scope on loopback

Download [linux-socket-scope-lab.py]({{ '/assets/labs/linux-socket-scope-lab.py' | relative_url }}){: download="linux-socket-scope-lab.py" }. Use an owned Linux environment with Python 3.12, procfs, IPv4 loopback and iproute2 `ss`. The script starts a child on an ephemeral port bound to `127.0.0.1`, connects locally and cleans up the child and sockets. It changes no namespace or security setting and prints only the checks for the lab exchange.

```sh
python3 linux-socket-scope-lab.py
```

Expect seven `PASS` lines. The two processes have the same network namespace, and both tables show the listener. Only the child holds the listener FD. The client and accepted server socket are established with different inodes. A duplicated client FD still points to the same inode. Finally, `ss` confirms the listener's PID and the separate holders of the two established sockets.

If a file lookup fails, check that procfs is mounted and the environment permits reading your own child process's descriptors. If `ss` lacks process fields, verify that your sandbox exposes the lab PID and permits socket diagnostics. Run from an authorized Linux environment with those interfaces available. The lab does not require privilege escalation. We reproduced all seven checks as an unprivileged user on Linux 6.18.57 with iproute2 6.15.0 and Python 3.12.14. Cross-namespace, IPv6 and production collection paths were outside this execution scope.

## 6. Check your reasoning

1. **A port appears under `/proc/1090/net/tcp`. Does PID 1090 hold it?** The socket is visible in PID 1090's network namespace. Check inode and FD evidence in the correct PID scope.
2. **Two descriptors reference the same inode. Are these two independent connections?** They may be two references to the same socket. Compare inode and endpoints, and record both holders if there are multiple processes.
3. **A sensor saw a connection yesterday and today's snapshot is empty. Was there no process?** The snapshot covers current sockets. Seek retained endpoint, proxy or network evidence for the original time.

**Completion check.** Reproduce the seven results. Explain the namespace and descriptor observations in two sentences, then list the extra evidence you would need to attribute yesterday's connection.

## Official references

Reviewed 2026-11-22. The Linux man-pages and kernel documentation describe the interfaces. Exact output and permissions depend on kernel, iproute2 and collector context. The lab versions are listed above.

- Linux man-pages [network namespaces](https://man7.org/linux/man-pages/man7/network_namespaces.7.html) · [PID namespaces and procfs](https://man7.org/linux/man-pages/man7/pid_namespaces.7.html) · [namespace identifiers](https://man7.org/linux/man-pages/man7/namespaces.7.html)
- Linux man-pages [namespace network tables](https://man7.org/linux/man-pages/man5/proc_pid_net.5.html) · [process descriptors](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html) · [process start time](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html) · [procfs permissions](https://man7.org/linux/man-pages/man5/proc.5.html)
- [iproute2 ss manual](https://man7.org/linux/man-pages/man8/ss.8.html) · [Linux kernel TCP procfs interface](https://docs.kernel.org/networking/proc_net_tcp.html) · [Linux socket diagnostics](https://man7.org/linux/man-pages/man7/sock_diag.7.html)

[Previous · Linux process evidence]({{ '/wiki/linux-process-evidence/' | relative_url }}) · [Next · Endpoint collection evidence]({{ '/wiki/endpoint-collection-evidence/' | relative_url }})
