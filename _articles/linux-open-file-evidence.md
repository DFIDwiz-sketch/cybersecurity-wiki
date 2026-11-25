---
title: "Investigate Linux Open Files and Deleted Paths"
description: "Use descriptors, inode identity and mount context to investigate log rotation and unlinked files."
category: dfir
tags: [Linux, File Descriptors, procfs, Filesystems, DFIR, Blue Team]
level: Beginner
updated: "2026-11-25"
translation_url: /ko/wiki/linux-open-file-evidence/
---

A service still uses disk space after its log was removed. The old path is missing, yet the service has an open descriptor. To understand what is happening, compare the live file object, the current pathname and the process instance across a recorded observation window.

## 1. A pathname and an open file have separate lifetimes

A **pathname** resolves through directory entries to a file object. An **inode** describes a file on a filesystem, including metadata such as the hard-link count. Two directory entries can refer to the same inode. The pair **device and inode** identifies a live object in a particular filesystem view. Record the mount and time as well. An inode number can later be reused, and an inode number alone can occur on different devices.

A **file descriptor** (FD) is a small integer in a process's table. It references an **open file description**, which holds the file offset and status flags. Duplicated descriptors can share one open file description and offset. Independent opens of the same inode can have different offsets. An FD number can also be reused after close.

`unlink` removes a directory entry. If that was the last hard link and a process still holds the file open, the file remains accessible through the reference. After the last relevant reference is released the filesystem can reclaim it. Neither event reports who read the file or what bytes they consumed.

| Evidence | What it answers | What to corroborate |
| --- | --- | --- |
| Current pathname and its metadata | Which object the name resolves to now | Device, inode and mount context |
| `/proc/PID/fd/N` link | What descriptor N referred to when observed | Object type, process lifetime and a second observation |
| `/proc/PID/fdinfo/N` | Offset, octal flags, mount ID and available type-specific details | Relevant mount view and whether the descriptor changed |
| Metadata through the descriptor | Object type, device/inode, size and link count | Live read/write changes and collection time |
| Audit or deployment record | Actor or reason, when the operation was logged | Event result, original object identity and service impact |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/linux-open-file-evidence-en.svg' | relative_url }}" alt="Opening, rotating and unlinking a log leaves the descriptor referring to the original file. Its storage can be reclaimed after the last reference closes.">
  <figcaption>The old name and the open reference can disappear at different times.</figcaption>
</figure>

## 2. Follow a normal log rotation

Fictional timeline on a Linux host. A service opens `status.log` at 10:00 UTC. FD 7 points to inode 410 on the service's log filesystem.

1. At 10:10 the rotation service renames the file to `status.log.1` and creates a fresh `status.log`, inode 422 on the same device. The original FD still refers to inode 410. If the service has not reopened its log, a reader of the new pathname and the writer that holds FD 7 are looking at different files.
2. At 10:20 a retention job unlinks `status.log.1`. The original FD can survive with a `(deleted)` suffix in the proc link and a link count of zero. Storage use can remain higher than a directory walk suggests.
3. At 10:22 an approved reload causes the service to reopen its log. Check the process and FD again. The number may be 7 again but refer to inode 422. Confirm entries in the new log and review storage metrics. Other descriptors, mappings or filesystem behavior can affect reclamation.

A pathname ending in `(deleted)` is a display clue. A filename can contain that literal text. Check object type and link count. A zero-link regular file can also be intentional, for example an unnamed temporary file. Expected log rotation, temporary work files and upgrades can produce observations similar to deliberate removal of a pathname. The proc link alone cannot establish an actor, malicious intent, execution, or transfer.

## 3. Collect, detect and respond

1. **Define the observer's view.** Record host, boot identity, UTC collection time, PID namespace, mount namespace and process start time. Field 22 of `/proc/PID/stat` gives start time in clock ticks after boot. Keep the raw record and use a parser that handles the parenthesized process name. Splitting the entire line on spaces can break field positions. A PID seen from a container may differ from the host PID.
2. **Collect metadata first.** Record FD number, raw link, `fdinfo` and the target's metadata. Proc links can represent regular files, sockets, pipes or kernel objects. Use metadata for triage. Opening arbitrary descriptors as a byte stream can have consequences, for instance by consuming pipe data or blocking. Collect file content only when authorized, with a collector that verifies the actual object is a regular file, applies a size bound and records identity, UTC time and hash. A live file may change during acquisition, and the hash describes the captured bytes.
3. **Cross-check process and mount identity.** Compare `fdinfo`'s `mnt_id` with the mount ID column in that process's `mountinfo`, where visible. An absent match can reflect an FD from a different or no longer attached mount. Preserve the missing relationship as a gap. The file offset is a position at observation time. It is not a count of bytes read by that process. Repeat metadata and verify PID start time around the read. A vanished entry can be a normal close or exit. The repeated sample reduces ambiguity without making the collection atomic.
4. **Establish a baseline and test alternatives.** Compare long-lived, zero-link regular files by service, mount, size and age since first observation. Correlate with rotation, package and application records. Accumulating zero-link file sizes after expected reopen time can be a leak or service failure. For a sensitive file, compare the opener, service role and Audit records if rules captured the relevant operation. Event time, audit result and object identity matter. Do not multiply storage estimates by counting the same live inode once for every FD.
5. **Record the decision.** Validate a benign log reopen using new application messages and disk metrics. If suspicious evidence is corroborated, preserve relevant metadata and authorized bytes before a restart where feasible. A restart can close the only remaining reference. If historical audit coverage is absent, report the observed object without attributing the unlink or asserting the bytes were used.

### Metadata-only example on an authorized Linux host

Use the PID and FD supplied by your approved inventory or collector. The numbers below illustrate variable substitution. GNU Coreutils and procfs are required. Run in the appropriate namespace with approved read permissions. These commands sample live state and do not copy file contents.

~~~bash
pid=12015
fd=7
readlink -- "/proc/$pid/fd/$fd"
stat -L -c 'type=%F dev=%d inode=%i links=%h bytes=%s' -- "/proc/$pid/fd/$fd"
sed -n '/^pos:/p; /^flags:/p; /^mnt_id:/p; /^ino:/p' "/proc/$pid/fdinfo/$fd"
~~~

Interpret permission errors as collection limits. Dereferencing and reading proc links depend on access checks. `hidepid`, namespaces and security policy may restrict visibility. A missing entry requires checking process lifetime, FD closure and observer scope. Do not fill a denied or missing sample with a guessed value.

## 4. Approved local lab · four observations

<a href="{{ '/assets/labs/linux-open-file-lab.py' | relative_url }}" download="linux-open-file-lab.py">Download the Python descriptor lab</a>

Use Python 3 on Linux with `/proc/self/fd` and `/proc/self/fdinfo` available. The script creates its own temporary regular files and observes only its own descriptors. Use an ordinary local filesystem that permits rename and unlink of open files. No root access, service restart or other process's data is required.

~~~bash
python3 linux-open-file-lab.py
~~~

| Stage | Expected result |
| --- | --- |
| Open and duplicate | A read through the duplicate advances the offset seen via the original |
| Rotate | Old FD follows the renamed object; the new path has a different identity |
| Unlink | Old descriptor still yields the original test bytes; link count is zero |
| Close | The old descriptor entry disappears before any new open can reuse it |

Expect four PASS lines. If procfs is unavailable or an operation fails, verify the lab is on Linux and the temporary directory is writable and on a supported filesystem. An unsupported scope is an error to investigate. The result describes this isolated exercise. Container security policies and production filesystems need their own authorized validation.

## 5. Check your reasoning

1. **The new log pathname exists and the old descriptor is listed. Did the process reopen?** Compare the device and inode. The path can refer to the replacement while the original FD still refers to the old object.
2. **Two descriptors show the same inode. Do they share offsets?** A duplicate of one open does, but two distinct opens can have independent offsets.
3. **Can you infer bytes were transmitted from a high `pos`?** No. Seeking can change the offset. A shared descriptor can be used elsewhere, and transmission requires network or service evidence.
4. **A zero-link regular file is in a long-lived service. What distinguishes rotation from misuse?** Check retention, deployment, Audit and process evidence and the application's expected behavior. Link count describes a file object's state.

Finish by reproducing the four observations and recording one comparison with observer scope, PID and start identity, descriptor, device/inode, link count, UTC time and an uncertainty that needs separate evidence.

## Official references and next reading

Reviewed **2026-11-25**. Linux man-pages 6.19 and current kernel documentation describe the interfaces. Published interface notes include `mnt_id` since Linux 3.15, and the visibility of data depends on the running kernel and configuration. The lab and metadata commands were exercised on Linux 6.18.57 in the cloud. Production filesystems and policy configurations were reviewed by documentation.

- Path and descriptor lifetime. [open(2)](https://man7.org/linux/man-pages/man2/open.2.html) · [unlink(2)](https://man7.org/linux/man-pages/man2/unlink.2.html) · [dup(2)](https://man7.org/linux/man-pages/man2/dup.2.html)
- Descriptor observations and permissions. [proc_pid_fd(5)](https://man7.org/linux/man-pages/man5/proc_pid_fd.5.html) · [proc_pid_fdinfo(5)](https://man7.org/linux/man-pages/man5/proc_pid_fdinfo.5.html)
- Why the deleted suffix can be ambiguous. [Linux kernel path rendering](https://github.com/torvalds/linux/blob/master/fs/d_path.c)
- Process and mount identity. [proc_pid_stat(5)](https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html) · [proc_pid_mountinfo(5)](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html) · [Linux kernel procfs documentation](https://docs.kernel.org/filesystems/proc.html)

Previous · [Linux process evidence]({{ '/wiki/linux-process-evidence/' | relative_url }})  
Next · [Linux Audit file evidence]({{ '/wiki/linux-audit-file-evidence/' | relative_url }}) · [ELF runtime and mappings]({{ '/wiki/linux-elf-runtime-evidence/' | relative_url }})

## Trace the directory view behind an open file

Use [Linux mount namespace evidence]({{ '/wiki/linux-mount-view-evidence/' | relative_url }}) to compare the process root, mountinfo and the mount ID of an open descriptor.
