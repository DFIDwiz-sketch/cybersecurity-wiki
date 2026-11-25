---
title: "Linux Mount Namespace Evidence · Which File Did the Process See?"
description: "Read mountinfo, compare process roots and connect an open descriptor to the mount observed at collection time."
category: dfir
tags: [Linux, Mount Namespace, Procfs, Containers, Blue Team, DFIR]
level: Beginner
updated: "2026-11-26"
translation_url: /ko/wiki/linux-mount-view-evidence/
---

**Learning goal.** A responder hashes a service's configuration on the host, but the service reports a different revision. Establish which filesystem view the process had, which mount supplied the pathname and which object an already open descriptor still refers to.

## 1. Which part of a filesystem does a process see?

A **mount** attaches a filesystem or a subtree to a path. A **mount point** is where that tree appears in the current view. A **mount namespace** has its own list of mounts. Processes can share a namespace, and a process also has its own root directory. An absolute pathname starts at that process's root. That matters when a service runs in a container or has a changed root. A **bind mount** exposes an existing directory or file at another path. When a new mount covers an existing directory, the previous contents can remain on disk even though normal lookup through the covered path reaches the new view. **OverlayFS** presents a merged view, commonly backed by lower and upper layers.

An **open file descriptor** (FD) refers to an already opened object. Opening the same spelling later can reach a different object after a mount or pathname change. A **device and inode pair** (`st_dev`, `st_ino`) can compare live references on the same system and filesystem context. It is scoped evidence. Inodes can be reused, and OverlayFS can present different identifiers for objects across layer access or copy-up. Preserve the observer, time, mount view and any independent hash before comparing across contexts.

| Evidence | What it establishes | What needs a separate check |
| --- | --- | --- |
| `/proc/PID/ns/mnt` link | Mount namespace identity captured for that process | The process root and the particular mount tree at the time of the operation |
| `/proc/PID/mountinfo` | Visible mount rows, parents, roots, targets and attributes in the process view | Which object a historical path lookup or write reached |
| `/proc/PID/root` | A procfs entry point to the process's filesystem view | The process's credentials and the outcome of its original access |
| `fdinfo` and resolved FD metadata | The mount ID and object of a currently observed descriptor, when permitted | Who opened it, when, and whether any write succeeded |
| Deployment or audit records | Intended mount configuration or a recorded operation when logging covers it | The filesystem view or an effective change unless corroborated |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/linux-mount-view-evidence-en.svg' | relative_url }}" width="480" height="388" alt="The host and service use the same config pathname but resolve it through different mount views to different file objects. A service file descriptor can be matched to a mount row using its mount ID.">
  <figcaption>Start with the process's filesystem view. Compare current pathname lookup with any descriptor the process already holds.</figcaption>
</figure>

## 2. Read a normal deployment snapshot

In a fictional release, the host's `/app/current` contains an old test configuration. The service sees an approved bind mount at `/app/current` instead. The mounted subtree is the release directory. The service reads `/app/current/config.json` from that subtree. The path has the same spelling on both sides. A fresh host hash can therefore come from the test data. Compare the service's root and mount view with that host observation before drawing a conclusion.

Here is one fictional `mountinfo` row for the service:

```text
31 21 8:1 /srv/releases/v2 /app/current ro shared:12 - ext4 /dev/example rw
```

| Part | Read this row |
| --- | --- |
| ID and parent | Mount `31` attaches under mount `21` in this snapshot. A parent outside the process root may have no visible row. IDs can be reused after unmount. |
| Device | `8:1` is the row's device major:minor value. Other mounts can refer to the same filesystem. |
| Root and target | `/srv/releases/v2` is the exposed root within that filesystem. `/app/current` is where it appears relative to the process's root. The named source `/dev/example` is a filesystem source field. To establish a host bind source pathname, consult the host view and the deployment record. |
| Mount flags | `ro` before the separator is the flag for this mount. The `rw` after the separator is in the superblock options. Other mounts of the same filesystem may permit writes. |
| Optional fields and separator | `shared:12` identifies a shared peer group. A propagation setting describes where mount changes can spread. Compare peers and direction before attributing a change. The standalone `-` ends optional fields, followed by type, source and superblock options. |

The procfs format escapes certain pathname characters. For example, `\040` encodes a space. Split into fields before decoding. If two rows have the same target and one is the other's parent, the child mount covers its parent at that target. Follow parent relationships. Mount IDs do not encode order. Consider mounts further up the path and symlinks before inferring what a fresh lookup would reach.

## 3. Investigate unexpected views and changes

| Observation | Plausible explanations | Evidence to compare |
| --- | --- | --- |
| A file is visible on the host and absent in the service | A covering mount, different process root, different release or a permissions issue | Process start and root, service and host mount snapshots, syscall or application error |
| A sensitive subtree appears inside a workload | Approved bind mount, configuration drift or unauthorized configuration change | Annotated service spec, known-good mount root and flags, deployment or audit actor and time |
| An open FD has another mount ID than the current path | An earlier open, a covered or detached mount, or a passed descriptor | FD lifetime, snapshot timing, process identity and matching rows if visible |
| Data changes on an OverlayFS view | A routine copy-up due to writing, a new layer or a different mount | Overlay view and layer evidence, approved workload changes, actual file-operation logs |

Mount options and visibility affect what access is possible. They cannot establish which file was read or written. An authorized defensive validation can compare an approved deployment with a read-only baseline and use owned temporary files to exercise how an FD relates to one mount. Avoid inferring a live operation from file names alone.

## 4. Collect and correlate evidence

1. **Identify the observer and process.** Record host identity, boot identity, UTC, PID namespace, PID, process start time and mount namespace. Capture the same process instance before and after collection when possible. PIDs and mount IDs can be reused. A container ID, workload revision or supervisor record can constrain the time window.
2. **Preserve the views.** Collect the host and relevant process mount tables, process root information and the relevant FD details where approved. When an FD has a `mnt_id`, look up the same numeric ID in that process's captured `mountinfo`. For an absent row, keep both observations. The mount may be detached, outside the visible view or recorded in a different lifetime. A proc path can become unavailable when the process or descriptor exits.
3. **Scope access and intent.** Compare the mount's expected target, root, filesystem and flags against the deployment baseline. Investigate unplanned exposure of a sensitive tree or a difference in write policy after a change. Release volumes and layered filesystems can be normal. Correlate an approved or unplanned configuration change with telemetry for the actual operation. Audit coverage depends on configured rules and retention. Treat absent records as coverage limits.
4. **Preserve before changing state.** Keep the minimum necessary metadata and any approved artifact digest, including capture time and provenance. Consult the service owner before changing live mount state. If an unintended exposure is confirmed, remove it through the owning service or workload configuration, verify the resulting view and investigate relevant file operations separately.

For a known PID and FD in an approved Linux investigation, these examples assume a mounted procfs, GNU `stat`, initialized shell variables and the required access to the target process. Use values from inventory or collected evidence. Stay within approved paths and avoid content reads during metadata triage.

```sh
readlink "/proc/$pid/ns/mnt"
cat "/proc/$pid/mountinfo"
grep '^mnt_id:' "/proc/$pid/fdinfo/$fd"
stat -Lc 'dev=%d inode=%i type=%F' "/proc/$pid/fd/$fd"
stat -Lc 'dev=%d inode=%i type=%F' \
  "/proc/$pid/root/app/current/config.json"
```

`-L` follows the procfs link and `%d` is the numeric device ID, which you can convert to a major and minor pair with your collection tooling. This observes the second pathname as seen through the process's filesystem view and accessed under collection permissions. Review symlinks and races in that path. Procfs access depends on credentials, ptrace access checks where applicable, mount options such as `hidepid` and security policy. Record a denied request or vanished PID as a collection limit. Avoid widening access merely to complete an observation.

On util-linux versions with `findmnt --task`, `findmnt --task "$pid" -o ID,PARENT,MAJ:MIN,FSROOT,TARGET,FSTYPE` is a display aid. Preserve raw `mountinfo` for evidence. Record the utility version and check its installed help before using the column list.

## 5. Offline drill and an owned-file observation

Download <a href="{{ '/assets/labs/linux-mount-view-lab.py' | relative_url }}" download>the Python checker</a> and <a href="{{ '/assets/labs/linux-mount-view-cases.json' | relative_url }}" download>the seven fictional snapshots</a> into an approved directory you control. Predict each FD's matching row. Run with Python 3 on Linux with procfs and a writable temporary directory that supports hard links. The script creates and deletes two names for its own temporary file, reads its own procfs view and prints only the comparison predicates. It changes no mounts.

```sh
python3 linux-mount-view-lab.py
```

| Case | Outcome to explain |
| --- | --- |
| A | FD mount ID 31 points at the release subtree exposed at `/app/current`. |
| B and C | The same mount point has two distinct rows. B's FD matches the covering tmpfs and C's matches the covered ext4 mount. The higher ID belongs to the covered row. |
| D | The recorded FD ID lacks a visible row. The evidence leaves the cause open. |
| E | An escaped space becomes a literal space after field parsing. |
| F | The row identifies the overlay view. Layer identity needs other evidence. |
| G | A separate snapshot reuses A's ID and target with a different filesystem and root. |

Expect `7/7 mount evidence cases matched.` and `Owned file: hard-link identity=True, FD mount row found=True`. As a negative control, copy the JSON and remove the row beginning `40 90` from B only. Run `python3 linux-mount-view-lab.py --fixtures-only altered.json` with the copied filename. Expect B to show `null`, six matches and exit status 1. If procfs is missing or the temporary filesystem rejects hard links, use `--fixtures-only` and record that you skipped the live check. If the altered case still passes, confirm the input filename and B's row. The cloud run exercised the fictional snapshots and an actual owned file under Linux 6.18.57. Separate namespaces, mount stacking, bind mounts and OverlayFS behavior are documented or modeled here. The lab does not create those mounts.

## 6. Check your understanding

1. **The host and the service show the same pathname. Which evidence would support comparing two live references?** Record their observer and mount views, resolve the paths under collection permission and compare device plus inode for those objects in that interval.
2. **Does `ro` on this target prove the filesystem cannot be written anywhere?** It describes a mount-level restriction. Other mounts of the same filesystem may have different flags. Inspect their scope and any relevant operation outcome.
3. **An FD's mount row is absent. Can you conclude it belonged to a detached mount?** A detached mount is one possibility. Verify capture order, process lifetime and namespace or root restrictions before attributing the gap.
4. **A workload legitimately received a bind mount. What establishes use of a sensitive file?** Look for an operation or an observed descriptor with the relevant object identity. Use an appropriate audit or application record to confirm the claimed action and result.

**Completion.** Explain why the host pathname and service pathname can diverge. Find the matching row and the covering relationship in B and C. Reproduce the original and altered fixture outcomes and identify one source needed to establish historical access.

## Official references

Reviewed 2026-11-26. The procedure covers Linux procfs and Linux mount views, the current upstream OverlayFS guide and the util-linux display option. Container bind examples use Docker Engine documentation. Check the kernel, filesystem and utility versions on your collection host.

- Namespace, binding and propagation. [Linux mount_namespaces(7)](https://man7.org/linux/man-pages/man7/mount_namespaces.7.html) · [Docker Engine bind mounts](https://docs.docker.com/engine/storage/bind-mounts/)
- Mount row fields, process root and path resolution. [proc_pid_mountinfo(5)](https://man7.org/linux/man-pages/man5/proc_pid_mountinfo.5.html) · [proc_pid_root(5)](https://man7.org/linux/man-pages/man5/proc_pid_root.5.html) · [path_resolution(7)](https://man7.org/linux/man-pages/man7/path_resolution.7.html)
- Layer behavior and stat identity. [Linux kernel OverlayFS](https://docs.kernel.org/filesystems/overlayfs.html)
- Display aid. [util-linux findmnt(1)](https://man7.org/linux/man-pages/man1/findmnt.1.html)
- Descriptor mount identity. [proc_pid_fdinfo(5)](https://man7.org/linux/man-pages/man5/proc_pid_fdinfo.5.html)

[Previous · Linux file permissions]({{ '/wiki/linux-file-permissions-evidence/' | relative_url }}) · [Next · Linux open file evidence]({{ '/wiki/linux-open-file-evidence/' | relative_url }})
