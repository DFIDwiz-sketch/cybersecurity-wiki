---
title: "Linux inotify · Explain File Replacement and Watch Gaps"
description: "Compare inode and directory watches, correlate rename events, and recover file-integrity coverage after a lost watch or overflowing queue."
category: blue-team
tags: [Linux, inotify, File Integrity, Detection Engineering, DFIR, Blue Team]
level: Beginner
updated: "2026-11-27"
translation_url: /ko/wiki/linux-inotify-watch-evidence/
---

A deployment tool replaces `app.conf` at the same pathname. The file-integrity monitor reports a change and then falls quiet. Did the file stop changing, or did the monitor lose the object it was watching? On Linux, inotify tells you which events reached a watch. Incident analysis also needs the watch lifecycle, current filesystem state, and an independent record of the process that made the change.

## 1. A path and a watch can separate

A **pathname** is how a program asks the filesystem to find an object. A **directory entry** associates a name with an object. An **inode** identifies the object within its filesystem while that object exists. Record the device ID with the inode number, and keep the time and mount namespace. Inode numbers alone can be reused and do not compare reliably across filesystems.

An **inotify instance** is the kernel notification queue and its set of watches. A program opens one instance, configures which events each watch should receive with a bit mask, and reads notifications from the instance's file descriptor. The kernel returns a **watch descriptor** (`wd`) for every watch. The number identifies a watch within that instance and is distinct from a process ID and the file descriptor used to read events.

| Scope or field | What it identifies | What it helps you observe |
| --- | --- | --- |
| Watch on `app.conf` | Inode resolved when the watch was added | Activity on that object, including activity via another hard link to it. |
| Watch on its parent directory | The directory object and, according to the mask, its immediate entries | A file arriving at the name `app.conf`, plus in-place writes via names within that directory. Subdirectories require their own watches. |
| `name` | Child name for an event about an entry in a watched directory | Join to the parent watch's recorded path and view. At collection time the entry may already have changed. |
| Rename `cookie` | Kernel value shared by the move notifications the reader can observe for a rename | Match `IN_MOVED_FROM` and `IN_MOVED_TO` within one instance and a short window. A move across the watch boundary may yield only one end. |

## 2. A normal deployment that changes the inode

1. The service has `app.conf` at inode A. The deployment tool writes its replacement to a new file `app.conf.next` at inode B in the same directory and closes it.
2. The tool calls `rename` to put B at the existing name `app.conf`. Within this filesystem the replacement of the destination name is atomic. A subsequent pathname lookup finds B. A process that already held A open can continue to use A.
3. The parent watch can report a move from `app.conf.next` to `app.conf`, with the same cookie on both records. If the old object is removed, the individual watch can report `IN_DELETE_SELF` followed by `IN_IGNORED`. `IN_IGNORED` marks a removed watch and also occurs with explicit removal or filesystem unmount. Whether and when the old object disappears depends on references to it.
4. If the monitor still needs an inode watch as well as entry coverage, it resolves and verifies the destination again and adds a new watch. Keeping the old number in a cache cannot attach that watch to B.

<figure>
  <img src="{{ '/assets/diagrams/linux-inotify-watch-evidence.svg' | relative_url }}" width="560" height="330" alt="Before rename, app.conf names inode A and the direct watch observes A. After replacement, app.conf names inode B. The parent watch sees the name change, and B needs its own direct watch.">
  <figcaption>Watch the parent to observe the name transition. Resolve the new target before relying on a direct watch.</figcaption>
</figure>

A file written **in place** can produce `IN_MODIFY` or `IN_CLOSE_WRITE` without changing the inode. A close-write event reports closure of a writable file descriptor. Review current file metadata and an approved baseline or hash to determine whether the content now differs. Compare both inode identity and hashes, since a replacement can preserve identical content.

## 3. Collect and respond when the feed goes quiet

| Observation | Check next | What you can say |
| --- | --- | --- |
| Same-cookie move pair, name now resolves to B | Compare the watch scope, deployment record, current metadata and signed release or known-good hash | The watcher saw a rename within its scope. The deployment and integrity sources establish whether it was expected. |
| One half of a move, or path gone at read time | Allow a bounded pairing window across reads. Check watch coverage on both parents and collect a fresh directory snapshot. | The observed side is evidence. The other name or final object may be unknown. |
| `IN_IGNORED` for an expected watch | Find the removal reason if logs allow, verify the current path and mount view, and reattach the required watches | That watch ended. New-object coverage requires a separate watch when needed. |
| `IN_Q_OVERFLOW` with `wd=-1` | Mark the instance's cached state uncertain. Stop relying on pending rename pairs, rebuild or reconcile watches and scan the intended scope. | Events were dropped from that instance. The rescan establishes state at the time of the scan and leaves the missing event sequence unresolved. |

**Start with coverage.** Record sensor and boot identity, an instance generation identifier created by the collector, the requested paths and masks, whether each watch was installed, the service’s mount namespace, and collection timestamps. Log lifecycle events and watch-add failures, including `ENOSPC`, which can indicate the user’s watch limit or a resource allocation failure. The instance queue limit is set when the instance is created. Keep collector health separate from downstream log delivery so a queue gap and an export failure do not get merged into one diagnosis.

**Reconcile after loss.** Preserve the last known good snapshot and the first sign of trouble. Rebuild the instance if its descriptor-to-path mapping cannot be trusted, then install watches and take a fresh inventory with a reconciliation step for changes during setup. For newly seen subdirectories, scan just after adding a watch because entries may already be present. Mark the uncertain interval in alerts and compare with Linux Audit, endpoint telemetry, and deployment logs that were enabled for the affected scope at the time.

**Investigate unexpected changes.** Compare the observed object with a verified version and correlate the time and path with a trusted record of processes and accounts. A normal update and an unauthorized change can produce the same rename pattern. Investigate a new digest outside the release window, a missing expected watch, or a group of hosts losing coverage around the same time. Preserve records before containment. Avoid assigning an actor based on the notification, which carries neither the modifying PID nor a username.

Other gaps matter too. Identical queued events can merge. A remote change on a network filesystem may escape local inotify. Some memory-mapped I/O changes are unreported, and a mount placed over a watched directory can change the visible tree without a matching inotify event. Verify the intended mount view and inventory even when no overflow was recorded.

## 4. Authorized lab · Watch a harmless replacement

Use Linux with glibc and Python 3.9 or later, from a directory you control on a local Linux filesystem. The program creates a temporary directory there, writes only its own fixtures, then removes the directory. It uses no elevated permissions, production paths, or network access.

- <a href="{{ '/assets/labs/linux-inotify-watch-evidence/watch_replace.py' | relative_url }}" download="watch_replace.py">Download watch_replace.py</a>

```sh
python3 watch_replace.py
```

Expect three observations. The parent watch reports a rename pair with a shared nonzero cookie and the device/inode identity changes. A later write to the new file reaches the parent while the original direct watch has ended. After reattaching, the direct watch sees a third write. The actual watch numbers, inode numbers, and cookie vary between runs. The lab checks event relationships and does not require a fixed event sequence. If it fails before watching, check your working directory permissions, local filesystem, glibc, and whether a container policy permits the inotify calls. If coverage assertions fail, keep the emitted events and record the filesystem type before comparing with the example.

This example is from the cloud test on Linux 6.18.57 (`x86_64`), glibc 2.41, and Python 3.12.14. The event lines are excerpted from the first run.

```text
replacement wd=1 flags=IN_MOVED_FROM cookie=74 name=app.conf.next
replacement wd=1 flags=IN_MOVED_TO cookie=74 name=app.conf
replacement wd=2 flags=IN_IGNORED cookie=0 name=-
write-before-reattach wd=1 flags=IN_CLOSE_WRITE cookie=0 name=app.conf
write-after-reattach wd=3 flags=IN_CLOSE_WRITE cookie=0 name=-
```

**Paper exercise for overflow.** Suppose the watcher records `IN_MOVED_FROM cookie=42`, then `IN_Q_OVERFLOW wd=-1`, and later sees `app.conf` at inode B in a fresh inventory. Record a gap and a current observation of B. Treat cookie 42 as unresolved across the gap, discard the old correlation state, and look to independently retained deployment or audit records for the transition. The live lab verifies ordinary replacement and reattachment. The overflow case is fictional and was reviewed against the documented interface.

## 5. Check your reasoning

1. **The direct watch becomes silent after a deployment. Is the pathname stable?** Silence cannot establish that. Check for watch removal, compare device and inode, and reconcile against the parent stream.
2. **Two move records share a cookie but have different watch descriptors. Can they be connected?** Yes, if they are the appropriate two sides within the same instance and correlation window. A cross-directory rename can involve two watches.
3. **After an overflow the file hash differs. Can you identify the writer from the rescan?** The rescan establishes the new content state. Use independent process or audit evidence to identify an actor.

**Completion criteria.** Reproduce the three live observations and distinguish a path replacement from a write to the same object. For the paper exercise, state what was lost, what the rescan confirms, and which evidence could identify the process.

## Official references

Reviewed 2026-11-27. Interface scope is Linux inotify and rename behavior documented in the Linux man-pages 6.19 series and the kernel’s inotify design documentation. Filesystem, container, and collector behavior must be checked where deployed.

- Linux man-pages [inotify(7) · Masks, queue overflow and rename correlation](https://man7.org/linux/man-pages/man7/inotify.7.html) and [inotify_add_watch(2) · Permission and resource failures](https://man7.org/linux/man-pages/man2/inotify_add_watch.2.html).
- Linux man-pages [rename(2) · Destination replacement and object references](https://man7.org/linux/man-pages/man2/rename.2.html).
- Linux kernel documentation [Inotify · Instance and watch design](https://docs.kernel.org/filesystems/inotify.html).

[Previous · Open files and deleted paths]({{ '/wiki/linux-open-file-evidence/' | relative_url }}) · [Next · Linux Audit file activity]({{ '/wiki/linux-audit-file-evidence/' | relative_url }}) · [Check Linux Audit loss separately]({{ '/wiki/linux-audit-loss-evidence/' | relative_url }})
