---
title: "Linux ELF Runtime Evidence · Declared and Mapped Libraries"
description: "Compare declared dependencies with process mappings, investigate unexpected libraries and verify a benign runtime load."
category: blue-team
tags: [Linux, ELF, Process Evidence, Blue Team, DFIR]
level: Beginner
updated: "2026-11-23"
translation_url: /ko/wiki/linux-elf-runtime-evidence/
---

**Learning goal.** Compare a Linux executable's declared dependencies with a running process's mapped files. Explain why either source alone leaves questions about provenance and execution.

## 1. Why read an executable and a process separately?

**ELF** is a file format Linux commonly uses for executables and shared libraries. A **shared object** is a file that can supply code or data to a program. The **dynamic loader** resolves dependencies and maps shared objects when a dynamically linked program starts. One ELF file's **direct dependencies** are named in its `DT_NEEDED` entries. A library may declare its own dependencies. A program can also request a plugin after startup with an interface such as `dlopen()`.

A **mapping** is a range of a process's virtual address space. It can be backed by an on-disk file or be anonymous. Linux exposes the current regions in `/proc/PID/maps`, including permissions, offset, device and inode, and a pathname when available. An executable mapping, for example `r-xp`, shows that the region has execute permission. A memory map does not record which functions were called.

| Evidence | Shows | Leaves open |
| --- | --- | --- |
| ELF program headers | Segments, including the interpreter when declared. | The actual startup and runtime state. |
| ELF dynamic entries | Direct dependency names and declared search settings when present. | Which paths were chosen, indirect libraries and runtime plugins. |
| `/proc/PID/exe` and process identity | The executable link and the process to which you attached the observation. | All libraries and their activity. |
| `/proc/PID/maps` | A particular process's mapped regions at collection time. | Earlier mappings that ended, or instructions executed in a region. |
| Application or endpoint telemetry | Library load or application activity when the source records it. | Anything outside that source's coverage. |

<figure style="margin-inline: 0">
  <img src="{{ '/assets/diagrams/linux-elf-runtime-evidence-en.svg' | relative_url }}" alt="Compare ELF declarations on disk with mappings of the identified process. Application evidence can support whether a mapped component did work.">
  <figcaption>Declared dependency, observed mapping and application effect answer different questions.</figcaption>
</figure>

## 2. Follow a normal application

A reporting app starts with a C library and loads a vendor-provided formatter when someone selects CSV export. The executable's dynamic table names the C library. Once the process is running, its mappings include that library. After the export feature initializes, another snapshot can show the formatter. The formatter need not appear in the executable's `DT_NEEDED` entries. The app's export audit, separately matched to the process and request, can show whether a report was actually produced.

A declaration is not a path resolution result. For example, GNU/Linux systems using glibc can resolve a library name through search paths, a loader cache or default directories. `DT_RUNPATH` is scoped to direct dependencies of the object carrying it. The legacy `DT_RPATH` has different inheritance and precedence. Avoid applying a single glibc search order to other loaders, secure-execution contexts or containers. Compare results from the relevant release and mount namespace.

## 3. Investigate an unexpected mapping

A service can load an unintended library if dependency provenance or path permissions are weak. A suspicious path, replacement on disk, or a name mismatch justifies further checks. Ordinary upgrades can leave old libraries mapped by long-running services. A `(deleted)` suffix on a file mapping can reflect an unlinked file, and the textual suffix is ambiguous. A current path can point to a new inode after an update. An anonymous executable region can come from a runtime that generates code. Do not conclude compromise from one mapping, one path or shared-object name.

1. **Identify the process.** Record the source host and boot identity, PID namespace, process start time, PID, `exe` target, parent or service when available, and the UTC collection window. A PID can be reused. Confirm the process did not change between reads.
2. **Preserve a bounded view.** Collect the relevant maps rows and their device and inode fields, permission bits, offset, and name. Separate a current filesystem hash from mapped file identity. Compare the path through the same mount namespace, and preserve the file or package evidence under your incident procedure. Avoid collecting arbitrary memory or unrelated process environment values.
3. **Test competing explanations.** Check package or image manifests, approved deployment and plugin lists, file ownership or directory writability, and update timestamps. Match current load telemetry or application results if available. Baseline by application version, feature and container image. A practical alert can combine a new mapped inode in a writable location with an unexpected service identity and a change outside an approved rollout.
4. **Respond and verify.** If the combined evidence supports an unauthorized change, preserve the process and file observations before coordinated isolation or restart when feasible. Restore a trusted package or image and verify the intended configuration, fresh process identity and post-recovery mappings. Record any unobserved execution or outcome as unresolved.

For read-only investigation on an authorized Linux system, GNU `readelf -l` shows program headers and `readelf -d` shows the dynamic section of an approved copy. Use an isolated analysis environment and patched parsing tools for suspect files. Linux man-pages cautions against using `ldd` on an untrusted executable. If reading runtime evidence on a live system is allowed, inspect `/proc/PID/maps` for the verified process, subject to procfs and ptrace access checks. If it is inaccessible, use the approved collection path and record the gap. A dead process has no live maps file.

## 4. Run the approved offline lab

Download the <a href="{{ '/assets/labs/linux-elf-runtime-evidence.py' | relative_url }}" download="linux-elf-runtime-evidence.py">Python script</a> and run it in your own approved Linux workspace. It needs Python 3, a C compiler and development headers, GNU `readelf`, working procfs and a temporary directory that allows execution. It builds its own small host and library, uses the lab's explicit library path, and examines the host's own maps before and after loading. It does not take an external binary, read other processes, change system loader settings or use the network.

```bash
python3 linux-elf-runtime-evidence.py
```

```text
PASS: ELF declares startup dependencies, but not the lab plugin
PASS: plugin is absent from the process maps before loading
PASS: plugin is mapped after the explicit runtime load
```

If `cc` or `readelf` is missing, use a Linux lab with the compiler and Binutils installed. If execution fails in your temporary directory, use an approved temporary workspace that permits execution. If the runtime snapshot fails, verify procfs and environment restrictions. The example was run on Linux with GNU Binutils 2.44 and GCC 14.2.0. It verifies a mapping of the lab-built file, not a production service's application behavior.

## 5. Check your reasoning

- **Does a plugin have to appear in the executable's `DT_NEEDED` list to be mapped?** No. A runtime load can add it after startup.
- **Does `r-xp` prove a specific function ran?** No. It describes a private mapping with read and execute permissions. Use appropriate execution or application evidence for the effect.
- **The package was upgraded and a mapping looks deleted. Is that proof of tampering?** Correlate the mapping's device and inode, package history and process start. An old mapped copy can persist until the process exits or unmaps it.

Finish when all three checks pass and you can identify the independent evidence needed to verify both the mapped file and the claimed application outcome.

## Official references

Reviewed November 23, 2026. The lab uses Linux procfs and GNU Binutils 2.44. Loader ordering examples refer specifically to glibc; other systems can differ.

- Tool switches and file inspection. [GNU Binutils 2.44 readelf](https://sourceware.org/binutils/docs-2.44/binutils/readelf.html)
- GNU loader path rules and runtime library loading. [Linux man-pages ld.so](https://man7.org/linux/man-pages/man8/ld.so.8.html) · [dlopen](https://man7.org/linux/man-pages/man3/dlopen.3.html)
- Mapping, process image and inspection limits. [Linux man-pages proc_pid_maps](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html) · [proc_pid_exe](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html) · [ldd](https://man7.org/linux/man-pages/man1/ldd.1.html)

[Previous · Linux process evidence]({{ '/wiki/linux-process-evidence/' | relative_url }}) · [Related · Linux socket scope]({{ '/wiki/linux-socket-scope-evidence/' | relative_url }})
