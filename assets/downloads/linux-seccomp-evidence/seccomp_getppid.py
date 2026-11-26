"""Apply one restrictive seccomp rule to this disposable Python process only."""

import ctypes
import errno
import os
import sys
from pathlib import Path


SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_ERRNO_EPERM = 0x00050000 | errno.EPERM
STATUS_FIELDS = ("NoNewPrivs", "Seccomp", "Seccomp_filters")


def read_status():
    status = {}
    for line in Path("/proc/self/status").read_text().splitlines():
        name, _, value = line.partition(":")
        if name in STATUS_FIELDS:
            status[name] = int(value.strip())
    if status.keys() != set(STATUS_FIELDS):
        raise RuntimeError("This exercise requires procfs with Seccomp_filters (Linux 5.9+).")
    return status


def bind(library, name, return_type, *argument_types):
    fn = getattr(library, name)
    fn.restype = return_type
    fn.argtypes = argument_types
    return fn


def check_library_call(result, operation):
    if result < 0:
        raise OSError(-result, f"{operation}: {os.strerror(-result)}")


def main():
    if sys.platform != "linux":
        raise RuntimeError("This exercise requires Linux.")

    seccomp = ctypes.CDLL("libseccomp.so.2")
    libc = ctypes.CDLL(None, use_errno=True)
    ptr, integer, u32 = ctypes.c_void_p, ctypes.c_int, ctypes.c_uint32
    init = bind(seccomp, "seccomp_init", ptr, u32)
    release = bind(seccomp, "seccomp_release", None, ptr)
    resolve = bind(seccomp, "seccomp_syscall_resolve_name", integer, ctypes.c_char_p)
    add = bind(seccomp, "seccomp_rule_add_array", integer, ptr, u32, integer, ctypes.c_uint, ptr)
    load = bind(seccomp, "seccomp_load", integer, ptr)
    syscall = bind(libc, "syscall", ctypes.c_long, ctypes.c_long)

    syscall_number = resolve(b"getppid")
    if syscall_number < 0:
        raise RuntimeError("libseccomp could not resolve getppid on this ABI.")
    before = read_status()
    ctypes.set_errno(0)
    original = syscall(syscall_number)
    if original < 0:
        raise RuntimeError(f"getppid was already denied (errno {ctypes.get_errno()}).")
    print(f"Before: getppid={original}; status={before}", flush=True)

    filter_context = init(SCMP_ACT_ALLOW)
    if not filter_context:
        raise RuntimeError("seccomp_init failed.")
    try:
        check_library_call(add(filter_context, SCMP_ACT_ERRNO_EPERM, syscall_number, 0, None),
                           "seccomp_rule_add_array")
        check_library_call(load(filter_context), "seccomp_load")
    finally:
        release(filter_context)

    ctypes.set_errno(0)
    blocked = syscall(syscall_number)
    error = ctypes.get_errno()
    after = read_status()
    print(f"After: getppid={blocked}; errno={error}; status={after}")
    if (blocked, error) != (-1, errno.EPERM) or after["Seccomp"] != 2:
        raise RuntimeError("Expected a filtered getppid returning EPERM.")
    if after["Seccomp_filters"] != before["Seccomp_filters"] + 1:
        raise RuntimeError("Expected exactly one additional filter.")
    print("PASS: this process added one filter and getppid returned EPERM.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError, AttributeError) as error:
        print(f"Exercise stopped: {error}", file=sys.stderr)
        sys.exit(1)
