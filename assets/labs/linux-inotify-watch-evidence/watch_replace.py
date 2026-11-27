"""Observe benign file replacement in a private temporary directory on Linux."""

import ctypes
import os
from pathlib import Path
import struct
import sys
from tempfile import TemporaryDirectory

FLAGS = {
    "MODIFY": 0x00000002,
    "CLOSE_WRITE": 0x00000008,
    "MOVED_FROM": 0x00000040,
    "MOVED_TO": 0x00000080,
    "DELETE_SELF": 0x00000400,
    "Q_OVERFLOW": 0x00004000,
    "IGNORED": 0x00008000,
}
HEADER = struct.Struct("=iIII")


def checked(result):
    if result == -1:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code))
    return result


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def drain(fd, stage):
    events = []
    while True:
        try:
            data = os.read(fd, 65536)
        except BlockingIOError:
            break
        offset = 0
        while offset < len(data):
            wd, mask, cookie, size = HEADER.unpack_from(data, offset)
            start = offset + HEADER.size
            offset = start + size
            name = os.fsdecode(data[start:offset].split(b"\0", 1)[0])
            printed = ",".join("IN_" + flag for flag, bit in FLAGS.items() if mask & bit)
            print(f"{stage} wd={wd} flags={printed or hex(mask)} cookie={cookie} name={name or '-'}")
            require(not mask & FLAGS["Q_OVERFLOW"], "Unexpected queue overflow in the live lab")
            events.append((wd, mask, cookie, name))
    return events


def has(events, wd, flag, name=""):
    return any(watch == wd and mask & FLAGS[flag] and child == name
               for watch, mask, _, child in events)


def append(path, text):
    with path.open("a", encoding="utf-8") as target:
        target.write(text + "\n")


def run(linux):
    with TemporaryDirectory(prefix="inotify-replace-", dir=Path.cwd()) as folder:
        parent = Path(folder)
        target = parent / "app.conf"
        staged = parent / "app.conf.next"
        target.write_text("fixture version A\n", encoding="utf-8")
        original = target.stat()

        fd = checked(linux.inotify_init1(os.O_NONBLOCK | os.O_CLOEXEC))
        try:
            def watch(path, *flags):
                mask = sum(FLAGS[flag] for flag in flags)
                return checked(linux.inotify_add_watch(fd, os.fsencode(path), mask))

            directory_wd = watch(parent, "MOVED_FROM", "MOVED_TO", "CLOSE_WRITE")
            original_wd = watch(target, "MODIFY", "CLOSE_WRITE", "DELETE_SELF")

            staged.write_text("fixture version B\n", encoding="utf-8")
            staged.replace(target)
            after = target.stat()

            replaced = drain(fd, "replacement")
            cookie_sets = []
            for flag, name in (("MOVED_FROM", staged.name), ("MOVED_TO", target.name)):
                cookie_sets.append({cookie for wd, mask, cookie, child in replaced
                                    if wd == directory_wd and mask & FLAGS[flag]
                                    and cookie and child == name})
            require(bool(cookie_sets[0] & cookie_sets[1]), "Missing paired rename on the parent")
            require((original.st_dev, original.st_ino) != (after.st_dev, after.st_ino),
                    "Device/inode identity did not change")
            require(has(replaced, original_wd, "IGNORED"), "Original direct watch did not end")
            print(f"PASS replacement identity {original.st_dev}:{original.st_ino} "
                  f"-> {after.st_dev}:{after.st_ino}")

            append(target, "fixture write on B")
            current = drain(fd, "write-before-reattach")
            require(has(current, directory_wd, "CLOSE_WRITE", target.name),
                    "Parent did not see the write at app.conf")
            require(not has(current, original_wd, "CLOSE_WRITE"),
                    "Original direct watch unexpectedly reported the write")
            require(target.stat().st_ino == after.st_ino, "In-place write changed the inode")
            print("PASS parent sees the new object while the original direct watch is gone")

            new_wd = watch(target, "MODIFY", "CLOSE_WRITE")
            append(target, "fixture write on B with a fresh watch")
            renewed = drain(fd, "write-after-reattach")
            require(has(renewed, new_wd, "CLOSE_WRITE"), "New direct watch did not see a write")
            print("PASS the new direct watch sees a write")
        finally:
            os.close(fd)


def main():
    if sys.platform != "linux":
        print("This lab requires Linux with glibc.", file=sys.stderr)
        return 1
    try:
        linux = ctypes.CDLL("libc.so.6", use_errno=True)
        linux.inotify_init1.argtypes = [ctypes.c_int]
        linux.inotify_add_watch.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_uint32]
        run(linux)
    except (OSError, RuntimeError) as error:
        print(f"FAIL: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
