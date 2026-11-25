"""Observe file descriptors, rotation and unlink using only temporary local files."""

import os
from pathlib import Path
import stat
import tempfile


BEFORE = b"original lab log\n"
AFTER = b"replacement lab log\n"


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def identity(metadata):
    return metadata.st_dev, metadata.st_ino


def read_fdinfo(number):
    path = Path("/proc/self/fdinfo") / str(number)
    return dict(line.split(":\t", 1) for line in path.read_text().splitlines())


def inspect_files(directory):
    current = directory / "status.log"
    rotated = directory / "status.log.1"
    current.write_bytes(BEFORE)
    with current.open("rb", buffering=0) as handle:
        number = handle.fileno()
        entry = Path("/proc/self/fd") / str(number)
        original = identity(os.fstat(number))
        require(stat.S_ISREG(entry.stat().st_mode), "Expected a regular lab file")
        other = os.dup(number)
        try:
            require(os.read(other, 4) == BEFORE[:4], "Unexpected duplicate read")
            fields = read_fdinfo(number)
            require(int(fields["pos"]) == 4, "Duplicate did not advance the original offset")
            require(int(fields["mnt_id"]) > 0, "Mount ID unavailable")
        finally:
            os.close(other)
        print(f"PASS 1: shared offset {fields['pos']}; mount ID {fields['mnt_id']}")

        current.rename(rotated)
        current.write_bytes(AFTER)
        require(identity(entry.stat()) == identity(rotated.stat()) == original,
                "Open descriptor changed during rename")
        require(identity(current.stat()) != original, "Replacement file has the old identity")
        require(entry.readlink() == rotated, "Expected the rotated pathname before unlink")
        print(f"PASS 2: rotated inode {original[1]}; new inode {current.stat().st_ino}")

        rotated.unlink()
        require(not rotated.exists(), "Rotated pathname still exists")
        opened = entry.stat()
        require(identity(opened) == original and opened.st_nlink == 0,
                "Expected the original regular file with zero links")
        require(entry.read_bytes() == BEFORE, "Opened object did not contain the original bytes")
        require(current.read_bytes() == AFTER, "Replacement path did not contain the new bytes")
        print(f"PASS 3: old link count {opened.st_nlink}; original bytes still readable")

    # is_symlink uses metadata only and does not open a replacement descriptor.
    require(not entry.is_symlink(), "Old proc descriptor did not disappear after close")
    print("PASS 4: descriptor entry disappeared after close")


def main():
    if not Path("/proc/self/fdinfo").is_dir():
        raise SystemExit("Linux procfs with /proc/self/fdinfo is required")
    try:
        with tempfile.TemporaryDirectory(prefix="linux-open-file-") as temp:
            inspect_files(Path(temp).resolve())
    except (OSError, KeyError, RuntimeError, ValueError) as error:
        raise SystemExit(f"Lab failed: {error}") from None


if __name__ == "__main__":
    main()
