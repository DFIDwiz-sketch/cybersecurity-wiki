"""Exercise Linux mode bits and POSIX-style ACLs on disposable files."""
import ctypes
import ctypes.util
import os
from pathlib import Path
import stat
import sys
from tempfile import TemporaryDirectory


# Linux values from include/uapi/linux/posix_acl.h.
ACL_ACCESS = 0x8000
ACL_DEFAULT = 0x4000


def load_acl():
    library = ctypes.util.find_library("acl")
    if not library:
        raise RuntimeError("libacl is required (libacl1 on Debian/Ubuntu, libacl on RHEL).")
    acl = ctypes.CDLL(library, use_errno=True)
    functions = (
        ("acl_from_text", [ctypes.c_char_p], ctypes.c_void_p),
        ("acl_set_file", [ctypes.c_char_p, ctypes.c_int, ctypes.c_void_p], ctypes.c_int),
        ("acl_get_file", [ctypes.c_char_p, ctypes.c_int], ctypes.c_void_p),
        ("acl_to_text", [ctypes.c_void_p, ctypes.c_void_p], ctypes.c_void_p),
        ("acl_free", [ctypes.c_void_p], ctypes.c_int),
    )
    for name, arguments, result in functions:
        function = getattr(acl, name)
        function.argtypes = arguments
        function.restype = result
    return acl


def set_acl(acl, path, kind, rules):
    handle = acl.acl_from_text(rules.encode())
    if not handle:
        raise RuntimeError("Could not parse the lab ACL.")
    try:
        if acl.acl_set_file(os.fsencode(path), kind, handle) != 0:
            raise OSError(ctypes.get_errno(), "Could not set ACL on temporary file or directory")
    finally:
        acl.acl_free(handle)


def access_acl(acl, path):
    handle = acl.acl_get_file(os.fsencode(path), ACL_ACCESS)
    if not handle:
        raise OSError(ctypes.get_errno(), "Could not read ACL")
    try:
        output = acl.acl_to_text(handle, None)
        if not output:
            raise RuntimeError("Could not format ACL")
        try:
            return ctypes.string_at(output).decode()
        finally:
            acl.acl_free(output)
    finally:
        acl.acl_free(handle)


def require(condition, label):
    if not condition:
        raise RuntimeError(f"Unexpected result for {label}")
    print(f"PASS: {label}")


def create(path):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o666)
    with os.fdopen(fd, "w") as stream:
        stream.write("training data\n")


def main():
    if sys.platform != "linux" or os.geteuid() == 0:
        raise RuntimeError("Run on Linux using an ordinary account without DAC override capabilities.")
    acl = load_acl()
    mask = os.umask(0o077)
    try:
        with TemporaryDirectory(prefix="wiki-permissions-") as work:
            root = Path(work)
            plain = root / "plain"
            inherited_dir = root / "inherited"
            inherited_dir.mkdir()
            create(plain)
            require(stat.S_IMODE(plain.stat().st_mode) == 0o600, "umask 077 produces mode 0600")
            set_acl(acl, inherited_dir, ACL_DEFAULT, "u::rwx,g::r-x,o::---")
            inherited = inherited_dir / "report"
            create(inherited)
            require(stat.S_IMODE(inherited.stat().st_mode) == 0o640, "default ACL produces mode 0640")
            set_acl(acl, plain, ACL_ACCESS, f"u::rw-,g::---,g:{os.getegid()}:rw-,m::r--,o::---")
            original = access_acl(acl, plain)
            named = next(line.split()[0] for line in original.splitlines()
                         if line.startswith("group:") and not line.startswith("group::"))
            require(named.endswith(":rw-") and "mask::r--" in original, "named group entry is limited by the mask")
            plain.chmod(0o600)
            changed = access_acl(acl, plain)
            require(named in changed and "mask::---" in changed, "chmod changes the mask, keeping the named entry")
            with inherited.open() as existing:
                inherited_dir.chmod(0o600)
                try:
                    try:
                        inherited.open().close()
                    except PermissionError:
                        blocked = True
                    else:
                        blocked = False
                    require(blocked, "new open fails when its parent lacks search permission")
                    require(existing.read() == "training data\n", "already open descriptor still reads the file")
                finally:
                    inherited_dir.chmod(0o700)
    finally:
        os.umask(mask)
    print("6 checks passed.")


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        sys.exit(f"Lab stopped: {error}")
