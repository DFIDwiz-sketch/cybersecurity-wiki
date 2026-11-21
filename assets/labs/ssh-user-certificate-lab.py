#!/usr/bin/env python3
"""Generate and inspect disposable OpenSSH certificates and a local KRL."""

from pathlib import Path
from tempfile import TemporaryDirectory
import os
import shutil
import subprocess


def run(directory, *args):
    return subprocess.run(
        ("ssh-keygen", *args), cwd=directory, capture_output=True, text=True,
        env=dict(os.environ, LC_ALL="C", TZ="UTC"), check=False,
    )


def checked(directory, *args):
    result = run(directory, *args)
    if result.returncode:
        raise SystemExit(result.stdout + result.stderr)
    return result.stdout


def exercise(directory):
    for name in ("ca-a", "ca-b", "student"):
        checked(directory, "-q", "-t", "ed25519", "-N", "", "-f", name)

    def issue(name, signer, serial, key_id, validity):
        public = f"{name}.pub"
        shutil.copyfile(directory / "student.pub", directory / public)
        checked(directory, "-q", "-s", signer, "-I", key_id, "-n", "lab-auditor",
                "-z", str(serial), "-V", validity, public)
        return f"{name}-cert.pub"

    revoked = issue("revoked", "ca-a", 42, "lab-issued-42", "-1m:+10m")
    sibling = issue("sibling", "ca-a", 43, "lab-issued-43", "-1m:+10m")
    other_ca = issue("other-ca", "ca-b", 42, "lab-other-ca-42", "-1m:+10m")
    expired = issue("expired", "ca-a", 44, "lab-expired-44", "20000101000000:20000101010000")

    report = checked(directory, "-L", "-f", revoked)
    for value in ("user certificate", "lab-issued-42", "Serial: 42", "lab-auditor"):
        if value not in report:
            raise SystemExit(f"FAIL certificate inspection: missing {value}")
    print("PASS A: type, key ID, serial and principal inspected")

    (directory / "revoke.txt").write_text("serial: 42\n", encoding="ascii")
    checked(directory, "-k", "-f", "lab.krl", "-s", "ca-a.pub", "revoke.txt")
    for label, cert, expected_code, expected_marker in (
        ("B", revoked, 1, "REVOKED"),
        ("C", sibling, 0, "ok"),
        ("D", other_ca, 0, "ok"),
        ("E", expired, 0, "ok"),
    ):
        result = run(directory, "-Q", "-f", "lab.krl", cert)
        output = result.stdout + result.stderr
        if result.returncode != expected_code or f": {expected_marker}" not in output:
            raise SystemExit(f"FAIL {label} rc={result.returncode}: {output}")
        print(f"PASS {label}: {output.strip()}")
    print("5/5 OpenSSH tool checks matched. No SSH session was attempted.")


if __name__ == "__main__":
    if not shutil.which("ssh-keygen"):
        raise SystemExit("Install OpenSSH client tools in the approved test environment.")
    with TemporaryDirectory(prefix="wiki-sshcert-") as directory:
        exercise(Path(directory))
