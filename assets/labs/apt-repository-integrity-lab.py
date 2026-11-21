#!/usr/bin/env python3
"""Model APT integrity checks with OpenSSL. No package installation or network access."""

from email.utils import format_datetime
from pathlib import Path
from tempfile import TemporaryDirectory
from datetime import datetime, timedelta, timezone
import hashlib
import shutil
import subprocess


def run(*args):
    return subprocess.run(args, capture_output=True, check=False)


def require(*args):
    result = run(*args)
    if result.returncode:
        raise SystemExit(result.stderr.decode(errors="replace"))
    return result.stdout


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def verify(verifier, release, signature, index, package, index_path, package_path):
    result = run("openssl", "pkeyutl", "-verify", "-rawin", "-pubin",
                 "-inkey", str(verifier), "-in", str(release), "-sigfile", str(signature))
    if result.returncode:
        return "Release signature rejected"
    expected_index = release.read_text().split("SHA256:\n", 1)[1].strip().split()
    index_data = index.read_bytes()
    if expected_index != [sha256(index_data), str(len(index_data)), index_path]:
        return "Packages index digest or size mismatch"
    fields = dict(line.split(": ", 1) for line in index_data.decode().splitlines())
    package_data = package.read_bytes()
    if (fields["Filename"], fields["Size"], fields["SHA256"]) != (
        package_path, str(len(package_data)), sha256(package_data)
    ):
        return ".deb digest or size mismatch"
    return "signature and both digests match"


def main(root):
    for executable in ("openssl", "dpkg-deb"):
        if not shutil.which(executable):
            raise SystemExit(f"Required program unavailable: {executable}")

    release = root / "Release"
    signature = root / "Release.sig"
    index_path = "main/binary-all/Packages"
    package_path = "pool/wiki-archive-lab_1.0_all.deb"
    index = root / index_path
    package = root / package_path
    index.parent.mkdir(parents=True)
    package.parent.mkdir()

    build = root / "build"
    control = build / "DEBIAN" / "control"
    readme = build / "usr" / "share" / "doc" / "wiki-archive-lab" / "README"
    control.parent.mkdir(parents=True)
    readme.parent.mkdir(parents=True)
    metadata = ("Package: wiki-archive-lab\nVersion: 1.0\nArchitecture: all\n"
                "Maintainer: Wiki Lab <lab@example.invalid>\nDescription: Offline text-only fixture\n")
    control.write_text(metadata)
    readme.write_text("A text-only package for the offline archive-integrity exercise.\n")
    require("dpkg-deb", "--root-owner-group", "--build", str(build), str(package))

    archive_bytes = package.read_bytes()
    index.write_text(metadata + f"Filename: {package_path}\nSize: {len(archive_bytes)}\n"
                     f"SHA256: {sha256(archive_bytes)}\n")
    index_bytes = index.read_bytes()
    now = datetime.now(timezone.utc)
    release.write_text("Origin: Wiki Lab\nLabel: Wiki Lab\nSuite: lab\nCodename: lab\n"
                       f"Date: {format_datetime(now, usegmt=True)}\n"
                       f"Valid-Until: {format_datetime(now + timedelta(days=1), usegmt=True)}\n"
                       "Architectures: all\nComponents: main\n"
                       f"SHA256:\n {sha256(index_bytes)} {len(index_bytes)} {index_path}\n")

    public_keys = []
    for label in ("archive", "unrelated"):
        private = root / f"{label}-private.pem"
        public = root / f"{label}-public.pem"
        require("openssl", "genpkey", "-algorithm", "ED25519", "-out", str(private))
        require("openssl", "pkey", "-in", str(private), "-pubout", "-out", str(public))
        public_keys.append(public)
    verifier, unrelated = public_keys
    require("openssl", "pkeyutl", "-sign", "-rawin", "-inkey", str(root / "archive-private.pem"),
            "-in", str(release), "-out", str(signature))

    changed_release = root / "changed.Release"
    changed_release.write_text(release.read_text().replace("Origin: Wiki Lab", "Origin: Changed"))
    changed_index = root / "changed.Packages"
    changed_index.write_bytes(index_bytes.replace(b"1.0", b"1.1", 1))
    changed_package = root / "changed.deb"
    changed_package.write_bytes(archive_bytes[:-1] + bytes([archive_bytes[-1] ^ 1]))
    cases = [
        ("original", verifier, release, index, package, "signature and both digests match"),
        ("unrelated public key", unrelated, release, index, package, "Release signature rejected"),
        ("changed Release", verifier, changed_release, index, package, "Release signature rejected"),
        ("changed Packages", verifier, release, changed_index, package, "Packages index digest or size mismatch"),
        ("changed .deb", verifier, release, index, changed_package, ".deb digest or size mismatch"),
    ]
    for label, keyring, rel, idx, deb, expected in cases:
        actual = verify(keyring, rel, signature, idx, deb, index_path, package_path)
        if actual != expected:
            raise SystemExit(f"FAIL {label}: {actual}, expected {expected}")
        print(f"PASS {label}: {actual}")
    print(f"{len(cases)}/{len(cases)} archive-integrity controls matched.")


if __name__ == "__main__":
    with TemporaryDirectory(prefix="aptlab-") as directory:
        main(Path(directory))
