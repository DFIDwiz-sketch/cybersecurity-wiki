#!/usr/bin/env python3
"""Run six CRL controls with disposable local OpenSSL material."""
import platform
import shutil
import subprocess
import tempfile
import time
from pathlib import Path

CONFIG = """[req]
distinguished_name = dn
[dn]
[ca]
default_ca = lab
[lab]
database = index.txt
new_certs_dir = issued
certificate = root.pem
private_key = root.key
serial = serial
crlnumber = crlnumber
default_days = 7
default_crl_days = 1
default_md = sha256
policy = policy
x509_extensions = leaf
[policy]
commonName = supplied
[leaf]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:reports.lab.example
"""


def execute(directory, *arguments):
    return subprocess.run(["openssl", *arguments], cwd=directory, text=True,
                          capture_output=True, check=False, timeout=30)


def generate(directory, *arguments):
    result = execute(directory, *arguments)
    if result.returncode:
        raise RuntimeError(f"OpenSSL {arguments[0]} failed:\n{result.stderr}")
    return result.stdout.strip()


def issue(directory, name):
    generate(directory, "req", "-config", "lab.cnf", "-new", "-newkey",
             "rsa:2048", "-noenc", "-subj", f"/CN={name}",
             "-keyout", f"{name}.key", "-out", f"{name}.csr")
    generate(directory, "ca", "-config", "lab.cnf", "-batch", "-notext",
             "-in", f"{name}.csr", "-out", f"{name}.pem")


def verify(directory, label, name, expected, *extra):
    result = execute(directory, "verify", "-CAfile", "root.pem", "-no-CApath",
                     "-no-CAstore", "-purpose", "sslserver", "-verify_hostname",
                     "reports.lab.example", *extra, f"{name}.pem")
    output = (result.stdout + result.stderr).strip()
    passed = result.returncode == 0 if expected == "OK" else result.returncode != 0
    if not passed or expected.lower() not in output.lower():
        raise RuntimeError(f"{label}: expected {expected}\n{output}")
    print(f"PASS {label}: {expected}")


def main():
    if not shutil.which("openssl"):
        raise SystemExit("OpenSSL 3.x must be on PATH.")
    with tempfile.TemporaryDirectory(prefix="wiki-crl-") as temporary:
        directory = Path(temporary)
        print(f"Python {platform.python_version()} | {generate(directory, 'version')}")
        (directory / "issued").mkdir()
        (directory / "lab.cnf").write_text(CONFIG, encoding="ascii")
        (directory / "index.txt").touch()
        (directory / "serial").write_text("1000\n", encoding="ascii")
        (directory / "crlnumber").write_text("1000\n", encoding="ascii")
        generate(directory, "req", "-config", "lab.cnf", "-x509", "-newkey",
                 "rsa:2048", "-noenc", "-sha256", "-days", "10",
                 "-subj", "/CN=Offline Revocation Lab Root",
                 "-addext", "basicConstraints=critical,CA:TRUE",
                 "-addext", "keyUsage=critical,keyCertSign,cRLSign",
                 "-keyout", "root.key", "-out", "root.pem")
        issue(directory, "service")
        issue(directory, "sibling")
        ca = ("ca", "-config", "lab.cnf", "-batch")
        generate(directory, *ca, "-gencrl", "-out", "before.pem")
        verify(directory, "fresh CRL before revocation", "service", "OK",
               "-crl_check", "-CRLfile", "before.pem")

        generate(directory, *ca, "-revoke", "service.pem", "-crl_reason", "keyCompromise")
        generate(directory, *ca, "-gencrl", "-out", "after.pem")
        print(generate(directory, "x509", "-in", "service.pem", "-noout", "-issuer", "-serial"))
        print(generate(directory, "crl", "-in", "after.pem", "-noout", "-issuer",
                       "-lastupdate", "-nextupdate", "-crlnumber"))

        verify(directory, "same leaf without CRL checks", "service", "OK")
        verify(directory, "fresh CRL lists the leaf", "service", "certificate revoked",
               "-crl_check", "-CRLfile", "after.pem")
        verify(directory, "required CRL missing", "service", "unable to get certificate CRL",
               "-crl_check")
        later = str(int(time.time()) + 2 * 86400)
        verify(directory, "expired CRL while leaf remains valid", "sibling", "CRL has expired",
               "-crl_check", "-CRLfile", "after.pem", "-attime", later)
        verify(directory, "different serial under the same CA", "sibling", "OK",
               "-crl_check", "-CRLfile", "after.pem")
        print("6/6 CRL controls matched.")


if __name__ == "__main__":
    main()
