#!/usr/bin/env python3
"""Disposable offline PKI lab; no trust-store changes or network requests."""
import datetime
import pathlib
import subprocess
import tempfile
import time

def run(*args):
    p = subprocess.run(args, capture_output=True, text=True)
    if p.returncode:
        raise RuntimeError(p.stderr or p.stdout)
    return p.stdout.strip()

print(run("openssl", "version"))
with tempfile.TemporaryDirectory(prefix="wiki-cert-validation-") as folder:
    d = pathlib.Path(folder)
    def p(name):
        return str(d / name)
    def write(name, text):
        (d / name).write_text(text, encoding="utf-8")
    write("empty.cnf", "[req]\ndistinguished_name=dn\n[dn]\n")
    # Use an explicit config so host defaults do not add surprise extensions.
    for name in ("root", "other", "intermediate", "leaf"):
        run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
            "rsa_keygen_bits:3072", "-out", p(name + ".key"))
    for name, serial in (("root", "1"), ("other", "2")):
        run("openssl", "req", "-new", "-x509", "-sha256",
            "-config", p("empty.cnf"), "-key", p(name + ".key"),
            "-subj", "/CN=Wiki Lab " + name, "-set_serial", serial,
            "-days", "365", "-out", p(name + ".pem"),
            "-addext", "basicConstraints=critical,CA:TRUE,pathlen:1",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
            "-addext", "subjectKeyIdentifier=hash")
    for name in ("intermediate", "leaf"):
        run("openssl", "req", "-new", "-sha256", "-config", p("empty.cnf"),
            "-key", p(name + ".key"), "-subj", "/CN=Wiki Lab " + name,
            "-out", p(name + ".csr"))
    write("intermediate.ext",
          "basicConstraints=critical,CA:TRUE,pathlen:0\n"
          "keyUsage=critical,keyCertSign,cRLSign\n"
          "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    write("leaf.ext",
          "basicConstraints=critical,CA:FALSE\n"
          "keyUsage=critical,digitalSignature\n"
          "extendedKeyUsage=serverAuth\n"
          "subjectAltName=DNS:lab.example.test\n"
          "subjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid,issuer\n")
    run("openssl", "x509", "-req", "-sha256", "-in", p("intermediate.csr"),
        "-CA", p("root.pem"), "-CAkey", p("root.key"), "-set_serial", "10",
        "-days", "30", "-extfile", p("intermediate.ext"), "-out", p("intermediate.pem"))
    run("openssl", "x509", "-req", "-sha256", "-in", p("leaf.csr"),
        "-CA", p("intermediate.pem"), "-CAkey", p("intermediate.key"),
        "-set_serial", "100", "-days", "1", "-extfile", p("leaf.ext"),
        "-out", p("leaf.pem"))
    # Verification has no platform store fallback; only the explicit CAfile.
    def check(label, expected, error=None, ca="root.pem", chain=True,
              host="lab.example.test", purpose="sslserver", at=None):
        args = ["openssl", "verify", "-no-CApath", "-no-CAstore", "-CAfile", p(ca),
                "-purpose", purpose, "-verify_hostname", host]
        if chain:
            args += ["-untrusted", p("intermediate.pem")]
        if at is not None:
            args += ["-attime", str(at)]
        result = subprocess.run(args + [p("leaf.pem")], capture_output=True, text=True)
        out = result.stdout + result.stderr
        assert (result.returncode == 0) == expected, label + ": " + out
        if error is not None:
            assert error in out, label + ": unexpected failure: " + out
        print("PASS: " + label)
        print(out.strip().replace(str(d), "<TEMP>"))
    print("Leaf metadata:")
    print(run("openssl", "x509", "-in", p("leaf.pem"), "-noout",
              "-subject", "-issuer", "-serial", "-dates", "-ext",
              "subjectAltName,extendedKeyUsage,basicConstraints"))
    check("valid chain, hostname and server purpose", True)
    check("wrong hostname rejected", False, "hostname mismatch", host="wrong.example.test")
    check("missing intermediate rejected", False, "unable to get local issuer certificate",
          chain=False)
    check("server-only leaf rejected for client purpose", False,
          "unsuitable certificate purpose", purpose="sslclient")
    check("unrelated trust anchor rejected", False,
          "unable to get local issuer certificate", ca="other.pem")
    # Evaluate two days later without changing the operating-system clock.
    check("expired leaf rejected at simulated future time", False,
          "certificate has expired", at=int(time.time()) + 2 * 86400)
print("DONE: six controls passed; temporary keys and certificates removed")
