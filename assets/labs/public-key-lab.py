#!/usr/bin/env python3
"""Offline educational lab. Creates disposable keys only in a temporary folder."""
import pathlib
import subprocess
import tempfile

def run(*args, ok=True):
    p = subprocess.run(args, capture_output=True, text=True)
    if ok and p.returncode:
        raise RuntimeError(p.stderr)
    return p

print(run("openssl", "version").stdout.strip())
with tempfile.TemporaryDirectory(prefix="wiki-public-key-") as folder:
    d = pathlib.Path(folder)
    def path(name):
        return str(d / name)
    for name in ("recipient", "signer", "wrong"):
        run("openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt",
            "rsa_keygen_bits:3072", "-out", path(name + ".pem"))
        run("openssl", "pkey", "-in", path(name + ".pem"), "-pubout",
            "-out", path(name + ".pub.pem"))
    message = d / "message.txt"
    message.write_bytes(b"Approve lab change 42\n")
    oaep = ("-pkeyopt", "rsa_padding_mode:oaep",
            "-pkeyopt", "rsa_oaep_md:sha256",
            "-pkeyopt", "rsa_mgf1_md:sha256")
    run("openssl", "pkeyutl", "-encrypt", "-pubin", "-inkey",
        path("recipient.pub.pem"), "-in", str(message),
        "-out", path("cipher.bin"), *oaep)
    run("openssl", "pkeyutl", "-decrypt", "-inkey", path("recipient.pem"),
        "-in", path("cipher.bin"), "-out", path("plain.txt"), *oaep)
    assert (d / "plain.txt").read_bytes() == message.read_bytes()
    print("PASS: recipient decrypts exact original bytes")
    p = run("openssl", "pkeyutl", "-decrypt", "-inkey", path("wrong.pem"),
            "-in", path("cipher.bin"), "-out", path("wrong.txt"), *oaep, ok=False)
    assert p.returncode != 0
    print("PASS: wrong decryption key rejected")
    pss = ("-sigopt", "rsa_padding_mode:pss",
           "-sigopt", "rsa_pss_saltlen:digest",
           "-sigopt", "rsa_mgf1_md:sha256")
    run("openssl", "dgst", "-sha256", "-sign", path("signer.pem"),
        "-out", path("signature.bin"), *pss, str(message))
    def verify(key, file):
        return run("openssl", "dgst", "-sha256", "-verify", path(key),
                   "-signature", path("signature.bin"), *pss, path(file), ok=False)
    assert verify("signer.pub.pem", "message.txt").returncode == 0
    print("PASS: original message signature verified")
    (d / "changed.txt").write_bytes(b"Approve lab change 43\n")
    assert verify("signer.pub.pem", "changed.txt").returncode != 0
    print("PASS: changed message signature rejected")
    assert verify("wrong.pub.pem", "message.txt").returncode != 0
    print("PASS: wrong verification key rejected")
print("DONE: temporary lab keys and files removed")
