"""Verify two fictional records offline using one fixed scrypt policy."""

from dataclasses import dataclass, replace
import hashlib
import hmac
import secrets


@dataclass(frozen=True)
class LabRecord:
    salt: bytes
    derived: bytes


def derive(password, salt):
    return hashlib.scrypt(
        password,
        salt=salt,
        n=2**17,
        r=8,
        p=1,
        maxmem=256 * 1024 * 1024,
        dklen=32,
    )


def new_record(password):
    salt = secrets.token_bytes(16)
    return LabRecord(salt, derive(password, salt))


def matches(password, record):
    candidate = derive(password, record.salt)
    return hmac.compare_digest(candidate, record.derived)


def check(condition, label):
    if not condition:
        raise SystemExit(f"FAIL: {label}")
    print(f"PASS: {label}")


def main():
    if not hasattr(hashlib, "scrypt"):
        raise SystemExit("This Python build does not provide OpenSSL-backed scrypt.")
    password = b"Fictional phrase for a local wiki exercise"
    first = new_record(password)
    second = new_record(password)

    check(
        first.salt != second.salt and first.derived != second.derived,
        "separate salts and verifier values",
    )
    check(
        matches(password, first) and matches(password, second),
        "both records accept the matching password",
    )
    check(
        not matches(b"Incorrect fictional phrase", first),
        "an incorrect password is rejected",
    )
    changed = replace(first, salt=second.salt)
    check(not matches(password, changed), "changing the stored salt breaks verification")


if __name__ == "__main__":
    main()
