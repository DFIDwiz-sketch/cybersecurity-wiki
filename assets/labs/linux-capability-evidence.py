#!/usr/bin/env python3
"""Inspect this process and exercise a reduced Linux capability model."""

import ctypes
import os
from pathlib import Path
import subprocess
import sys


STATUS = Path("/proc/self/status")
FIELDS = ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb", "NoNewPrivs")
PR_SET_NO_NEW_PRIVS = 38
BIND_SERVICE = 1 << 10


def status_fields():
    observed = dict(
        line.split(":", 1) for line in STATUS.read_text().splitlines()
        if ":" in line
    )
    missing = sorted(set(FIELDS) - observed.keys())
    if missing:
        raise RuntimeError("missing procfs fields: " + ", ".join(missing))
    return {field: observed[field].strip() for field in FIELDS}


def modeled_exec(*, inheritable=0, bounding=0, ambient=0,
                 file_inheritable=0, file_permitted=0, file_effective=False,
                 privileged_file=False):
    """Compute permitted/effective for the documented ordinary-case model."""
    surviving_ambient = 0 if privileged_file else ambient
    permitted = (
        (inheritable & file_inheritable)
        | (file_permitted & bounding)
        | surviving_ambient
    )
    effective = permitted if file_effective else surviving_ambient
    return permitted, effective


def run_model_controls():
    bit = BIND_SERVICE
    cases = [
        ("file bit admitted", dict(bounding=bit, file_permitted=bit,
                                    file_effective=True), (bit, bit)),
        ("file bit outside bounding", dict(file_permitted=bit,
                                             file_effective=True), (0, 0)),
        ("inheritable branch independent of bounding",
         dict(inheritable=bit, file_inheritable=bit), (bit, 0)),
        ("ambient through ordinary exec",
         dict(inheritable=bit, bounding=bit, ambient=bit), (bit, bit)),
        ("ambient removed on privileged file",
         dict(inheritable=bit, bounding=bit, ambient=bit,
              privileged_file=True), (0, 0)),
    ]
    for label, inputs, expected in cases:
        observed = modeled_exec(**inputs)
        if observed != expected:
            raise RuntimeError(
                f"{label}: got {observed}, expected {expected}"
            )
        print(f"MODEL {label}: permitted={observed[0]:x}, effective={observed[1]:x}")
    print(f"{len(cases)} model controls passed.")


def child_after_setting_flag():
    prctl = ctypes.CDLL(None, use_errno=True).prctl
    prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    prctl.restype = ctypes.c_int
    if prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    print(f"before exec: NoNewPrivs={status_fields()['NoNewPrivs']}", flush=True)
    os.execv(sys.executable, [sys.executable, __file__, "--after-exec"])


def main():
    if sys.argv[1:] == ["--child"]:
        child_after_setting_flag()
    if sys.argv[1:] == ["--after-exec"]:
        print(f"after exec: NoNewPrivs={status_fields()['NoNewPrivs']}")
        return
    if len(sys.argv) != 1:
        raise RuntimeError("run without arguments")

    print("LIVE parent thread snapshot")
    for field, value in status_fields().items():
        print(f"{field}: {value}")
    run_model_controls()

    child = subprocess.run(
        [sys.executable, __file__, "--child"], capture_output=True, text=True
    )
    if child.returncode:
        raise RuntimeError(child.stderr.strip() or f"child exit {child.returncode}")
    expected = ["before exec: NoNewPrivs=1", "after exec: NoNewPrivs=1"]
    if child.stdout.splitlines() != expected:
        raise RuntimeError(f"unexpected flag inheritance: {child.stdout!r}")
    print(child.stdout, end="")
    print("Live child inheritance check passed.")


if __name__ == "__main__":
    try:
        main()
    except (AttributeError, OSError, RuntimeError) as error:
        sys.exit(f"Lab failed: {error}")
