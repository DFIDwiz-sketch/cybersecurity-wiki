#!/usr/bin/env python3
"""Decode EDNS option bytes in a fictional, offline DNS evidence fixture."""

import argparse
import json
from pathlib import Path
from struct import unpack_from

EDE = 15


def decode_options(data):
    errors = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 4:
            raise ValueError("incomplete option header")
        kind, size = unpack_from("!HH", data, offset)
        offset += 4
        end = offset + size
        if end > len(data):
            raise ValueError("option extends beyond OPT data")
        if kind == EDE:
            if size < 2:
                raise ValueError("EDE missing its two-byte INFO-CODE")
            code, = unpack_from("!H", data, offset)
            text = data[offset + 2:end].decode("utf-8")
            errors.append({"code": code, "text": text})
        offset = end
    return errors


def observe(example):
    rcode = example["rcode"]
    options = example["opt_hex"]
    if rcode is None:
        return {"state": "no-response"}
    result = {"rcode": rcode, "tc": example["tc"], "answers": example["answers"]}
    if options is None:
        return {**result, "state": "no-opt"}
    try:
        ede = decode_options(bytes.fromhex(options))
    except ValueError as error:
        return {**result, "state": "malformed-opt", "error": str(error)}
    return {**result, "state": "ede" if ede else "opt-without-ede", "ede": ede}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path, nargs="?",
                        default=Path(__file__).with_suffix(".json"))
    args = parser.parse_args()
    try:
        cases = json.loads(args.fixture.read_text(encoding="utf-8"))["cases"]
        if not cases:
            raise ValueError("fixture contains no observations")
        rows = [(case["id"], observe(case), case["expected"]) for case in cases]
    except (OSError, ValueError, KeyError, TypeError) as error:
        parser.exit(2, f"{args.fixture}: {error}\n")

    matches = 0
    for case_id, observed, expected in rows:
        passed = observed == expected
        matches += passed
        status = "OK" if passed else "FAIL"
        print(f"{case_id} {status} {json.dumps(observed, ensure_ascii=True)}")
    print(f"{matches}/{len(rows)} observations matched.")
    return 0 if matches == len(rows) else 1


if __name__ == "__main__":
    raise SystemExit(main())
