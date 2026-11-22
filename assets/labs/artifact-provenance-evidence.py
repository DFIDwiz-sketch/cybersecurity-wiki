"""Check bytes and a fictional attestation decision. This is not a verifier."""
import argparse
import hashlib
import json
from pathlib import Path


def decision(digest, policy, record):
    if record["verification"] == "rejected":
        return "verification_rejected"
    if record["verification"] != "verified":
        return "verification_missing"
    if record["subject_sha256"] != digest:
        return "subject_mismatch"
    for field in ("repo_id", "signer", "source_ref", "predicate"):
        if record.get(field) is None:
            return f"{field}_unknown"
        if record[field] != policy[field]:
            return f"{field}_mismatch"
    if record.get("release_hold"):
        return "release_hold"
    return "provenance_policy_pass"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("cases", type=Path)
    args = parser.parse_args()
    with args.artifact.open("rb") as data:
        digest = hashlib.file_digest(data, "sha256").hexdigest()
    document = json.loads(args.cases.read_text(encoding="utf-8"))
    for record in document["cases"]:
        result = decision(digest, document["policy"], record)
        print(f'{record["id"]}: {result}')


if __name__ == "__main__":
    main()
