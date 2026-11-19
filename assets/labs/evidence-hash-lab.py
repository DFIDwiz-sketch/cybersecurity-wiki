"""Verify disposable copies of the bundled fictional log offline."""
import hashlib
import json
from pathlib import Path
import shutil
from tempfile import TemporaryDirectory
from zipfile import ZipFile

def sha256(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()

source = Path(__file__).with_name("evidence-sample.jsonl")
original = sha256(source)
with TemporaryDirectory(prefix="wiki-evidence-") as folder:
    scratch = Path(folder)
    unchanged = scratch / "working.jsonl"
    shutil.copyfile(source, unchanged)
    assert sha256(unchanged) == original
    print("PASS: working copy matches source")

    renamed = unchanged.rename(scratch / "renamed.jsonl")
    assert sha256(renamed) == original
    print("PASS: renaming did not change bytes")

    converted = scratch / "changed-line-endings.jsonl"
    data = renamed.read_bytes()
    assert b"\n" in data and b"\r" not in data, "Download the original LF fixture"
    converted.write_bytes(data.replace(b"\n", b"\r\n"))
    assert sha256(converted) != original
    print("PASS: line-ending conversion changed the hash")

    archive_path = scratch / "handover.zip"
    with ZipFile(archive_path, "w") as archive:
        archive.write(renamed, arcname=source.name)
    with ZipFile(archive_path) as archive:
        extracted = archive.read(source.name)
    payload_hash = hashlib.sha256(extracted).hexdigest()
    manifest = {
        "algorithm": "SHA-256",
        "payload": {"name": source.name, "digest": original},
        "archive": {"name": archive_path.name, "digest": sha256(archive_path)},
    }
    assert payload_hash == manifest["payload"]["digest"]
    assert manifest["archive"]["digest"] != original
    print("PASS: ZIP has its own hash and extracted payload matches")
    print(json.dumps(manifest, indent=2))

assert sha256(source) == original
print("DONE: four checks passed; original fixture unchanged")
