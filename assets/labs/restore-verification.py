"""Offline restore exercise. Generates only fictional SQLite data."""

from contextlib import closing
from hashlib import sha256
from pathlib import Path
from shutil import copyfile
import sqlite3
from tempfile import TemporaryDirectory
from time import perf_counter

# Minutes since 08:00 UTC in the fictional incident.
OUTAGE = 120
MAX_LOSS = 15
EXPECTED = {1: 1250, 2: 2400, 3: 750}
CASES = {
    "A-good": "ready_for_lab_use",
    "B-stale": "outside_rpo",
    "C-wrong-total": "business_check_failed",
    "D-broken-reference": "foreign_key_failed",
    "E-changed-bytes": "digest_mismatch",
}


def create_backup(root, name, *, through=112, wrong_total=False, bad_ref=False):
    source = root / f"{name}-source.db"
    snapshot = root / f"{name}-backup.db"
    with closing(sqlite3.connect(source)) as db:
        # Seed an invalid relationship only in the disposable negative control.
        db.execute("PRAGMA foreign_keys = OFF" if bad_ref else "PRAGMA foreign_keys = ON")
        with db:
            db.executescript("""
                CREATE TABLE customers (id INTEGER PRIMARY KEY);
                CREATE TABLE orders (
                    id INTEGER PRIMARY KEY,
                    customer_id INTEGER NOT NULL REFERENCES customers(id),
                    cents INTEGER NOT NULL
                );
                CREATE TABLE checkpoint (complete_through INTEGER NOT NULL);
            """)
            db.execute("INSERT INTO customers VALUES (1)")
            db.execute("INSERT INTO checkpoint VALUES (?)", (through,))
            db.executemany(
                "INSERT INTO orders VALUES (?, ?, ?)",
                [
                    (number, 99 if number == 2 and bad_ref else 1,
                     cents + 50 if number == 2 and wrong_total else cents)
                    for number, cents in EXPECTED.items()
                ],
            )
        with closing(sqlite3.connect(snapshot)) as target:
            db.backup(target)
    return snapshot


def digest(path):
    return sha256(path.read_bytes()).hexdigest()


def inspect_restore(snapshot, restored, expected_digest):
    copyfile(snapshot, restored)
    if digest(restored) != expected_digest:
        return "digest_mismatch", "database not opened"
    with closing(sqlite3.connect(restored.as_uri() + "?mode=ro", uri=True)) as db:
        if db.execute("PRAGMA integrity_check").fetchall() != [("ok",)]:
            return "sqlite_integrity_failed", "verify snapshot and copy"
        if db.execute("PRAGMA foreign_key_check").fetchone() is not None:
            return "foreign_key_failed", "integrity_check=ok; broken reference"
        checkpoint, = db.execute("SELECT complete_through FROM checkpoint").fetchone()
        loss = OUTAGE - checkpoint
        if not 0 <= loss <= MAX_LOSS:
            return "outside_rpo", f"possible data-loss window={loss} min"
        orders = dict(db.execute("SELECT id, cents FROM orders"))
        if orders != EXPECTED:
            return "business_check_failed", f"possible data-loss window={loss} min; order amounts differ"
    return "ready_for_lab_use", f"possible data-loss window={loss} min; order amounts match"


def main():
    begun = perf_counter()
    with TemporaryDirectory(prefix="restore-learning-") as directory:
        root = Path(directory)
        for name, expected_result in CASES.items():
            backup = create_backup(
                root, name, through=25 if name == "B-stale" else 112,
                wrong_total=name == "C-wrong-total",
                bad_ref=name == "D-broken-reference",
            )
            # Models a separately protected digest recorded at backup time.
            expected_digest = digest(backup)
            if name == "E-changed-bytes":
                with backup.open("ab") as artifact:
                    artifact.write(b"fictional change after recording digest\n")
            result, evidence = inspect_restore(backup, root / f"{name}-restored.db", expected_digest)
            print(f"{name}: {result} ({evidence})")
            if result != expected_result:
                raise SystemExit(f"Unexpected result for {name}: expected {expected_result}")
    print(f"PASS: {len(CASES)} cases. Local exercise only: {perf_counter() - begun:.3f} s.")


if __name__ == "__main__":
    main()
