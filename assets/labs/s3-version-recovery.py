"""Offline S3 version evidence exercise for a single key with versioning enabled."""

from dataclasses import dataclass


@dataclass(frozen=True)
class Version:
    version_id: str
    marker: bool = False


V1 = Version("v1")
V2 = Version("v2")
MARKER = Version("m1", marker=True)


def list_evidence(history):
    """Project the newest-first fixture into latest, Versions and DeleteMarkers."""
    latest = history[0].version_id if history else None
    versions = tuple(item.version_id for item in history if not item.marker)
    markers = tuple(item.version_id for item in history if item.marker)
    return latest, versions, markers


def head_status(history, version_id=None):
    """Assume authorized access, including list permission for missing keys."""
    if version_id is None:
        return 200 if history and not history[0].marker else 404
    for item in history:
        if item.version_id == version_id:
            return 405 if item.marker else 200
    return 404


def main():
    # Observations supplied by the exercise, newest version first.
    # expected = (latest, historical data IDs, marker IDs, current HEAD, HEAD m1)
    cases = (
        ("normal", (V2, V1), ("v2", ("v2", "v1"), (), 200, 404)),
        ("marker-added", (MARKER, V2, V1), ("m1", ("v2", "v1"), ("m1",), 404, 405)),
        ("older-version-removed", (MARKER, V2), ("m1", ("v2",), ("m1",), 404, 405)),
        ("protected-version-denied", (MARKER, V2), ("m1", ("v2",), ("m1",), 404, 405)),
        ("marker-removed", (V2,), ("v2", ("v2",), (), 200, 404)),
        ("marker-only", (MARKER,), ("m1", (), ("m1",), 404, 405)),
        ("empty", (), (None, (), (), 404, 404)),
    )
    for label, history, expected in cases:
        observed = (*list_evidence(history), head_status(history), head_status(history, "m1"))
        if observed != expected:
            raise SystemExit(f"{label}: expected {expected!r}; got {observed!r}")
        latest, versions, markers, current, exact = observed
        print(f"{label}: latest={latest} data={versions} markers={markers} "
              f"HEAD current={current} HEAD m1={exact}")


if __name__ == "__main__":
    main()
