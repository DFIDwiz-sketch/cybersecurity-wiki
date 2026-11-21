"""Review the supplied Group Policy worksheet without accessing a domain."""
import json
from pathlib import Path


def split_version(value):
    """Decode a signed or unsigned 32-bit representation as two counters."""
    if not -(1 << 31) <= value < (1 << 32):
        raise ValueError("Group Policy version outside the 32-bit range")
    return (value >> 16) & 0xFFFF, value & 0xFFFF


def inspect(case):
    a, b = case["dc_a"], case["dc_b"]
    if a["sysvol"] is None or b["sysvol"] is None:
        return "SYSVOL_UNOBSERVED"
    versions = [(split_version(dc["directory"]), split_version(dc["sysvol"])) for dc in (a, b)]
    if any(directory != sysvol for directory, sysvol in versions):
        return "WITHIN_DC_VERSION_MISMATCH"
    if versions[0] != versions[1]:
        return "BETWEEN_DC_VERSION_MISMATCH"
    if a["content"] != b["content"]:
        return "CONTENT_DIFFERS_AT_EQUAL_VERSION"
    if case["link_change"]:
        return "LINK_CHANGED_WITH_EQUAL_VERSIONS"
    return {
        "applied": "CLIENT_APPLICATION_OBSERVED",
        "security-filtered": "CLIENT_NOT_APPLIED_BY_FILTER",
        "unverified": "CLIENT_OUTCOME_UNOBSERVED",
    }[case["client"]]


def audit_key(record):
    return tuple(record[key] for key in ("dc", "correlation", "object", "attribute"))


def main():
    path = Path(__file__).with_name("gpo-evidence-cases.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    results = {case["id"]: inspect(case) for case in data["cases"]}
    first, *later = data["events"]
    results["E01"] = [
        event["id"] for event in later
        if audit_key(event) == audit_key(first) and event["operation"] == "Value Added"
    ]
    results["VERSION_BITS"] = [split_version(196615), split_version(196616), split_version(-2147483647)]
    expected = {
        "G01": "CLIENT_APPLICATION_OBSERVED",
        "G02": "WITHIN_DC_VERSION_MISMATCH",
        "G03": "BETWEEN_DC_VERSION_MISMATCH",
        "G04": "SYSVOL_UNOBSERVED",
        "G05": "CONTENT_DIFFERS_AT_EQUAL_VERSION",
        "G06": "LINK_CHANGED_WITH_EQUAL_VERSIONS",
        "G07": "CLIENT_NOT_APPLIED_BY_FILTER",
        "G08": "CLIENT_OUTCOME_UNOBSERVED",
        "E01": ["E02"],
        "VERSION_BITS": [(3, 7), (3, 8), (32768, 1)],
    }
    if results != expected:
        raise AssertionError(f"Unexpected results: {results}")
    for item, result in results.items():
        print(f"{item}: {result}")
    print(f"{len(results)} synthetic checks passed.")


if __name__ == "__main__":
    main()
