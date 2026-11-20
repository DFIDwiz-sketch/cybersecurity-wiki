"""Review the supplied synthetic worksheet, with no systemd or network calls."""
import csv
from pathlib import Path


def review(row):
    """Return separate findings for inventory, execution, outcome and cause."""
    if row["loaded_matches_disk"] == "false":
        inventory = "DISK_RUNTIME_DIFFER"
    elif row["manager_state"] == "inactive":
        inventory = "INSTALLED_BUT_INACTIVE"
    else:
        inventory = "TIMER_ACTIVE"

    execution = "INVOCATION_OBSERVED" if row["invocation"] else "INVOCATION_UNOBSERVED"
    if row["service_result"] == "exit-code":
        outcome = "SERVICE_FAILED"
    elif row["app_receipt"] == "verified":
        outcome = "APP_OUTCOME_VERIFIED"
    else:
        outcome = "APP_OUTCOME_UNVERIFIED"

    cause = ("MANUAL_REQUEST_OBSERVED"
             if row["trigger_evidence"] == "independent-manual-request"
             else "TRIGGER_UNPROVEN")
    coverage = row["journal_coverage"].upper()
    return inventory, execution, outcome, cause, coverage


EXPECTED = {
    "T01": ("TIMER_ACTIVE", "INVOCATION_OBSERVED", "APP_OUTCOME_VERIFIED",
            "TRIGGER_UNPROVEN", "COVERED"),
    "T02": ("INSTALLED_BUT_INACTIVE", "INVOCATION_UNOBSERVED", "APP_OUTCOME_UNVERIFIED",
            "TRIGGER_UNPROVEN", "COVERED"),
    "T03": ("TIMER_ACTIVE", "INVOCATION_OBSERVED", "SERVICE_FAILED",
            "TRIGGER_UNPROVEN", "COVERED"),
    "T04": ("TIMER_ACTIVE", "INVOCATION_UNOBSERVED", "APP_OUTCOME_UNVERIFIED",
            "TRIGGER_UNPROVEN", "UNVERIFIED"),
    "T05": ("DISK_RUNTIME_DIFFER", "INVOCATION_UNOBSERVED", "APP_OUTCOME_UNVERIFIED",
            "TRIGGER_UNPROVEN", "COVERED"),
    "T06": ("TIMER_ACTIVE", "INVOCATION_OBSERVED", "APP_OUTCOME_VERIFIED",
            "MANUAL_REQUEST_OBSERVED", "COVERED"),
}


def main():
    path = Path(__file__).with_name("systemd-timer-cases.csv")
    with path.open(encoding="utf-8", newline="") as source:
        rows = list(csv.DictReader(source))
    results = {row["case"]: review(row) for row in rows}
    if len(rows) != len(EXPECTED) or results != EXPECTED:
        raise AssertionError(f"Unexpected findings: {results}")
    for case, findings in results.items():
        print(f"{case}: {' | '.join(findings)}")
    print(f"{len(results)} synthetic cases checked.")


if __name__ == "__main__":
    main()
