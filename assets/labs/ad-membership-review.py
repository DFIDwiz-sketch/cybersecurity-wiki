"""Review fictional Windows event excerpts. Reads files and performs no Windows actions."""

import json
from pathlib import Path

REMOVE_IDS = {4728: 4729, 4732: 4733, 4756: 4757}


def membership_key(event):
    return event["group_authority"], event["group_sid"], event["member_sid"]


def has_actor_logon(change, logons):
    return any(
        event["computer"] == change["computer"]
        and event["target_sid"] == change["actor_sid"]
        and event["target_logon_id"] == change["subject_logon_id"]
        and event["minute"] <= change["minute"]
        for event in logons
    )


def resource_evidence(case, change, logons):
    if case["resource"] is None:
        return "resource_session_unobserved"
    session, = [
        e for e in logons
        if e["computer"] == case["resource"] and e["target_sid"] == change["member_sid"]
        and e["minute"] >= change["minute"]
    ]
    fragments = [
        e for e in case["events"]
        if e["event_id"] == 4627 and e["computer"] == session["computer"]
        and e["target_sid"] == session["target_sid"]
        and e["target_logon_id"] == session["target_logon_id"]
    ]
    totals = {e["event_count_total"] for e in fragments}
    if len(totals) != 1:
        return "group_list_incomplete"
    indices = {e["event_idx"] for e in fragments}
    if indices != set(range(1, totals.pop() + 1)):
        return "group_list_incomplete"
    if any(change["group_sid"] in e["group_sids"] for e in fragments):
        return "group_sid_observed_in_logon"
    return "group_sid_absent_in_observed_logon"


def review(case):
    events = case["events"]
    change, = [e for e in events if e["event_id"] in REMOVE_IDS]
    logons = [e for e in events if e["event_id"] == 4624]
    actor = "actor_logon_linked" if has_actor_logon(change, logons) else "actor_logon_unconfirmed"
    removal = "removal_unobserved"
    for event in events:
        if (event["event_id"] == REMOVE_IDS[change["event_id"]]
                and event["minute"] > change["minute"]
                and membership_key(event) == membership_key(change)):
            removal = f'removal_observed_after_{event["minute"] - change["minute"]}m'
            break
    return actor, removal, resource_evidence(case, change, logons)


def main():
    dataset = Path(__file__).with_name("ad-membership-cases.json")
    cases = json.loads(dataset.read_text(encoding="utf-8"))
    for case in cases:
        print(f'{case["case"]}: {", ".join(review(case))}')
    print(f"Reviewed: {len(cases)} synthetic cases")


if __name__ == "__main__":
    main()
