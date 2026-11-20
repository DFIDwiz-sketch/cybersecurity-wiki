"""Explore App Control correlation on synthetic Windows event XML."""
from dataclasses import dataclass
from uuid import UUID
from xml.etree import ElementTree as ET


NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
CHANNEL = "Microsoft-Windows-CodeIntegrity/Operational"
PROVIDER = "Microsoft-Windows-CodeIntegrity"


@dataclass(frozen=True)
class Event:
    host: str
    record: int
    event_id: int
    activity: UUID | None
    signature_count: int | None


def read_event(xml):
    root = ET.fromstring(xml)
    system = root.find("e:System", NS)
    if (system.findtext("e:Channel", namespaces=NS) != CHANNEL
            or system.find("e:Provider", NS).get("Name") != PROVIDER):
        raise ValueError("Unexpected source in the training fixture")
    correlation = system.find("e:Correlation", NS)
    activity = correlation.get("ActivityID") if correlation is not None else None
    activity_id = UUID(activity) if activity else None
    count = root.findtext("e:EventData/e:Data[@Name='TotalSignatureCount']", namespaces=NS)
    return Event(
        system.findtext("e:Computer", namespaces=NS).casefold(),
        int(system.findtext("e:EventRecordID", namespaces=NS)),
        int(system.findtext("e:EventID", namespaces=NS)),
        activity_id if activity_id and activity_id.int else None,
        int(count) if count is not None else None,
    )


def signature_evidence(decision, records):
    if decision.activity is None:
        return "NO_ACTIVITY_ID"
    counts = {
        e.record: e.signature_count
        for e in records
        if e.event_id == 3089 and e.host == decision.host and e.activity == decision.activity
    }
    if not counts:
        return "NO_MATCHED_3089"
    values = set(counts.values())
    if len(values) != 1 or None in values:
        return "INCONSISTENT_SIGNATURE_METADATA"
    total = next(iter(values))
    if total == 0 and len(counts) == 1:
        return "REPORTED_UNSIGNED"
    if total > 0 and len(counts) < total:
        return "PARTIAL_SIGNATURE_RECORDS"
    if total > 0 and len(counts) == total:
        return "MATCHED_SIGNATURE_RECORDS"
    return "INCONSISTENT_SIGNATURE_METADATA"


def fixture(event_id, record, activity, *, host="pc-a.example", count=None):
    guid = f"{{12345678-1234-1234-1234-{activity:012d}}}" if activity is not None else ""
    correlation = f'<Correlation ActivityID="{guid}"/>' if guid else ""
    data = f'<Data Name="TotalSignatureCount">{count}</Data>' if count is not None else ""
    return f"""<Event xmlns="{NS['e']}">
  <System>
    <Provider Name="{PROVIDER}"/>
    <EventID>{event_id}</EventID>
    <EventRecordID>{record}</EventRecordID>
    {correlation}
    <Channel>{CHANNEL}</Channel>
    <Computer>{host}</Computer>
  </System>
  <EventData>{data}</EventData>
</Event>"""


documents = [
    fixture(3076, 1, 101),
    fixture(3089, 2, 101, count=0),
    fixture(3077, 3, 102),
    fixture(3089, 4, 102, count=2),
    fixture(3089, 5, 102, count=2, host="PC-A.EXAMPLE"),
    fixture(3077, 6, 103),
    fixture(3089, 7, 103, count=2),
    fixture(3089, 7, 103, count=2),  # Duplicate forwarded copy
    fixture(3076, 8, 104),
    fixture(3089, 2, 104, count=0, host="pc-b.example"),
    fixture(3077, 9, None),
    fixture(3089, 10, None, count=0),
    fixture(3077, 11, 105),
    fixture(3089, 12, 105, count=1),
    fixture(3089, 13, 105, count=2),
    fixture(3076, 14, 106),
    fixture(3099, 15, 106),
]
expected = [
    ("AUDIT", "REPORTED_UNSIGNED"),
    ("BLOCK", "MATCHED_SIGNATURE_RECORDS"),
    ("BLOCK", "PARTIAL_SIGNATURE_RECORDS"),
    ("AUDIT", "NO_MATCHED_3089"),
    ("BLOCK", "NO_ACTIVITY_ID"),
    ("BLOCK", "INCONSISTENT_SIGNATURE_METADATA"),
    ("AUDIT", "NO_MATCHED_3089"),
]

if __name__ == "__main__":
    events = [read_event(doc) for doc in documents]
    decisions = [e for e in events if e.event_id in {3076, 3077}]
    actual = [
        ("AUDIT" if d.event_id == 3076 else "BLOCK", signature_evidence(d, events))
        for d in decisions
    ]
    if actual != expected:
        raise AssertionError(f"Expected {expected}, observed {actual}")
    for decision, (mode, evidence) in zip(decisions, actual):
        print(f"Record {decision.record}: {mode} / {evidence}")
    print(f"{len(actual)} synthetic decisions checked.")
