"""Correlate the bundled fictional WFP cases using only local XML."""

import argparse
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET


NS = {"w": "http://schemas.microsoft.com/win/2004/08/events/event"}
PROVIDER = "Microsoft-Windows-Security-Auditing"
DECISIONS = {5156: "PERMITTED", 5157: "BLOCKED"}
TUPLE_FIELDS = ("SourceAddress", "SourcePort", "DestAddress", "DestPort", "Protocol")
APP_WINDOW_SECONDS = 2


def instant(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def parse_event(event):
    system = event.find("w:System", NS)
    if system is None:
        raise ValueError("Missing namespaced System element")
    provider = system.find("w:Provider", NS)
    if (provider is None or provider.get("Name") != PROVIDER
            or system.findtext("w:Channel", namespaces=NS) != "Security"):
        raise ValueError("Unexpected source channel or provider")

    event_id = int(system.findtext("w:EventID", namespaces=NS))
    if event_id not in DECISIONS:
        raise ValueError("Unexpected event ID")
    event_data = event.findall("w:EventData/w:Data", NS)
    data = {field.attrib["Name"]: field.text for field in event_data}
    if len(data) != len(event_data):
        raise ValueError("Repeated EventData field")
    return (
        event_id,
        system.findtext("w:Computer", namespaces=NS),
        instant(system.find("w:TimeCreated", NS).attrib["SystemTime"]),
        data,
    )


def review(case):
    event_id, host, event_time, data = parse_event(case.find("w:Event", NS))
    pid = int(data["ProcessID"])
    image = data["Application"].casefold()
    process_matches = [
        process.attrib["instance"]
        for process in case.findall("Process")
        if process.attrib["host"].casefold() == host.casefold()
        and int(process.attrib["pid"]) == pid
        and process.attrib["image"].casefold() == image
        and instant(process.attrib["start"]) <= event_time < instant(process.attrib["end"])
    ]
    process = process_matches[0] if len(process_matches) == 1 else "UNRESOLVED"
    service_matches = [
        service for service in case.findall("Service")
        if service.attrib["clientHost"].casefold() == host.casefold()
        and all(service.attrib[field] == data[field] for field in TUPLE_FIELDS)
        and 0 <= (instant(service.attrib["time"]) - event_time).total_seconds() <= APP_WINDOW_SECONDS
    ]
    # A near-time service record cannot be attributed to a blocked attempt
    # merely from a tuple. The fixture has no cross-source attempt identifier.
    service_result = "CORROBORATED" if event_id == 5156 and len(service_matches) == 1 else "UNCONFIRMED"
    return DECISIONS[event_id], process, service_result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    args = parser.parse_args()
    root = ET.parse(args.fixture).getroot()
    if root.tag != "Lab" or not root.findall("Case"):
        parser.error("Expected the bundled Lab and Case structure")

    failed = False
    for case in root.findall("Case"):
        result = review(case)
        expected = tuple(case.attrib[key] for key in ("decision", "process", "service"))
        matches = result == expected
        failed |= not matches
        status = "PASS" if matches else "FAIL"
        print(f"{status} {case.attrib['id']}: {' / '.join(result)}")
        if not matches:
            print(f"  Expected: {' / '.join(expected)}")
    return int(failed)


if __name__ == "__main__":
    raise SystemExit(main())
