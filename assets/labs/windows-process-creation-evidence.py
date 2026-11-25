"""Inspect abbreviated, fictional Windows process events in the bundled lab XML."""

import json
import sys
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree as ET


NS = {"w": "http://schemas.microsoft.com/win/2004/08/events/event"}


def integer(value):
    return int(value, 16 if value.lower().startswith("0x") else 10)


def read_record(wrapped):
    node = wrapped.find("w:Event", NS)
    system = node.find("w:System", NS)
    if (system.find("w:Provider", NS).get("Name") != "Microsoft-Windows-Security-Auditing"
            or system.findtext("w:Channel", namespaces=NS) != "Security"):
        raise ValueError("expected Microsoft Windows Security Auditing")
    event_id = int(system.findtext("w:EventID", namespaces=NS))
    if event_id not in (4688, 4689):
        raise ValueError(f"unexpected event ID {event_id}")
    when = system.find("w:TimeCreated", NS).get("SystemTime")
    if not when.endswith("Z"):
        raise ValueError("expected UTC SystemTime")
    data = {entry.attrib["Name"]: entry.text or ""
            for entry in node.findall("w:EventData/w:Data", NS)}
    return {
        "scope": (system.findtext("w:Computer", namespaces=NS).casefold(), wrapped.attrib["boot"]),
        "time": datetime.fromisoformat(when[:-1] + "+00:00"),
        "event": event_id,
        "record": int(system.findtext("w:EventRecordID", namespaces=NS)),
        "data": data,
    }


def find_creator(child, timeline):
    pid = integer(child["data"]["ProcessId"])
    previous = [e for e in timeline if e["scope"] == child["scope"] and e["time"] < child["time"]]
    starts = [e for e in previous if e["event"] == 4688 and integer(e["data"]["NewProcessId"]) == pid]
    if not starts:
        return "no_candidate", None
    start_time = max(e["time"] for e in starts)
    newest = [e for e in starts if e["time"] == start_time]
    if len(newest) != 1:
        return "ambiguous_start", None
    candidate = newest[0]
    if any(e["event"] == 4689 and start_time < e["time"] and integer(e["data"]["ProcessId"]) == pid
           for e in previous):
        return "closed_before_child", None

    image = child["data"].get("ParentProcessName", "")
    if image and image.casefold() != candidate["data"]["NewProcessName"].casefold():
        return "creator_image_mismatch", None
    return "candidate", candidate["record"]


def target_context(data):
    sid, session = data.get("TargetUserSid"), data.get("TargetLogonId")
    if not sid or sid == "S-1-0-0" or not session or integer(session) == 0:
        return "not_recorded"
    if sid != data["SubjectUserSid"] or integer(session) != integer(data["SubjectLogonId"]):
        return "distinct"
    return "same"


def assess(case):
    timeline = [read_record(entry) for entry in case.findall("Record")]
    needle = int(case.attrib["inspect"])
    match = [e for e in timeline if e["record"] == needle and e["event"] == 4688]
    if len(match) != 1:
        raise ValueError(f"expected one inspected start with record ID {needle}")
    child = match[0]
    data = child["data"]
    state, creator_record = find_creator(child, timeline)
    command = data.get("CommandLine")
    return {
        "pid": integer(data["NewProcessId"]),
        "creator": state,
        "creator_record": creator_record,
        "target_context": target_context(data),
        "command": "absent" if command is None else "recorded" if command else "empty",
    }


def main():
    if len(sys.argv) != 2:
        print("Usage: python3 windows-process-creation-evidence.py CASES.xml", file=sys.stderr)
        return 2
    try:
        root = ET.fromstring(Path(sys.argv[1]).read_bytes())
        cases = root.findall("Case")
        if root.tag != "ProcessCreationLab" or not cases:
            raise ValueError("expected the bundled ProcessCreationLab XML")
        results = [(c.attrib["name"], assess(c), json.loads(c.findtext("Expected"))) for c in cases]
    except (OSError, ET.ParseError, AttributeError, KeyError, TypeError, ValueError) as error:
        print(f"Unable to read cases: {error}", file=sys.stderr)
        return 2

    failures = 0
    for name, actual, expected in results:
        same = actual == expected
        failures += int(not same)
        print(f"{'PASS' if same else 'FAIL'} {name} {json.dumps(actual)}")
        if not same:
            print(f"  expected {json.dumps(expected)}")
    return int(failures > 0)


if __name__ == "__main__":
    sys.exit(main())
