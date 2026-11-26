"""Compare fictional Sysmon canaries across local, forwarded and indexed evidence."""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from xml.etree import ElementTree


EVENT_NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
PROVIDER = "Microsoft-Windows-Sysmon"


def timestamp(text):
    value = datetime.fromisoformat(text.replace("Z", "+00:00"))
    if value.utcoffset() is None:
        raise ValueError("timestamps require a UTC offset")
    return value


def from_xml(text):
    root = ElementTree.fromstring(text)
    system = root.find("e:System", EVENT_NS)
    provider = system.find("e:Provider", EVENT_NS)
    created = system.find("e:TimeCreated", EVENT_NS)
    fields = {
        node.get("Name"): node.text or ""
        for node in root.findall("e:EventData/e:Data", EVENT_NS)
    }
    return {
        "provider": provider.get("Name", ""),
        "computer": system.findtext("e:Computer", default="", namespaces=EVENT_NS),
        "event_id": int(system.findtext("e:EventID", namespaces=EVENT_NS)),
        "time": created.get("SystemTime"),
        "process_guid": fields.get("ProcessGuid", ""),
        "image": fields.get("Image", ""),
        "command_line": fields.get("CommandLine", ""),
    }


def decision(case):
    start, end = timestamp(case["start"]), timestamp(case["end"])
    marker = case["marker"]
    if not marker or start >= end:
        raise ValueError("each case requires a marker and an increasing UTC window")
    computer, image = case["computer"].casefold(), case["image"].casefold()

    def in_scope(event):
        return (
            event["event_id"] == 1
            and event["provider"] == PROVIDER
            and event["computer"].casefold() == computer
            and start <= timestamp(event["time"]) < end
        )

    def has_required_fields(event):
        return event.get("image", "").casefold() == image and marker in event.get("command_line", "")

    local = [from_xml(text) for text in case["local_xml"]]
    ids = {
        row["process_guid"].casefold()
        for row in local
        if in_scope(row) and row["process_guid"] and has_required_fields(row)
    }
    if not ids:
        return "no-local-canary"
    if len(ids) != 1:
        return "ambiguous-local-canary"
    process_guid = ids.pop()

    def same_process(event):
        return in_scope(event) and event.get("process_guid", "").casefold() == process_guid

    forwarded = [from_xml(text) for text in case["forwarded_xml"]]
    if not any(same_process(row) and has_required_fields(row) for row in forwarded):
        return "no-collector-match"
    indexed = [row for row in case["indexed"] if same_process(row)]
    if not indexed:
        return "no-index-match"
    if not any(has_required_fields(row) for row in indexed):
        return "missing-index-fields"
    return "verified"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    path = parser.parse_args().fixture
    try:
        cases = json.loads(path.read_text(encoding="utf-8"))["cases"]
        if not cases:
            raise ValueError("empty case list")
        results = [(case["id"], decision(case), case["expected"]) for case in cases]
    except (OSError, ValueError, TypeError, KeyError, AttributeError, ElementTree.ParseError) as error:
        parser.error(str(error))

    passed = 0
    for case_id, actual, expected in results:
        match = actual == expected
        passed += match
        print(f"{'PASS' if match else 'FAIL'} {case_id}: {actual} (expected {expected})")
    print(f"{passed}/{len(results)} cases match")
    return 0 if passed == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
