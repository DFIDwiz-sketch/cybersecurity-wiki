#!/usr/bin/env python3
"""Read the fictional Windows XML fixture and exercise eight correlation controls."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
import re
import sys
import xml.etree.ElementTree as ET

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
SECURITY = ("Microsoft-Windows-Security-Auditing", "Security")
SYSMON = ("Microsoft-Windows-Sysmon", "Microsoft-Windows-Sysmon/Operational")
WINDOW_SECONDS = 2


@dataclass
class Record:
    source: tuple
    number: int
    record_id: int
    host: str
    when: datetime
    emission_pid: int
    data: dict


def records(path):
    for event in ET.parse(path).getroot().findall("e:Event", NS):
        system = event.find("e:System", NS)
        time = system.find("e:TimeCreated", NS).attrib["SystemTime"]
        yield Record(
            source=(system.find("e:Provider", NS).attrib["Name"],
                    system.findtext("e:Channel", namespaces=NS)),
            number=int(system.findtext("e:EventID", namespaces=NS)),
            record_id=int(system.findtext("e:EventRecordID", namespaces=NS)),
            host=system.findtext("e:Computer", namespaces=NS).casefold(),
            when=datetime.fromisoformat(time.replace("Z", "+00:00")),
            emission_pid=int(system.find("e:Execution", NS).attrib["ProcessID"]),
            data={x.attrib["Name"]: x.text or ""
                  for x in event.findall("e:EventData/e:Data", NS)},
        )


def pid(record):
    value = record.data["ProcessId"]
    return int(value, 16 if value.lower().startswith("0x") else 10)


def user_path(path):
    prefixes = ("\\registry\\user\\", "hku\\", "hkey_users\\")
    path = path.casefold()
    for prefix in prefixes:
        if path.startswith(prefix):
            tail = path[len(prefix):]
            if re.match(r"s-1-(?:[0-9]+-)+[0-9]+\\", tail):
                return tail
    return None


def writer_lifetimes(rows, target, image):
    for start in rows:
        if not (
            start.source == SYSMON and start.number == 1
            and start.host == target.host and pid(start) == pid(target)
            and start.when <= target.when
            and start.data["Image"].casefold() == image.casefold()
        ):
            continue
        guid = start.data["ProcessGuid"]
        ended = any(
            event.source == SYSMON and event.number == 5
            and event.host == start.host and event.data["ProcessGuid"] == guid
            and start.when <= event.when <= target.when
            for event in rows
        )
        if not ended:
            yield guid


def matching_writes(rows, audit):
    target = user_path(audit.data["ObjectName"] + "\\" + audit.data["ObjectValueName"])
    image = audit.data["ProcessName"]
    writers = list(writer_lifetimes(rows, audit, image))
    if audit.data["OperationType"] != "Existing registry value modified":
        return []
    if not target or len(writers) != 1:
        return []
    return [
        event.record_id for event in rows
        if event.source == SYSMON and event.number == 13
        and event.data["EventType"] == "SetValue"
        and event.host == audit.host and pid(event) == pid(audit)
        and abs((event.when - audit.when).total_seconds()) <= WINDOW_SECONDS
        and user_path(event.data["TargetObject"]) == target
        and event.data["ProcessGuid"] == writers[0]
        and event.data["Image"].casefold() == image.casefold()
    ]


def main():
    path = Path(__file__).with_name("windows-registry-change-events.xml")
    rows = list(records(path))
    entries = {r.record_id: r for r in rows}
    if len(entries) != len(rows):
        raise ValueError("the fixture requires unique record IDs across sources")
    audit, = [r for r in rows if r.source == SECURITY and r.number == 4657]
    paired, other, decoy, reused, create, rename = (entries[n] for n in (112, 111, 113, 116, 117, 118))
    operations = [
        ("unique cross-provider pair", matching_writes(rows, audit) == [112]),
        ("provider/channel gate", decoy.number == 13 and decoy.source != SYSMON),
        ("native/user hive path", user_path(audit.data["ObjectName"] + "\\" + audit.data["ObjectValueName"])
         == user_path(paired.data["TargetObject"])),
        ("caller PID differs from emission PID", pid(audit) == pid(paired) == 5000 != audit.emission_pid),
        ("different target SID", user_path(other.data["TargetObject"]) != user_path(paired.data["TargetObject"])),
        ("reused PID, different lifetime", pid(reused) == pid(paired)
         and list(writer_lifetimes(rows, reused, reused.data["Image"])) == [reused.data["ProcessGuid"]]
         and reused.data["ProcessGuid"] != paired.data["ProcessGuid"]),
        ("key creation", create.source == SYSMON and create.number == 12
         and create.data["EventType"] == "CreateKey"),
        ("value rename", rename.source == SYSMON and rename.number == 14
         and rename.data["EventType"] == "RenameValue"
         and rename.data["NewName"].casefold() != rename.data["TargetObject"].casefold()),
    ]
    for label, passed in operations:
        print(f"{label}: {'pass' if passed else 'FAIL'}")
    passed = sum(1 for _, ok in operations if ok)
    print(f"{passed}/{len(operations)} controls passed.")
    return 0 if passed == len(operations) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (AttributeError, KeyError, OSError, ValueError, ET.ParseError) as error:
        sys.exit(f"Unable to read fixture: {error}")
