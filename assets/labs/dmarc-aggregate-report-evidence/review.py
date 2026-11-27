"""Read the fictional plain-XML reports shipped with this lesson."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
from ipaddress import ip_address
from pathlib import Path
from xml.etree import ElementTree

NAMESPACE = "{urn:ietf:params:xml:ns:dmarc-2.0}"
MAX_BYTES = 1024 * 1024


def required_text(node, path):
    value = node.findtext(path, default="").strip()
    if not value:
        raise ValueError(f"Missing {path}")
    return value


def utc(value):
    return datetime.fromtimestamp(value, tz=timezone.utc).isoformat()


def read_report(path):
    with path.open("rb") as source:
        data = source.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise ValueError("XML exceeds the fixture size limit")
    # Read only plain UTF-8 fixtures. Reject document types before parsing.
    xml = data.decode("utf-8-sig")
    if "\x00" in xml or "<!DOCTYPE" in xml:
        raise ValueError("Only plain UTF-8 XML without a document type is accepted")

    root = ElementTree.fromstring(xml)
    if root.tag not in ("feedback", NAMESPACE + "feedback"):
        raise ValueError("Unsupported report root or namespace")
    ns = NAMESPACE if root.tag.startswith(NAMESPACE) else ""

    def field(node, path):
        return required_text(node, "/".join(ns + part for part in path.split("/")))

    reporter = field(root, "report_metadata/org_name")
    policy_domain = field(root, "policy_published/domain").lower()
    report_id = field(root, "report_metadata/report_id")
    begin = int(field(root, "report_metadata/date_range/begin"))
    end = int(field(root, "report_metadata/date_range/end"))
    if not 0 <= begin <= end:
        raise ValueError("Invalid reporting interval")
    interval_text = f"{utc(begin)} to {utc(end)}"

    records = root.findall(ns + "record")
    if not records:
        raise ValueError("No report records")
    rows = []
    for record in records:
        ip = str(ip_address(field(record, "row/source_ip")))
        count = int(field(record, "row/count"))
        if count < 1:
            raise ValueError("Expected a positive message count")
        aligned_dkim = field(record, "row/policy_evaluated/dkim")
        aligned_spf = field(record, "row/policy_evaluated/spf")
        if {aligned_dkim, aligned_spf} - {"pass", "fail"}:
            raise ValueError("Unknown DMARC alignment result")
        disposition = field(record, "row/policy_evaluated/disposition")
        if disposition not in {"none", "pass", "quarantine", "reject"}:
            raise ValueError("Unknown disposition")
        raw_pass = any(
            field(result, "result") == "pass"
            for method in ("dkim", "spf")
            for result in record.findall(ns + "auth_results/" + ns + method)
        )
        header_from = field(record, "identifiers/header_from")
        aligned = "pass" in (aligned_dkim, aligned_spf)
        rows.append((ip, header_from, count, raw_pass, aligned, disposition))

    return (reporter, policy_domain), report_id, (begin, end), interval_text, sha256(data).digest(), rows


def review(paths):
    by_id = {}
    intervals = {}
    issue = False
    for path in paths:
        try:
            scope, report_id, interval, interval_text, fingerprint, rows = read_report(path)
            # Fixture identities are trusted labels, never verified reporter identities.
            key = (scope, report_id)
            if key in by_id:
                if by_id[key] == fingerprint:
                    print(f"DUPLICATE {path.name}: exact report already counted")
                    continue
                raise ValueError("conflicting content under the same report ID")
            if any(interval[0] <= end and begin <= interval[1]
                   for begin, end in intervals.get(scope, ())):
                raise ValueError("overlapping window for the same reporter and policy domain")
            by_id[key] = fingerprint
            intervals.setdefault(scope, []).append(interval)

            total = passed = rejected = raw_only_rows = 0
            for ip, header_from, count, raw_pass, aligned, disposition in rows:
                total += count
                passed += count if aligned else 0
                rejected += count if disposition == "reject" else 0
                raw_only_rows += int(raw_pass and not aligned)
                print(f"  {ip} {header_from}: count={count} raw_pass={raw_pass} "
                      f"aligned_pass={aligned} disposition={disposition}")
            print(f"REPORT {path.name}: {scope[0]} / {scope[1]} / {interval_text}")
            print(f"  messages={total} aligned_pass={passed} without_aligned_pass={total - passed} "
                  f"reported_reject={rejected} raw_pass_without_alignment_rows={raw_only_rows} "
                  f"aligned_share={passed / total:.2%}")
        except (OSError, ValueError, OverflowError, ElementTree.ParseError) as error:
            print(f"HOLD {path.name}: {error}")
            issue = True
    return int(issue)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("reports", nargs="+", type=Path)
    return review(parser.parse_args().reports)


if __name__ == "__main__":
    raise SystemExit(main())
