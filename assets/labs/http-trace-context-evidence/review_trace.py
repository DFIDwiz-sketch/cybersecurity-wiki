"""Compare fictional gateway, application, trace, and job evidence offline."""

import argparse
from collections import Counter
from datetime import datetime
import json
from pathlib import Path
import re

TRACEPARENT_V00 = re.compile(r"00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})")


def parse_v00(value):
    match = TRACEPARENT_V00.fullmatch(value) if isinstance(value, str) else None
    if match is None:
        return None
    trace_id, parent_id, flags = match.groups()
    if int(trace_id, 16) == 0 or int(parent_id, 16) == 0:
        return None
    return trace_id, parent_id, bool(int(flags, 16) & 1)


def inside_window(start, observed, seconds):
    start_time = datetime.fromisoformat(start.replace("Z", "+00:00"))
    observed_time = datetime.fromisoformat(observed.replace("Z", "+00:00"))
    if start_time.utcoffset() is None or observed_time.utcoffset() is None:
        raise ValueError("Explicit time zones are required")
    # A small offset in either direction may reflect clock skew in this fixture.
    return abs((observed_time - start_time).total_seconds()) <= seconds


def app_result(edge, trace_id, attempt, app_records):
    outbound = parse_v00(attempt["outbound_traceparent"])
    if outbound is None or outbound[0] != trace_id:
        raise ValueError("Invalid or mismatched outbound trace context")
    _, outbound_span_id, _ = outbound
    hits = [
        app for app in app_records
        if app["environment"] == edge["environment"] and app["route"] == edge["route"]
        and app["peer"] == attempt["peer"] and app["trace_id"] == trace_id
        and app["parent_span_id"] == outbound_span_id
        and inside_window(attempt["timestamp"], app["timestamp"], 5)
    ]
    if len(hits) > 1:
        return "ambiguous"
    return hits[0]["status"] if hits else None


def job_result(edge, jobs):
    enqueue = edge.get("enqueued_job")
    if enqueue is None:
        return None
    hits = [
        job for job in jobs
        if job["environment"] == edge["environment"] and job["queue"] == enqueue["queue"]
        and job["job_id"] == enqueue["job_id"]
        and inside_window(enqueue["timestamp"], job["timestamp"], 60)
    ]
    if len(hits) > 1:
        return "ambiguous"
    return hits[0]["outcome"] if hits else None


def assess(data):
    edges = data["gateway_records"]
    request_keys = [(edge["environment"], edge["gateway"], edge["request_id"]) for edge in edges]
    if len(set(request_keys)) != len(request_keys):
        raise ValueError("Duplicate gateway request key")
    incoming = [parse_v00(edge.get("incoming_traceparent")) for edge in edges]
    external_counts = Counter(context[0] for context in incoming if context is not None)
    stored = {(record["environment"], record["trace_id"]) for record in data["trace_inventory"]}
    output = {}
    for edge, context, key in zip(edges, incoming, request_keys):
        internal = parse_v00(edge["internal_traceparent"])
        if internal is None:
            raise ValueError("Invalid internal trace context")
        trace_id, _, sampled = internal
        output["/".join(key)] = {
            "edge_status": edge["status"],
            "app_statuses": [app_result(edge, trace_id, attempt, data["application_records"])
                             for attempt in edge["attempts"]],
            "other_requests_with_incoming_trace": external_counts[context[0]] - 1 if context else 0,
            "edge_sampled": sampled,
            "trace_in_inventory": (edge["environment"], trace_id) in stored,
            "job_outcome": job_result(edge, data["worker_records"]),
        }
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=Path)
    opts = parser.parse_args()
    try:
        data = json.loads(opts.fixture.read_text(encoding="utf-8"))
        actual = assess(data)
        expected = data["expected"]
        if actual.keys() != expected.keys():
            raise ValueError("Fixture and results name different requests")
        passed = 0
        for request_id, result in actual.items():
            matches = result == expected[request_id]
            passed += int(matches)
            print(f"{'PASS' if matches else 'FAIL'} {request_id}: {json.dumps(result)}")
            if not matches:
                print(f"  Expected: {json.dumps(expected[request_id])}")
        return int(passed != len(expected))
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(f"Invalid fixture: {error}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
