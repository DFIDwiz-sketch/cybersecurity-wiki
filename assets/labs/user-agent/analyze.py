#!/usr/bin/env python3
"""Offline educational string matching, not malware attribution. Python 3 only."""
import json
import sys
from pathlib import Path


def matches(value, entry):
    if not isinstance(value, str) or not value:
        return False
    pattern = entry['pattern']
    mode = entry['match']
    if mode == 'exact':
        return value == pattern
    if mode == 'prefix':
        return value.startswith(pattern)
    if mode == 'contains':
        return pattern in value
    raise ValueError('Unsupported match mode: ' + mode)


def analyze(events, entries):
    candidates = []
    for event in events:
        hits = [entry for entry in entries if entry['group'] in
                {'malware', 'overlap', 'rule'} and matches(event.get('ua'), entry)]
        if hits:
            candidates.append({'event_id': event['event_id'],
                               'reference_ids': [entry['id'] for entry in hits],
                               'associations': [entry['name'] for entry in hits]})
    return candidates


def main():
    if len(sys.argv) != 3:
        raise SystemExit('Usage: python analyze.py events.jsonl user-agents.json')
    events = [json.loads(line) for line in Path(sys.argv[1]).read_text(encoding='utf-8').splitlines() if line.strip()]
    entries = json.loads(Path(sys.argv[2]).read_text(encoding='utf-8'))['entries']
    candidates = analyze(events, entries)
    present = sum(isinstance(e.get('ua'), str) and bool(e['ua']) for e in events)
    empty = sum(e.get('ua') == '' for e in events)
    unavailable = sum(e.get('ua') is None for e in events)
    print('events=' + str(len(events)))
    print(f'ua_present={present} ua_empty={empty} ua_unavailable={unavailable}')
    print('association_candidates=' + str(len(candidates)))
    print('candidate_ids=' + ','.join(c['event_id'] for c in candidates))
    for candidate in candidates:
        print(json.dumps(candidate, ensure_ascii=False))


if __name__ == '__main__':
    main()
