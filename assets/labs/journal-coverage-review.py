"""Compare the supplied synthetic journal projections. No host logs are read."""
from collections import defaultdict
import json
from pathlib import Path

INPUT = Path(__file__).with_name('journal-coverage-cases.json')

def index(rows):
    indexed = defaultdict(list)
    incomplete = []
    for row in rows:
        journal = row['journal']
        key = (journal.get('_MACHINE_ID'), row.get('namespace'),
               journal.get('_BOOT_ID'), journal.get('__CURSOR'))
        if all(isinstance(field, str) and field for field in key):
            indexed[key].append(row)
        else:
            incomplete.append(row)
    return indexed, incomplete

def compare(local, central):
    if not local:
        return 'central_only'
    if not central:
        return 'local_only'
    reference = local[0]['journal']
    if any(row['journal'] != reference for row in local + central):
        return 'conflicting_payload'
    return 'paired_with_duplicate' if len(local) + len(central) > 2 else 'paired'

def clock_steps(rows):
    boots = defaultdict(list)
    for (machine, namespace, boot, _), group in rows.items():
        boots[machine, namespace, boot].append(group[0])
    for group in boots.values():
        ordered = sorted(group, key=lambda row: int(row['journal']['__MONOTONIC_TIMESTAMP']))
        for a, b in zip(ordered, ordered[1:]):
            before, after = a['journal'], b['journal']
            if (int(before['__MONOTONIC_TIMESTAMP']) < int(after['__MONOTONIC_TIMESTAMP'])
                    and int(before['__REALTIME_TIMESTAMP']) > int(after['__REALTIME_TIMESTAMP'])):
                yield f'{a["case"]} -> {b["case"]} journal wall clock moves backwards'

def main():
    data = json.loads(INPUT.read_text(encoding='utf-8'))
    local, local_missing = index(data['local'])
    central, central_missing = index(data['central'])
    results = []
    for key in local.keys() | central.keys():
        a, b = local.get(key, []), central.get(key, [])
        row = (a or b)[0]
        results.append((row['case'], row['namespace'], compare(a, b)))
    for row in local_missing + central_missing:
        results.append((row['case'], row['namespace'], 'incomplete_identity'))
    for result in sorted(results):
        print(*result)
    for finding in clock_steps(local):
        print(finding)

if __name__ == '__main__':
    main()
