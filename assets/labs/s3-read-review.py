"""Correlate the two normalized, synthetic CSVs supplied with the S3 lesson."""
import csv
from collections import defaultdict
from pathlib import Path

FOLDER = Path(__file__).resolve().parent

def load(name):
    grouped = defaultdict(list)
    with (FOLDER / name).open(encoding='utf-8', newline='') as source:
        for row in csv.DictReader(source):
            key = (row['bucket'], row['request_id'])
            if row not in grouped[key]:
                grouped[key].append(row)
    return grouped

def classify(cloudtrail, access):
    if len(cloudtrail) > 1 or len(access) > 1:
        return 'conflicting_rows', None
    if not cloudtrail:
        return 'access_log_only', None
    if not access:
        return 'cloudtrail_only', None

    event, log = cloudtrail[0], access[0]
    operations = {'GetObject': 'REST.GET.OBJECT', 'HeadObject': 'REST.HEAD.OBJECT'}
    if (event['object_key'] != log['object_key']
            or operations.get(event['operation']) != log['operation']):
        return 'join_mismatch', None

    status = int(log['http_status'])
    if event['error_code'] == 'AccessDenied' and status == 403:
        return 'denied', None
    if event['error_code'] or status not in (200, 206):
        return 'outcome_needs_review', None
    if event['operation'] == 'HeadObject':
        return ('metadata_only' if status == 200 else 'outcome_needs_review'), None
    size = 0 if log['bytes_sent'] == '-' else int(log['bytes_sent'])
    return ('partial_response' if status == 206 else 'object_response'), size

def main():
    trail = load('s3-cloudtrail-projection.csv')
    access = load('s3-access-projection.csv')
    total = 0
    for key in sorted(trail.keys() | access.keys()):
        verdict, size = classify(trail.get(key, []), access.get(key, []))
        if size is not None:
            total += size
        print(f'{key[1]} {verdict}' + (f' {size} bytes' if size is not None else ''))
    print(f'Paired successful GET bytes in this fixture: {total}')

if __name__ == '__main__':
    main()
