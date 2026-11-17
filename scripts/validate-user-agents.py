#!/usr/bin/env python3
"""Validate reference consistency and false-positive controls; no dependencies."""
import csv
import json
from pathlib import Path
import re
import runpy

ROOT = Path(__file__).resolve().parents[1]
data = json.loads((ROOT / '_data/user_agents.json').read_text())
assert data == json.loads((ROOT / 'assets/data/user-agents.json').read_text())
entries = data['entries']
assert len(entries) == 100
assert len({e['id'] for e in entries}) == len(entries)
assert sum(e['group'] in {'browser', 'library', 'bot', 'tool'} for e in entries) == 34
for entry in entries:
    assert entry['match'] in {'exact', 'prefix', 'contains'}
    assert entry['source_url'].startswith('https://')
    assert all(entry[k] for k in ['meaning_en', 'meaning_ko', 'evidence', 'source_period', 'reviewed'])
    assert '\n' not in entry['pattern']
with (ROOT / 'assets/data/user-agents.csv').open(encoding='utf-8-sig', newline='') as handle:
    assert list(csv.DictReader(handle)) == entries
lab = runpy.run_path(str(ROOT / 'assets/labs/user-agent/analyze.py'))
events = [json.loads(line) for line in (ROOT / 'assets/labs/user-agent/events.jsonl').read_text().splitlines()]
assert len(events) == 20 and len({e['event_id'] for e in events}) == 20
assert all(e['synthetic'] and e['host'].endswith('.example') for e in events)
assert [e['event_id'] for e in lab['analyze'](events, entries)] == [f'E{i:02}' for i in [4,5,6,7,8,9,10,11,12,20]]
record = next(e for e in entries if e['pattern'] == 'record')
assert lab['matches']('record', record)
assert not any(lab['matches'](v, record) for v in ['recording-client/2', 'Record', ' record', '', None])
prefix = next(e for e in entries if e['pattern'] == 'Ares_ldr_v_')
assert lab['matches']('Ares_ldr_v_1', prefix) and not lab['matches']('xAres_ldr_v_1', prefix)
assert len('TeslaBrowser/5.5'.encode('ascii')) == 16
assert events[10]['ua'] == events[11]['ua']
slugs = [p.stem for p in (ROOT / '_articles').glob('user-agent-*.md')]
assert len(slugs) == 6
for slug in slugs:
    for folder, translation in [('_articles', '/ko/wiki/'), ('_ko_articles', '/wiki/')]:
        text = (ROOT / folder / (slug + '.md')).read_text()
        assert f'translation_url: "{translation}{slug}/"' in text
        assert text.count('```') % 2 == 0
        assert text.count('{% include ua-series.html %}') == 2
        for path in re.findall(r"'(/[^']+)'\s*\|\s*relative_url", text):
            if path.startswith('/assets/'):
                assert (ROOT / path.lstrip('/')).is_file(), path
            elif path.startswith(('/wiki/', '/ko/wiki/')):
                local = '_ko_articles' if path.startswith('/ko/') else '_articles'
                assert (ROOT / local / (path.rstrip('/').split('/')[-1] + '.md')).exists(), path
print('PASS: 100 entries, 12 translated articles, CSV/JSON parity, 20 events, 10 expected candidates, matching controls and internal links')
