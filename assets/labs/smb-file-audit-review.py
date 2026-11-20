"""Review only the packaged synthetic Windows Security event projections."""
import json
import ntpath
from pathlib import Path

INPUT = Path(__file__).with_name('smb-file-audit-cases.json')
MATCH_WINDOW_SECONDS = 5

def session(event):
    return (event['server'].casefold(), event['boot'], event['sid'],
            int(event['logon_id'], 16))

def review(case):
    events = case['events']
    shares = [event for event in events if event['event_id'] == 5145]
    filesystem = [event for event in events if event['event_id'] in (4656, 4663)]
    logons = {session(event) for event in events
              if event['event_id'] == 4624 and event['logon_type'] == 3}
    if not shares:
        if any(event['event_id'] == 4656 and event['outcome'] == 'failure'
               and session(event) in logons for event in filesystem):
            return 'file_handle_denied_network_session'
        return 'no_share_check'
    check, = shares  # Each supplied case contains at most one 5145.
    if check['outcome'] == 'failure':
        return 'share_check_denied'
    target = ntpath.join(check['share_local_path'], check['relative_target']).casefold()
    matches = [
        event for event in filesystem
        if event['event_id'] == 4663 and session(event) == session(check)
        and event['object_name'].casefold() == target
        and 0 <= event['second'] - check['second'] <= MATCH_WINDOW_SECONDS
    ]
    if len(matches) > 1:
        return 'ambiguous_object_records'
    if not matches:
        return 'share_check_without_matched_use'
    mask = int(matches[0]['access_mask'], 16)
    if case['target_kind'] == 'directory' and mask & 0x1:
        return 'directory_list_right_used'
    if case['target_kind'] == 'file' and mask & 0x1:
        return 'file_read_data_right_used'
    if case['target_kind'] == 'file' and mask & 0x2:
        return 'file_write_data_right_used'
    return 'attributes_only' if mask == 0x80 else 'review_other_rights'

def main():
    cases = json.loads(INPUT.read_text(encoding='utf-8'))
    for case in cases:
        print(case['case'], review(case))

if __name__ == '__main__':
    main()
