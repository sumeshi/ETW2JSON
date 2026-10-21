"""Compare replayed values with PerfView's checked-in text oracle, conservatively.

This does not validate native reading or UTC. It uses independent exported
timestamps/PID/TID/payload length to associate records with reference text, and
only compares untruncated literal fields common to both representations.
"""

import argparse
import datetime
import json
import re
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--records', type=Path, required=True)
parser.add_argument('--actual', type=Path, required=True)
parser.add_argument('--reference', type=Path, required=True)
parser.add_argument('--report', type=Path, required=True)
args = parser.parse_args()

records = [json.loads(line) for line in args.records.read_text().splitlines() if line.strip()]
actual = [json.loads(line) for line in args.actual.read_text().splitlines() if line.strip()]
if any(any(item['ext_type'] == 11 for item in row['extended_data']) for row in records):
    raise SystemExit('This comparison requires a corpus without skipped TraceLogging records.')
if len(records) != len(actual):
    raise SystemExit('Record count mismatch; establish raw conservation before comparing values.')

pattern = re.compile(r'^EVENT ([\d,.]+): (.*?) PID=(\d+); TID=(\d+); .*?DataLen=([\d,]+); (.*)$')
reference = []
for line in args.reference.read_text(encoding='utf-8-sig').splitlines():
    match = pattern.match(line)
    if not match:
        continue
    time, name, pid, tid, length, fields = match.groups()
    reference.append({
        'relative_ms': float(time.replace(',', '')), 'name': name,
        'pid': int(pid), 'tid': int(tid), 'length': int(length.replace(',', '')),
        'fields': dict(field.split('=', 1) for field in fields.split('; ') if '=' in field),
    })

start = datetime.datetime.fromisoformat(records[0]['reference_timestamp_utc'])
outcomes = []
compared = mismatches = 0
for row, event in zip(records, actual):
    if event['decode_status'] != 'decoded':
        continue
    relative = (datetime.datetime.fromisoformat(row['reference_timestamp_utc']) - start).total_seconds() * 1000
    candidates = [entry for entry in reference
                  if entry['pid'] == row['process_id'] and entry['tid'] == row['thread_id']
                  and entry['length'] == row['payload_length']
                  and abs(entry['relative_ms'] - relative) <= 0.015]
    outcome = {'record_index': row['record_index'], 'relative_ms': relative,
               'decoder_name': event['event_name'], 'compared_fields': [], 'skipped_fields': {}, 'mismatches': []}
    if len(candidates) != 1:
        outcome['unverified_reason'] = f'{len(candidates)} matching baseline records; not resolved using decoder values.'
        outcomes.append(outcome)
        continue
    expected = candidates[0]
    outcome['reference_name'] = expected['name']
    for field, actual_value in event['properties'].items():
        if field not in expected['fields']:
            outcome['skipped_fields'][field] = 'Field not present under the same name in the text baseline.'
            continue
        text = expected['fields'][field].strip()
        if '...' in text:
            outcome['skipped_fields'][field] = 'Reference text is truncated.'
            continue
        if text in ('True', 'False'):
            expected_value = text == 'True'
        elif re.fullmatch(r'-?[\d,]+', text):
            expected_value = int(text.replace(',', ''))
        elif re.fullmatch(r'0x[\da-fA-F]+', text):
            expected_value = int(text, 16)
        elif isinstance(actual_value, str):
            expected_value = text
        else:
            outcome['skipped_fields'][field] = 'Reference formats this value symbolically; no enum mapping assumed.'
            continue
        compared += 1
        outcome['compared_fields'].append(field)
        if actual_value != expected_value:
            mismatches += 1
            outcome['mismatches'].append({'field': field, 'expected': expected_value, 'actual': actual_value})
    outcomes.append(outcome)

report = {
    'scope': 'Literal value comparison with PerfView text baseline; not native reading or UTC validation.',
    'decoded_records': len(outcomes),
    'uniquely_matched_reference_records': sum('reference_name' in row for row in outcomes),
    'records_with_compared_values': sum(bool(row['compared_fields']) for row in outcomes),
    'compared_field_values': compared,
    'mismatched_field_values': mismatches,
    'outcomes': outcomes,
}
with args.report.open('x') as stream:
    json.dump(report, stream, indent=2)
print(json.dumps({key: value for key, value in report.items() if key != 'outcomes'}))
raise SystemExit(0 if compared > 0 and mismatches == 0 else 2)
