"""Independently compare stack extension bytes with emitted stack values."""

import argparse
import base64
import json
import struct
from itertools import zip_longest
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--records', type=Path, required=True)
parser.add_argument('--actual', type=Path, required=True)
parser.add_argument('--report', type=Path, required=True)
args = parser.parse_args()

def lines(path):
    with path.open() as stream:
        for line in stream:
            if line.strip(): yield json.loads(line)

def replayed(path):
    for row in lines(path):
        if not any(item['ext_type'] == 11 for item in row['extended_data']): yield row

checked_records = checked_frames = mismatches = invalid_references = 0
examples = []
for row, event in zip_longest(replayed(args.records), lines(args.actual)):
    if row is None or event is None:
        raise SystemExit('Input/output record count mismatch; compare raw conservation first.')
    items = [item for item in row['extended_data'] if item['ext_type'] in (5, 6)]
    if not items:
        continue
    if len(items) != 1:
        invalid_references += 1
        continue
    item = items[0]
    data = base64.b64decode(item['data_base64'], validate=True)
    width = 4 if item['ext_type'] == 5 else 8
    if len(data) < 8 or (len(data) - 8) % width:
        invalid_references += 1
        continue
    match_id = struct.unpack_from('<Q', data)[0]
    count = (len(data) - 8) // width
    frames = list(struct.unpack_from('<' + ('I' if width == 4 else 'Q') * count, data, 8))
    checked_records += 1
    checked_frames += count
    if event.get('stack_match_id', 0) != match_id or event.get('stacks') != frames:
        mismatches += 1
        if len(examples) < 20: examples.append(row['record_index'])

report = {
    'scope': 'Independent little-endian decoding of exported real ETL stack bytes versus emitted fields; not native ETL reading or symbolization.',
    'checked_stack_records': checked_records, 'checked_stack_frames': checked_frames,
    'mismatched_records': mismatches, 'invalid_or_ambiguous_reference_records': invalid_references,
    'mismatch_record_examples': examples,
}
with args.report.open('x') as stream:
    json.dump(report, stream, indent=2)
print(json.dumps(report))
raise SystemExit(0 if checked_records and not mismatches and not invalid_references else 2)
