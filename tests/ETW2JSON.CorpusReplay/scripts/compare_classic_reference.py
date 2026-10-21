"""Compare every selected Process/Image/File wire value with an external oracle."""

import argparse
import json
from collections import Counter
from itertools import zip_longest
from pathlib import Path

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--records', type=Path, required=True)
parser.add_argument('--actual', type=Path, required=True)
parser.add_argument('--reference', type=Path, required=True)
parser.add_argument('--report', type=Path, required=True)
args = parser.parse_args()

reference = {row['record_index']: row for row in (json.loads(line) for line in args.reference.read_text().splitlines() if line.strip())}

def lines(path):
    with path.open() as stream:
        for line in stream:
            if line.strip(): yield json.loads(line)

def replayed_records(path):
    for row in lines(path):
        if not any(item['ext_type'] == 11 for item in row['extended_data']): yield row

counts = Counter()
by_family = {}
problems = []
seen = set()
sources = set()
for row, event in zip_longest(replayed_records(args.records), lines(args.actual)):
    if row is None or event is None:
        raise SystemExit('Record count mismatch; establish raw conservation before comparing values.')
    sources.add(row['source_file'])
    if len(sources) != 1:
        raise SystemExit('This comparison expects records from one source ETL.')
    index = row['record_index']
    if index not in reference:
        continue
    expected = reference[index]
    seen.add(index)
    family = expected['reference_symbol'].split('/')[0]
    per_family = by_family.setdefault(family, Counter())
    counts['selected_records'] += 1
    per_family['selected_records'] += 1
    if event['decode_status'] != 'decoded':
        counts['not_decoded_records'] += 1
        per_family['not_decoded_records'] += 1
        if len(problems) < 20:
            problems.append({'record_index': index, 'status': event['decode_status'], 'issue': 'Expected supported reference record was not decoded.'})
        continue
    counts['decoded_records'] += 1
    per_family['decoded_records'] += 1
    actual_properties = {name.casefold(): value for name, value in event['properties'].items()}
    for name, value in expected['reference_properties'].items():
        key = name.casefold()
        if key not in actual_properties:
            counts['missing_fields'] += 1
            per_family['missing_fields'] += 1
            if len(problems) < 20:
                problems.append({'record_index': index, 'field': name, 'issue': 'Missing property.'})
            continue
        counts['compared_field_values'] += 1
        per_family['compared_field_values'] += 1
        if actual_properties[key] != value:
            counts['mismatched_field_values'] += 1
            per_family['mismatched_field_values'] += 1
            if len(problems) < 20:
                problems.append({'record_index': index, 'field': name, 'expected': value, 'actual': actual_properties[key]})

counts['reference_records_not_found_in_input'] = len(reference.keys() - seen)
for key in ('selected_records', 'decoded_records', 'not_decoded_records', 'compared_field_values', 'missing_fields', 'mismatched_field_values'):
    counts.setdefault(key, 0)
report = {
    'scope': 'Property-value comparison against dissect.etl 3.14 in an independent process for explicitly selected classic layouts; not native ETL reading validation.',
    'counts': dict(counts), 'by_family': by_family, 'problems': problems,
}
with args.report.open('x') as stream:
    json.dump(report, stream, indent=2)
print(json.dumps({key: value for key, value in report.items() if key != 'problems'}))
failed = any(counts[key] for key in ('not_decoded_records', 'missing_fields', 'mismatched_field_values', 'reference_records_not_found_in_input'))
raise SystemExit(0 if counts['compared_field_values'] > 0 and not failed else 2)
