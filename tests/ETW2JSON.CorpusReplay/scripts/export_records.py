import base64
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from uuid import UUID

from dissect.etl import ETL

parser = argparse.ArgumentParser(description='Export public ETL corpus records with dissect.etl 3.14 for managed replay, not native validation.')
parser.add_argument('--samples', type=Path, default=Path('/tmp/etw2json-corpus/samples'))
parser.add_argument('--output', type=Path, default=Path('/tmp/etw2json-corpus/exports'))
parser.add_argument('--all-large', action='store_true', help='Also export every record of the larger trace.')
args = parser.parse_args()
SAMPLES = args.samples
OUT = args.output
OUT.mkdir(exist_ok=True, parents=True)
TARGETS = {
    'b3e675d7-2554-4f18-830b-2762732560de',
    'bbccf6c1-6cd1-48c4-80ff-839482e37671',
    'def2fe46-7bd6-4b80-bd94-f57fe20d0ce3',
}
INVESTIGATION = {
    '3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c',
    '3d6fa8d1-fe05-11d0-9dda-00c04fd7ba7c',
    '2cb15d1d-5fc1-11d2-abe1-00a0c911f518',
    '90cbdc39-4a3e-11d1-84f4-0000f80464e3',
    'ae53722e-c863-11d2-8659-00c04fa321a1',
    '9a280ac0-c8e0-11d1-84e2-00c04fb998a2',
    'bf3a50c5-a9c9-4988-a005-2df0b7c80f80',
    '3d6fa8d4-fe05-11d0-9dda-00c04fd7ba7c',
}

def b64(value):
    return base64.b64encode(bytes(value)).decode('ascii')

def record_row(record, etl, index, buffer_index, record_offset, name):
    h = record.header
    raw = h.header
    kind = type(h).__name__
    is_event = kind == 'EventHeader'
    is_classic_full = kind == 'EventTraceHeader'
    provider = str(UUID(bytes_le=raw.ProviderId)) if hasattr(raw, 'ProviderId') else str(h.provider_id)
    version = (raw.Version >> 16) & 0xff if is_classic_full else raw.Version & 0xff
    opcode = raw.Version & 0xff if is_classic_full else getattr(h, 'opcode', 0)
    extensions = h.header_extensions if is_event and raw.Flags & 1 else []
    extension_bytes = sum(item.size for item in extensions)
    payload = bytes(h.payload[extension_bytes:])
    return {
        'source_file': name,
        'record_index': index,
        'buffer_index': buffer_index,
        'record_offset_within_buffer_data': record_offset,
        'etl_header_kind': kind,
        'etl_header_marker': h.marker,
        'etl_header_is_64bit': h.is_64bit,
        'etl_header_flags': getattr(raw, 'Flags', None),
        'etl_header_version_field': raw.Version,
        'provider_guid_raw_base64': b64(raw.ProviderId) if hasattr(raw, 'ProviderId') else None,
        'provider_guid': provider,
        'event_id': raw.Id if is_event else 0,
        'version': version,
        'opcode': opcode,
        'level': (raw.Version >> 8) & 0xff if is_classic_full else getattr(raw, 'Level', 0),
        'channel': getattr(raw, 'Channel', 0),
        'task': getattr(raw, 'Task', 0),
        'keyword': getattr(raw, 'Keywords', 0),
        # On-disk flags do not contain native OpenTrace's 32/64/classic normalization.
        'replay_flags': (getattr(raw, 'Flags', 0) | (0x40 if h.is_64bit else 0x20) | (0 if is_event else 0x100)),
        'process_id': getattr(raw, 'ProcessId', None),
        'thread_id': getattr(raw, 'ThreadId', None),
        'activity_id': str(UUID(bytes_le=raw.ActivityId)) if is_event else None,
        'raw_timestamp': h.time_delta,
        'reference_timestamp_utc': h.timestamp.isoformat(),
        'session_pointer_size': etl.pointer_size,
        'trace_clock': {
            'performance_frequency': etl.logfile_header.header.PerfFreq,
            'start_time': etl.logfile_header.header.StartTime,
            'boot_time': etl.logfile_header.header.BootTime,
            'reserved_flags': etl.logfile_header.header.ReservedFlags,
        },
        'extended_data': [
            {'ext_type': int(item.ext_type), 'data_size': item.data_size, 'data_base64': b64(item.raw_data[:item.data_size])}
            for item in extensions
        ],
        'payload_base64': b64(payload),
        'payload_length': len(payload),
        'raw_header_base64': b64(h.data[:h.minimal_size]),
        'raw_record_base64': b64(h.data[:h.size]),
    }

summaries = []
for path in sorted(SAMPLES.glob('*.etl')):
    large = path.name == 'net.4.5.x86.etl'
    destinations = {'samples' if large else 'all': (OUT / (path.stem + ('.samples' if large else '.all') + '.jsonl')).open('w')}
    if large:
        destinations['custom'] = (OUT / (path.stem + '.custom.jsonl')).open('w')
        destinations['investigation'] = (OUT / (path.stem + '.investigation.jsonl')).open('w')
        if args.all_large:
            destinations['all_large'] = (OUT / (path.stem + '.all.jsonl')).open('w')
    total = 0
    header_types = Counter()
    flags = Counter()
    providers = Counter()
    selected = Counter()
    try:
        with path.open('rb') as stream:
            etl = ETL(stream)
            for bindex, buffer in enumerate(etl.buffers()):
                offset = 0
                for record in buffer:
                    row = record_row(record, etl, total, bindex, offset, path.name)
                    total += 1
                    offset += record.aligned_size
                    header_types[row['etl_header_kind']] += 1
                    flags[str((row['etl_header_kind'], row['etl_header_is_64bit'], row['etl_header_flags']))] += 1
                    key = f"{row['provider_guid']}:{row['opcode']}:{row['version']}"
                    providers[key] += 1
                    if not large:
                        destinations['all'].write(json.dumps(row) + '\n')
                    else:
                        if args.all_large:
                            destinations['all_large'].write(json.dumps(row) + '\n')
                        if selected[key] < 3:
                            destinations['samples'].write(json.dumps(row) + '\n')
                            selected[key] += 1
                        if row['provider_guid'] in TARGETS:
                            destinations['custom'].write(json.dumps(row) + '\n')
                        if row['provider_guid'] in INVESTIGATION:
                            destinations['investigation'].write(json.dumps(row) + '\n')
            summaries.append({
                'name': path.name,
                'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
                'bytes': path.stat().st_size,
                'total_records': total,
                'session_pointer_size': etl.pointer_size,
                'header_types': dict(header_types),
                'raw_flags': dict(flags),
                'provider_opcode_version_counts': dict(providers),
            })
    finally:
        for destination in destinations.values(): destination.close()

(OUT / 'summary.json').write_text(json.dumps(summaries, indent=2))
print(json.dumps([{k:v for k,v in s.items() if k not in ('provider_opcode_version_counts','raw_flags')} for s in summaries], indent=2))
