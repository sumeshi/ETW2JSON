"""Export independent classic Process/Image/File values using dissect.etl 3.14.

Only the listed layouts are selected. Dissect is an external reference process;
no decoder code or manifests from that project are copied into ETW2JSON.
"""

import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path
from uuid import UUID

from dissect.etl import ETL, manifest
from dissect.etl.etl import Event
from dissect.util.sid import read_sid

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--etl', type=Path, required=True)
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--summary', type=Path, required=True)
args = parser.parse_args()

layouts = {
    '3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c': ('Process', 4, {1, 2, 3, 4}),
    '2cb15d1d-5fc1-11d2-abe1-00a0c911f518': ('Image', 2, {2, 3, 4, 10}),
    '90cbdc39-4a3e-11d1-84f4-0000f80464e3': ('File', 2, {0, 32, 35, 36}),
}
counts = Counter()
failures = []
digest = hashlib.sha256(args.etl.read_bytes()).hexdigest()
with args.output.open('x') as out, args.etl.open('rb') as stream:
    etl = ETL(stream)
    for index, record in enumerate(etl):
        h = record.header
        guid = UUID(bytes_le=h.header.ProviderId) if hasattr(h.header, 'ProviderId') else h.provider_id
        if str(guid) not in layouts:
            continue
        family, version, opcodes = layouts[str(guid)]
        if h.version != version or h.opcode not in opcodes:
            continue
        try:
            module = manifest.lookup(guid)
            if h.is_64bit:
                module.c_parser.EtwPointer.as_64bit()
                module.c_parser.UserSID_blob.as_64bit()
            else:
                module.c_parser.EtwPointer.as_32bit()
                module.c_parser.UserSID_blob.as_32bit()
            event = Event(h, module)
            if event._struct is None:
                raise ValueError('No independently supported reference template.')
            properties = dict(event._struct.__values__)
            if 'UserSID' in properties:
                properties['UserSID'] = read_sid(properties['UserSID'].sid.dumps())
            properties = {k: v.decode('utf-8') if isinstance(v, bytes) else v for k, v in properties.items()}
            if family == 'File':
                # PerfView calls the name ID FileKey; it is not an open-file handle.
                properties['FileKey'] = properties.pop('FileObject')
            row = {
                'source_file': args.etl.name, 'source_etl_sha256': digest,
                'record_index': index, 'provider_guid': str(guid),
                'version': version, 'opcode': h.opcode, 'is_64bit': h.is_64bit,
                'reference_symbol': event.symbol(), 'reference_properties': properties,
                'reference_reader': 'dissect.etl 3.14; external process',
            }
            out.write(json.dumps(row) + '\n')
            counts[f'{family}:{h.opcode}'] += 1
        except Exception as exc:
            failures.append({'record_index': index, 'family': family, 'error': f'{type(exc).__name__}: {exc}'})

summary = {'reference_counts': dict(counts), 'failed_reference_records': failures,
           'note': 'Independent parser output, not native OpenTrace/TDH validation. No failed reference record is silently treated as verified.'}
with args.summary.open('x') as stream:
    json.dump(summary, stream, indent=2)
print(json.dumps(summary))
