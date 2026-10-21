# Replay an independently exported ETL corpus

This helper validates managed decoding and raw conservation using records read
from public, Windows-produced ETLs by a separate parser. It **does not run or
validate OpenTrace, ProcessTrace, TDH, native record normalization, UTC conversion,
or acquisition completeness**. Do not use its zero exit status as a finding that
all events were decoded correctly.

The helper reconstructs unmanaged `EVENT_RECORD` data, performs schema-only
preflight and conversion passes with the same resolver classes as the CLI, then
checks output count/order, original header fields, PID/TID/activity, raw payload,
extended-data types/bytes, raw timestamp, and source file. Each record's allocations are released after the
callback. It disables analysis-host metadata and explicitly skips records carrying
TraceLogging metadata because TDH cannot run on Linux. Skipped counts are
reported separately. Output and summary files must not already exist.

## Corpus provenance

[`corpus-manifest.json`](corpus-manifest.json) records the source commit, file
hashes and license. The ETLs and PerfView reference text come from
[`microsoft/perfview` at `29b21620`](https://github.com/microsoft/perfview/tree/29b21620a6c295979e83dc99008262ad2f3c6a2d),
which is MIT licensed by the .NET Foundation and Contributors. Preserve its
LICENSE.TXT with downloaded samples. The samples are performance/test traces,
not a representative incident-response corpus.

The exporter uses **dissect.etl 3.14** in a separate Python process. That tool is
AGPL licensed; its code is not copied into or linked into ETW2JSON. Its manifest
parser is also useful as an independent reference for supported classic events.
Its existence does not make it an infallible oracle: record matching, formatting
and coverage differences must be examined.

One concrete reference limitation is `primitive-types.etl`: its field named
`int64_type` has raw TraceLogging type byte `0x0A` (UInt64), as does
`uint64_type`. The PerfView text baseline prints the former as a negative Int64.
TraceEvent 4.0.0's dynamic TDH `PayloadFetch` maps UInt64 to `System.Int64`,
which explains that representation difference. Neither the field name nor that
baseline text can establish signedness. The raw declarations and payload bytes
must be considered when comparing values.

The on-disk ETL header is not a native callback record. The exporter retains raw
record/header bytes and marks the inferred `replay_flags`, deriving 32/64-bit and
classic bits from on-disk header markers. Disk buffer order also differs from
native ProcessTrace ordering. Its `reference_timestamp_utc` is a Dissect
calculation used for comparison, not a separately verified wall-clock anchor.
Modern provider GUIDs are exported from their raw bytes using Windows' GUID
byte order; this avoids a GUID display endianness issue in Dissect 3.14.

## Obtain the pinned samples

From the repository root, use a new working directory outside the checkout:

```bash
corpus_dir="$(mktemp -d /tmp/etw2json-corpus.XXXXXX)"
mkdir -p "$corpus_dir/samples"
git clone --filter=blob:none --no-checkout https://github.com/microsoft/perfview.git "$corpus_dir/perfview"
corpus_commit=29b21620a6c295979e83dc99008262ad2f3c6a2d
git -C "$corpus_dir/perfview" show "$corpus_commit:LICENSE.TXT" > "$corpus_dir/LICENSE.TXT"
for sample in primitive-types.etl.zip gcevents.etl.zip net.4.5.x64.etl.zip primitive-types.baseline.txt gcevents.baseline.txt net.4.5.x64.baseline.txt; do
  git -C "$corpus_dir/perfview" show "$corpus_commit:src/TraceEvent/TraceEvent.Tests/inputs/$sample" > "$corpus_dir/samples/$sample"
done
git -C "$corpus_dir/perfview" show "$corpus_commit:src/TraceEvent/TraceEvent.Tests/inputs/Regression/SelfDescribingSingleEvent.etl" > "$corpus_dir/samples/SelfDescribingSingleEvent.etl"
git -C "$corpus_dir/perfview" show "$corpus_commit:src/TraceEvent/Parsers/ClrEtwAll.man" > "$corpus_dir/samples/ClrEtwAll.man"
python3 - "$corpus_dir/samples" <<'PY'
import pathlib, sys, zipfile
root = pathlib.Path(sys.argv[1])
for path in root.glob('*.zip'):
    with zipfile.ZipFile(path) as archive:
        for member in archive.namelist():
            if member.lower().endswith('.etl'):
                (root / pathlib.PurePosixPath(member).name).write_bytes(archive.read(member))
PY
```

Check downloaded file SHA-256 values against `corpus-manifest.json` before
continuing. The archive named `net.4.5.x64.etl.zip` contains an ETL named
`net.4.5.x86.etl`; its session pointer size is 8 and it includes both 32-bit and
64-bit event headers. Do not infer event architecture from the filename.

## Export and replay

```bash
python3 -m venv "$corpus_dir/venv"
"$corpus_dir/venv/bin/pip" install -r tests/ETW2JSON.CorpusReplay/reference-requirements.txt
"$corpus_dir/venv/bin/python" tests/ETW2JSON.CorpusReplay/scripts/export_records.py \
  --samples "$corpus_dir/samples" --output "$corpus_dir/exports" --all-large
dotnet restore tests/ETW2JSON.CorpusReplay/ETW2JSON.CorpusReplay.csproj --locked-mode
dotnet build tests/ETW2JSON.CorpusReplay/ETW2JSON.CorpusReplay.csproj -c Release --no-restore
replay_dll=tests/ETW2JSON.CorpusReplay/bin/Release/net10.0-windows/ETW2JSON.CorpusReplay.dll
dotnet "$replay_dll" \
  --input "$corpus_dir/exports/PerfViewData.all.jsonl" \
  --manifest "$corpus_dir/samples/ClrEtwAll.man" \
  --output "$corpus_dir/clr.jsonl" --summary "$corpus_dir/clr.summary.json"
dotnet "$replay_dll" \
  --input "$corpus_dir/exports/net.4.5.x86.investigation.jsonl" \
  --output "$corpus_dir/kernel.jsonl" --summary "$corpus_dir/kernel.summary.json"
dotnet "$replay_dll" \
  --input "$corpus_dir/exports/primitive-types.all.jsonl" \
  --input "$corpus_dir/exports/SelfDescribingSingleEvent.all.jsonl" \
  --input "$corpus_dir/exports/net.4.5.x86.custom.jsonl" \
  --output "$corpus_dir/custom.jsonl" --summary "$corpus_dir/custom.summary.json"
```

The small samples export every physical record. For the larger ETL, the exporter
emits a representative sample per provider/opcode/version, all existing custom
parser inputs, and all Process/Thread/Image/File/TCPIP/UDP/Disk inputs as separate
files. It also records full-file counts in `exports/summary.json`. There are no
registry records in that selected trace.
The requested `--all-large` also produces `net.4.5.x86.all.jsonl`.
The C# replay streams its expected records during the comparison so it does not
retain the whole exported corpus in memory.

For a full-trace coverage check, replay `net.4.5.x86.all.jsonl` twice to new output
and summary paths, first without a manifest and then with `ClrEtwAll.man`.
Run `compare_classic_reference.py` against each full output to check that broader
input does not change the selected kernel values. Compare status distributions
and skipped counts as well as raw conservation; additional inputs must not be
hidden by a successful record count.

```bash
dotnet "$replay_dll" --input "$corpus_dir/exports/net.4.5.x86.all.jsonl" \
  --output "$corpus_dir/full.jsonl" --summary "$corpus_dir/full.summary.json"
dotnet "$replay_dll" --input "$corpus_dir/exports/net.4.5.x86.all.jsonl" \
  --manifest "$corpus_dir/samples/ClrEtwAll.man" \
  --output "$corpus_dir/full-clr.jsonl" --summary "$corpus_dir/full-clr.summary.json"
```

Summary `status_counts` and `by_source_provider_opcode` show actual decoding
coverage. `metadata_missing`, `unsupported` and `decode_error` outcomes are not
successful property interpretation. An empty `roundtrip_mismatch_counts` only
establishes conservation of the checked fields for records that were replayed.

## Compare values with the independent reference

```bash
python3 tests/ETW2JSON.CorpusReplay/scripts/compare_baseline.py \
  --records "$corpus_dir/exports/PerfViewData.all.jsonl" \
  --actual "$corpus_dir/clr.jsonl" \
  --reference "$corpus_dir/samples/gcevents.baseline.txt" \
  --report "$corpus_dir/clr.baseline-comparison.json"
```

This comparison associates decoded records by independently exported time,
PID/TID and payload length. It checks only common, untruncated literal values;
it leaves symbolic enum mappings, truncated paths and ambiguous records
unverified. The report lists both compared and skipped fields. The script
returns nonzero for a mismatch or zero actual value comparisons.

For a complete, field-level comparison of the selected Process v4, Image v2 and
File name v2 records, generate a separate reference using the independent parser:

```bash
"$corpus_dir/venv/bin/python" tests/ETW2JSON.CorpusReplay/scripts/export_classic_reference.py \
  --etl "$corpus_dir/samples/net.4.5.x86.etl" \
  --output "$corpus_dir/kernel.reference.jsonl" --summary "$corpus_dir/kernel.reference.summary.json"
python3 tests/ETW2JSON.CorpusReplay/scripts/compare_classic_reference.py \
  --records "$corpus_dir/exports/net.4.5.x86.investigation.jsonl" \
  --actual "$corpus_dir/kernel.jsonl" --reference "$corpus_dir/kernel.reference.jsonl" \
  --report "$corpus_dir/kernel.reference-comparison.json"
```

Unlike the text-baseline comparison, this checks every selected record and every
reference property, including process parent/command line, SID, image path and
file-name key. It returns nonzero for an undecoded selected record, a missing
field, any unequal value, or absent reference records. Original NT paths remain
untranslated. A file-name `FileKey` identifies a name entry and must not be
treated as an open-file `FileObject` handle.

For full-trace output, verify derived stack addresses separately from raw bytes:

```bash
python3 tests/ETW2JSON.CorpusReplay/scripts/compare_stacks.py \
  --records "$corpus_dir/exports/net.4.5.x86.all.jsonl" \
  --actual "$corpus_dir/full.jsonl" --report "$corpus_dir/stacks.reference-comparison.json"
```

This independently reads the stack match ID and each 32/64-bit address using
Python's standard binary decoder. It does not resolve symbols or establish
which activity caused a sample.
