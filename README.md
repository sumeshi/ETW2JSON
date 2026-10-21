# ETW2JSON

ETW2JSON converts Windows ETL files to JSON Lines (JSONL) or legacy-shaped JSON.
This fork extends [Microsoft ETW2JSON](https://github.com/microsoft/ETW2JSON) for
analysis of traces acquired from another Windows installation. It retains the
native `OpenTrace`, `ProcessTrace`, and TDH reader and uses .NET 10.

## What it can tell you

- Decode supported EventSource, TraceLogging, manifest and recovered PE schemas,
  while recording where each interpretation came from.
- Extract parent/child PIDs and command lines from selected kernel Process v4
  records, module paths from Image v2 records, and FileKey/name mappings from
  FileIO name v2 records. The supported layouts are listed below.
- Inventory missing metadata and retain original headers, payloads, extended
  metadata and diagnostics for events that need further examination.

**Windows is required for ETL conversion. Successful conversion does not prove
complete collection, complete decoding or forensic accuracy.** TCP/IP, Thread,
WPP and other unlisted kernel layouts are not covered by these built-in parsers.
File-name snapshots do not establish file access, and raw timestamps are not UTC.
Controlled Windows smoke tests and public ETL native comparisons have passed
for the checked fields; decoding coverage remains limited. See the measured results
and remaining gaps in [Investigation validation](docs/investigation-validation.md)
and the [validation procedure](docs/validation.md).

## What changed from Microsoft ETW2JSON

The comparison below uses the [upstream implementation at
`4d145bf`](https://github.com/microsoft/ETW2JSON/tree/4d145bf61e9daad98a58166ae8d220577eaf51bc)
as its baseline.

| Investigation problem in the upstream workflow | Customization | What it enables |
| --- | --- | --- |
| Metadata lookup used TDH on the analysis host, with EventSource XML fallback; output did not identify the schema's origin. A different host can have different provider registrations. | Record `metadata_source` and provenance. Analysis-host registration requires `--allow-local-metadata`; it is off by default. | Distinguish ETL-embedded and supplied evidence schemas from analysis-host fallback when assessing a decoded value. |
| The CLI could not accept recovered provider manifests, evidence PE resources, or publisher exports. An acquired ETL can lack the schemas installed on its source system. | Add repeatable `--manifest`, static `--resource`, and `--provider-info` inputs. | Decode supported events using recovered `.man`/PE schemas, and use exported publisher information to guide further collection. |
| The unknown-event fallback set event ID/version to zero and omitted the original payload. | Preserve event header identity, Base64 `raw_payload`, source file, and per-event decode status. | Keep unresolved events identifiable and retain their payload for later analysis with better metadata. |
| Inherited kernel parsers assumed fixed layouts without identifying their origin; selected investigation records lacked dedicated decoders. | Correct pointer-width handling, label built-in layouts and add limited Process v4, Image v2 and FileIO name v2 parsers. | Examine process ancestry, command lines, module paths and file-name inventories within the supported layouts. |
| Some extended metadata was absent from output, and collection-loss counters were ignored. | Preserve raw extended data and stacks; report invalid extensions and ETL loss counters. | Retain self-describing schemas and other extension bytes for review, and recognize reported collection gaps. |
| Output was a nested JSON document; there was no metadata inventory or missing-metadata report. | Add JSONL, a schema preflight pass, `--scan`, and `--report-missing`. | Inspect coverage before conversion, identify metadata recovery targets, and process events one JSON line at a time. |
| Opening the output used `FileMode.Create`, which could replace an existing file. | Create a new output file and refuse an existing destination. | Avoid overwriting evidence or a previous result through the CLI's output option. |

This remains an extension of the original decoder, including its custom parsers;
it is not a new implementation of the ETL format.

## Get the CLI

**ETL reading and conversion require Windows.** Linux can build the Windows-targeted
projects and run the portable unit tests, but cannot run the native ETW reader.

A GitHub Release published with a tag such as `vX.Y.Z` or `vX.Y.Z-beta.1`
triggers a Windows x64 ZIP build containing `etw2json.exe`. That executable is
self-contained and does not require a separate .NET installation. After extracting
a release, set the executable path in PowerShell:

```powershell
$etw = '.\etw2json.exe'
& $etw --help
```

To build from source, install the .NET SDK selected by [global.json](global.json),
then run these commands from the repository root:

```powershell
dotnet restore ETW2JSON.sln --locked-mode
dotnet build ETW2JSON.sln -c Release --no-restore
$etw = '.\bin\Release\net10.0-windows\etw2json.exe'
& $etw --help
```

The examples below use `& $etw` in PowerShell. Use a new output path for each run;
existing output files are rejected. Prefer `--output` to shell redirection, which
can replace a file before ETW2JSON starts.

## Investigation workflow

Work from acquired copies and retain the original ETL and recovered metadata.
Record their hashes, the tool's release/commit, the command line, and stderr with
the case notes. ETW2JSON does not create a complete acquisition or audit record.

### 1. Inventory the trace and identify missing metadata

```powershell
& $etw .\evidence\trace.etl --scan
& $etw .\evidence\trace.etl --report-missing

# Structured reports saved to new files
& $etw .\evidence\trace.etl --scan --format json --output .\analysis\scan.json
& $etw .\evidence\trace.etl --report-missing --format json --output .\analysis\missing.json
```

The scan counts provider/event ID/version tuples and reports schema resolution.
Classic/MOF records also use `classic_opcode` in JSON scans/reports to distinguish
event types that share header ID 0. Their GUID may identify an event class rather
than a modern publisher; the report gives classic-specific collection guidance.
`--report-missing` includes unresolved, conflicting, invalid, and unsupported
metadata, with collection guidance. Without `--format json`, these reports are
human-readable text.

**A scan status of `Resolved` means that a schema or built-in layout was identified;
the scan does not decode the payload or prove its values are correct.** Conversion
must still be checked. `Mixed` means that only part of a group has usable metadata;
for example, supported and unsupported TraceLogging variants can share an event
ID/version. Such groups remain in the missing-metadata report. The scan groups
observations, so retain the individual output events when examining a particular
source or schema.

### 2. Recover metadata from the evidence system

For a live evidence system, the matching publisher registry key and exported
publisher XML can identify candidate binaries. Use collection procedures
appropriate to the investigation. Substitute the GUID and registered publisher
name identified by the report or `wevtutil ep`:

```powershell
$guid = '{00000000-0000-0000-0000-000000000000}'
$key = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Publishers\$guid"
Get-ItemProperty $key | Select-Object ResourceFileName, MessageFileName, ParameterFileName
wevtutil gp 'Microsoft-Windows-Example' /ge:true /gm:false /f:xml |
  Set-Content -Encoding utf8 .\provider.xml
```

For a disk image, inspect the evidence SOFTWARE hive and filesystem using
forensic tools. Interpret registry paths and environment-variable references
against that installation. The CLI does not load an offline hive, resolve its
paths, or retrieve files automatically.

Recover the referenced DLL/EXE/SYS files from the evidence installation, along
with the original provider `.man` when available. Keep each file's origin and
hash. A registry path is a recovery lead; it does not establish that a file from
the analysis host is the matching schema.

| Option | Accepted input | Role |
| --- | --- | --- |
| `--manifest PATH` | Event manifest `.man` XML | Supplies a payload schema for matching provider/event/version records. |
| `--resource PATH` | Recovered DLL/EXE/SYS | Parses supported event resources statically, without loading or executing the binary. |
| `--provider-info PATH` | `wevtutil gp` publisher XML | Supplies publisher names and candidate paths for reports. **It does not supply a payload schema.** |

All three options can be repeated. Rerun the scan with the same metadata inputs
that will be used for conversion:

```powershell
& $etw .\evidence\trace.etl --manifest .\evidence\schema.man `
  --resource .\evidence\provider.dll --provider-info .\evidence\provider.xml `
  --scan --format json --output .\analysis\scan-with-metadata.json
```

### 3. Convert to JSONL

```powershell
& $etw .\evidence\trace.etl --manifest .\evidence\schema.man `
  --resource .\evidence\provider.dll --provider-info .\evidence\provider.xml `
  --output .\analysis\trace.jsonl
$LASTEXITCODE
```

Metadata options are optional; a conversion without them still retains events
whose schemas are missing. JSONL is the default. To use the historical nested
`Events` / `Event` shape with the added forensic fields:

```powershell
& $etw .\evidence\trace.etl --format json --output .\analysis\trace.json
```

Multiple ETLs may be supplied before the options. They are processed in input
order, one file at a time; the result is not a globally time-sorted merge.
Conversion makes a schema preflight pass and then reads the inputs again.
Keep the input files unchanged throughout the run.

### 4. Review decoding outcomes and preserve raw output

Inspect `decode_status`, `metadata_source`, `metadata_provenance` when present,
and `decode_note` for the events relevant to a finding. For example, list events
that were not fully decoded:

```powershell
Get-Content .\analysis\trace.jsonl -Encoding UTF8 | ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object decode_status -ne 'decoded' |
  Select-Object source_file, provider_guid, event_id, version, decode_status, decode_note
```

| JSONL field | Interpretation |
| --- | --- |
| `event_header` | Original record header: `provider_guid`, `event_id`, `version`, `flags`, `channel`, `level`, `opcode`, `task`, and `keyword`. Retained separately from the decoder's identity. |
| `provider_guid`, `event_id`, `version` | Identity used by the schema or custom parser; it can differ from `event_header` for classic/custom events. Unknown-event fallback retains the original header identity. |
| `properties` | Values produced by the selected decoder. Assess them together with the status and schema provenance. |
| `metadata_source` | Schema/decoder origin: `embedded`, `trace_logging`, `external_manifest`, `external_pe_resource`, `builtin_parser`, `local_cache`, or `unknown`. |
| `metadata_provenance` | Supplied manifest/PE provenance includes SHA-256 information. `builtin_parser` identifies the parser/layout revision, record version and pointer size. |
| `decode_status`, `decode_note` | The event's interpretation outcome and diagnostic reason when available. |
| `raw_payload` | Base64 bytes of the event payload, retained for decoded and unresolved events. This is not a copy of the complete ETL record or file. |
| `raw_extended_data` | Extension type/flags, declared size and Base64 `raw_data`, including unparsed SID/session/TraceLogging metadata. Process-local native addresses are excluded. |
| `extended_data_errors` | Invalid extension lengths, pointers, duplicate interpretations or snapshot-limit failures. An unavailable item's `raw_data` is `null`, with `data_error`; it is not fabricated zero bytes. |
| `source_file` | Input ETL path for this event. |
| `stack_match_id`, `stacks` | Stack correlation ID and numeric addresses from extended event data, when present. Addresses are not symbolized. |
| `timestamp`, `raw_timestamp`, `trace_clock` | Raw ETW clock value and available clock context. **`timestamp` is not a UTC timestamp.** |

Legacy JSON also preserves the original header at `Events[].Event.event_header`;
`raw_extended_data` and `extended_data_errors` are under that same event object.
Its existing stack fields are named `StackMatchId` and `Stacks`.
Use JSON tools that preserve 64-bit integers when handling timestamps, keywords,
pointers, or stack addresses; floating-point-only consumers can round these values.
Extended-data snapshots are limited to 1,024 items and 16 MiB per event; exceeding
a limit produces diagnostics. Keep the original ETL for bytes that could not be copied.

Statuses include `decoded`, `metadata_missing`, `unsupported`, `partial`, and
`decode_error`. Treat the last four as requiring review; retain the raw payload
and diagnostic rather than interpreting an empty property bag as an empty event.
A `decoded` result records what this implementation could interpret with its
selected schema or custom parser; it does not independently authenticate that
schema or the underlying evidence.

Generated schema decoders and built-in parsers must consume the complete payload
before emitting a `decoded` event. Extra or truncated bytes produce a `decode_error` raw fallback
rather than publishing incomplete properties as decoded. Full consumption does
not prove that the chosen layout is correct. Schema conflict comparisons also
account for array counts, length rules, and their reference targets, since
matching property names and primitive types alone do not establish the same
layout.

The default excludes analysis-host provider registration. If you deliberately
need it as a final fallback, enable it explicitly:

```powershell
& $etw .\evidence\trace.etl --allow-local-metadata --output .\analysis\trace-local.jsonl
```

Those events are labeled `local_cache`. This option does not check whether the
host's provider build matches the acquired system. It also does not start or
consume a real-time ETW session. Keep this choice in the case notes and review
any results derived from it.

### 5. Query the supported kernel investigation records

These built-in parsers accept classic records with an unambiguous 32/64-bit
header flag. Other versions/opcodes retain raw output unless another supported
schema resolves them. Paths remain as recorded, including NT device paths; they
are not mapped through the analysis host's drive letters.

| Layout | Supported event names | Useful properties |
| --- | --- | --- |
| Process v4 | `Kernel/Process/Start`, `Stop`, `DCStart`, `DCStop` | `ProcessId`, `ParentId`, `UniqueProcessKey`, `ImageFileName`, `CommandLine`, `UserSID` |
| Image v2 | `Kernel/Image/Load`, `Unload`, `DCStart`, `DCStop` | `ProcessId`, `ImageBase`, `ImageSize`, `FileName` |
| FileIO name v2 | `Kernel/FileIO/Name`, `FileCreate`, `FileDelete`, `FileRundown` | `FileKey`, `FileName` |

For example, stream decoded built-in records from a saved JSONL file:

```powershell
function Read-Trace {
  Get-Content -LiteralPath .\analysis\trace.jsonl -Encoding UTF8 |
    ForEach-Object { $_ | ConvertFrom-Json } |
    Where-Object { $_.metadata_source -eq 'builtin_parser' -and $_.decode_status -eq 'decoded' }
}

# Process starts: use the payload PID, not the event header's reporting PID.
Read-Trace | Where-Object event_name -eq 'Kernel/Process/Start' |
  Select-Object source_file, raw_timestamp,
    @{n='ProcessId'; e={$_.properties.ProcessId}}, @{n='ParentId'; e={$_.properties.ParentId}},
    @{n='UniqueProcessKey'; e={$_.properties.UniqueProcessKey}},
    @{n='CommandLine'; e={$_.properties.CommandLine}}

# Module paths, keeping load/unload/rundown observations distinguishable.
Read-Trace | Where-Object event_name -like 'Kernel/Image/*' |
  Select-Object source_file, raw_timestamp, event_name,
    @{n='ProcessId'; e={$_.properties.ProcessId}}, @{n='FileName'; e={$_.properties.FileName}}

# Preserve each FileKey/name observation rather than replacing earlier mappings.
Read-Trace | Where-Object event_name -like 'Kernel/FileIO/*' |
  Select-Object source_file, raw_timestamp, event_name,
    @{n='FileKey'; e={'0x{0:x}' -f [UInt64]$_.properties.FileKey}},
    @{n='FileName'; e={$_.properties.FileName}}
```

`DCStart`/`DCStop` and `FileRundown` describe snapshots, not the time of the
underlying creation, load or access. FileName output can consist mostly of
rundown records. **FileKey is a name-mapping key, not an open FileObject; these
records do not establish reads, writes or which process accessed a file.** PID
and key reuse also require source/time context; the CLI does not reconstruct a
complete process tree or join file operations. TCP/IP and Thread decoding are
outside this built-in coverage. All example timestamps remain raw, not UTC.

### Exit codes and incomplete results

| Code | Meaning |
| --- | --- |
| `0` | The requested operation completed; unresolved/invalid events or reported collection loss may still be present. |
| `1` | Invalid command line or missing input arguments. |
| `2` | Input/output or metadata-file access/read failure. |
| `3` | ETL processing failed during preflight or conversion. |

Check stderr and the exit code before using a result. An output file may remain
after a failed conversion; the presence of JSON or JSONL alone does not prove the
run completed. `--report-missing` can return `0` while listing missing metadata.
Conversion also prints `Event decode outcomes` to stderr, with `total`, `decoded`,
`metadata_missing`, `unsupported`, `partial` and `decode_error` counts. These come
from the conversion pass; the scan reports schema availability. Review all
non-decoded outcomes even when the command returns `0` or prints `Finished`.
If the ETL header reports `EventsLost` or `BuffersLost`, stderr includes a
source-specific `WARNING` with both counters. Conversion continues and can
return `0`; records lost during collection cannot be recovered by decoding.
Zero counters or no warning also do not prove that collection was complete.

## Coverage and validation

WPP/TraceMessage decoding is unsupported; classic/MOF coverage is limited. Static
compiled-manifest parsing supports a subset of CRIM 3.1/5.1. Map-dependent records
and unsupported arrays/structures are reported rather than fully decoded. Native
Windows compatibility, malformed/truncated ETLs, and broad provider coverage
require further testing. Compare representative events, counts, identities, and
values with an independent decoder before relying on a new provider or build.
See [Investigation validation](docs/investigation-validation.md) for measured
results and usefulness limits, and the
[validation procedure](docs/validation.md) for acceptance criteria.

Run the portable tests after building:

```powershell
dotnet test ETW2JSON.sln -c Release --no-build
```

For the native ETW smoke test, run elevated Windows PowerShell at the repository
root:

```powershell
.\tests\fixtures\Verify-EventSourceFixture.ps1
```

The script generates repository-owned EventSource, EventWrite, and TraceLogging
events in a temporary ETW session; checks default/external-manifest/static-PE
conversion, scan and missing reports, expected counts and values, raw payloads,
and ETL hashes; and removes the session. Generated ETL files remain local.
Both CI workflows include this check. Its existence or a portable unit-test pass
does not establish that it ran successfully on the current build or that
real-world evidence has equivalent coverage.

Microsoft attribution and the MIT license are retained in [LICENSE](LICENSE).
