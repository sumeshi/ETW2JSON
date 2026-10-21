# ETW2JSON

ETW2JSON converts Windows ETL files to JSON Lines (JSONL) or legacy-shaped JSON.
This fork extends [Microsoft ETW2JSON](https://github.com/microsoft/ETW2JSON) for
analysis of traces acquired from another Windows installation. It retains the
native `OpenTrace`, `ProcessTrace`, and TDH reader and uses .NET 10.

The aim is to make the origin and limits of a decode visible: supply schemas
recovered with the evidence, distinguish them from analysis-host metadata, and
retain raw event payloads when decoding is unavailable. **Successful conversion
does not establish forensic accuracy or complete decoding.** Real-world ETL
coverage and agreement with independent decoders still need validation; see
[Validation and investigation readiness](docs/validation.md).

## What changed from Microsoft ETW2JSON

The comparison below uses the [upstream implementation at
`4d145bf`](https://github.com/microsoft/ETW2JSON/tree/4d145bf61e9daad98a58166ae8d220577eaf51bc)
as its baseline.

| Investigation problem in the upstream workflow | Customization | What it enables |
| --- | --- | --- |
| Metadata lookup used TDH on the analysis host, with EventSource XML fallback; output did not identify the schema's origin. A different host can have different provider registrations. | Record `metadata_source` and provenance. Analysis-host registration requires `--allow-local-metadata`; it is off by default. | Distinguish ETL-embedded and supplied evidence schemas from analysis-host fallback when assessing a decoded value. |
| The CLI could not accept recovered provider manifests, evidence PE resources, or publisher exports. An acquired ETL can lack the schemas installed on its source system. | Add repeatable `--manifest`, static `--resource`, and `--provider-info` inputs. | Decode supported events using recovered `.man`/PE schemas, and use exported publisher information to guide further collection. |
| The unknown-event fallback set event ID/version to zero and omitted the original payload. | Preserve event header identity, Base64 `raw_payload`, source file, and per-event decode status. | Keep unresolved events identifiable and retain their payload for later analysis with better metadata. |
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
`--report-missing` includes unresolved, conflicting, invalid, and unsupported
metadata, with collection guidance. Without `--format json`, these reports are
human-readable text.

**A scan status of `Resolved` means that a schema was found; the scan does not
decode the payload or prove that its values can be read correctly.** Conversion
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
Get-Content .\analysis\trace.jsonl | ForEach-Object { $_ | ConvertFrom-Json } |
  Where-Object decode_status -ne 'decoded' |
  Select-Object source_file, provider_guid, event_id, version, decode_status, decode_note
```

| JSONL field | Interpretation |
| --- | --- |
| `event_header` | Original record header: `provider_guid`, `event_id`, `version`, `flags`, `channel`, `level`, `opcode`, `task`, and `keyword`. Retained separately from the decoder's identity. |
| `provider_guid`, `event_id`, `version` | Identity used by the schema or custom parser; it can differ from `event_header` for classic/custom events. Unknown-event fallback retains the original header identity. |
| `properties` | Values produced by the selected decoder. Assess them together with the status and schema provenance. |
| `metadata_source` | Schema origin, such as `embedded`, `trace_logging`, `external_manifest`, `external_pe_resource`, `local_cache`, or `unknown`. |
| `metadata_provenance` | Additional source information when available; supplied manifest/PE metadata includes file/resource provenance and SHA-256 information. |
| `decode_status`, `decode_note` | The event's interpretation outcome and diagnostic reason when available. |
| `raw_payload` | Base64 bytes of the event payload, retained for decoded and unresolved events. This is not a copy of the complete ETL record or file. |
| `source_file` | Input ETL path for this event. |
| `stack_match_id`, `stacks` | Stack correlation ID and numeric addresses from extended event data, when present. Addresses are not symbolized. |
| `timestamp`, `raw_timestamp`, `trace_clock` | Raw ETW clock value and available clock context. **`timestamp` is not a UTC timestamp.** |

Legacy JSON also preserves the original header at `Events[].Event.event_header`;
its existing stack fields are named `StackMatchId` and `Stacks`.
Use JSON tools that preserve 64-bit integers when handling timestamps, keywords,
pointers, or stack addresses; floating-point-only consumers can round these values.

Statuses include `decoded`, `metadata_missing`, `unsupported`, `partial`, and
`decode_error`. Treat the last four as requiring review; retain the raw payload
and diagnostic rather than interpreting an empty property bag as an empty event.
A `decoded` result records what this implementation could interpret with its
selected schema or custom parser; it does not independently authenticate that
schema or the underlying evidence.

Generated schema decoders must consume the complete payload before emitting a
`decoded` event. Extra or truncated bytes produce a `decode_error` raw fallback
rather than publishing incomplete properties as decoded. This consumption check
does not cover the inherited custom parsers. Schema conflict comparisons also
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

### Exit codes and incomplete results

| Code | Meaning |
| --- | --- |
| `0` | The requested operation completed; unresolved or unsupported events may still be present. |
| `1` | Invalid command line or missing input arguments. |
| `2` | Input/output or metadata-file access/read failure. |
| `3` | ETL processing failed during preflight or conversion. |

Check stderr and the exit code before using a result. An output file may remain
after a failed conversion; the presence of JSON or JSONL alone does not prove the
run completed. `--report-missing` can return `0` while listing missing metadata.

## Coverage and validation

WPP/TraceMessage decoding is unsupported; classic/MOF coverage is limited. Static
compiled-manifest parsing supports a subset of CRIM 3.1/5.1. Map-dependent records
and unsupported arrays/structures are reported rather than fully decoded. Native
Windows compatibility, malformed/truncated ETLs, and broad provider coverage
require further testing. Compare representative events, counts, identities, and
values with an independent decoder before relying on a new provider or build.
See [Validation and investigation readiness](docs/validation.md) for the acceptance
criteria and remaining checks.

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
