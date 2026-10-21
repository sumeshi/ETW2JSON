# Native ETL comparison harness

This Windows x64 console compares the CLI with an independent raw-record consumer
and Microsoft TraceEvent **4.0.0**. It is a validation tool, not an ETL converter.
It does not reference ETW2JSON's assembly, native declarations or deserializer.

Build from the repository root with the SDK selected by `global.json`:

```powershell
dotnet restore tests/ETW2JSON.NativeValidation/ETW2JSON.NativeValidation.csproj --locked-mode
dotnet build tests/ETW2JSON.NativeValidation/ETW2JSON.NativeValidation.csproj -c Release --no-restore
dotnet tests/ETW2JSON.NativeValidation/bin/Release/net10.0-windows/ETW2JSON.NativeValidation.dll --self-check
```

`--self-check` runs portable checks of the declared interop layout, streaming
index serialization, value comparisons and bounded record matching, including
extra/omitted callbacks, ambiguous matches and PID/TID fixups. It does not read
an ETL or validate native execution.

On Windows x64, supply the built application DLL, one ETL, and a directory that
does not yet exist. Metadata options for the application can follow `--`:

```powershell
dotnet tests/ETW2JSON.NativeValidation/bin/Release/net10.0-windows/ETW2JSON.NativeValidation.dll `
  bin/Release/net10.0-windows/etw2json.dll trace.etl validation-results

dotnet tests/ETW2JSON.NativeValidation/bin/Release/net10.0-windows/ETW2JSON.NativeValidation.dll `
  bin/Release/net10.0-windows/etw2json.dll trace.etl validation-with-manifest `
  -- --manifest provider.man
```

The harness starts the CLI in a child `dotnet` process, retaining stdout, stderr,
exit code and JSONL. It independently consumes every native `EVENT_RECORD` using
`OpenTraceW`/`ProcessTrace` in `EVENT_RECORD | RAW_TIMESTAMP` mode, then compares
each JSONL event in callback order for:

- Exact event count; original provider GUID, ID, version, flags, channel, level,
  opcode, task and keyword from `event_header`.
- Original process/thread IDs and unconverted raw timestamp.
- Byte-for-byte raw payload and input source path.

Activity/related-activity IDs, stack extensions and other extended-data items are
not compared. A raw match is limited to the fields listed above.

It also reads the ETL with `ETWTraceEventSource`, first learning embedded manifests
and then comparing payload values. It registers TraceEvent's Dynamic, CLR and
Kernel parsers. A reference event is associated with a native/application record
using a window of at most 128 records and an 8 Mi-character buffer budget (plus
one pending record). The matching key includes raw clock, payload hash/length,
source provider, version, and original modern ID or classic opcode; TraceLogging
synthetic IDs are excluded. Classic source providers use public `TaskGuid`, which
is distinct from TraceEvent's normalized `ProviderGuid`.

Matching PID/TID is preferred; when TraceEvent has fixed them up, only a unique
strong-key candidate is accepted and that choice is counted. Ambiguous matches
are skipped. An extra reference callback does not consume a native record;
omitted callbacks do not shift every following comparison. Forward
resynchronization can evict a window only when all its raw timestamps precede
the current reference timestamp. Large reorderings, changed payloads and
out-of-window candidates remain unmatched. No reflection or private TraceEvent
API is used.

TraceEvent exposes `EventData()` and the public `TimeStampQPC` accessor, which reads
the unconverted header timestamp for this source. It does not publicly expose
the original `EVENT_RECORD`. Its source rewrites TraceLogging IDs and can fix up
classic identities or payloads before dispatch. The independent native pass is
therefore necessary; reference IDs are never substituted for original headers.

For mapped records, scalar values and supported arrays/structures are compared
with the application's `properties` when the application reports `decoded`.
Missing dynamic-parser fields are mismatches. Static-parser property aliases are
not guessed; absent names, unsupported values, reference read failures, and
reference-decodable events the application did not decode are counted separately.
The reference Dynamic parser may consult analysis-host TDH registration. Agreement
does not establish that those registrations match the acquired Windows system.

Results are written to `comparison.json`, with per-provider decoding coverage,
comparison/skip counters, source hashes, available event-loss indicators and the
up to 20 diagnostics per phase and 100 overall. `native-index.jsonl` stores a streaming raw-record index;
reference callback counts and unmatched native/reference records are semantic
coverage indicators. They do not change the separate full native-to-CLI raw
comparison outcome. The implementation retains the bounded matching window,
current event, provider counters and bounded diagnostics in memory. Artifacts can contain sensitive evidence paths and data;
keep them with the case's local validation results.

`application_not_decoded_reasons` records application `decode_status` and
`decode_note` counts, globally under `semantic` and per provider. It covers every
nondecoded application event, including events without reference payload fields.
One `application_coverage` diagnostic is emitted for each retained provider/reason,
so repeated missing-schema records do not hide a later unsupported reason. These
are coverage diagnostics, not raw or semantic mismatches. Reason dictionaries
retain up to 32 global or 16 per-provider reason variants; additional variants
are counted in an overflow bucket, and the original notes remain in the JSONL.

The reference kernel path mapper is explicitly set to the identity function so
file-name comparisons use the stored NT path. TraceEvent otherwise translates
those names through drive mappings. TraceEvent 4.0.0 also folds unsigned dynamic
integers into signed CLR types. A separate bounded reader checks flat
TraceLogging scalar declarations directly in extension type 11. Only a declared
UInt16/UInt32/UInt64 with default output format permits a negative reference
short/int/long to be reinterpreted at that width. These cases appear in
`reference_unsigned_reinterpretations`. Names do not select a type; signed
declarations, nondefault formats, arrays and unverified layouts use ordinary
comparison. This reader does not validate the complete extended-data output.
The documented classic Image v2 `TimeDateStamp` also has a scoped UInt32 rule:
the provider GUID, ID 0, version 2 and supported opcodes must all match before
TraceEvent's negative Int32 representation can be reinterpreted. The independent
MOF comparison confirms the four affected values. Other static fields retain
ordinary comparison, and this rule shares the separate reinterpretation counter.

The corpus wrapper has separate negative cases for absent metadata and a
self-describing struct. It requires the pinned input hash, complete native raw
equality and exact provider/status/source/reason counts. Accepted negative cases
keep exit `4` and `semantic_validation_completed=false`; they demonstrate the
specified fallback and do not pass semantic validation.

Run `pwsh -NoProfile -File tests/fixtures/Verify-CorpusContracts.ps1` from the
repository root to exercise the wrapper's acceptance rules without Windows ETW
or network access. The checks include rejection of changed hashes, extra records,
unexpected fallback reasons and semantic mismatches.

| Exit code | Meaning |
| --- | --- |
| `0` | `passed_with_limits`: raw records match and at least one payload field was compared without a mismatch. Read coverage and skipped outcomes; this does not mean all fields/providers were decoded. |
| `1` | Invalid invocation or paths. |
| `2` | CLI failed, raw/field mismatch, count mismatch, or a zero-record run. |
| `3` | Unsupported host or execution failed, including a callback failure. |
| `4` | Raw records match, but no semantic field could be compared. This is incomplete validation. |

Compilation/restoration on Linux does not execute the native comparison. Both raw
consumers rely on Windows' ETW container reader, so this is independent decoder
comparison rather than an independent implementation of the ETL file format.
An event-loss indicator also describes collection completeness, which comparison
of the available records cannot restore.

API/layout references: Windows SDK `evntrace.h` and `evntcons.h`,
[EVENT_TRACE_LOGFILEW](https://learn.microsoft.com/windows/win32/api/evntrace/ns-evntrace-event_trace_logfilew),
[EVENT_RECORD](https://learn.microsoft.com/windows/win32/api/evntcons/ns-evntcons-event_record),
and [TraceEvent v4.0.0 source](https://github.com/microsoft/perfview/tree/v4.0.0/src/TraceEvent)
(`TraceEvent.cs`, `ETWTraceEventSource.cs`, `DynamicTraceEventParser.cs`).
