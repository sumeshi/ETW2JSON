# Investigation validation record

This review uses Windows-produced public ETLs as well as synthetic error cases.
The useful unit of confidence is a tested event layout and field interpretation,
not the number of passing unit tests or a successful conversion exit code.

## Corpus and independent references

The four ETLs and the CLR manifest come from the MIT-licensed
[`microsoft/perfview` commit `29b21620`](https://github.com/microsoft/perfview/tree/29b21620a6c295979e83dc99008262ad2f3c6a2d/src/TraceEvent/TraceEvent.Tests/inputs).
Exact hashes, sizes, provenance, and license information are in the
[corpus manifest](../tests/ETW2JSON.CorpusReplay/corpus-manifest.json).

| ETL | Physical records read independently on Linux | Purpose |
| --- | ---: | --- |
| `primitive-types.etl` | 7 | TraceLogging scalar types and raw-record retention. |
| `PerfViewData.etl` from `gcevents.etl.zip` | 71 | Supplied CLR manifest and literal-value checks against the upstream baseline. |
| `SelfDescribingSingleEvent.etl` | 23 | A self-describing regression trace, including unsupported metadata. |
| `net.4.5.x86.etl` from `net.4.5.x64.etl.zip` | 176,217 | Mixed event families, kernel investigation records and custom symbol metadata. |

These are performance and regression traces, not a representative incident
response corpus. No registry events occur in the selected large trace. The
archive/file name is not an architecture indicator: that ETL's session pointer
size is 8 and it also contains 32-bit modern event headers.

Three checks have different scopes:

1. A separate **Dissect ETL 3.14** process reads the actual ETL container and
   exports records. The managed replay checks original data conservation and
   exercises the decoder. Native callback flags must be inferred from on-disk
   markers, and buffer order differs from `ProcessTrace` order. This does not
   validate the native reader. Dissect is an external AGPL tool; its source is
   not copied into or linked into ETW2JSON.
2. A separate Dissect manifest parser supplies an oracle for every selected
   Process v4, ImageLoad v2 and FileIOName v2 record. The comparer requires every
   selected record and reference field to decode and match. A negative control
   that changes one `ParentId` value produces exactly one mismatch and a failing
   exit status.
3. On Windows, an independent SDK-declared raw reader checks native callback
   records against the CLI's output. TraceEvent 4.0.0 separately compares fields
   for records it can map and decode. Its identity/PID fixups and metadata lookup
   are accounted for; unresolved or ambiguous mappings remain unverified.

Reproduction instructions are in the [managed replay helper](../tests/ETW2JSON.CorpusReplay/README.md)
and [Windows validator](../tests/ETW2JSON.NativeValidation/README.md).
The native raw check does not compare activity IDs or extended-data items;
portable replay and dedicated snapshot tests cover those fields separately.

## What the additional review found

The original first-pass tests did not establish sufficient investigation utility.
The second review found and addressed the following problems:

- All 17,296 selected process/thread/image/file/network/disk records initially
  remained `metadata_missing` with default settings. Added parsers are limited
  to layouts independently checked in this corpus, as detailed below.
- Classic events with header event ID 0 were conflated across opcodes, and
  embedded classic schemas used the wrong provider identity. The cache and
  inventory now retain the class EventGuid and a separate `classic_opcode`.
- The inherited image/symbol parsers used incorrect pointer widths or discarded
  payload process IDs. Their layout handling, provenance and scan outcomes were
  corrected, and malformed/extra payload is retained as a decoding error.
- TraceLogging provider traits used the wrong extension type constant (`0xD`
  rather than Windows' `0xC`), affecting schema identity and validation.
- Trace loss counters were ignored. Collection loss now emits a source-specific
  warning; the missing events cannot be recovered by conversion.
- SID/session/schema/unknown extended-data bytes were discarded. They are now
  snapshotted with bounds and diagnostics, separately from payload bytes.
- Windows scalar comparison found boolean `False`/`True` represented as numeric
  `0`/`1`, and signed Int64 values represented as huge unsigned values. Generated
  decoding now respects these TDH output types without changing wire lengths or
  array-count references.

## Verified managed decoding coverage

For the selected 17,296 investigation records, the original output retained all
records but decoded **0**. After the version-limited additions:

| Family | Strictly supported layout | Records | Independent property values compared |
| --- | --- | ---: | ---: |
| Process | v4, opcodes 1/2/3/4 | 76 | 912 |
| ImageLoad | v2, opcodes 10/2/3/4 | 3,920 | 47,040 |
| FileIOName | v2, opcodes 0/32/35/36 | 11,183 | 22,366 |
| Total | These layouts only | **15,179** | **70,318** |

All selected reference records and property values matched; missing fields,
undecoded selected records and mismatches were zero. The 17,296-record replay
also had no checked header, payload, extended-data, timestamp, source, PID/TID,
activity or output-count mismatches. The remaining **2,117** records were
`metadata_missing`, not successfully decoded. The real classic records in this
comparison are 64-bit; 32-bit layout support is additionally tested synthetically.

The file result is mostly **11,112 rundown name records**. This is not an 88%
success rate for file access operations. `FileKey` identifies a name entry and
is not an open-file `FileObject`. Raw NT paths are not translated through the
analysis host's drives or device mappings.

With the supplied official CLR manifest, the 71-record GC trace yielded 22
`decoded`, 14 `unsupported` and 35 `metadata_missing` records. Of the 22 decoded
records, 11 could be uniquely associated with untruncated upstream text baseline
records; their 26 common literal field values matched. The other 11 remain
unverified against that text baseline because of ambiguous matches or rounding.

## An investigation question checked with the sample

The new process parser identifies target PID **3404**, parent **1664**, image
`Test.exe`, and command line `test.exe`. The matching process key identifies an
exit about **5.0441312 seconds** later with exit status 0. There are 25 image-load
records for that payload process ID. These values agree with the independent
reference, so process lineage, command-line review and module inventory are
concrete supported uses for the checked layouts.

The process-start **header** PID is 1664, while its **payload** `ProcessId` is
3404. The header can identify the creator/executing context rather than the
subject of the event. Use payload semantics for the investigation question and
retain the original header for provenance. PID and key reuse, missing records,
and rundown events must be accounted for when linking a real case.

## Windows execution and remaining limits

The Windows run for commit `e2425a5` passed the unit suite and the repository's
generated EventSource/EventWrite/TraceLogging smoke test. The subsequent
[diagnostic run](https://github.com/sumeshi/ETW2JSON/actions/runs/39565658668)
confirmed native raw equality for the 7-record scalar trace and 23-record
self-describing trace. It also exposed the scalar type errors described above
and reported zero compared fields for the self-describing trace; those results
were failures/incomplete coverage, not a successful semantic validation.

The current changes require another Windows comparison run. A self-describing
record retained as `unsupported` is useful evidence preservation, but does not
establish that its properties can be used in a finding. Passing raw checks or
some field comparisons must not conceal those coverage gaps.

These results support scoped extraction of the checked process/module/name
layouts and metadata recovery work. They do not establish a general Windows
forensic timeline or complete event coverage. Thread, TCP/IP, UDP, disk and
other versions still need supported schemas or additional validated parsers;
registry investigation has not been exercised. Timestamps remain raw clocks,
not validated UTC. No claim is made about every Windows build, live acquisition,
collection completeness, or resistance of the Windows ETL parser itself to
arbitrary hostile files.
