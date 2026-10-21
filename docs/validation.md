# Validation and investigation readiness

## Current assessment

ETW2JSON has useful evidence-oriented features, but it has not yet demonstrated
broad reliability on real investigation ETLs. Portable tests exercise controlled
event records and metadata; they cannot establish that Windows reads every
record in an acquired file correctly or that a recovered schema matches the
system that produced it. Treat a new provider/build combination as unvalidated
until it passes the native and reference checks below.

This page records the initial review and the validation procedure. The later
review includes Windows native runs, public ETL replay and independent field
comparisons; see [Investigation validation](investigation-validation.md) for the
current measured results, supported layouts and remaining failures or gaps.

The first review was checked on 2026-10-21, starting from commit `61a71fe`, on
Linux with the SDK selected by `global.json`. At that point, native ETW
conversion, the Windows fixture and independent decoder comparisons had not
been run. The following results are that initial record, not the latest suite
size or Windows outcome:

| Initial check | Historical result on Linux / .NET SDK 10.0.401 |
| --- | --- |
| Locked solution restore | Passed; dependency declarations and lockfiles unchanged. |
| Release solution build | Passed; 0 errors, 16 existing obsolete-API/unused-variable warnings. |
| Portable tests after the first review changes | 108 passed, 0 failed, 0 skipped (42 existing tests and 66 added regression cases). |
| Native Windows fixture | Not run at the time of the first review. |
| Acquired ETL corpus / independent decoder comparison | Not run at the time of the first review. |

## Regression checks from the first investigation review

The review first reproduced the failure in a test, then changed the decoder or
reporting behavior. These tests use synthetic records, not acquired ETLs.

| Failure or evidence gap | Required behavior | Regression tests |
| --- | --- | --- |
| Equal property names/types hid different array counts, lengths, or reference targets; conflict fallback could mislabel supplied schemas as embedded. | Compare the complete operand layout; report conflicting schemas with their actual origin and keep raw bytes instead of choosing an interpretation. | `SchemaConflictTests` |
| A short schema read only a prefix of a payload and reported `decoded`. | Generated schema decoders must consume the complete payload before committing an event. A mismatch emits a raw `decode_error` event; subsequent events remain readable in JSONL and legacy JSON. | `PayloadValidationTests` |
| Reversed counted strings read their two-byte count in the wrong order; odd UTF-16 byte counts could be silently shortened. | Respect the declared byte order, reject invalid lengths, and leave the next field at the correct offset. | `CountedStringTests` |
| Supported and unsupported records sharing a provider/ID/version could appear fully resolved in the scan. | Keep per-record failures visible, including in the missing-metadata report (`Mixed` within one source; differing outcomes across sources may be `Conflict`). A genuinely missing schema can still be resolved by a later embedded manifest. | `ScanIntegrityTests` |
| Cross-source scan comparison ignored operand lengths/counts and could label legitimate distinct TraceLogging shapes as conflicts. | Compare full layouts for schemas identified by provider/ID/version; allow self-describing TraceLogging records to carry different valid shapes. | `ScanSchemaShapeTests` |
| JSONL omitted extended stack data already retained by the runtime and legacy writer. | Preserve 32/64-bit stack addresses and match IDs without carrying them into the next event. | `JsonlStackTests` |
| Schema/custom-parser identities can differ from the original record, and header flags/channel were absent. | Add an `event_header` object copied from the original record in both output formats. Preserve the existing decoder identity fields. | `EventHeaderPreservationTests` |
| Failed TDH lookup for a self-describing TraceLogging record could lose its schema origin and fall through to an unrelated external schema; external conflicts could also override valid self-describing records. | Resolve self-describing metadata before supplied schemas, retain per-record failures as diagnostic/raw fallback, and keep failures in the scan. Inject native error responses to test the managed control flow; actual TDH execution still requires Windows. | `TraceLoggingFailureTests` |

The initial payload-consumption check covered generated schema decoders. The
later review also adds consumption checks to built-in parsers and independently
compares selected kernel layouts; those results are in the current investigation
validation record. Full consumption does not prove that a schema is correct:
two different layouts can consume the same number of bytes.

## Run the portable checks

From the repository root with the pinned .NET SDK available:

```powershell
dotnet restore ETW2JSON.sln --locked-mode
dotnet build ETW2JSON.sln -c Release --no-restore
dotnet test ETW2JSON.sln -c Release --no-build
```

Record the actual test summary and failures. A build or CLI help check alone is
not a decoder validation. A schema-only scan does not read property values.
Conversion's stderr `Event decode outcomes` summary reports actual interpretation
statuses from the conversion pass. Preserve it with the exit status and other
diagnostics; an exit code of `0` permits unresolved or erroneous event decodes.

## Establish a Windows baseline

Run the repository-owned fixture on an elevated Windows host after building:

```powershell
.\tests\fixtures\Verify-EventSourceFixture.ps1
```

Keep its generated ETL, manifests, synthetic provider PE, expected values,
`generation.json`, conversion outputs, scans, and reports with the validation
record. Record the Windows build, SDK/runtime versions, tool commit, exact
command, stdout/stderr, and exit status. The fixture checks known emitted values
and counts for EventSource, EventWrite and TraceLogging; it also checks raw
payload preservation and that the ETL hash is unchanged. It does not cover every
Windows provider or compare the decoder with an independent implementation.

For the native error paths, test malformed self-describing metadata and TDH
failures as well as valid events. Native calls must not cause a record with a
bad per-event schema to borrow an unrelated external schema or disappear behind
another record's successful scan result.

## Validate representative investigation traces

Use legally shareable generated or sanitized traces with independently known
expected records. Keep real case data outside the repository. Collect source
Windows build/provider versions and matching metadata, then repeat with a
different analysis host so accidental dependence on local registration is
detectable.

| Scenario | Acceptance evidence |
| --- | --- |
| ETL and matching original `.man` or provider PE | Check provider/ID/version, property names, types, values and event counts against known emitted data and an independent reader. |
| No recovered metadata | Relevant unresolved records remain with their original header identity, exact payload bytes and an explicit status. No analysis-host registration is used without opt-in. |
| Wrong or conflicting metadata | Conflicts and length/layout errors are visible. No plausible-looking decoded values are accepted solely because the CLI exits successfully. Include equal-size wrong layouts in manual/reference checks. |
| Multiple ETLs and reused provider/ID/version | Check per-source provenance and schema isolation, including differing provider builds and TraceLogging event shapes. Do not assume a globally timestamp-sorted merge. |
| Truncated/corrupt ETL or callback/output failure | Check nonzero exit status, stderr, and which records were emitted. Mark any residual output incomplete. Verify the input hash is unchanged. |
| 32/64-bit events, stacks and activity links | Check original header flags, IDs, address widths, stack frames, activity and related-activity IDs against the source reader. |
| Raw clocks and timeline correlation | Verify clock type/frequency and an independently known time anchor before converting or comparing timestamps. The current `timestamp` is not UTC. |
| Large traces and collection loss | Measure time/memory, compare record counts, and check the trace's loss information independently. Successful conversion cannot recover events lost during collection. |

Suitable Windows reference tools include `tracerpt` and a separate established
ETW reader such as PerfView/TraceEvent or WPA. Record the exact tool/version and
metadata configuration. Compare matching event semantics rather than JSON
formatting. A disagreement requires investigation; agreement between two readers
using the same incorrect host schema is not proof of correctness.

Do not infer complete coverage from equal total counts alone. Match individual
records by source, original header identity, timestamp and sequence/activity
information where available; account explicitly for control and metadata
records. Preserve raw outputs from both readers and document excluded fields or
events with a reason.

## Remaining development priorities

1. Extend the Windows and independent-reader baseline to representative
   investigation traces and additional provider builds. Resolve remaining
   mismatches and unverified comparisons described in the current investigation
   record before claiming broader coverage, including other classic/MOF layouts.
2. Add persistent run records containing tool/version, options, input/metadata
   hashes and completion state. Conversion now reports per-status counts on
   stderr; the examiner must still retain the other details separately.
3. Extend collection-loss warnings into persistent completeness records and add
   validated UTC normalization where the trace clock supplies sufficient context.
   Neither an empty missing-metadata report nor readable JSON proves a complete
   timeline, and zero reported loss counters do not establish complete collection.
4. Expand schema support from observed, tested investigation needs. WPP,
   map-dependent records, and unsupported array/structure forms remain explicit
   coverage limits; do not silently reinterpret them as supported.

For a finding, retain the original ETL and metadata, tool identity, command and
diagnostics, output hashes, relevant raw records, and reference comparison.
Acceptance should be scoped to the providers, versions, event types and hosts
actually exercised.
