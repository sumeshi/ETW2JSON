# Saved portable replay results

These compact reports were produced on **2026-10-21 UTC** after the final
empty-template fix, from application and helper source at commit
`f6d8db5722637d4a87d39b1f95423202cc097757`. The replay ran after that commit
(08:15:08–08:15:30 UTC). [`index.json`](index.json) records the executed assembly
hashes, input provenance, timings, and saved report hashes. Incremental build
output timestamps can predate the commit that records the same source.

This is managed decoding on Linux. It does not validate native `OpenTrace`,
`ProcessTrace`, TDH, UTC conversion, symbolization, or acquisition completeness.
It uses public PerfView test traces and a separate Dissect reader. Instructions
and pinned dependencies are in the
[replay helper README](../../../tests/ETW2JSON.CorpusReplay/README.md).

## Reports

| Report | What it checks |
| --- | --- |
| `full-default.summary.json` | All 176,217 physical records, without an external manifest; output count, order, original headers, payload, extended bytes, timestamp and source. |
| `full-clr-manifest.summary.json` | The same records with the pinned official CLR manifest; coverage and conservation. |
| `gcevents-clr-manifest.summary.json` | All 71 records of the smaller GC trace with that manifest. |
| `full-*.reference-comparison.json` | Each of 15,179 supported kernel records and 70,318 property values against the independent Dissect reference. |
| `gcevents.baseline-comparison.json` | 26 literal values in 11 unambiguously matched upstream reference records. Other decoded records remain unverified by this comparison. |
| `stacks-comparison.json` | Match IDs and 19,660 addresses in 374 stack records, independently read from extension bytes. |
| `empty-template-error-comparison.json` | All 271 incomplete-schema records retain manifest provenance and report all 425 payload bytes as unconsumed. They remain decoding errors. |

An additional check at **2026-10-21 08:34:28 UTC** is saved in
[`image-timestamp-reference-comparison.json`](image-timestamp-reference-comparison.json).
The [official Image_Load MOF reference](https://learn.microsoft.com/en-us/windows/win32/etw/image-load)
and Dissect's v2 schema both declare `TimeDateStamp` as UInt32. In all four
selected records, raw bytes `82fc1699` at offset 24 decode to **2,568,420,482**,
matching the independent oracle and application output; TraceEvent 4.0.0's
static `Int32` property represents those same bits as **−1,726,546,814**. The
report pins the official documentation source commit, schema hash, raw record
indices, and existing replay output hash. This supplements the original replay;
its source commit and assembly hashes in `index.json` are unchanged.

All comparisons above have zero mismatches. Coverage limits and unsupported
records remain visible in the reports; matching raw bytes alone does not verify
decoded properties. None of these inputs contains TraceLogging metadata; the
portable helper would explicitly skip such records.

Large JSONL outputs and public ETL files are intentionally kept outside the
checkout. `${CORPUS_DIR}` replaces the temporary absolute directory in saved
summary paths. Summary `output_sha256` values identify the original, unmodified
JSONL outputs, including their original manifest provenance paths.

The empty-template report was checked by streaming the full manifest output:
every `decode_error` had provider `763fd754-7086-4dfe-95eb-c01a46faf4ca`, event
4/version 2, empty properties, `metadata_source=external_manifest`, the pinned
manifest SHA-256 in provenance, and the exact note
`InvalidOperationException: Event payload has 425 unconsumed bytes; the schema does not describe the complete payload.`
All 271 payloads were independently Base64-decoded to confirm their 425-byte
length. This checks diagnostic accuracy, not a schema for those fields.
