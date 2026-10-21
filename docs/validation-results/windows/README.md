# Saved Windows check summaries

[`check-summaries.json`](check-summaries.json) preserves the actual public check
annotations from the successful [Windows x64 run](https://github.com/sumeshi/ETW2JSON/actions/runs/39570311868)
at commit `06eaa76f3cb0bec89d8b785aa53fae887f25f069` on 2026-10-21 UTC.
The recorded job steps all succeeded, including unit/self/contract checks,
the generated ETL smoke fixture and the public corpus comparison.

These are **compact public summaries**, not complete `comparison.json` files.
They retain complete raw/semantic/skip counters and sampled diagnostics. Full
per-provider reports, before/after input hashes, CLI outputs and logs are in the
linked run's `etw2json-validation-39570311868` artifact, retained for 14 days.
The wrapper checks those hashes and requires zero raw mismatches before accepting
any case; the compact annotations do not include the hash fields.

The positive cases compare only supported, mapped fields. The metadata-missing
and nested-struct cases are explicit negative tests, with exact provider/status/
source/reason counts and `semantic_validation_completed=false`. Their acceptance
does not verify decoded values. Skipped/unmatched records and all nondecoded
outcomes remain unverified for interpretation.

See the [validation record](../../investigation-validation.md) for results and
limits, and the [validator instructions](../../../tests/ETW2JSON.NativeValidation/README.md)
for reproduction. Both native consumers use the Windows ETW container reader;
the [portable Dissect comparison](../portable/README.md) provides a separate
container implementation for its documented scope.

## Final acceptance run

[`acceptance-check-summaries.json`](acceptance-check-summaries.json) records the
successful [run at `c2149b0`](https://github.com/sumeshi/ETW2JSON/actions/runs/39575882804)
after correcting descriptor-dependent TraceLogging name caching. It includes the
same five public corpus cases and the generated fixture's same-schema START/
STOP assertions in JSONL and legacy JSON. The run passed 251 unit tests, 102
validator self-checks and 27 corpus-contract checks. Its complete artifact is
`etw2json-validation-39575882804`, also retained for 14 days. The compact-summary
limitations above apply to this file as well.
