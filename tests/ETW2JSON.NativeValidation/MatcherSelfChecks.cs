namespace ETW2JSON.NativeValidation;

internal static class MatcherSelfChecks
{
    internal static int Run()
    {
        int checks = 0;
        Guid provider = Guid.Parse("11111111-2222-3333-4444-555555555555");
        RawIndex Record(long ordinal, long? timestamp = null) => new(ordinal, provider, 0, 7, 1, 0, false,
            100, 200, timestamp ?? ordinal, 3, "payload", true);
        ReferenceIdentity Reference(RawIndex native) => new(native.ProviderGuid, (native.Flags & 0x100) != 0,
            native.EventId, native.Version, native.Opcode, native.ProcessId, native.ThreadId,
            native.RawTimestamp, native.PayloadLength, native.PayloadSha256);
        BoundedRecordMatcher Matcher(params RawIndex[] records)
        {
            int next = 0;
            return new BoundedRecordMatcher(() => next < records.Length ? new RecordPair(records[next++], "{}") : null);
        }
        void Require(bool passed, string message)
        {
            if (!passed) throw new InvalidOperationException("Bounded matcher check failed: " + message);
            checks++;
        }

        RawIndex first = Record(1), second = Record(2), third = Record(3);
        var matcher = Matcher(first, second, third);
        Require(matcher.Match(Reference(first)).Pair?.Native.Ordinal == 1, "exact record association");
        Require(matcher.Match(Reference(third)).Pair?.Native.Ordinal == 3, "omitted reference callback resynchronizes");
        Require(matcher.Match(Reference(second)).Pair?.Native.Ordinal == 2, "an earlier buffered record is retained");

        matcher = Matcher(first, second);
        Require(matcher.Match(Reference(first) with { PayloadSha256 = "extra-reference" }).Pair == null,
            "extra reference callback remains unmatched");
        Require(matcher.Match(Reference(first)).Pair?.Native.Ordinal == 1,
            "extra reference callback does not shift the native stream");

        MatchResult fixedUp = Matcher(first).Match(Reference(first) with { ProcessId = 900, ThreadId = 901 });
        Require(fixedUp.Pair?.Native.Ordinal == 1 && fixedUp.ContextFixedUp,
            "unique strong identity permits a reported PID/TID fixup");
        RawIndex differentContext = first with { Ordinal = 2, ProcessId = 101 };
        MatchResult preferred = Matcher(first, differentContext).Match(Reference(differentContext));
        Require(preferred.Pair?.Native.Ordinal == 2 && !preferred.ContextFixedUp,
            "matching raw PID/TID disambiguates candidates");
        MatchResult ambiguous = Matcher(first, first with { Ordinal = 2 }).Match(Reference(first));
        Require(ambiguous.Pair == null && ambiguous.FailureReason == "ambiguous_reference_to_native_mapping",
            "indistinguishable candidates are skipped");

        Require(Matcher(first).Match(Reference(first) with { EventId = 8 }).Pair == null,
            "different modern event IDs are not paired");
        RawIndex traceLogging = first with { EventId = 0, TraceLogging = true };
        Require(Matcher(traceLogging).Match(Reference(traceLogging) with { EventId = 123 }).Pair != null,
            "TraceLogging's synthetic reference ID is not treated as an original ID");
        RawIndex classic = first with { Flags = 0x100, EventId = 0, Opcode = 32 };
        Require(Matcher(classic).Match(Reference(classic)).Pair != null, "classic source/task GUID matching");
        Require(Matcher(classic).Match(Reference(classic) with { Opcode = 33 }).Pair == null,
            "different classic opcodes are not paired");
        Require(Matcher(classic).Match(Reference(classic) with { SourceProviderGuid = Guid.Empty }).Pair == null,
            "classic source provider is not a wildcard");
        Require(Matcher(first).Match(Reference(first) with { Version = 2 }).Pair == null,
            "different versions are not paired");

        var many = Enumerable.Range(1, 400).Select(i => Record(i)).ToArray();
        matcher = Matcher(many);
        Require(matcher.Match(Reference(many[299])).Pair?.Native.Ordinal == 300,
            "older windows can be evicted to resynchronize after many omissions");
        Require(matcher.NativeRecordsEvicted > 0 && matcher.PeakBufferedRecords <= BoundedRecordMatcher.MaximumBufferedRecords,
            "forward resynchronization retains a bounded window and records omissions");
        return checks;
    }
}
