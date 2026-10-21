namespace ETW2JSON.NativeValidation;

/// <summary>
/// Associates reference callbacks with a bounded window of independently observed
/// native records. A missing or extra reference callback must not shift every
/// later comparison by one record.
/// </summary>
internal sealed class BoundedRecordMatcher(Func<RecordPair?> readNext)
{
    internal const int MaximumBufferedRecords = 128;
    private const int MaximumBufferedCharacters = 8 * 1024 * 1024;
    private readonly List<RecordPair> window = [];
    private RecordPair? pending;
    private bool exhausted;
    private int bufferedCharacters;

    internal long NativeRecordsEvicted { get; private set; }
    internal int PeakBufferedRecords { get; private set; }

    internal MatchResult Match(ReferenceIdentity reference)
    {
        Fill();
        while (true)
        {
            List<RecordPair> candidates = window.Where(pair => StrongKeyMatches(pair.Native, reference)).ToList();
            List<RecordPair> exactContext = candidates.Where(pair => pair.Native.ProcessId == reference.ProcessId
                && pair.Native.ThreadId == reference.ThreadId).ToList();
            if (exactContext.Count == 1)
                return Consume(exactContext[0], false);
            if (exactContext.Count > 1 || candidates.Count > 1)
                return new MatchResult(null, false, "ambiguous_reference_to_native_mapping");
            if (candidates.Count == 1)
                return Consume(candidates[0], true);

            // ProcessTrace normally presents these file callbacks in time order.
            // Move past an older native prefix only when the entire current
            // window is older than this reference timestamp. Never drain a
            // window of equal/future timestamps in pursuit of an extra callback.
            if (window.Count != 0 && window.All(pair => pair.Native.RawTimestamp < reference.RawTimestamp))
            {
                NativeRecordsEvicted += window.Count;
                window.Clear();
                bufferedCharacters = 0;
                Fill();
                if (window.Count != 0) continue;
            }
            return new MatchResult(null, false, exhausted && window.Count == 0
                ? "reference_has_no_remaining_native_peer" : "reference_not_matched_within_bounded_window");
        }
    }

    private MatchResult Consume(RecordPair pair, bool contextFixedUp)
    {
        window.Remove(pair);
        bufferedCharacters -= pair.ApplicationLine.Length;
        return new MatchResult(pair, contextFixedUp, null);
    }

    private void Fill()
    {
        while (window.Count < MaximumBufferedRecords && !exhausted)
        {
            RecordPair? pair = pending ?? readNext();
            pending = null;
            if (pair == null) { exhausted = true; break; }
            if (window.Count != 0 && bufferedCharacters + pair.ApplicationLine.Length > MaximumBufferedCharacters)
            {
                pending = pair;
                break;
            }
            window.Add(pair);
            bufferedCharacters += pair.ApplicationLine.Length;
            PeakBufferedRecords = Math.Max(PeakBufferedRecords, window.Count);
        }
    }

    private static bool StrongKeyMatches(RawIndex native, ReferenceIdentity reference)
    {
        bool classic = (native.Flags & 0x0100) != 0;
        return native.ProviderGuid == reference.SourceProviderGuid && classic == reference.Classic
            && native.Version == reference.Version && native.RawTimestamp == reference.RawTimestamp
            && native.PayloadLength == reference.PayloadLength && native.PayloadSha256 == reference.PayloadSha256
            // TraceEvent rewrites TraceLogging IDs. For other modern records its
            // public ID retains the native ID. Classic lookup uses raw opcode.
            && (classic ? native.Opcode == reference.Opcode : native.TraceLogging || native.EventId == reference.EventId);
    }
}

internal sealed record RecordPair(RawIndex Native, string ApplicationLine);
internal sealed record ReferenceIdentity(Guid SourceProviderGuid, bool Classic, int EventId, int Version, int Opcode,
    uint ProcessId, uint ThreadId, long RawTimestamp, int PayloadLength, string PayloadSha256);
internal sealed record MatchResult(RecordPair? Pair, bool ContextFixedUp, string? FailureReason);
