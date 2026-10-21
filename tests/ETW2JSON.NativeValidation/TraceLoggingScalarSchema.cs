using System.Buffers.Binary;
using System.Text;

namespace ETW2JSON.NativeValidation;

internal readonly record struct TraceLoggingScalarDeclaration(int WireType, int Format = 0);

/// <summary>
/// Reads a conservative flat-field subset of EXT_TYPE_EVENT_SCHEMA_TL metadata.
/// This validation-only reader is independent of TDH and the product decoder.
/// </summary>
internal static class TraceLoggingScalarSchema
{
    // Encoding reference: the MIT-licensed dotnet/runtime TraceLogging encoder,
    // FieldMetadata.cs, Statics.cs and TraceLoggingDataType.cs. The layout is:
    // size16, event tags (1..4 bytes), event name UTF8Z, then field declarations.
    // Field flags select arrays (unsupported here), an optional format byte,
    // and an optional bounded field-tag sequence. No encoder code is copied.
    private static readonly UTF8Encoding StrictUtf8 = new(false, true);

    internal static bool TryRead(ReadOnlySpan<byte> metadata,
        out Dictionary<string, TraceLoggingScalarDeclaration> fields)
    {
        fields = new Dictionary<string, TraceLoggingScalarDeclaration>(StringComparer.Ordinal);
        if (metadata.Length < 5 || metadata.Length > ushort.MaxValue
            || BinaryPrimitives.ReadUInt16LittleEndian(metadata) != metadata.Length)
            return false;

        int position = 2;
        if (!TrySkipTags(metadata, ref position)
            || !TryReadName(metadata, ref position, out _))
            return false;

        var parsed = new Dictionary<string, TraceLoggingScalarDeclaration>(StringComparer.Ordinal);
        while (position < metadata.Length)
        {
            if (!TryReadName(metadata, ref position, out string name) || position == metadata.Length)
                return false;
            byte input = metadata[position++];
            // Both fixed and variable/custom count flags make this non-scalar.
            if ((input & 0x60) != 0) return false;
            int wireType = input & 0x1f;
            if (!IsSupportedScalar(wireType)) return false;

            int format = 0;
            if ((input & 0x80) != 0)
            {
                if (position == metadata.Length) return false;
                byte output = metadata[position++];
                format = output & 0x7f;
                if (!IsSupportedFormat(format)) return false;
                if ((output & 0x80) != 0 && !TrySkipTags(metadata, ref position)) return false;
            }

            if (!parsed.TryAdd(name, new TraceLoggingScalarDeclaration(wireType, format))) return false;
        }

        fields = parsed;
        return true;
    }

    /// <summary>
    /// TraceEvent can expose an unsigned wire value through its same-width signed
    /// CLR type. Reinterpret only a negative value whose declaration proves the
    /// unsigned width and default formatting. All other references stay unchanged.
    /// </summary>
    internal static object? NormalizeUnsignedReference(TraceLoggingScalarDeclaration declaration, object? reference)
    {
        if (declaration.Format != 0) return reference;
        return (declaration.WireType, reference) switch
        {
            (6, short value) when value < 0 => unchecked((ushort)value),
            (8, int value) when value < 0 => unchecked((uint)value),
            (10, long value) when value < 0 => unchecked((ulong)value),
            _ => reference,
        };
    }

    private static bool TrySkipTags(ReadOnlySpan<byte> metadata, ref int position)
    {
        // TraceLogging tags contain at most 28 bits, encoded in 1..4 groups.
        for (int group = 0; group < 4 && position < metadata.Length; group++)
        {
            if ((metadata[position++] & 0x80) == 0) return true;
        }
        return false;
    }

    private static bool TryReadName(ReadOnlySpan<byte> metadata, ref int position, out string name)
    {
        name = string.Empty;
        if ((uint)position >= (uint)metadata.Length) return false;
        int length = metadata[position..].IndexOf((byte)0);
        if (length <= 0) return false;
        try
        {
            name = StrictUtf8.GetString(metadata.Slice(position, length));
        }
        catch (DecoderFallbackException)
        {
            return false;
        }
        position += length + 1;
        return true;
    }

    private static bool IsSupportedScalar(int wireType) =>
        wireType is >= 1 and <= 15 or 17 or 18 or 20 or 21 or 22 or 23;

    // The documented public TraceLogging/EventFieldFormat subset. Other format
    // values are deliberately rejected rather than guessed or masked away.
    private static bool IsSupportedFormat(int format) => format is 0 or 2 or 3 or 4 or 11 or 12 or 15;
}
