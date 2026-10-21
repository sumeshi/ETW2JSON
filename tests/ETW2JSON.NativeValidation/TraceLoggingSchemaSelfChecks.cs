using System.Buffers.Binary;
using System.Text;

namespace ETW2JSON.NativeValidation;

internal static class TraceLoggingSchemaSelfChecks
{
    internal static int Run()
    {
        int checks = 0;
        byte[] basic = Metadata(("u16", [6]), ("u32", [8]), ("u64", [10]),
            ("s16", [5]), ("s32", [7]), ("s64", [9]), ("character", [0x84, 2]), ("boolean", [0x84, 3]));
        Require(TraceLoggingScalarSchema.TryRead(basic, out var fields)
            && fields.Count == 8 && fields["u64"] == new TraceLoggingScalarDeclaration(10)
            && fields["character"] == new TraceLoggingScalarDeclaration(4, 2)
            && fields["boolean"] == new TraceLoggingScalarDeclaration(4, 3), "flat declarations");
        Require(TraceLoggingScalarSchema.TryRead(Metadata(("explicitDefault", [0x8a, 0])), out var explicitDefault)
            && explicitDefault["explicitDefault"].Format == 0, "explicit default format");
        Require(TraceLoggingScalarSchema.TryRead(Metadata(), out var empty) && empty.Count == 0, "zero-field event");
        Require(TraceLoggingScalarSchema.TryRead(Metadata(("非ASCII", [8])), out var unicode)
            && unicode.ContainsKey("非ASCII"), "UTF-8 field name");

        var tags = Metadata(("tagged", [0x88, 0x80, 0x80, 0x80, 0x80, 1]));
        Require(TraceLoggingScalarSchema.TryRead(tags, out var tagged)
            && tagged["tagged"] == new TraceLoggingScalarDeclaration(8), "bounded field tags");
        var eventTags = Metadata(("value", [10]));
        eventTags = eventTags[..2].Concat(new byte[] { 0x80, 0x80, 0x80, 1 }).Concat(eventTags[3..]).ToArray();
        FixSize(eventTags);
        Require(TraceLoggingScalarSchema.TryRead(eventTags, out _), "bounded event tags");

        Reject([], "empty metadata");
        Reject([0xff, 0xff, 0, (byte)'E', 0], "negative/signed size cannot expand the span");
        var wrongSize = (byte[])basic.Clone();
        wrongSize[0]--;
        Reject(wrongSize, "declared size mismatch");
        Reject(new byte[ushort.MaxValue + 1], "metadata size cap");
        Reject(Metadata(("u16", [6]), ("u16", [8])), "duplicate field names");
        Reject(Metadata(("", [6])), "empty field name");
        Reject(Metadata(("array", [0x26, 2, 0])), "fixed array");
        Reject(Metadata(("array", [0x46])), "variable array");
        Reject(Metadata(("custom", [0x66, 0, 0])), "custom count");
        Reject(Metadata(("negativeCount", [0x26, 0xff, 0xff])), "negative/signed fixed count");
        Reject(Metadata(("structure", [0x98, 2]), ("first", [6]), ("second", [8])), "structure");
        Reject(Metadata(("unknown", [31])), "unknown wire type");
        Reject(Metadata(("unknownFormat", [0x8a, 0x7f])), "unknown format");
        Reject(Metadata(("truncatedType", [])), "truncated wire type");
        Reject(Metadata(("truncatedFormat", [0x86])), "truncated format");
        Reject(Metadata(("truncatedTags", [0x86, 0x80])), "truncated field tags");
        Reject(Metadata(("longTags", [0x86, 0x80, 0x80, 0x80, 0x80, 0x80, 0])), "overlong field tags");
        var overlongEventTags = Metadata(("value", [10]));
        overlongEventTags = overlongEventTags[..2].Concat(new byte[] { 0x80, 0x80, 0x80, 0x80, 0 })
            .Concat(overlongEventTags[3..]).ToArray();
        FixSize(overlongEventTags);
        Reject(overlongEventTags, "overlong event tags");
        var invalidUtf8 = Metadata(("value", [10]));
        invalidUtf8[3] = 0xff;
        Reject(invalidUtf8, "invalid UTF-8 event name");
        var invalidFieldUtf8 = Metadata(("value", [10]));
        invalidFieldUtf8[9] = 0xff;
        Reject(invalidFieldUtf8, "invalid UTF-8 field name");
        var unterminated = Metadata(("field", [10]));
        unterminated.AsSpan(9).Fill((byte)'x');
        Reject(unterminated, "unterminated field name");

        Normalize(6, 0, (short)-1, ushort.MaxValue);
        Normalize(8, 0, -1, uint.MaxValue);
        Normalize(10, 0, -1L, ulong.MaxValue);
        Normalize(6, 0, short.MinValue, (ushort)32768);
        Normalize(8, 0, int.MinValue, 2147483648u);
        Normalize(10, 0, long.MinValue, 9223372036854775808ul);
        Preserve(5, 0, (short)-1, "signed 16-bit declaration");
        Preserve(7, 0, -1, "signed 32-bit declaration");
        Preserve(9, 0, -1L, "signed 64-bit declaration");
        Preserve(6, 2, (short)-1, "formatted unsigned declaration");
        Preserve(10, 17, -1L, "nondefault formatting");
        Preserve(6, 0, -1, "mismatched CLR width");
        Preserve(8, 0, -1L, "mismatched CLR width");
        Preserve(10, 0, -1, "mismatched CLR width");
        Preserve(4, 0, (sbyte)-1, "unsigned8 is outside the correction scope");
        Preserve(10, 0, 1L, "nonnegative reference");
        Preserve(10, 0, ulong.MaxValue, "already unsigned reference");
        Preserve(10, 0, null, "null reference");

        // Public MIT PerfView primitive-types.etl metadata. The name int64_type
        // itself is not authority: both 64-bit fields declare wire type UInt64.
        var actual = Convert.FromBase64String("tgAAUHJpbWl0aXZlVHlwZXNUZXN0AHN0cmluZ190eXBlAAJib29sZWFuX3R5cGUAhANjaGFyX3R5cGUAhAJpbnQxNl90eXBlAAVpbnQzMl90eXBlAAd1aW50MTZfdHlwZQAGdWludDMyX3R5cGUACGludDY0X3R5cGUACnVpbnQ2NF90eXBlAApndWlkX3R5cGUAD2ZpbGVfdGltZV90eXBlABFzeXN0ZW1fdGltZV90eXBlABI=");
        Require(TraceLoggingScalarSchema.TryRead(actual, out var actualFields) && actualFields.Count == 12
            && actualFields["int64_type"].WireType == 10 && actualFields["uint64_type"].WireType == 10,
            "public scalar corpus declaration");
        return checks;

        void Require(bool condition, string name)
        {
            if (!condition) throw new InvalidOperationException("TraceLogging scalar-schema self-check failed: " + name);
            checks++;
        }

        void Reject(byte[] metadata, string name)
        {
            bool accepted = TraceLoggingScalarSchema.TryRead(metadata, out var rejectedFields);
            Require(!accepted && rejectedFields.Count == 0, name + " (including no partial declarations)");
        }

        void Normalize(int wire, int format, object value, object expected)
        {
            object? normalized = TraceLoggingScalarSchema.NormalizeUnsignedReference(new(wire, format), value);
            Require(normalized?.GetType() == expected.GetType() && Equals(normalized, expected), "schema-qualified unsigned normalization");
        }

        void Preserve(int wire, int format, object? value, string name)
        {
            object? normalized = TraceLoggingScalarSchema.NormalizeUnsignedReference(new(wire, format), value);
            Require(ReferenceEquals(value, normalized), name);
        }
    }

    private static byte[] Metadata(params (string Name, byte[] Declaration)[] fields)
    {
        using var stream = new MemoryStream();
        stream.Write([0, 0, 0]); // size16 placeholder and zero event tags
        stream.Write(Encoding.UTF8.GetBytes("Event\0"));
        foreach (var field in fields)
        {
            stream.Write(Encoding.UTF8.GetBytes(field.Name));
            stream.WriteByte(0);
            stream.Write(field.Declaration);
        }
        byte[] bytes = stream.ToArray();
        FixSize(bytes);
        return bytes;
    }

    private static void FixSize(byte[] metadata) => BinaryPrimitives.WriteUInt16LittleEndian(metadata, checked((ushort)metadata.Length));
}
