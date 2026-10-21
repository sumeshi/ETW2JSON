namespace ETW2JSON.NativeValidation;

internal static class ReferenceScalarTypes
{
    private static readonly Guid ImageGuid = new("2cb15d1d-5fc1-11d2-abe1-00a0c911f518");

    internal static object? NormalizeClassicImageTimestamp(RawIndex record, string field, object? reference)
    {
        // Image_Load v2 declares TimeDateStamp as uint32. TraceEvent's static
        // ImageLoadTraceData exposes it as int. Scope this rule to that exact
        // classic layout; a matching field name alone does not establish a type.
        // https://learn.microsoft.com/en-us/windows/win32/etw/image-load
        if ((record.Flags & 0x100) != 0 && record.ProviderGuid == ImageGuid
            && record.EventId == 0 && record.Version == 2 && record.Opcode is 10 or 2 or 3 or 4
            && field == "TimeDateStamp" && reference is int value && value < 0)
            return unchecked((uint)value);
        return reference;
    }

    internal static int RunSelfChecks()
    {
        var image = new RawIndex(1, ImageGuid, 0x140, 0, 2, 10, false, 0, 0, 0, 0, "hash", true);
        int negative = unchecked((int)2568420482u);
        int checks = 0;
        foreach (byte opcode in new byte[] { 10, 2, 3, 4 })
        {
            if (NormalizeClassicImageTimestamp(image with { Opcode = opcode }, "TimeDateStamp", negative) is not uint value
                || value != 2568420482u) throw new InvalidOperationException("Image v2 UInt32 reference interpretation failed.");
            checks++;
        }
        foreach (var other in new[]
        {
            image with { ProviderGuid = Guid.Empty }, image with { Version = 1 }, image with { Version = 3 },
            image with { Opcode = 1 }, image with { EventId = 1 }, image with { Flags = 0x40 },
        }) Preserve(other, "TimeDateStamp", negative);
        Preserve(image, "OtherTimestamp", negative);
        Preserve(image, "TimeDateStamp", (long)negative);
        Preserve(image, "TimeDateStamp", 123);
        Preserve(image, "TimeDateStamp", null);
        return checks;

        void Preserve(RawIndex record, string field, object? value)
        {
            if (!ReferenceEquals(value, NormalizeClassicImageTimestamp(record, field, value)))
                throw new InvalidOperationException("An unrelated reference value was reinterpreted as Image v2 UInt32.");
            checks++;
        }
    }
}
