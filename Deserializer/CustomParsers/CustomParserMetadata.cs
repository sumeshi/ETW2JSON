namespace ETWDeserializer.CustomParsers
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.Text;

    internal static class CustomParserMetadata
    {
        public static EventMetadata Create(Guid provider, ushort id, string name, PropertyMetadata[] properties, string layout)
        {
            return new EventMetadata(provider, id, 0, name, properties, "Windows kernel trace",
                MetadataSource.BuiltinParser, DecodeStatus.Decoded, "builtin:" + name + ";layout_revision:1;layout:" + layout);
        }

        public static EventMetadata Bind(EventMetadata template, RuntimeEventMetadata runtime)
        {
            string width = (runtime.Flags & (Etw.EVENT_HEADER_FLAG_32_BIT_HEADER | Etw.EVENT_HEADER_FLAG_64_BIT_HEADER)) switch
            {
                Etw.EVENT_HEADER_FLAG_32_BIT_HEADER => "4",
                Etw.EVENT_HEADER_FLAG_64_BIT_HEADER => "8",
                _ => "unknown",
            };
            return new EventMetadata(runtime.ProviderId, runtime.EventId, runtime.Version, template.Name, template.Properties,
                template.ProviderName, MetadataSource.BuiltinParser, DecodeStatus.Decoded,
                template.Provenance + ";version:" + runtime.Version + ";pointer_size:" + width);
        }

        public static int PointerSize(RuntimeEventMetadata runtime)
        {
            return (runtime.Flags & (Etw.EVENT_HEADER_FLAG_32_BIT_HEADER | Etw.EVENT_HEADER_FLAG_64_BIT_HEADER)) switch
            {
                Etw.EVENT_HEADER_FLAG_32_BIT_HEADER => 4,
                Etw.EVENT_HEADER_FLAG_64_BIT_HEADER => 8,
                _ => throw new InvalidOperationException("The event header does not specify an unambiguous pointer size; the raw payload is retained."),
            };
        }

        public static string ReadUtf8String(EventRecordReader reader)
        {
            var bytes = new List<byte>();
            byte value;
            while ((value = reader.ReadUInt8()) != 0) bytes.Add(value);
            return new UTF8Encoding(false, true).GetString(bytes.ToArray());
        }

        public static string ReadWbemSid(EventRecordReader reader, int pointerSize)
        {
            // Process MOF records contain a TOKEN_USER followed by its SID. A
            // null token is encoded as one DWORD, including in a 64-bit event.
            if (reader.ReadUInt32() == 0) return null;
            reader.ReadBinary(pointerSize * 2 - sizeof(uint));
            byte revision = reader.ReadUInt8();
            byte count = reader.ReadUInt8();
            if (revision != 1 || count > 15) throw new InvalidOperationException("The process SID has an invalid revision or sub-authority count.");
            byte[] authorityBytes = reader.ReadBinary(6);
            ulong authority = 0;
            foreach (byte value in authorityBytes) authority = (authority << 8) | value;
            var sid = new StringBuilder("S-1-");
            sid.Append(authority > uint.MaxValue ? "0x" + authority.ToString("x12", CultureInfo.InvariantCulture)
                : authority.ToString(CultureInfo.InvariantCulture));
            for (int i = 0; i < count; i++) sid.Append('-').Append(reader.ReadUInt32().ToString(CultureInfo.InvariantCulture));
            return sid.ToString();
        }

        public static PropertyMetadata Property(string name, TDH_IN_TYPE type)
        {
            return new PropertyMetadata(type, TDH_OUT_TYPE.TDH_OUTTYPE_NULL, name, false, false, 0, null);
        }
    }
}
