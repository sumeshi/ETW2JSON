namespace ETWDeserializer.CustomParsers
{
    using System;
    using System.Collections.Generic;
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
    }
}
