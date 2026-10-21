namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Text.Json;
    using ETWDeserializer;
    using Xunit;

    public sealed unsafe class TraceLoggingProviderTraitsTests
    {
        [Theory]
        [InlineData(0x000C, 4)] // EVENT_HEADER_EXT_TYPE_PROV_TRAITS, Windows SDK.
        [InlineData(0x000D, 2)] // PROCESS_START_KEY is unrelated to schema identity.
        public void SchemaCacheIncludesProviderTraitsButNotProcessStartKey(ushort extensionType, int expectedCalls)
        {
            int calls = 0;
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var deserializer = new Deserializer<JsonlEventWriter>(writer)
            {
                TdhInformationLookup = (EVENT_RECORD* record, uint count, IntPtr context, byte* buffer, ref uint size) =>
                {
                    calls++;
                    string name = ((byte*)record->ExtendedData[1].DataPtr)[2] == 'A' ? "First" : "Other";
                    byte[] encoded = Encoding.Unicode.GetBytes(name + "\0");
                    uint required = (uint)(sizeof(TRACE_EVENT_INFO) + encoded.Length);
                    if (buffer == null) { size = required; return 122; }
                    Assert.Equal(required, size);
                    *(TRACE_EVENT_INFO*)buffer = new TRACE_EVENT_INFO
                    {
                        ProviderGuid = record->ProviderId,
                        DecodingSource = DECODING_SOURCE.DecodingSourceTlg,
                        ProviderNameOffset = (uint)sizeof(TRACE_EVENT_INFO),
                    };
                    Marshal.Copy(encoded, 0, (IntPtr)(buffer + sizeof(TRACE_EVENT_INFO)), encoded.Length);
                    return 0;
                },
            };
            byte* schema = stackalloc byte[] { 3, 0, 0 };
            byte* traits = stackalloc byte[] { 4, 0, (byte)'A', 0 };
            EVENT_HEADER_EXTENDED_DATA_ITEM* extensions = stackalloc EVENT_HEADER_EXTENDED_DATA_ITEM[2];
            extensions[0] = new EVENT_HEADER_EXTENDED_DATA_ITEM { ExtType = 0x000B, DataSize = 3, DataPtr = (ulong)schema };
            extensions[1] = new EVENT_HEADER_EXTENDED_DATA_ITEM { ExtType = extensionType, DataSize = 4, DataPtr = (ulong)traits };
            var record = new EVENT_RECORD { ProviderId = Guid.NewGuid(), ExtendedData = extensions, ExtendedDataCount = 2 };

            deserializer.Deserialize(&record);
            traits[2] = (byte)'B';
            deserializer.Deserialize(&record);

            Assert.Null(deserializer.LastError);
            Assert.Equal(expectedCalls, calls);
            string[] lines = Encoding.UTF8.GetString(output.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal(2, lines.Length);
            using var first = JsonDocument.Parse(lines[0]);
            using var second = JsonDocument.Parse(lines[1]);
            Assert.Equal("First", first.RootElement.GetProperty("provider_name").GetString());
            Assert.Equal(extensionType == 0x000C ? "Other" : "First", second.RootElement.GetProperty("provider_name").GetString());
        }
    }
}
