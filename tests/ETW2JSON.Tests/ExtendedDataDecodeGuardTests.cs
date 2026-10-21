namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using ETW2JSON.Analysis;
    using ETWDeserializer;
    using Xunit;

    public sealed unsafe class ExtendedDataDecodeGuardTests
    {
        [Theory]
        [InlineData("null-array", false)]
        [InlineData("null-array", true)]
        [InlineData("low-array", false)]
        [InlineData("low-array", true)]
        [InlineData("count-limit", false)]
        [InlineData("count-limit", true)]
        [InlineData("null-data", false)]
        [InlineData("null-data", true)]
        [InlineData("low-data", false)]
        [InlineData("low-data", true)]
        [InlineData("overflow-data", false)]
        [InlineData("overflow-data", true)]
        [InlineData("truncated-related", false)]
        [InlineData("truncated-related", true)]
        public void InvalidExtendedMetadataIsNotReadAgainAndCannotDisappearFromInventory(string failure, bool failedFirst)
        {
            Guid provider = Guid.NewGuid();
            var scan = new ScanService(new MetadataResolver());
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            int tdhCalls = 0;
            var deserializer = new Deserializer<JsonlEventWriter>(writer)
            {
                ResolverChain = new ValidSchema(provider),
                TdhInformationLookup = (EVENT_RECORD* record, uint count, IntPtr context, byte* buffer, ref uint size) => { tdhCalls++; throw new InvalidOperationException("Unexpected unsafe lookup."); },
                SourceFile = "guard.etl",
                SourceObserver = (source, key, operand) => scan.Observe(source, key, operand),
            };

            Send(deserializer, provider, failure, failedFirst);
            Send(deserializer, provider, failure, !failedFirst);
            scan.Refresh(new PreflightMetadata(new MetadataResolver()));

            Assert.Null(deserializer.LastError);
            Assert.Equal(0, tdhCalls);
            Assert.Equal("Mixed", Assert.Single(scan.Entries).Value.MetadataStatus);
            string[] lines = Encoding.UTF8.GetString(output.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal(2, lines.Length);
            using var bad = JsonDocument.Parse(lines[failedFirst ? 0 : 1]);
            Assert.Equal("decode_error", bad.RootElement.GetProperty("decode_status").GetString());
            Assert.NotEmpty(bad.RootElement.GetProperty("extended_data_errors").EnumerateArray());
            Assert.Empty(bad.RootElement.GetProperty("properties").EnumerateObject());
            Assert.Equal(new byte[] { 42, 0, 0, 0 }, bad.RootElement.GetProperty("raw_payload").GetBytesFromBase64());
            using var good = JsonDocument.Parse(lines[failedFirst ? 1 : 0]);
            Assert.Equal("decoded", good.RootElement.GetProperty("decode_status").GetString());
            Assert.Equal(42, good.RootElement.GetProperty("properties").GetProperty("Value").GetInt32());
        }

        private static void Send(Deserializer<JsonlEventWriter> deserializer, Guid provider, string failure, bool invalid)
        {
            int payload = 42;
            byte* related = stackalloc byte[17];
            new Span<byte>(related, 17).Clear();
            EVENT_HEADER_EXTENDED_DATA_ITEM item = default;
            item.ExtType = ETWDeserializer.Etw.EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL;
            item.DataSize = 4;
            item.DataPtr = failure switch { "null-data" => 0, "low-data" => 1, _ => ulong.MaxValue };
            if (failure == "truncated-related")
            {
                item.ExtType = ETWDeserializer.Etw.EVENT_HEADER_EXT_TYPE_RELATED_ACTIVITYID;
                item.DataSize = 17;
                item.DataPtr = (ulong)related;
            }
            var record = new EVENT_RECORD { ProviderId = provider, Id = 1, UserData = (byte*)&payload, UserDataLength = 4 };
            if (invalid)
            {
                record.ExtendedDataCount = failure == "count-limit" ? (ushort)(ExtendedEventDataSnapshot.MaximumItems + 1) : (ushort)1;
                record.ExtendedData = failure switch
                {
                    "null-array" => null,
                    "low-array" or "count-limit" => (EVENT_HEADER_EXTENDED_DATA_ITEM*)1,
                    _ => &item,
                };
            }
            deserializer.Deserialize(&record);
        }

        private sealed class ValidSchema : IMetadataResolverChain
        {
            private readonly IEventTraceOperand operand;
            public ValidSchema(Guid provider)
            {
                var property = new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_INT32, TDH_OUT_TYPE.TDH_OUTTYPE_NULL, "Value", false, false, 0, null);
                this.operand = new EventTraceOperand(new EventMetadata(provider, 1, 0, "Provider/Event", new[] { property }, "Provider",
                    MetadataSource.ExternalManifest, DecodeStatus.Decoded, "schema.man"), 0,
                    new[] { new EventTracePropertyOperand(property, 0, false, false, false, false, false) });
            }
            public ResolutionResult Resolve(EventKey key) => new ResolutionResult(this.operand, MetadataSource.ExternalManifest, "schema.man");
        }
    }
}
