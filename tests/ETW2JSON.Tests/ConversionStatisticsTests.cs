namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Text;
    using ETW2JSON.Analysis;
    using ETWDeserializer;
    using Xunit;

    public sealed unsafe class ConversionStatisticsTests
    {
        [Fact]
        public void CountsActualDecodeFallbacksAndFollowingRecordsOncePerRecord()
        {
            var statistics = new ConversionStatistics();
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var reader = new Deserializer<JsonlEventWriter>(writer)
            {
                ResolverChain = new Resolver(),
                Observer = statistics.Observe,
            };
            Send(reader, 1, new byte[] { 42, 0, 0, 0 });
            Send(reader, 1, new byte[] { 1 });
            Send(reader, 3, new byte[] { 2, 3 });
            Send(reader, 1, new byte[] { 99, 0, 0, 0 });

            Assert.Null(reader.LastError);
            Assert.Equal(4, statistics.Total);
            Assert.Equal(2, statistics.Count(DecodeStatus.Decoded));
            Assert.Equal(1, statistics.Count(DecodeStatus.DecodeError));
            Assert.Equal(1, statistics.Count(DecodeStatus.MetadataMissing));
            Assert.Equal(4, Encoding.UTF8.GetString(output.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries).Length);
            using var text = new StringWriter();
            statistics.WriteText(text);
            Assert.Contains("metadata_missing=1", text.ToString());
            Assert.Contains("decode_error=1", text.ToString());
        }

        private static void Send(Deserializer<JsonlEventWriter> reader, ushort id, byte[] payload)
        {
            fixed (byte* bytes = payload)
            {
                var record = new EVENT_RECORD { ProviderId = Resolver.Provider, Id = id, UserData = bytes, UserDataLength = (ushort)payload.Length };
                reader.Deserialize(&record);
            }
        }

        private sealed class Resolver : IMetadataResolverChain
        {
            public static readonly Guid Provider = Guid.Parse("11111111-1111-1111-1111-111111111111");
            public ResolutionResult Resolve(EventKey key)
            {
                if (key.EventId != 1) return ResolutionResult.Unresolved;
                var property = new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_INT32, TDH_OUT_TYPE.TDH_OUTTYPE_NULL,
                    "value", false, false, 0, null);
                var field = new EventTracePropertyOperand(property, 0, false, false, false, false, false);
                var metadata = new EventMetadata(Provider, 1, 0, "Provider/Event", new[] { property }, "Provider",
                    MetadataSource.ExternalManifest, DecodeStatus.Decoded, "fixture");
                return new ResolutionResult(new EventTraceOperand(metadata, 0, new[] { field }), MetadataSource.ExternalManifest, "fixture");
            }
        }
    }
}
