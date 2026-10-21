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

    public sealed unsafe class TraceLoggingFailureTests
    {
        [Fact]
        public void SelfDescribingRecordIsNotOverriddenByConflictingExternalSchemas()
        {
            var key = new EventKey(Guid.NewGuid(), 0, 0);
            var external = new CountingExternalResolver(key, conflicting: true);
            var chain = new MetadataResolver();
            chain.Add(external);
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var deserializer = new Deserializer<JsonlEventWriter>(writer)
            {
                TdhInformationLookup = new TdhScenario(key.ProviderGuid, "none").Lookup,
                ResolverChain = new PreflightMetadata(chain),
            };

            SendRecord(deserializer, key, "none", false);

            Assert.Null(deserializer.LastError);
            using var json = JsonDocument.Parse(output.ToArray());
            Assert.Equal("decoded", json.RootElement.GetProperty("decode_status").GetString());
            Assert.Equal("trace_logging", json.RootElement.GetProperty("metadata_source").GetString());
            Assert.Equal(0, external.Calls);
        }

        [Theory]
        [InlineData("initial-error", false)]
        [InlineData("initial-error", true)]
        [InlineData("read-error", false)]
        [InlineData("read-error", true)]
        [InlineData("short-buffer", false)]
        [InlineData("short-buffer", true)]
        [InlineData("oversized-buffer", false)]
        [InlineData("oversized-buffer", true)]
        [InlineData("changed-size", false)]
        [InlineData("changed-size", true)]
        [InlineData("malformed-info", false)]
        [InlineData("malformed-info", true)]
        [InlineData("wrong-source", false)]
        [InlineData("wrong-source", true)]
        [InlineData("wrong-identity", false)]
        [InlineData("wrong-identity", true)]
        [InlineData("empty-schema", false)]
        [InlineData("empty-schema", true)]
        [InlineData("null-schema", false)]
        [InlineData("null-schema", true)]
        public void FailedSelfDescribingSchemaKeepsRawEventAndCannotDisappearFromScan(string failure, bool failedFirst)
        {
            var key = new EventKey(Guid.NewGuid(), 0, 0);
            var scenario = new TdhScenario(key.ProviderGuid, failure);
            var external = new CountingExternalResolver(key);
            var scan = new ScanService(external);
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var deserializer = new Deserializer<JsonlEventWriter>(writer)
            {
                TdhInformationLookup = scenario.Lookup,
                ResolverChain = external,
                SourceFile = "synthetic.etl",
                SourceObserver = (source, observed, operand) => scan.Observe(source, observed, operand),
            };

            SendRecord(deserializer, key, failure, failedFirst);
            SendRecord(deserializer, key, failure, !failedFirst);
            scan.Refresh(new PreflightMetadata(new MetadataResolver()));

            Assert.Null(deserializer.LastError);
            Assert.Equal(0, external.Calls);
            var entry = Assert.Single(scan.Entries).Value;
            Assert.Equal(2, entry.Count);
            Assert.Equal("Mixed", entry.MetadataStatus);
            Assert.Contains("TraceLogging", entry.Reason);
            string[] lines = Encoding.UTF8.GetString(output.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries);
            Assert.Equal(2, lines.Length);
            using var failed = JsonDocument.Parse(lines[failedFirst ? 0 : 1]);
            Assert.Equal("decode_error", failed.RootElement.GetProperty("decode_status").GetString());
            Assert.Equal("trace_logging", failed.RootElement.GetProperty("metadata_source").GetString());
            Assert.Equal(new byte[] { 0xA5 }, failed.RootElement.GetProperty("raw_payload").GetBytesFromBase64());
            Assert.Empty(failed.RootElement.GetProperty("properties").EnumerateObject());
            using var valid = JsonDocument.Parse(lines[failedFirst ? 1 : 0]);
            Assert.Equal("decoded", valid.RootElement.GetProperty("decode_status").GetString());
        }

        private static void SendRecord(Deserializer<JsonlEventWriter> deserializer, EventKey key, string failure, bool failed)
        {
            byte* schema = stackalloc byte[] { 3, 0, failed ? (byte)1 : (byte)2 };
            byte* payload = stackalloc byte[] { 0xA5 };
            EVENT_HEADER_EXTENDED_DATA_ITEM extended = default;
            extended.ExtType = Etw.EVENT_HEADER_EXT_TYPE_EVENT_SCHEMA_TL;
            extended.DataSize = failed && failure == "empty-schema" ? (ushort)0 : (ushort)3;
            extended.DataPtr = failed && failure == "null-schema" ? 0 : unchecked((ulong)schema);
            var record = new EVENT_RECORD
            {
                ProviderId = key.ProviderGuid,
                Id = key.EventId,
                ExtendedData = &extended,
                ExtendedDataCount = 1,
                UserData = failed ? payload : null,
                UserDataLength = failed ? (ushort)1 : (ushort)0,
            };
            deserializer.Deserialize(&record);
        }

        private sealed class TdhScenario
        {
            private readonly Guid provider;
            private readonly string failure;
            public TdhScenario(Guid provider, string failure) { this.provider = provider; this.failure = failure; }
            public int Lookup(EVENT_RECORD* record, uint count, IntPtr context, byte* buffer, ref uint size)
            {
                bool failed = ((byte*)record->ExtendedData[0].DataPtr)[2] == 1;
                if (failed && this.failure == "initial-error") return 1168;
                if (buffer == null)
                {
                    size = failed && this.failure == "short-buffer" ? 1U
                        : failed && this.failure == "oversized-buffer" ? 17U * 1024 * 1024
                        : (uint)sizeof(TRACE_EVENT_INFO);
                    return 122;
                }
                if (failed && this.failure == "read-error") return 13;
                if (failed && this.failure == "changed-size") { size++; return 0; }
                Assert.Equal((uint)sizeof(TRACE_EVENT_INFO), size);
                * (TRACE_EVENT_INFO*)buffer = new TRACE_EVENT_INFO
                {
                    ProviderGuid = failed && this.failure == "wrong-identity" ? Guid.NewGuid() : this.provider,
                    DecodingSource = failed && this.failure == "wrong-source" ? DECODING_SOURCE.DecodingSourceXMLFile : DECODING_SOURCE.DecodingSourceTlg,
                    PropertyCount = failed && this.failure == "malformed-info" ? uint.MaxValue : 0,
                };
                return 0;
            }
        }

        private sealed class CountingExternalResolver : IMetadataResolverChain, IMetadataResolver
        {
            private readonly IEventTraceOperand operand;
            private readonly bool conflicting;
            public CountingExternalResolver(EventKey key, bool conflicting = false)
            {
                this.conflicting = conflicting;
                this.operand = new EventTraceOperand(new EventMetadata(key.ProviderGuid, key.EventId, key.Version, "External/Event",
                    Array.Empty<PropertyMetadata>(), "External", MetadataSource.ExternalManifest, DecodeStatus.Decoded, "external.man"),
                    0, Array.Empty<IEventTracePropertyOperand>());
            }
            public MetadataSource Source => MetadataSource.ExternalManifest;
            public int Calls { get; private set; }
            public ResolutionResult Resolve(EventKey key)
            {
                this.Calls++;
                if (this.conflicting) return ResolutionResult.UnresolvedResult(ResolutionStatus.Conflict,
                    this.Source, "external.man", "Conflicting external schemas.");
                return new ResolutionResult(this.operand, MetadataSource.ExternalManifest, "external.man");
            }
        }
    }
}
