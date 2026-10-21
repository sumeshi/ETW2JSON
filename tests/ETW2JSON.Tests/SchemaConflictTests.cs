namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text.Json;
    using ETWDeserializer;
    using Xunit;

    public class SchemaConflictTests
    {
        [Theory]
        [InlineData("fixed-array", false)]
        [InlineData("fixed-array", true)]
        [InlineData("fixed-length", false)]
        [InlineData("fixed-length", true)]
        [InlineData("variable-array", false)]
        [InlineData("variable-array", true)]
        [InlineData("variable-length", false)]
        [InlineData("variable-length", true)]
        [InlineData("scalar-array", false)]
        [InlineData("scalar-array", true)]
        public void DifferentPayloadLayoutsAreConflicts(string layout, bool sharedCache)
        {
            var key = new EventKey(Guid.NewGuid(), 1, 0);
            IMetadataResolverChain resolver = BuildCache(key, BuildOperand(key, layout, false), BuildOperand(key, layout, true), sharedCache);

            var result = resolver.Resolve(key);

            Assert.Equal(ResolutionStatus.Conflict, result.Status);
            Assert.False(result.Resolved);
            Assert.Contains("first schema", result.Provenance);
            Assert.Contains("second schema", result.Provenance);
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void RepeatedEquivalentPayloadLayoutsRemainResolvable(bool sharedCache)
        {
            var key = new EventKey(Guid.NewGuid(), 1, 0);
            var resolver = BuildCache(key, BuildOperand(key, "variable-length", false), BuildOperand(key, "variable-length", false), sharedCache);

            Assert.True(resolver.Resolve(key).Resolved);
        }

        [Fact]
        public unsafe void ConflictingArrayLayoutsRetainTheOriginalEventWithoutInterpretedProperties()
        {
            var key = new EventKey(Guid.NewGuid(), 1, 0);
            var resolver = BuildCache(key, BuildOperand(key, "fixed-array", false), BuildOperand(key, "fixed-array", true), false);
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var deserializer = new Deserializer<JsonlEventWriter>(writer) { ResolverChain = resolver };
            byte* payload = stackalloc byte[] { 42, 0, 0, 0, 99, 0, 0, 0 };
            var record = new EVENT_RECORD { ProviderId = key.ProviderGuid, Id = key.EventId, Version = key.Version, UserData = payload, UserDataLength = 8 };

            deserializer.Deserialize(&record);

            Assert.Null(deserializer.LastError);
            using var document = JsonDocument.Parse(output.ToArray());
            var root = document.RootElement;
            Assert.Equal("decode_error", root.GetProperty("decode_status").GetString());
            Assert.Empty(root.GetProperty("properties").EnumerateObject());
            Assert.Equal(new byte[] { 42, 0, 0, 0, 99, 0, 0, 0 }, root.GetProperty("raw_payload").GetBytesFromBase64());
            Assert.Equal(key.ProviderGuid.ToString("D"), root.GetProperty("provider_guid").GetString());
            Assert.Equal(key.EventId, root.GetProperty("event_id").GetUInt16());
        }

        [Theory]
        [InlineData(MetadataSource.ExternalManifest, "external_manifest")]
        [InlineData(MetadataSource.ExternalPeResource, "external_pe_resource")]
        public unsafe void ExternalConflictPreservesItsMetadataSourceAndProvenance(MetadataSource source, string expectedSource)
        {
            var key = new EventKey(Guid.NewGuid(), 1, 0);
            var chain = new MetadataResolver();
            chain.Add(new ConflictingResolver(source));
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var deserializer = new Deserializer<JsonlEventWriter>(writer) { ResolverChain = new PreflightMetadata(chain) };
            byte* payload = stackalloc byte[] { 42 };
            var record = new EVENT_RECORD { ProviderId = key.ProviderGuid, Id = key.EventId, UserData = payload, UserDataLength = 1 };

            deserializer.Deserialize(&record);

            Assert.Null(deserializer.LastError);
            using var document = JsonDocument.Parse(output.ToArray());
            var root = document.RootElement;
            Assert.Equal(expectedSource, root.GetProperty("metadata_source").GetString());
            Assert.Equal("evidence:first;second", root.GetProperty("metadata_provenance").GetString());
            Assert.Equal("decode_error", root.GetProperty("decode_status").GetString());
            Assert.Equal(new byte[] { 42 }, root.GetProperty("raw_payload").GetBytesFromBase64());
        }

        private sealed class ConflictingResolver : IMetadataResolver
        {
            public ConflictingResolver(MetadataSource source) => this.Source = source;
            public MetadataSource Source { get; }
            public ResolutionResult Resolve(EventKey key) => ResolutionResult.UnresolvedResult(
                ResolutionStatus.Conflict, this.Source, "evidence:first;second", "Conflicting supplied schemas.");
        }

        private static IMetadataResolverChain BuildCache(EventKey key, IEventTraceOperand first, IEventTraceOperand second, bool sharedCache)
        {
            var firstResult = new ResolutionResult(first, MetadataSource.Embedded, "first schema");
            var secondResult = new ResolutionResult(second, MetadataSource.Embedded, "second schema");
            if (sharedCache)
            {
                var cache = new CachedSchemaResolver();
                cache.Store(key, firstResult);
                cache.Store(key, secondResult);
                var chain = new MetadataResolver();
                chain.Add(cache);
                return chain;
            }

            var preflight = new PreflightMetadata(new MetadataResolver());
            preflight.Store(key, firstResult);
            preflight.Store(key, secondResult);
            return preflight;
        }

        private static IEventTraceOperand BuildOperand(EventKey key, string layout, bool alternate)
        {
            bool referenced = layout.StartsWith("variable-", StringComparison.Ordinal);
            var firstCount = NewProperty("FirstCount", 0, TDH_IN_TYPE.TDH_INTYPE_UINT32);
            var secondCount = NewProperty("SecondCount", 1, TDH_IN_TYPE.TDH_INTYPE_UINT32);
            bool array = layout == "fixed-array" || layout == "variable-array" || layout == "scalar-array" && alternate;
            bool length = layout == "fixed-length" || layout == "variable-length";
            var value = NewProperty("Value", referenced ? 2 : 0,
                length ? TDH_IN_TYPE.TDH_INTYPE_BINARY : TDH_IN_TYPE.TDH_INTYPE_UINT32,
                layout == "variable-array", array && layout != "variable-array",
                layout == "variable-length", layout == "fixed-length");
            if (layout == "fixed-array") value.SetFixedArraySize(alternate ? 2 : 1);
            if (layout == "scalar-array" && alternate) value.SetFixedArraySize(1);
            if (layout == "fixed-length") value.SetFixedLengthSize(alternate ? 8 : 4);
            if (referenced)
            {
                var reference = alternate ? secondCount : firstCount;
                reference.IsReferencedByOtherProperties = true;
                if (layout == "variable-array") value.SetVariableArraySize(reference);
                else value.SetVariableLengthSize(reference);
            }

            var operands = referenced ? new[] { firstCount, secondCount, value } : new[] { value };
            var metadata = new EventMetadata(key.ProviderGuid, key.EventId, key.Version, "TestProvider/Event",
                operands.Select(property => property.Metadata).ToArray(), "TestProvider", MetadataSource.Embedded, DecodeStatus.Decoded, "embedded");
            return new EventTraceOperand(metadata, 0, operands);
        }

        private static EventTracePropertyOperand NewProperty(string name, int index, TDH_IN_TYPE type,
            bool variableArray = false, bool fixedArray = false, bool variableLength = false, bool fixedLength = false)
        {
            return new EventTracePropertyOperand(new PropertyMetadata(type, TDH_OUT_TYPE.TDH_OUTTYPE_NOPRINT, name, false, false, 0, null),
                index, variableArray, fixedArray, variableLength, fixedLength, false);
        }
    }
}
