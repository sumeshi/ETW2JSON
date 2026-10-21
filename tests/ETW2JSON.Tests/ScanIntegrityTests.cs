namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Text.Json;
    using ETW2JSON.Analysis;
    using ETWDeserializer;
    using Xunit;

    public sealed class ScanIntegrityTests
    {
        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public void UnsupportedTraceLoggingShapeCannotDisappearBehindSupportedShape(bool unsupportedFirst)
        {
            var key = new EventKey(Guid.NewGuid(), 0, 0);
            var supported = Operand(key, "Provider/Supported", MetadataSource.TraceLogging, DecodeStatus.Decoded);
            var unsupported = Operand(key, "Provider/Unsupported", MetadataSource.TraceLogging, DecodeStatus.Unsupported,
                "Unsupported TraceLogging field.");
            var scan = new ScanService(new MetadataResolver());
            scan.Observe("source.etl", key, unsupportedFirst ? unsupported : supported);
            scan.Observe("source.etl", key, unsupportedFirst ? supported : unsupported);

            scan.Refresh(new PreflightMetadata(new MetadataResolver()));

            var entry = Assert.Single(scan.Entries).Value;
            Assert.Equal(2, entry.Count);
            Assert.Equal("Mixed", entry.MetadataStatus);
            Assert.Contains("Unsupported TraceLogging field", entry.Reason);
            using var stream = new MemoryStream();
            MissingMetadataReport.WriteJson(stream, scan.Entries.Values);
            using var json = JsonDocument.Parse(stream.ToArray());
            var missing = json.RootElement.GetProperty("Missing");
            Assert.Equal(1, missing.GetArrayLength());
            Assert.Equal("Mixed", missing[0].GetProperty("metadata_status").GetString());
        }

        [Fact]
        public void UnsupportedHeaderCannotDisappearBehindSupportedRecordWithSameIdentity()
        {
            var key = new EventKey(Guid.NewGuid(), 1, 0);
            var scan = new ScanService(new MetadataResolver());
            scan.Observe("source.etl", key, Operand(key, "Provider/Supported", MetadataSource.Embedded, DecodeStatus.Decoded));
            scan.Observe("source.etl", key, Operand(key, "UnsupportedHeader", MetadataSource.Unknown, DecodeStatus.Unsupported,
                "WPP/TraceMessage payload decoding is unsupported; the raw payload is retained."));

            scan.Refresh(new PreflightMetadata(new MetadataResolver()));

            Assert.Equal("Mixed", Assert.Single(scan.Entries).Value.MetadataStatus);
        }

        [Fact]
        public void DifferentSupportedTraceLoggingShapesRemainResolved()
        {
            var key = new EventKey(Guid.NewGuid(), 0, 0);
            var scan = new ScanService(new MetadataResolver());
            scan.Observe("source.etl", key, Operand(key, "Provider/First", MetadataSource.TraceLogging, DecodeStatus.Decoded));
            scan.Observe("source.etl", key, Operand(key, "Provider/Second", MetadataSource.TraceLogging, DecodeStatus.Decoded));

            scan.Refresh(new PreflightMetadata(new MetadataResolver()));

            Assert.Equal("Resolved", Assert.Single(scan.Entries).Value.MetadataStatus);
        }

        [Fact]
        public void LateSchemaStillResolvesEarlierMissingMetadata()
        {
            var key = new EventKey(Guid.NewGuid(), 1, 0);
            var scan = new ScanService(new MetadataResolver());
            scan.Observe("source.etl", key, null);
            var operand = Operand(key, "Provider/Event", MetadataSource.Embedded, DecodeStatus.Decoded);
            scan.Observe("source.etl", key, operand);
            var resolver = new PreflightMetadata(new MetadataResolver());
            resolver.SetCurrentSource("source.etl");
            resolver.Store(key, new ResolutionResult(operand, MetadataSource.Embedded, "source.etl"));

            scan.Refresh(resolver);

            Assert.Equal("Resolved", Assert.Single(scan.Entries).Value.MetadataStatus);
        }

        private static IEventTraceOperand Operand(EventKey key, string name, MetadataSource source, DecodeStatus status, string reason = null)
        {
            var metadata = new EventMetadata(key.ProviderGuid, key.EventId, key.Version, name,
                Array.Empty<PropertyMetadata>(), "Provider", source, status, "source.etl", reason);
            return new EventTraceOperand(metadata, 0, Array.Empty<IEventTracePropertyOperand>());
        }
    }
}
