namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Text.Json;
    using ETW2JSON.Analysis;
    using ETWDeserializer;
    using Xunit;

    public sealed class ScanSchemaShapeTests
    {
        [Fact]
        public void DifferentArrayCountsAcrossSourcesAreReportedAsDifferentSchemas()
        {
            var key = new EventKey(Guid.NewGuid(), 1, 0);
            var scan = Scan(key, Operand(key, MetadataSource.Embedded, "Provider/Event", 1),
                Operand(key, MetadataSource.Embedded, "Provider/Event", 2));

            Assert.Equal("Conflict", Assert.Single(scan.Entries).Value.MetadataStatus);
        }

        [Fact]
        public void IdenticalSchemasAcrossSourcesRemainResolved()
        {
            var key = new EventKey(Guid.NewGuid(), 1, 0);
            var scan = Scan(key, Operand(key, MetadataSource.Embedded, "Provider/Event", 2),
                Operand(key, MetadataSource.Embedded, "Provider/Event", 2));

            var entry = Assert.Single(scan.Entries).Value;
            Assert.Equal("Resolved", entry.MetadataStatus);
            Assert.Equal(2, entry.Count);
        }

        [Fact]
        public void DifferentSupportedTraceLoggingShapesAcrossSourcesAreNotSchemaConflicts()
        {
            var key = new EventKey(Guid.NewGuid(), 0, 0);
            var scan = Scan(key, Operand(key, MetadataSource.TraceLogging, "Provider/First", 1),
                Operand(key, MetadataSource.TraceLogging, "Provider/Second", 2));

            Assert.Equal("Resolved", Assert.Single(scan.Entries).Value.MetadataStatus);
            using var stream = new MemoryStream();
            MissingMetadataReport.WriteJson(stream, scan.Entries.Values);
            using var json = JsonDocument.Parse(stream.ToArray());
            Assert.Equal(0, json.RootElement.GetProperty("Missing").GetArrayLength());
        }

        private static ScanService Scan(EventKey key, IEventTraceOperand first, IEventTraceOperand second)
        {
            var scan = new ScanService(new MetadataResolver());
            scan.Observe("first.etl", key, first);
            scan.Observe("second.etl", key, second);
            scan.Refresh(new PreflightMetadata(new MetadataResolver()));
            return scan;
        }

        private static IEventTraceOperand Operand(EventKey key, MetadataSource source, string name, int count)
        {
            var property = new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_INT32, TDH_OUT_TYPE.TDH_OUTTYPE_NULL,
                "values", false, false, 0, null);
            var field = new EventTracePropertyOperand(property, 0, false, true, false, false, false);
            field.SetFixedArraySize(count);
            var metadata = new EventMetadata(key.ProviderGuid, key.EventId, key.Version, name,
                new[] { property }, "Provider", source, DecodeStatus.Decoded, "test-schema");
            return new EventTraceOperand(metadata, 0, new[] { field });
        }
    }
}
