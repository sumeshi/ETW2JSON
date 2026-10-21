namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Runtime.InteropServices;
    using System.Text;
    using System.Text.Json;
    using ETW2JSON.Analysis;
    using ETWDeserializer;
    using ETWDeserializer.CustomParsers;
    using Xunit;

    public sealed unsafe class ClassicEmbeddedSchemaTests
    {
        [Fact]
        public void EmbeddedMofSchemaMatchesTheClassGuidAndOpcode()
        {
            Guid systemProvider = Guid.NewGuid();
            Guid eventClass = Guid.NewGuid();
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var deserializer = new Deserializer<JsonlEventWriter>(writer);
            SendMetadata(deserializer, BuildSchema(systemProvider, eventClass, 10, 0, 1));
            SendData(deserializer, eventClass, 10, 0, 1, 42);

            var evt = ReadEvents(output).Last();
            Assert.Null(deserializer.LastError);
            Assert.Equal("decoded", evt.GetProperty("decode_status").GetString());
            Assert.Equal(42, evt.GetProperty("properties").GetProperty("Value").GetInt32());
            Assert.Equal(eventClass.ToString("D"), evt.GetProperty("provider_guid").GetString());
            Assert.Equal(eventClass.ToString("D"), evt.GetProperty("event_header").GetProperty("provider_guid").GetString());
            Assert.Equal(0, evt.GetProperty("event_header").GetProperty("event_id").GetInt32());
            Assert.Equal(10, evt.GetProperty("event_header").GetProperty("opcode").GetInt32());
            Assert.Equal(1, evt.GetProperty("event_header").GetProperty("version").GetInt32());
        }

        [Fact]
        public void PreflightAndInventorySeparateClassicOpcodesWithoutInventingEventIds()
        {
            Guid systemProvider = Guid.NewGuid();
            Guid eventClass = Guid.NewGuid();
            var preflight = new PreflightMetadata(new MetadataResolver());
            var scan = new ScanService(preflight);
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var firstPass = new Deserializer<JsonlEventWriter>(writer)
            {
                ResolverChain = preflight,
                SchemaOnly = true,
                SourceFile = "classic.etl",
                SourceObserver = (source, key, operand) => scan.Observe(source, key, operand),
            };
            firstPass.SetCurrentSource("classic.etl");
            SendData(firstPass, eventClass, 10, 0, 1, 42);
            SendData(firstPass, eventClass, 11, 0, 1, 99);
            SendMetadata(firstPass, BuildSchema(systemProvider, eventClass, 10, 0, 1));
            SendMetadata(firstPass, BuildSchema(systemProvider, eventClass, 11, 0, 1));
            scan.Refresh(preflight);

            var entries = scan.Entries.Values.Where(entry => entry.Key.ProviderGuid == eventClass).ToArray();
            Assert.Equal(2, entries.Length);
            Assert.All(entries, entry => Assert.Equal("Resolved", entry.MetadataStatus));
            using var scanOutput = new MemoryStream();
            scan.WriteJson(scanOutput);
            using var scanJson = JsonDocument.Parse(scanOutput.ToArray());
            var classic = scanJson.RootElement.GetProperty("Providers").EnumerateArray()
                .Where(entry => entry.GetProperty("provider_guid").GetString() == eventClass.ToString("D"))
                .SelectMany(entry => entry.GetProperty("events").EnumerateArray()).ToArray();
            Assert.Equal(new[] { 10, 11 }, classic.Select(entry => entry.GetProperty("classic_opcode").GetInt32()).OrderBy(value => value).ToArray());
            Assert.All(classic, entry => Assert.Equal(0, entry.GetProperty("event_id").GetInt32()));

            var secondPass = new Deserializer<JsonlEventWriter>(writer) { ResolverChain = preflight, SourceFile = "classic.etl" };
            secondPass.SetCurrentSource("classic.etl");
            SendData(secondPass, eventClass, 10, 0, 1, 42);
            SendData(secondPass, eventClass, 11, 0, 1, 99);
            Assert.Null(firstPass.LastError);
            Assert.Null(secondPass.LastError);
            var events = ReadEvents(output);
            Assert.Equal(2, events.Length);
            Assert.All(events, entry => Assert.Equal("decoded", entry.GetProperty("decode_status").GetString()));
            Assert.Equal(new[] { 42, 99 }, events.Select(entry => entry.GetProperty("properties").GetProperty("Value").GetInt32()));
        }

        [Fact]
        public void MissingClassicSchemasHaveClassSpecificRecoveryGuidance()
        {
            Guid eventClass = Guid.NewGuid();
            var scan = new ScanService(new MetadataResolver());
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var deserializer = new Deserializer<JsonlEventWriter>(writer)
            {
                SchemaOnly = true,
                SourceObserver = (source, key, operand) => scan.Observe(source, key, operand),
            };
            SendData(deserializer, eventClass, 10, 0, 0, 42);
            SendData(deserializer, eventClass, 11, 0, 0, 99);
            using var report = new MemoryStream();
            MissingMetadataReport.WriteJson(report, scan.Entries.Values);
            using var json = JsonDocument.Parse(report.ToArray());
            var missing = json.RootElement.GetProperty("Missing");
            Assert.Equal(2, missing.GetArrayLength());
            Assert.All(missing.EnumerateArray(), entry =>
            {
                Assert.Equal(JsonValueKind.Null, entry.GetProperty("registry_key_candidate").ValueKind);
                Assert.Contains("MOF", entry.GetProperty("guidance").GetString());
                Assert.True(entry.TryGetProperty("classic_opcode", out _));
            });
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void RecognizedSchemaContainersStayPartialWithoutFalseMissingMetadata(bool eventSource)
        {
            var scan = new ScanService(new MetadataResolver());
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var deserializer = new Deserializer<JsonlEventWriter>(writer)
            {
                SourceObserver = (source, key, operand) => scan.Observe(source, key, operand),
            };
            if (eventSource)
            {
                byte* payload = stackalloc byte[] { 1, 0, 0, 0x5B, 2, 0, 0, 0, 1, 2, 3 };
                var record = new EVENT_RECORD { ProviderId = Guid.NewGuid(), Id = 65534, Flags = 0x0040, UserData = payload, UserDataLength = 11 };
                deserializer.Deserialize(&record);
            }
            else SendMetadata(deserializer, BuildSchema(Guid.NewGuid(), Guid.NewGuid(), 10, 0, 0));
            scan.Refresh(new PreflightMetadata(new MetadataResolver()));

            Assert.Null(deserializer.LastError);
            using var json = JsonDocument.Parse(output.ToArray());
            Assert.Equal("partial", json.RootElement.GetProperty("decode_status").GetString());
            Assert.Equal("embedded", json.RootElement.GetProperty("metadata_source").GetString());
            Assert.Contains("metadata", json.RootElement.GetProperty("decode_note").GetString(), StringComparison.OrdinalIgnoreCase);
            Assert.Equal("Resolved", Assert.Single(scan.Entries).Value.MetadataStatus);
            using var report = new MemoryStream();
            MissingMetadataReport.WriteJson(report, scan.Entries.Values);
            using var missing = JsonDocument.Parse(report.ToArray());
            Assert.Empty(missing.RootElement.GetProperty("Missing").EnumerateArray());
        }

        [Theory]
        [InlineData((byte)0)]
        [InlineData((byte)2)]
        public void ManifestStyleEmbeddedSchemaKeepsItsProviderAndEventId(byte version)
        {
            Guid provider = Guid.NewGuid();
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var deserializer = new Deserializer<JsonlEventWriter>(writer);
            SendMetadata(deserializer, BuildSchema(provider, Guid.Empty, 5, 123, version));
            SendData(deserializer, provider, 5, 123, version, 42, classic: false);
            var evt = ReadEvents(output).Last();
            Assert.Equal("decoded", evt.GetProperty("decode_status").GetString());
            Assert.Equal(123, evt.GetProperty("event_id").GetInt32());
            Assert.Equal(provider.ToString("D"), evt.GetProperty("provider_guid").GetString());
            Assert.Null(deserializer.LastError);
        }

        private static byte[] BuildSchema(Guid provider, Guid eventClass, byte opcode, ushort id, byte version)
        {
            int propertiesOffset = (int)Marshal.OffsetOf<TRACE_EVENT_INFO>(nameof(TRACE_EVENT_INFO.EventPropertyInfoArray));
            int nameOffset = propertiesOffset + sizeof(EVENT_PROPERTY_INFO);
            byte[] propertyName = Encoding.Unicode.GetBytes("Value\0");
            byte[] schema = new byte[nameOffset + propertyName.Length];
            fixed (byte* bytes = schema)
            {
                var info = (TRACE_EVENT_INFO*)bytes;
                info->ProviderGuid = provider;
                info->EventGuid = eventClass;
                info->Id = id;
                info->Opcode = opcode;
                info->Version = version;
                info->DecodingSource = eventClass == Guid.Empty ? DECODING_SOURCE.DecodingSourceXMLFile : DECODING_SOURCE.DecodingSourceWbem;
                info->PropertyCount = 1;
                info->TopLevelPropertyCount = 1;
                var property = (EVENT_PROPERTY_INFO*)(bytes + propertiesOffset);
                property->NameOffset = (uint)nameOffset;
                property->NonStructType.InType = (ushort)TDH_IN_TYPE.TDH_INTYPE_INT32;
                property->count = 1;
                propertyName.CopyTo(schema, nameOffset);
            }
            return schema;
        }

        private static void SendMetadata(Deserializer<JsonlEventWriter> deserializer, byte[] schema)
        {
            fixed (byte* bytes = schema)
            {
                var record = new EVENT_RECORD { ProviderId = CustomParserGuids.KernelTraceControlMetaDataGuid, Opcode = 32, Flags = 0x0140, UserData = bytes, UserDataLength = (ushort)schema.Length };
                deserializer.Deserialize(&record);
            }
        }

        private static void SendData(Deserializer<JsonlEventWriter> deserializer, Guid provider, byte opcode, ushort id, byte version, int value, bool classic = true)
        {
            byte* bytes = stackalloc byte[4];
            *(int*)bytes = value;
            var record = new EVENT_RECORD { ProviderId = provider, Id = id, Opcode = opcode, Version = version,
                Flags = classic ? (ushort)0x0140 : (ushort)0x0040, UserData = bytes, UserDataLength = 4 };
            deserializer.Deserialize(&record);
        }

        private static JsonElement[] ReadEvents(MemoryStream output) => Encoding.UTF8.GetString(output.ToArray())
            .Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line =>
            {
                using var json = JsonDocument.Parse(line);
                return json.RootElement.Clone();
            }).ToArray();
    }
}
