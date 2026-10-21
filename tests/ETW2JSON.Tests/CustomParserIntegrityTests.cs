namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Text;
    using System.Text.Json;
    using ETW2JSON.Analysis;
    using ETWDeserializer;
    using ETWDeserializer.CustomParsers;
    using Xunit;

    public sealed unsafe class CustomParserIntegrityTests
    {
        [Theory]
        [InlineData("image", false)]
        [InlineData("image", true)]
        [InlineData("debug", false)]
        [InlineData("debug", true)]
        [InlineData("version", false)]
        [InlineData("version", true)]
        [InlineData("stack", false)]
        [InlineData("stack", true)]
        public void SupportedKernelLayoutsDecodeWithExplicitProvenance(string kind, bool is32Bit)
        {
            var events = Convert(kind, is32Bit, false, BuildPayload(kind, is32Bit));
            var evt = Assert.Single(events);
            Assert.Equal("decoded", evt.GetProperty("decode_status").GetString());
            Assert.Equal("builtin_parser", evt.GetProperty("metadata_source").GetString());
            Assert.Contains("builtin:", evt.GetProperty("metadata_provenance").GetString());
            Assert.Contains("version:0", evt.GetProperty("metadata_provenance").GetString());
            Assert.Equal(0, evt.GetProperty("event_header").GetProperty("event_id").GetInt32());
            var properties = evt.GetProperty("properties");
            if (kind == "image")
            {
                Assert.Equal(is32Bit ? 0x12345678UL : 0x100000001UL, properties.GetProperty("ImageSize").GetUInt64());
                Assert.Equal(1234U, properties.GetProperty("ProcessID").GetUInt32());
                Assert.Equal("証拠.dll", properties.GetProperty("OriginalFileName").GetString());
            }
            else if (kind == "debug")
            {
                Assert.Equal(is32Bit ? 0x12345678UL : 0xFEDCBA9876543210UL, properties.GetProperty("ImageBase").GetUInt64());
                Assert.Equal("証拠.pdb", properties.GetProperty("PdbFileName").GetString());
                Assert.Equal("00112233-4455-6677-8899-aabbccddeeff", properties.GetProperty("GuidSig").GetString());
            }
            else if (kind == "stack")
            {
                Assert.Equal(2, properties.GetProperty("Stacks").GetArrayLength());
                Assert.Equal(is32Bit ? 0xDEADBEEFUL : 0xFEDCBA9876543210UL, properties.GetProperty("Stacks")[0].GetUInt64());
            }
        }

        [Theory]
        [InlineData("image", false)]
        [InlineData("image", true)]
        [InlineData("debug", false)]
        [InlineData("debug", true)]
        [InlineData("version", false)]
        [InlineData("version", true)]
        [InlineData("stack", false)]
        [InlineData("stack", true)]
        public void MalformedKernelPayloadDoesNotConsumeOrCorruptTheFollowingRecord(string kind, bool legacy)
        {
            byte[] valid = BuildPayload(kind, false);
            byte[] trailing = valid.Concat(new byte[] { 0xFF }).ToArray();
            var events = Convert(kind, false, legacy, trailing, Array.Empty<byte>(), valid);
            Assert.Equal(3, events.Length);
            Assert.Equal("decode_error", events[0].GetProperty("decode_status").GetString());
            Assert.Equal("decode_error", events[1].GetProperty("decode_status").GetString());
            Assert.Equal("decoded", events[2].GetProperty("decode_status").GetString());
            Assert.Equal(trailing, events[0].GetProperty("raw_payload").GetBytesFromBase64());
            Assert.Equal("builtin_parser", events[0].GetProperty("metadata_source").GetString());
        }

        [Theory]
        [InlineData("image")]
        [InlineData("debug")]
        [InlineData("version")]
        [InlineData("stack")]
        public void SupportedKernelParserIsNotReportedAsMissingMetadata(string kind)
        {
            var scan = new ScanService(new MetadataResolver());
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var deserializer = new Deserializer<JsonlEventWriter>(writer)
            {
                SchemaOnly = true,
                SourceFile = "kernel.etl",
                SourceObserver = (source, key, operand) => scan.Observe(source, key, operand),
            };
            Send(deserializer, kind, BuildPayload(kind, false), 0x0140);
            scan.Refresh(new PreflightMetadata(new MetadataResolver()));
            var entry = Assert.Single(scan.Entries).Value;
            Assert.Equal("Resolved", entry.MetadataStatus);
            Assert.Equal("BuiltinParser", entry.MetadataSource.ToString());
            using var report = new MemoryStream();
            MissingMetadataReport.WriteJson(report, scan.Entries.Values);
            using var json = JsonDocument.Parse(report.ToArray());
            Assert.Empty(json.RootElement.GetProperty("Missing").EnumerateArray());
            Assert.Null(deserializer.LastError);
        }

        [Theory]
        [InlineData((ushort)0x0100)]
        [InlineData((ushort)0x0160)]
        public void AmbiguousPointerWidthIsNotGuessed(ushort flags)
        {
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var deserializer = new Deserializer<JsonlEventWriter>(writer);
            Send(deserializer, "stack", BuildPayload("stack", false), flags);
            using var json = JsonDocument.Parse(output.ToArray());
            Assert.Equal("decode_error", json.RootElement.GetProperty("decode_status").GetString());
            Assert.Contains("pointer", json.RootElement.GetProperty("decode_note").GetString(), StringComparison.OrdinalIgnoreCase);
        }

        private static JsonElement[] Convert(string kind, bool is32Bit, bool legacy, params byte[][] payloads)
        {
            using var output = new MemoryStream();
            if (legacy)
            {
                using var writer = new LegacyJsonEventWriter(output);
                var deserializer = new Deserializer<LegacyJsonEventWriter>(writer);
                foreach (byte[] payload in payloads) Send(deserializer, kind, payload, is32Bit ? (ushort)0x0120 : (ushort)0x0140);
                Assert.Null(deserializer.LastError);
                writer.Complete();
                using var json = JsonDocument.Parse(output.ToArray());
                return json.RootElement.GetProperty("Events").EnumerateArray().Select(item => item.GetProperty("Event").Clone()).ToArray();
            }
            using (var writer = new JsonlEventWriter(output))
            {
                var deserializer = new Deserializer<JsonlEventWriter>(writer);
                foreach (byte[] payload in payloads) Send(deserializer, kind, payload, is32Bit ? (ushort)0x0120 : (ushort)0x0140);
                Assert.Null(deserializer.LastError);
            }
            return Encoding.UTF8.GetString(output.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line =>
            {
                using var json = JsonDocument.Parse(line);
                return json.RootElement.Clone();
            }).ToArray();
        }

        private static void Send<TWriter>(Deserializer<TWriter> deserializer, string kind, byte[] payload, ushort flags) where TWriter : IEtwWriter
        {
            fixed (byte* bytes = payload)
            {
                var record = new EVENT_RECORD
                {
                    ProviderId = kind == "stack" ? CustomParserGuids.KernelStackWalkGuid : CustomParserGuids.KernelTraceControlImageIdGuid,
                    Opcode = kind switch { "stack" => 32, "debug" => 36, "version" => 64, _ => 0 },
                    Flags = flags,
                    UserData = bytes,
                    UserDataLength = (ushort)payload.Length,
                };
                deserializer.Deserialize(&record);
            }
        }

        private static byte[] BuildPayload(string kind, bool is32Bit)
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream, Encoding.UTF8, true);
            if (kind == "stack")
            {
                writer.Write(123456UL); writer.Write(1234U); writer.Write(5678U);
                WritePointer(writer, is32Bit ? 0xDEADBEEFUL : 0xFEDCBA9876543210UL, is32Bit);
                WritePointer(writer, 0x10203040UL, is32Bit);
            }
            else if (kind == "image")
            {
                WritePointer(writer, is32Bit ? 0x12345678UL : 0xFEDCBA9876543210UL, is32Bit);
                WritePointer(writer, is32Bit ? 0x12345678UL : 0x100000001UL, is32Bit);
                writer.Write(1234U); writer.Write(0x12345678U);
                writer.Write(Encoding.Unicode.GetBytes("証拠.dll\0"));
            }
            else if (kind == "debug")
            {
                WritePointer(writer, is32Bit ? 0x12345678UL : 0xFEDCBA9876543210UL, is32Bit);
                writer.Write(1234U); writer.Write(Guid.Parse("00112233-4455-6677-8899-aabbccddeeff").ToByteArray()); writer.Write(7U);
                writer.Write(Encoding.UTF8.GetBytes("証拠.pdb\0"));
            }
            else
            {
                writer.Write(123U); writer.Write(0x12345678U);
                for (int i = 0; i < 10; i++) writer.Write(Encoding.Unicode.GetBytes("value" + i + "\0"));
            }
            return stream.ToArray();
        }

        private static void WritePointer(BinaryWriter writer, ulong value, bool is32Bit)
        {
            if (is32Bit) writer.Write((uint)value);
            else writer.Write(value);
        }
    }
}
