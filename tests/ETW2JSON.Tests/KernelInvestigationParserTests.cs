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

    public sealed unsafe class KernelInvestigationParserTests
    {
        [Theory]
        [InlineData("process", false)]
        [InlineData("process", true)]
        [InlineData("image", false)]
        [InlineData("image", true)]
        [InlineData("file", false)]
        [InlineData("file", true)]
        public void DocumentedKernelWireLayoutsRetainInvestigationFields(string kind, bool is32Bit)
        {
            var evt = Assert.Single(Decode(kind, is32Bit, BuildPayload(kind, is32Bit)));
            Assert.Equal("decoded", evt.GetProperty("decode_status").GetString());
            Assert.Equal("builtin_parser", evt.GetProperty("metadata_source").GetString());
            Assert.Contains("layout_revision:1", evt.GetProperty("metadata_provenance").GetString());
            Assert.Equal(999U, evt.GetProperty("process_id").GetUInt32());
            var properties = evt.GetProperty("properties");
            if (kind == "process")
            {
                Assert.Equal(1234U, properties.GetProperty("ProcessId").GetUInt32());
                Assert.Equal(5678U, properties.GetProperty("ParentId").GetUInt32());
                Assert.Equal("調査.exe --引数", properties.GetProperty("CommandLine").GetString());
                Assert.Equal("調査.exe", properties.GetProperty("ImageFileName").GetString());
                Assert.Equal("S-1-5-21-42", properties.GetProperty("UserSID").GetString());
                Assert.Equal(is32Bit ? 0x12345678UL : 0xFEDCBA9876543210UL, properties.GetProperty("UniqueProcessKey").GetUInt64());
            }
            else if (kind == "image")
            {
                Assert.Equal(1234U, properties.GetProperty("ProcessId").GetUInt32());
                Assert.Equal(is32Bit ? 0x12345678UL : 0x100000001UL, properties.GetProperty("ImageSize").GetUInt64());
                Assert.Equal("\\Device\\HarddiskVolume2\\証拠.dll", properties.GetProperty("FileName").GetString());
                Assert.Equal(0x12345678U, properties.GetProperty("TimeDateStamp").GetUInt32());
            }
            else
            {
                Assert.Equal(is32Bit ? 0x12345678UL : 0xFEDCBA9876543210UL, properties.GetProperty("FileKey").GetUInt64());
                Assert.Equal("\\Device\\HarddiskVolume2\\証拠.txt", properties.GetProperty("FileName").GetString());
                Assert.False(properties.TryGetProperty("FileObject", out _));
            }
        }

        [Theory]
        [InlineData("process")]
        [InlineData("image")]
        [InlineData("file")]
        public void IncompleteAndExtraPayloadsRemainRawAndDoNotBreakFollowingRecords(string kind)
        {
            byte[] valid = BuildPayload(kind, false);
            byte[] truncated = valid.Take(valid.Length - 1).ToArray();
            byte[] extra = valid.Concat(new byte[] { 0xFF }).ToArray();
            var events = Decode(kind, false, truncated, extra, valid);
            Assert.Equal(3, events.Length);
            Assert.Equal("decode_error", events[0].GetProperty("decode_status").GetString());
            Assert.Equal("decode_error", events[1].GetProperty("decode_status").GetString());
            Assert.Equal("decoded", events[2].GetProperty("decode_status").GetString());
            Assert.Equal(truncated, events[0].GetProperty("raw_payload").GetBytesFromBase64());
            Assert.Empty(events[0].GetProperty("properties").EnumerateObject());
            Assert.Equal("builtin_parser", events[0].GetProperty("metadata_source").GetString());
        }

        [Theory]
        [InlineData("process")]
        [InlineData("image")]
        [InlineData("file")]
        public void FutureVersionsAreNotDecodedWithAnOlderBuiltinLayout(string kind)
        {
            var evt = DecodeOne(kind, false, BuildPayload(kind, false), (byte)(Version(kind) + 1));
            Assert.Equal("metadata_missing", evt.GetProperty("decode_status").GetString());
            Assert.Equal("unknown", evt.GetProperty("metadata_source").GetString());
            Assert.Empty(evt.GetProperty("properties").EnumerateObject());
        }

        [Theory]
        [InlineData("process")]
        [InlineData("image")]
        [InlineData("file")]
        public void UnverifiedOpcodesStayUnknown(string kind)
        {
            var evt = DecodeOne(kind, false, BuildPayload(kind, false), Version(kind), opcode: 250);
            Assert.Equal("metadata_missing", evt.GetProperty("decode_status").GetString());
            Assert.Equal("unknown", evt.GetProperty("metadata_source").GetString());
        }

        [Theory]
        [InlineData("process")]
        [InlineData("image")]
        [InlineData("file")]
        public void ClassicFallbackIsNotAppliedToManifestStyleRecords(string kind)
        {
            var evt = DecodeOne(kind, false, BuildPayload(kind, false), Version(kind), classic: false);
            Assert.Equal("metadata_missing", evt.GetProperty("decode_status").GetString());
            Assert.Equal("unknown", evt.GetProperty("metadata_source").GetString());
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void NullProcessSidUsesItsFourByteWireMarker(bool is32Bit)
        {
            var evt = Assert.Single(Decode("process", is32Bit, BuildPayload("process", is32Bit, nullSid: true)));
            Assert.Equal("decoded", evt.GetProperty("decode_status").GetString());
            Assert.Equal(JsonValueKind.Null, evt.GetProperty("properties").GetProperty("UserSID").ValueKind);
            Assert.Equal("調査.exe --引数", evt.GetProperty("properties").GetProperty("CommandLine").GetString());
        }

        [Fact]
        public void MalformedSidKeepsTheCompleteRawPayload()
        {
            byte[] payload = BuildPayload("process", false);
            // Process v4 x64: fixed fields 36 bytes, TOKEN_USER 16 bytes, then SID revision/count.
            payload[52] = 9;
            var evt = Assert.Single(Decode("process", false, payload));
            Assert.Equal("decode_error", evt.GetProperty("decode_status").GetString());
            Assert.Equal(payload, evt.GetProperty("raw_payload").GetBytesFromBase64());
        }

        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void EmbeddedEvidenceSchemaAndItsConflictsTakePriorityOverBuiltinFallback(bool conflicting)
        {
            byte[] payload = BuildPayload("file", false);
            var resolver = EmbeddedFileSchema(payload.Length, conflicting);
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var deserializer = new Deserializer<JsonlEventWriter>(writer) { ResolverChain = resolver };
            Send(deserializer, "file", false, payload, 2);
            Assert.Null(deserializer.LastError);
            using var json = JsonDocument.Parse(output.ToArray());
            var evt = json.RootElement;
            Assert.Equal("embedded", evt.GetProperty("metadata_source").GetString());
            Assert.Equal(conflicting ? "decode_error" : "decoded", evt.GetProperty("decode_status").GetString());
            Assert.False(evt.GetProperty("properties").TryGetProperty("FileKey", out _));
            if (!conflicting) Assert.Equal(payload, evt.GetProperty("properties").GetProperty("EvidenceBytes").GetBytesFromBase64());
            Assert.Equal(payload, evt.GetProperty("raw_payload").GetBytesFromBase64());
        }

        [Fact]
        public void InventoryRefreshPromotesLateEmbeddedSchemaOverEarlierBuiltinFallback()
        {
            byte[] payload = BuildPayload("file", false);
            var resolver = new PreflightMetadata(new MetadataResolver());
            var scan = new ScanService(resolver);
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var deserializer = new Deserializer<JsonlEventWriter>(writer)
            {
                ResolverChain = resolver, SchemaOnly = true,
                SourceObserver = (source, key, operand) => scan.Observe(source, key, operand),
            };
            Send(deserializer, "file", false, payload, 2);
            var known = EmbeddedFileSchema(payload.Length, false);
            var key = new EventKey(Guid.Parse("90cbdc39-4a3e-11d1-84f4-0000f80464e3"), 0, 2, 36);
            resolver.Store(key, known.Resolve(key));

            scan.Refresh(resolver);

            var entry = Assert.Single(scan.Entries).Value;
            Assert.Equal("Resolved", entry.MetadataStatus);
            Assert.Equal(MetadataSource.Embedded, entry.MetadataSource);
        }

        private static PreflightMetadata EmbeddedFileSchema(int length, bool conflicting)
        {
            var key = new EventKey(Guid.Parse("90cbdc39-4a3e-11d1-84f4-0000f80464e3"), 0, 2, 36);
            var resolver = new PreflightMetadata(new MetadataResolver());
            for (int i = 0; i < (conflicting ? 2 : 1); i++)
            {
                var property = new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_BINARY, TDH_OUT_TYPE.TDH_OUTTYPE_NULL,
                    i == 0 ? "EvidenceBytes" : "ConflictingBytes", false, false, 0, null);
                var field = new EventTracePropertyOperand(property, 0, false, false, false, true, false);
                field.SetFixedLengthSize(length);
                var metadata = new EventMetadata(key.ProviderGuid, 0, 2, "Evidence/Event", new[] { property }, "Evidence", MetadataSource.Embedded,
                    DecodeStatus.Decoded, "etl:evidence");
                resolver.Store(key, new ResolutionResult(new EventTraceOperand(metadata, 0, new[] { field }), MetadataSource.Embedded, "etl:evidence"));
            }
            return resolver;
        }

        private static JsonElement[] Decode(string kind, bool is32Bit, params byte[][] payloads)
        {
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var deserializer = new Deserializer<JsonlEventWriter>(writer);
            foreach (byte[] payload in payloads) Send(deserializer, kind, is32Bit, payload, Version(kind));
            Assert.Null(deserializer.LastError);
            return Encoding.UTF8.GetString(output.ToArray()).Split('\n', StringSplitOptions.RemoveEmptyEntries).Select(line =>
            {
                using var json = JsonDocument.Parse(line);
                return json.RootElement.Clone();
            }).ToArray();
        }

        private static JsonElement DecodeOne(string kind, bool is32Bit, byte[] payload, byte version, byte? opcode = null, bool classic = true)
        {
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var deserializer = new Deserializer<JsonlEventWriter>(writer);
            Send(deserializer, kind, is32Bit, payload, version, opcode, classic);
            Assert.Null(deserializer.LastError);
            using var json = JsonDocument.Parse(output.ToArray());
            return json.RootElement.Clone();
        }

        private static void Send(Deserializer<JsonlEventWriter> deserializer, string kind, bool is32Bit, byte[] payload, byte version, byte? opcode = null, bool classic = true)
        {
            Guid provider = Guid.Parse(kind switch
            {
                "process" => "3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c",
                "image" => "2cb15d1d-5fc1-11d2-abe1-00a0c911f518",
                _ => "90cbdc39-4a3e-11d1-84f4-0000f80464e3",
            });
            fixed (byte* data = payload)
            {
                var record = new EVENT_RECORD { ProviderId = provider, ProcessId = 999, Version = version,
                    Opcode = opcode ?? (kind switch { "process" => (byte)1, "image" => (byte)10, _ => (byte)36 }),
                    Flags = (ushort)((is32Bit ? 0x0020 : 0x0040) | (classic ? 0x0100 : 0)), UserData = data, UserDataLength = (ushort)payload.Length };
                deserializer.Deserialize(&record);
            }
        }

        private static byte Version(string kind) => kind == "process" ? (byte)4 : (byte)2;

        private static byte[] BuildPayload(string kind, bool is32Bit, bool nullSid = false)
        {
            using var stream = new MemoryStream();
            using var writer = new BinaryWriter(stream, Encoding.UTF8, true);
            Pointer(writer, is32Bit ? 0x12345678UL : 0xFEDCBA9876543210UL, is32Bit);
            if (kind == "process")
            {
                writer.Write(1234U); writer.Write(5678U); writer.Write(1U); writer.Write(259U);
                Pointer(writer, 0xBE0D6000UL, is32Bit); writer.Write(0U);
                if (nullSid) writer.Write(0U);
                else
                {
                    Pointer(writer, 1UL, is32Bit); Pointer(writer, 0UL, is32Bit);
                    writer.Write(new byte[] { 1, 2, 0, 0, 0, 0, 0, 5 }); writer.Write(21U); writer.Write(42U);
                }
                writer.Write(Encoding.UTF8.GetBytes("調査.exe\0"));
                writer.Write(Encoding.Unicode.GetBytes("調査.exe --引数\0package\0app\0"));
            }
            else if (kind == "image")
            {
                Pointer(writer, is32Bit ? 0x12345678UL : 0x100000001UL, is32Bit);
                writer.Write(1234U); writer.Write(0xABCDEFU); writer.Write(0x12345678U); writer.Write(0U);
                Pointer(writer, 0x10203040UL, is32Bit);
                for (int i = 0; i < 4; i++) writer.Write(0U);
                writer.Write(Encoding.Unicode.GetBytes("\\Device\\HarddiskVolume2\\証拠.dll\0"));
            }
            else writer.Write(Encoding.Unicode.GetBytes("\\Device\\HarddiskVolume2\\証拠.txt\0"));
            return stream.ToArray();
        }

        private static void Pointer(BinaryWriter writer, ulong value, bool is32Bit)
        {
            if (is32Bit) writer.Write((uint)value);
            else writer.Write(value);
        }
    }
}
