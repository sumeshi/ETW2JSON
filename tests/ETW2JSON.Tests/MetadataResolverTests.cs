namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Text;
    using System.Xml;
    using ETWDeserializer;
    using ETW2JSON.Analysis;
    using Xunit;

    public class MetadataResolverTests
    {
        [Fact]
        [Trait("Task", "T15")]
        public void ManifestResolverRejectsDtd()
        {
            string path = Path.Combine(Path.GetTempPath(), "dtd-" + Guid.NewGuid().ToString("N") + ".man");
            File.WriteAllText(path, "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><instrumentationManifest>&xxe;</instrumentationManifest>");
            try
            {
                var resolver = new ManifestFileResolver();
                Assert.ThrowsAny<Exception>(() => resolver.AddFile(path));
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        [Trait("Task", "T12")]
        public void EmptyChainResolvesUnknown()
        {
            var chain = new MetadataResolver();
            var result = chain.Resolve(new EventKey(Guid.NewGuid(), 1, 0));
            Assert.False(result.Resolved);
            Assert.Equal(MetadataSource.Unknown, result.Source);
        }

        [Fact]
        public void ManifestResolverRejectsConflictingSchemasForSameProviderEventAndVersion()
        {
            Guid provider = Guid.NewGuid();
            string first = WriteManifest(provider, "win:Int32", "Payload");
            string second = WriteManifest(provider, "win:UnicodeString", "Payload");
            try
            {
                var resolver = new ManifestFileResolver();
                resolver.AddFile(first);
                resolver.AddFile(second);

                var result = resolver.Resolve(new EventKey(provider, 1, 0));

                Assert.False(result.Resolved);
                Assert.Equal(ResolutionStatus.Conflict, result.Status);
                Assert.Contains("different schemas", result.Reason);
            }
            finally
            {
                File.Delete(first);
                File.Delete(second);
            }
        }

        [Fact]
        public void ManifestResolverDoesNotDecodeAnUnmatchedTemplate()
        {
            Guid provider = Guid.NewGuid();
            string path = WriteManifest(provider, "win:Int32", "MissingTemplate");
            try
            {
                var resolver = new ManifestFileResolver();
                resolver.AddFile(path);

                var result = resolver.Resolve(new EventKey(provider, 1, 0));

                Assert.False(result.Resolved);
                Assert.Equal(ResolutionStatus.Missing, result.Status);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void ManifestArrayIsReportedUnsupportedAndKeptRaw()
        {
            Guid provider = Guid.NewGuid();
            string path = WriteManifest(provider, "win:UInt32", "Payload", "count=\"2\"");
            try
            {
                var resolver = new ManifestFileResolver();
                resolver.AddFile(path);

                var result = resolver.Resolve(new EventKey(provider, 1, 0));

                Assert.True(result.Resolved);
                Assert.Equal(ResolutionStatus.Unsupported, result.Status);
                Assert.Equal(DecodeStatus.Unsupported, result.Operand.Metadata.DecodeStatus);
                Assert.Empty(result.Operand.Metadata.Properties);
                Assert.Contains("arrays", result.Operand.Metadata.DecodeReason);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void PreflightReusesSchemaForSecondPassWhenItArrivesLate()
        {
            Guid provider = Guid.NewGuid();
            string path = WriteManifest(provider, "win:Int32", "Payload");
            try
            {
                var fileResolver = new ManifestFileResolver();
                fileResolver.AddFile(path);
                var sourceChain = new MetadataResolver();
                sourceChain.Add(fileResolver);
                var preflight = new PreflightMetadata(sourceChain);
                var key = new EventKey(provider, 1, 0);

                // Models a schema discovered after an earlier event in the scan.
                var resolved = fileResolver.Resolve(key);
                preflight.Store(key, resolved);
                var secondPass = preflight.Resolve(key);

                Assert.True(secondPass.Resolved);
                Assert.Equal(MetadataSource.ExternalManifest, secondPass.Source);
                Assert.Equal(resolved.Operand.Metadata.Properties[0].Name, secondPass.Operand.Metadata.Properties[0].Name);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void PreflightEmbeddedSchemasAreScopedBySourceAndConflictsStayRaw()
        {
            Guid provider = Guid.NewGuid();
            string firstPath = WriteManifest(provider, "win:Int32", "Payload");
            string secondPath = WriteManifest(provider, "win:UnicodeString", "Payload");
            try
            {
                var firstResolver = new ManifestFileResolver(); firstResolver.AddFile(firstPath);
                var secondResolver = new ManifestFileResolver(); secondResolver.AddFile(secondPath);
                var preflight = new PreflightMetadata(new MetadataResolver());
                var key = new EventKey(provider, 1, 0);

                preflight.SetCurrentSource("first.etl");
                preflight.Store(key, firstResolver.Resolve(key));
                preflight.SetCurrentSource("second.etl");
                preflight.Store(key, secondResolver.Resolve(key));

                Assert.Equal("TDH_INTYPE_UNICODESTRING", preflight.Resolve(key).Operand.Metadata.Properties[0].InType.ToString());
                preflight.SetCurrentSource("first.etl");
                Assert.Equal("TDH_INTYPE_INT32", preflight.Resolve(key).Operand.Metadata.Properties[0].InType.ToString());
                preflight.Store(key, secondResolver.Resolve(key));
                Assert.Equal(ResolutionStatus.Conflict, preflight.Resolve(key).Status);
            }
            finally
            {
                File.Delete(firstPath);
                File.Delete(secondPath);
            }
        }

        [Fact]
        public void ScanRefreshReportsEmbeddedSchemasLearnedAfterEarlierEvents()
        {
            Guid provider = Guid.NewGuid();
            string firstPath = WriteManifest(provider, "win:Int32", "Payload");
            string secondPath = WriteManifest(provider, "win:UnicodeString", "Payload");
            try
            {
                var firstResolver = new ManifestFileResolver(); firstResolver.AddFile(firstPath);
                var secondResolver = new ManifestFileResolver(); secondResolver.AddFile(secondPath);
                var resolver = new PreflightMetadata(new MetadataResolver());
                var scan = new ScanService(new MetadataResolver());
                var key = new EventKey(provider, 1, 0);
                scan.Observe("first.etl", key, null);
                scan.Observe("second.etl", key, null);
                resolver.SetCurrentSource("first.etl"); resolver.Store(key, firstResolver.Resolve(key));
                resolver.SetCurrentSource("second.etl"); resolver.Store(key, secondResolver.Resolve(key));

                scan.Refresh(resolver);

                var entry = Assert.Single(scan.Entries).Value;
                Assert.Equal(2, entry.Count);
                Assert.Equal("Conflict", entry.MetadataStatus);
                Assert.Contains("different metadata outcomes", entry.Reason);
            }
            finally
            {
                File.Delete(firstPath);
                File.Delete(secondPath);
            }
        }

        [Fact]
        public void ScanRefreshPromotesLateEmbeddedSchemaOverEarlierLocalCacheSchema()
        {
            Guid provider = Guid.NewGuid();
            var key = new EventKey(provider, 3, 0);
            var resolver = new PreflightMetadata(new MetadataResolver());
            resolver.SetCurrentSource("late-schema.etl");
            var embedded = CreateOperand(key, MetadataSource.Embedded, "etl:late-schema.etl");
            resolver.Store(key, new ResolutionResult(embedded, MetadataSource.Embedded, "etl:late-schema.etl"));

            var scan = new ScanService(new MetadataResolver());
            scan.Observe("late-schema.etl", key, CreateOperand(key, MetadataSource.LocalCache, "tdh:analysis-host-provider-registration"));
            scan.Refresh(resolver);

            var entry = Assert.Single(scan.Entries).Value;
            Assert.Equal("Resolved", entry.MetadataStatus);
            Assert.Equal(MetadataSource.Embedded, entry.MetadataSource);
        }

        [Fact]
        public void UnsupportedWppAndStringOnlyHeadersAreNotSchemaDecoded()
        {
            Assert.Contains("WPP", Deserializer<NullWriter>.GetUnsupportedHeaderReason(0x0008));
            Assert.Contains("String-only", Deserializer<NullWriter>.GetUnsupportedHeaderReason(0x0004));
            Assert.Null(Deserializer<NullWriter>.GetUnsupportedHeaderReason(0));
        }

        [Fact]
        public unsafe void WppHeaderBypassesMatchingManifestAndRetainsRawPayload()
        {
            Guid provider = Guid.NewGuid();
            string path = WriteManifest(provider, "win:Int32", "Payload");
            try
            {
                var resolver = new ManifestFileResolver();
                resolver.AddFile(path);
                var chain = new MetadataResolver();
                chain.Add(resolver);
                var writer = new NullWriter();
                int localCalls = 0;
                var scan = new ScanService(chain);
                var deserializer = new Deserializer<NullWriter>(writer)
                {
                    ResolverChain = chain,
                    AllowLocalMetadata = true,
                    LocalMetadataTestHook = key => { localCalls++; return CreateOperand(key, MetadataSource.LocalCache, "host"); },
                    SourceFile = "wpp.etl",
                    SourceObserver = (source, key, operand) => scan.Observe(source, key, operand),
                };
                byte* payload = stackalloc byte[1];
                payload[0] = 0xA5;
                var record = new EVENT_RECORD
                {
                    ProviderId = provider,
                    Id = 1,
                    Flags = 0x0008,
                    UserData = payload,
                    UserDataLength = 1,
                };
                deserializer.Deserialize(&record);

                Assert.Equal(DecodeStatus.Unsupported, writer.Metadata.DecodeStatus);
                Assert.Contains("WPP", writer.Metadata.DecodeReason);
                Assert.Equal(new byte[] { 0xA5 }, writer.RuntimeMetadata.GetRawPayload());
                Assert.Equal(0, localCalls);
                scan.Refresh(new PreflightMetadata(new MetadataResolver()));
                Assert.Equal("Unsupported", Assert.Single(scan.Entries).Value.MetadataStatus);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void LocalMetadataIsOptInAndClearlyClassifiedDuringSchemaOnlyScan()
        {
            Guid provider = Guid.NewGuid();
            var key = new EventKey(provider, 7, 2);
            int localCalls = 0;
            var defaultWriter = new NullWriter();
            var defaultDeserializer = new Deserializer<NullWriter>(defaultWriter)
            {
                LocalMetadataTestHook = eventKey => { localCalls++; return CreateOperand(eventKey, MetadataSource.LocalCache, "host"); },
            };
            SendEmptyEvent(defaultDeserializer, key);
            Assert.Equal(0, localCalls);
            Assert.Equal(DecodeStatus.MetadataMissing, defaultWriter.Metadata.DecodeStatus);

            IEventTraceOperand observed = null;
            var scanDeserializer = new Deserializer<NullWriter>(new NullWriter())
            {
                AllowLocalMetadata = true,
                SchemaOnly = true,
                LocalMetadataTestHook = eventKey => { localCalls++; return CreateOperand(eventKey, MetadataSource.Unknown, "test seam"); },
                Observer = (_, operand) => observed = operand,
            };
            SendEmptyEvent(scanDeserializer, key);

            Assert.Equal(1, localCalls);
            Assert.Equal(MetadataSource.LocalCache, observed.Metadata.MetadataSource);
            Assert.Equal("tdh:analysis-host-provider-registration", observed.Metadata.Provenance);
            Assert.Equal(ResolutionStatus.Resolved, observed.Metadata.ResolutionStatus);
        }

        [Fact]
        public unsafe void AnalysisHostIdentityAcceptsClassicEventGuidAndNormalizesHeaderIdentity()
        {
            Guid eventClass = Guid.NewGuid();
            Guid systemTraceProvider = Guid.NewGuid();
            var classicRecord = new EVENT_RECORD
            {
                ProviderId = eventClass,
                Id = 0,
                Version = 2,
                Opcode = 80,
                Flags = 0x0100,
            };
            var hostInfo = new TRACE_EVENT_INFO
            {
                ProviderGuid = systemTraceProvider,
                EventGuid = eventClass,
                Id = 0,
                Version = 2,
                Opcode = 80,
            };
            Assert.True(Deserializer<NullWriter>.DoesAnalysisHostIdentityMatchRecord(&classicRecord, &hostInfo));
            hostInfo.Opcode = 0;
            Assert.False(Deserializer<NullWriter>.DoesAnalysisHostIdentityMatchRecord(&classicRecord, &hostInfo));
            hostInfo.Opcode = 80;
            hostInfo.EventGuid = Guid.NewGuid();
            Assert.False(Deserializer<NullWriter>.DoesAnalysisHostIdentityMatchRecord(&classicRecord, &hostInfo));

            hostInfo.EventGuid = eventClass;
            var hostOperand = CreateOperand(new EventKey(systemTraceProvider, 0, 2), MetadataSource.LocalCache, "tdh:analysis-host-provider-registration");
            var normalized = Deserializer<NullWriter>.NormalizeLocalMetadataToRecordHeader(hostOperand, &classicRecord, 5);
            Assert.Equal(eventClass, normalized.Metadata.ProviderGuid);
            Assert.Equal((ushort)0, normalized.Metadata.Id);
            Assert.Equal((byte)2, normalized.Metadata.Version);
            Assert.Equal("TestProvider", normalized.Metadata.ProviderName);
            Assert.Equal(MetadataSource.LocalCache, normalized.Metadata.MetadataSource);
            Assert.Equal("tdh:analysis-host-provider-registration", normalized.Metadata.Provenance);
            Assert.Equal(5, normalized.EventMetadataTableIndex);

            var normalRecord = new EVENT_RECORD { ProviderId = systemTraceProvider, Id = 7, Version = 2 };
            var normalInfo = new TRACE_EVENT_INFO { ProviderGuid = systemTraceProvider, Id = 7, Version = 2 };
            Assert.True(Deserializer<NullWriter>.DoesAnalysisHostIdentityMatchRecord(&normalRecord, &normalInfo));
            normalInfo.ProviderGuid = Guid.NewGuid();
            Assert.False(Deserializer<NullWriter>.DoesAnalysisHostIdentityMatchRecord(&normalRecord, &normalInfo));
        }

        [Fact]
        public void ExplicitEvidenceWinsAndEvidenceConflictCannotBeBypassedByLocalMetadata()
        {
            Guid provider = Guid.NewGuid();
            var key = new EventKey(provider, 7, 2);
            int localCalls = 0;
            var evidence = CreateOperand(key, MetadataSource.ExternalManifest, "explicit.man");
            var evidenceWriter = new NullWriter();
            var evidenceDeserializer = new Deserializer<NullWriter>(evidenceWriter)
            {
                AllowLocalMetadata = true,
                ResolverChain = new FixedResolver(new ResolutionResult(evidence, MetadataSource.ExternalManifest, "explicit.man")),
                LocalMetadataTestHook = eventKey => { localCalls++; return CreateOperand(eventKey, MetadataSource.LocalCache, "host"); },
            };
            SendEmptyEvent(evidenceDeserializer, key);
            Assert.Equal(0, localCalls);
            Assert.Equal(MetadataSource.ExternalManifest, evidenceWriter.Metadata.MetadataSource);

            var conflictWriter = new NullWriter();
            var conflictDeserializer = new Deserializer<NullWriter>(conflictWriter)
            {
                AllowLocalMetadata = true,
                ResolverChain = new FixedResolver(ResolutionResult.UnresolvedResult(ResolutionStatus.Conflict, MetadataSource.ExternalManifest, "explicit.man", "conflicting evidence")),
                LocalMetadataTestHook = eventKey => { localCalls++; return CreateOperand(eventKey, MetadataSource.LocalCache, "host"); },
            };
            SendEmptyEvent(conflictDeserializer, key);
            Assert.Equal(0, localCalls);
            Assert.Equal(ResolutionStatus.Conflict, conflictWriter.Metadata.ResolutionStatus);
        }

        private static EventTraceOperand CreateOperand(EventKey key, MetadataSource source, string provenance)
        {
            var metadata = new EventMetadata(key.ProviderGuid, key.EventId, key.Version, "TestProvider/TestEvent", Array.Empty<PropertyMetadata>(),
                "TestProvider", source, DecodeStatus.Decoded, provenance, null, ResolutionStatus.Resolved);
            return new EventTraceOperand(metadata, 0, Array.Empty<IEventTracePropertyOperand>());
        }

        private static unsafe void SendEmptyEvent(Deserializer<NullWriter> deserializer, EventKey key)
        {
            var record = new EVENT_RECORD { ProviderId = key.ProviderGuid, Id = key.EventId, Version = key.Version };
            deserializer.Deserialize(&record);
        }

        private sealed class FixedResolver : IMetadataResolverChain
        {
            private readonly ResolutionResult result;
            public FixedResolver(ResolutionResult result) => this.result = result;
            public ResolutionResult Resolve(EventKey key) => this.result;
        }

        [Fact]
        public void DuplicateChunkZeroDoesNotDiscardAnIncompleteEventSourceManifest()
        {
            var manifest = new EventSourceManifest(Guid.NewGuid(), 1, 0, 0, 0x5B, 3);
            manifest.AddChunk(1, new byte[] { 2 });
            manifest.AddChunk(0, new byte[] { 1 });
            manifest.AddChunk(0, new byte[] { 1 });
            Assert.False(manifest.IsComplete);
            manifest.AddChunk(2, new byte[] { 3 });
            Assert.True(manifest.IsComplete);
            Assert.Throws<InvalidOperationException>(() => manifest.AddChunk(0, new byte[] { 9 }));
        }

        [Fact]
        public unsafe void EventSourceChunksBypassCachedHeaderActionAndRecoverSchemaAfterDuplicateZero()
        {
            Guid provider = Guid.NewGuid();
            string path = WriteManifest(provider, "win:Int32", "Payload");
            try
            {
                byte[] xml = Encoding.UTF8.GetBytes(File.ReadAllText(path));
                int cut1 = xml.Length / 3;
                int cut2 = (xml.Length * 2) / 3;
                byte[][] chunks =
                {
                    Slice(xml, 0, cut1), Slice(xml, cut1, cut2 - cut1), Slice(xml, cut2, xml.Length - cut2),
                };
                var preflight = new PreflightMetadata(new MetadataResolver());
                preflight.SetCurrentSource("chunks.etl");
                var preflightDeserializer = new Deserializer<NullWriter>(new NullWriter())
                {
                    ResolverChain = preflight,
                    SourceFile = "chunks.etl",
                    SchemaOnly = true,
                };
                SendIntEvent(preflightDeserializer, provider, 42);
                SendChunk(preflightDeserializer, provider, 65534, 3, 1, chunks[1]);
                SendChunk(preflightDeserializer, provider, 65534, 3, 0, chunks[0]);
                SendChunk(preflightDeserializer, provider, 65534, 3, 0, chunks[0]);
                SendChunk(preflightDeserializer, provider, 65534, 3, 2, chunks[2]);
                Assert.True(preflight.Resolve(new EventKey(provider, 1, 0)).Resolved);

                var writer = new NullWriter();
                var deserializer = new Deserializer<NullWriter>(writer) { ResolverChain = preflight, SourceFile = "chunks.etl" };
                deserializer.SetCurrentSource("chunks.etl");
                SendIntEvent(deserializer, provider, 42);
                SendChunk(deserializer, provider, 65534, 3, 1, chunks[1]);
                SendChunk(deserializer, provider, 65534, 3, 0, chunks[0]);
                SendChunk(deserializer, provider, 65534, 3, 0, chunks[0]);
                SendChunk(deserializer, provider, 65534, 3, 2, chunks[2]);

                string secondPath = WriteManifest(provider, "win:UnicodeString", "Payload");
                try
                {
                    byte[] secondXml = Encoding.UTF8.GetBytes(File.ReadAllText(secondPath));
                    int secondCut1 = secondXml.Length / 3;
                    int secondCut2 = (secondXml.Length * 2) / 3;
                    SendChunk(deserializer, provider, 65534, 3, 0, Slice(secondXml, 0, secondCut1));
                    SendChunk(deserializer, provider, 65534, 3, 1, Slice(secondXml, secondCut1, secondCut2 - secondCut1));
                    SendChunk(deserializer, provider, 65534, 3, 2, Slice(secondXml, secondCut2, secondXml.Length - secondCut2));
                }
                finally
                {
                    File.Delete(secondPath);
                }

                SendIntEvent(deserializer, provider, 42);

                Assert.Null(deserializer.LastError);
                Assert.Equal(new[] { 42 }, writer.Int32Values);
                Assert.Equal(9, writer.EventCount);
                Assert.Equal(ResolutionStatus.Conflict, preflight.Resolve(new EventKey(provider, 1, 0)).Status);
                Assert.Equal(ResolutionStatus.Conflict, writer.Metadata.ResolutionStatus);
            }
            finally
            {
                File.Delete(path);
            }
        }

        private static byte[] Slice(byte[] bytes, int start, int count)
        {
            var result = new byte[count];
            Buffer.BlockCopy(bytes, start, result, 0, count);
            return result;
        }

        private static unsafe void SendChunk(Deserializer<NullWriter> deserializer, Guid provider, ushort id, ushort total, ushort index, byte[] chunk)
        {
            var payload = new byte[8 + chunk.Length];
            payload[0] = 1; payload[1] = 0; payload[2] = 0; payload[3] = 0x5B;
            payload[4] = (byte)total; payload[5] = (byte)(total >> 8);
            payload[6] = (byte)index; payload[7] = (byte)(index >> 8);
            Buffer.BlockCopy(chunk, 0, payload, 8, chunk.Length);
            fixed (byte* ptr = payload)
            {
                var record = new EVENT_RECORD { ProviderId = provider, Id = id, UserData = ptr, UserDataLength = (ushort)payload.Length };
                deserializer.Deserialize(&record);
            }
        }

        private static unsafe void SendIntEvent(Deserializer<NullWriter> deserializer, Guid provider, int value)
        {
            byte* eventPayload = stackalloc byte[4];
            eventPayload[0] = (byte)value;
            eventPayload[1] = (byte)(value >> 8);
            eventPayload[2] = (byte)(value >> 16);
            eventPayload[3] = (byte)(value >> 24);
            var record = new EVENT_RECORD { ProviderId = provider, Id = 1, UserData = eventPayload, UserDataLength = 4 };
            deserializer.Deserialize(&record);
        }

        [Fact]
        public void ExcessiveArrayCountIsRejectedBeforeIteration()
        {
            var budget = new ArrayElementBudget();
            budget.Reserve(EventRecordReader.MaximumArrayElements);
            Assert.Contains("retained as raw payload", Assert.Throws<InvalidOperationException>(
                () => budget.Reserve(1)).Message);
        }

        private sealed class NullWriter : IEtwWriter
        {
            public EventMetadata Metadata { get; private set; }
            public RuntimeEventMetadata RuntimeMetadata { get; private set; }
            public int EventCount { get; private set; }
            public System.Collections.Generic.List<int> Int32Values { get; } = new System.Collections.Generic.List<int>();
            public void WriteEventBegin(EventMetadata metadata, RuntimeEventMetadata runtimeMetadata) { this.Metadata = metadata; this.RuntimeMetadata = runtimeMetadata; this.EventCount++; }
            public void WriteEventEnd() { }
            public void WriteStructBegin() { }
            public void WriteStructEnd() { }
            public void WritePropertyBegin(PropertyMetadata metadata) { }
            public void WritePropertyEnd() { }
            public void WriteArrayBegin() { }
            public void WriteArrayEnd() { }
            public void WriteAnsiString(string value) { }
            public void WriteUnicodeString(string value) { }
            public void WriteInt8(sbyte value) { }
            public void WriteUInt8(byte value) { }
            public void WriteInt16(short value) { }
            public void WriteUInt16(ushort value) { }
            public void WriteInt32(int value) { this.Int32Values.Add(value); }
            public void WriteUInt32(uint value) { }
            public void WriteInt64(long value) { }
            public void WriteUInt64(ulong value) { }
            public void WriteFloat(float value) { }
            public void WriteDouble(double value) { }
            public void WriteBoolean(bool value) { }
            public void WriteBinary(byte[] value) { }
            public void WriteGuid(Guid value) { }
            public void WritePointer(ulong value) { }
            public void WriteFileTime(DateTime value) { }
            public void WriteSystemTime(DateTime value) { }
            public void WriteSid(string value) { }
            public void WriteUnicodeChar(char value) { }
            public void WriteAnsiChar(char value) { }
            public void WriteHexDump(byte[] value) { }
            public void WriteWbemSid(string value) { }
        }

        private static string WriteManifest(Guid provider, string inType, string template, string extraDataAttributes = "")
        {
            string path = Path.Combine(Path.GetTempPath(), "manifest-" + Guid.NewGuid().ToString("N") + ".man");
            string xml = $"""
                <instrumentationManifest xmlns="http://schemas.microsoft.com/win/2004/08/events"
                                         xmlns:win="http://manifests.microsoft.com/win/2004/08/windows/events">
                  <instrumentation><events><provider name="Fixture" guid="{provider:B}">
                    <events><event value="1" version="0" template="{template}" /></events>
                    <templates><template tid="Payload"><data name="Value" inType="{inType}" {extraDataAttributes} /></template></templates>
                  </provider></events></instrumentation>
                </instrumentationManifest>
                """;
            File.WriteAllText(path, xml);
            return path;
        }
    }
}
