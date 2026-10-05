namespace ETW2JSON.Tests
{
    using System;
    using System.Buffers.Binary;
    using System.IO;
    using ETWDeserializer;
    using ETW2JSON.TestFixtures;
    using Xunit;

    public class WevtTemplateReaderTests
    {
        [Theory]
        [InlineData(3, 1)]
        [InlineData(5, 1)]
        public void ReadsSupportedScalarTemplateFromCrim(int major, int minor)
        {
            Guid providerGuid = Guid.Parse("12345678-1234-5678-9abc-def012345678");
            var result = WevtTemplateReader.ReadProviders(BuildManifest(providerGuid, major, minor, 8))[0];

            Assert.True(result.Status == WevtTemplateStatus.Supported, string.Join("; ", result.Reasons));
            Assert.Equal(providerGuid, result.ProviderGuid);
            var instrumentation = Assert.IsType<InstrumentationType>(result.Manifest.Items[0]);
            var eventList = Assert.IsType<EventsType>(instrumentation.Items[0]);
            var provider = Assert.IsType<ProviderType>(eventList.Items[0]);
            Assert.Equal(providerGuid.ToString("D"), provider.guid);
            var definitions = Assert.IsType<DefinitionType>(provider.Items[0]);
            var definition = Assert.Single(definitions.Items);
            Assert.Equal("7", definition.value);
            Assert.Equal("2", definition.version);
            var templateList = Assert.IsType<TemplateListType>(provider.Items[1]);
            var template = Assert.Single(templateList.template);
            var property = Assert.IsType<DataDefinitionType>(Assert.Single(template.Items));
            Assert.Equal("Value", property.name);
            Assert.Equal("UInt32", property.inType.Name);
        }

        [Fact]
        public void LeavesUnknownPropertyTypeUnsupported()
        {
            Guid providerGuid = Guid.NewGuid();
            var result = WevtTemplateReader.ReadProviders(BuildManifest(providerGuid, 5, 1, 0x7f))[0];

            Assert.Equal(WevtTemplateStatus.Unsupported, result.Status);
            Assert.NotEmpty(result.Reasons);
            var events = (EventsType)((InstrumentationType)result.Manifest.Items[0]).Items[0];
            var provider = Assert.IsType<ProviderType>(events.Items[0]);
            Assert.Empty(((DefinitionType)provider.Items[0]).Items);
        }

        [Fact]
        public void ReadsSyntheticCompiledManifestFromStaticPeResource()
        {
            string path = Path.Combine(Path.GetTempPath(), "etw2json-provider-" + Guid.NewGuid().ToString("N") + ".dll");
            File.WriteAllBytes(path, SyntheticProviderPeBuilder.Build());
            try
            {
                var pe = PeResourceReader.Read(path);
                var resolver = new PeResourceResolver();
                resolver.AddFile(path);
                var result = resolver.Resolve(new EventKey(SyntheticProviderPeBuilder.ProviderGuid, 1, 1));

                Assert.Single(pe.Resources);
                Assert.True(result.Resolved, result.Reason);
                Assert.Equal(MetadataSource.ExternalPeResource, result.Source);
                Assert.Equal(SyntheticProviderPeBuilder.ProviderGuid, result.Operand.Metadata.ProviderGuid);
                Assert.Equal(new[] { "sequence", "message", "correlation" },
                    System.Linq.Enumerable.Select(result.Operand.Metadata.Properties, property => property.Name));
                Assert.Equal(TDH_IN_TYPE.TDH_INTYPE_INT32, result.Operand.Metadata.Properties[0].InType);
                Assert.Equal(TDH_IN_TYPE.TDH_INTYPE_UNICODESTRING, result.Operand.Metadata.Properties[1].InType);
                Assert.Equal(TDH_IN_TYPE.TDH_INTYPE_GUID, result.Operand.Metadata.Properties[2].InType);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void RejectsStandaloneWevtWithoutProviderBinding()
        {
            string path = Path.Combine(Path.GetTempPath(), "etw2json-unbound-" + Guid.NewGuid().ToString("N") + ".dll");
            File.WriteAllBytes(path, SyntheticProviderPeBuilder.BuildStandaloneWevtResourcePe());
            try
            {
                var resolver = new PeResourceResolver();
                resolver.AddFile(path);
                var result = resolver.Resolve(new EventKey(SyntheticProviderPeBuilder.ProviderGuid, 1, 1));
                Assert.False(result.Resolved);
                Assert.Equal(ResolutionStatus.Unsupported, result.Status);
                Assert.Contains("no CRIM provider GUID binding", result.Reason);
            }
            finally
            {
                File.Delete(path);
            }
        }

        [Fact]
        public void ConflictingPeSchemasAreNotChosenByInputOrder()
        {
            string first = Path.Combine(Path.GetTempPath(), "etw2json-pe-a-" + Guid.NewGuid().ToString("N") + ".dll");
            string second = Path.Combine(Path.GetTempPath(), "etw2json-pe-b-" + Guid.NewGuid().ToString("N") + ".dll");
            File.WriteAllBytes(first, SyntheticProviderPeBuilder.Build("sequence"));
            File.WriteAllBytes(second, SyntheticProviderPeBuilder.Build("count"));
            try
            {
                var resolver = new PeResourceResolver();
                resolver.AddFile(first);
                resolver.AddFile(second);
                var result = resolver.Resolve(new EventKey(SyntheticProviderPeBuilder.ProviderGuid, 1, 1));
                Assert.False(result.Resolved);
                Assert.Equal(ResolutionStatus.Conflict, result.Status);
            }
            finally
            {
                File.Delete(first);
                File.Delete(second);
            }
        }

        private static byte[] BuildManifest(Guid providerGuid, int major, int minor, byte inType)
        {
            const int ProviderOffset = 36;
            const int WevtSize = 28;
            const int EventOffset = ProviderOffset + WevtSize;
            const int EventSize = 92;
            const int TemplateOffset = EventOffset + EventSize;
            const int ItemOffset = TemplateOffset + 40;
            const int NameOffset = ItemOffset + 20;
            const int BlobSize = NameOffset + 16;
            var bytes = new byte[BlobSize + 2]; // Some Windows resources include two trailing padding bytes.

            WriteUInt32(bytes, 0, 0x4d495243); // CRIM
            WriteUInt32(bytes, 4, BlobSize);
            WriteUInt16(bytes, 8, (ushort)major);
            WriteUInt16(bytes, 10, (ushort)minor);
            WriteUInt32(bytes, 12, 1);
            Array.Copy(providerGuid.ToByteArray(), 0, bytes, 16, 16);
            WriteUInt32(bytes, 32, ProviderOffset);

            WriteUInt32(bytes, ProviderOffset, 0x54564557); // WEVT
            WriteUInt32(bytes, ProviderOffset + 4, WevtSize);
            WriteUInt32(bytes, ProviderOffset + 8, uint.MaxValue);
            WriteUInt32(bytes, ProviderOffset + 12, 1);
            WriteUInt32(bytes, ProviderOffset + 20, EventOffset);

            WriteUInt32(bytes, EventOffset, 0x544e5645); // EVNT
            WriteUInt32(bytes, EventOffset + 4, EventSize);
            WriteUInt32(bytes, EventOffset + 8, 1);
            WriteUInt16(bytes, EventOffset + 16, 7);
            bytes[EventOffset + 18] = 2;
            WriteUInt32(bytes, EventOffset + 36, TemplateOffset);

            WriteUInt32(bytes, TemplateOffset, 0x504d4554); // TEMP
            WriteUInt32(bytes, TemplateOffset + 4, 40);
            WriteUInt32(bytes, TemplateOffset + 8, 1);
            WriteUInt32(bytes, TemplateOffset + 12, 1);
            WriteUInt32(bytes, TemplateOffset + 16, ItemOffset);
            WriteUInt32(bytes, TemplateOffset + 20, 1);

            bytes[ItemOffset + 4] = inType;
            WriteUInt32(bytes, ItemOffset + 16, NameOffset);
            WriteUInt32(bytes, NameOffset, 16);
            System.Text.Encoding.Unicode.GetBytes("Value\0").CopyTo(bytes, NameOffset + 4);
            return bytes;
        }

        private static void WriteUInt16(byte[] bytes, int offset, ushort value)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(new Span<byte>(bytes, offset, 2), value);
        }

        private static void WriteUInt32(byte[] bytes, int offset, uint value)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(new Span<byte>(bytes, offset, 4), value);
        }
    }
}
