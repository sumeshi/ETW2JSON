namespace ETW2JSON.Tests
{
    using System;
    using System.IO;
    using System.Text.Json;
    using ETWDeserializer;
    using Xunit;

    public sealed unsafe class ManifestEmptyTemplateTests
    {
        [Theory]
        [InlineData(false)]
        [InlineData(true)]
        public void PublicEmptyTemplateIsAZeroFieldSchemaAndNonemptyPayloadKeepsItsDiagnosticSource(bool nonempty)
        {
            string path = Path.Combine(AppContext.BaseDirectory, "fixtures", "clr-empty-template-reference.man");
            var key = new EventKey(Guid.Parse("763fd754-7086-4dfe-95eb-c01a46faf4ca"), 4, 2);
            var manifest = new ManifestFileResolver();
            manifest.AddFile(path);
            var resolution = manifest.Resolve(key);
            Assert.Equal(ResolutionStatus.Resolved, resolution.Status);
            Assert.Empty(resolution.Operand.Metadata.Properties);
            Assert.Equal(MetadataSource.ExternalManifest, resolution.Source);
            var resolver = new MetadataResolver();
            resolver.Add(manifest);
            using var output = new MemoryStream();
            using var writer = new JsonlEventWriter(output);
            var deserializer = new Deserializer<JsonlEventWriter>(writer) { ResolverChain = resolver };
            byte value = 0xA5;
            var record = new EVENT_RECORD { ProviderId = key.ProviderGuid, Id = key.EventId, Version = key.Version,
                UserData = nonempty ? &value : null, UserDataLength = nonempty ? (ushort)1 : (ushort)0 };

            deserializer.Deserialize(&record);

            Assert.Null(deserializer.LastError);
            using var json = JsonDocument.Parse(output.ToArray());
            var evt = json.RootElement;
            Assert.Equal(nonempty ? "decode_error" : "decoded", evt.GetProperty("decode_status").GetString());
            Assert.Equal("external_manifest", evt.GetProperty("metadata_source").GetString());
            Assert.Contains("sha256:", evt.GetProperty("metadata_provenance").GetString());
            Assert.Equal(nonempty ? new byte[] { 0xA5 } : Array.Empty<byte>(), evt.GetProperty("raw_payload").GetBytesFromBase64());
            if (nonempty) Assert.Contains("unconsumed", evt.GetProperty("decode_note").GetString());
        }

        [Theory]
        [InlineData("UnknownFutureType", "input type")]
        [InlineData("Binary", "length")]
        public void UnsupportedManifestDataTypesRetainTheirSourceWithoutThrowing(string type, string expectedReason)
        {
            string path = Path.Combine(Path.GetTempPath(), "manifest-type-" + Guid.NewGuid().ToString("N") + ".man");
            Guid provider = Guid.NewGuid();
            File.WriteAllText(path, "<instrumentationManifest xmlns=\"http://schemas.microsoft.com/win/2004/08/events\" xmlns:win=\"http://manifests.microsoft.com/win/2004/08/windows/events\"><instrumentation><events><provider name=\"Example\" guid=\"{" + provider + "}\"><events><event value=\"1\" template=\"T\"/></events><templates><template tid=\"T\"><data name=\"Value\" inType=\"win:" + type + "\"/></template></templates></provider></events></instrumentation></instrumentationManifest>");
            try
            {
                var manifest = new ManifestFileResolver();
                manifest.AddFile(path);
                var resolution = manifest.Resolve(new EventKey(provider, 1, 0));
                Assert.Equal(ResolutionStatus.Unsupported, resolution.Status);
                Assert.Equal(MetadataSource.ExternalManifest, resolution.Source);
                Assert.Contains(expectedReason, resolution.Operand.Metadata.DecodeReason, StringComparison.OrdinalIgnoreCase);
                var resolver = new MetadataResolver(); resolver.Add(manifest);
                using var output = new MemoryStream();
                using var writer = new JsonlEventWriter(output);
                var deserializer = new Deserializer<JsonlEventWriter>(writer) { ResolverChain = resolver };
                byte value = 0xA5;
                var record = new EVENT_RECORD { ProviderId = provider, Id = 1, UserData = &value, UserDataLength = 1 };
                deserializer.Deserialize(&record);
                Assert.Null(deserializer.LastError);
                using var json = JsonDocument.Parse(output.ToArray());
                Assert.Equal("unsupported", json.RootElement.GetProperty("decode_status").GetString());
                Assert.Equal("external_manifest", json.RootElement.GetProperty("metadata_source").GetString());
                Assert.Contains("sha256:", json.RootElement.GetProperty("metadata_provenance").GetString());
                Assert.Equal("pQ==", json.RootElement.GetProperty("raw_payload").GetString());
            }
            finally { File.Delete(path); }
        }
    }
}
