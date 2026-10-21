namespace ETWDeserializer
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Security.Cryptography;
    using System.Xml;
    using System.Xml.Serialization;
    using Microsoft.Xml.Serialization.GeneratedAssembly;

    /// <summary>
    /// Resolves schemas from explicitly supplied event manifest (.man) XML files.
    /// XML external entities and DTDs are disabled, and each file's hash is
    /// recorded as provenance.
    /// </summary>
    public sealed class ManifestFileResolver : IMetadataResolver
    {
        private readonly List<ManifestEntry> manifests = new List<ManifestEntry>();

        public ManifestFileResolver()
        {
        }

        public MetadataSource Source => MetadataSource.ExternalManifest;

        public IReadOnlyList<string> LoadedFiles
        {
            get
            {
                var result = new List<string>();
                foreach (var entry in this.manifests)
                {
                    result.Add(entry.Path);
                }

                return result;
            }
        }

        public void AddFile(string path)
        {
            var manifest = LoadXml(path, out string hash);
            this.manifests.Add(new ManifestEntry(path, hash, manifest));
        }

        public ResolutionResult Resolve(EventKey key)
        {
            if (key.ClassicOpcode.HasValue)
            {
                return ResolutionResult.UnresolvedResult(ResolutionStatus.Missing, MetadataSource.ExternalManifest, null,
                    "Event manifests do not supply classic/MOF class schemas; recover embedded trace metadata or the matching MOF definitions.");
            }
            ResolutionResult match = null;
            foreach (var entry in this.manifests)
            {
                var operand = this.Build(entry.Value, key, entry.Provenance());
                if (operand != null)
                {
                    var candidate = new ResolutionResult(operand, MetadataSource.ExternalManifest, entry.Provenance());
                    if (candidate.Status == ResolutionStatus.Conflict || candidate.Status == ResolutionStatus.Invalid)
                    {
                        return ResolutionResult.UnresolvedResult(candidate.Status, MetadataSource.ExternalManifest, entry.Provenance(), operand.Metadata.DecodeReason);
                    }

                    if (match == null)
                    {
                        match = candidate;
                    }
                    else if (!SchemaEquivalence.AreEquivalent(match.Operand, candidate.Operand))
                    {
                        return ResolutionResult.UnresolvedResult(
                            ResolutionStatus.Conflict,
                            MetadataSource.ExternalManifest,
                            match.Provenance + ";" + candidate.Provenance,
                            "Multiple external manifests define different schemas for " + key + ".");
                    }
                }
            }

            return match ?? ResolutionResult.UnresolvedResult(ResolutionStatus.Missing, MetadataSource.ExternalManifest, null, "No supplied manifest contains a matching provider/event/version.");
        }


        internal static instrumentationManifest LoadXml(string path, out string hash)
        {
            const int maximumManifestBytes = 64 * 1024 * 1024;
            var file = new FileInfo(path);
            if (!file.Exists || file.Length == 0 || file.Length > maximumManifestBytes)
            {
                throw new InvalidDataException("Manifest file is missing, empty, or exceeds the 64 MiB safety limit: " + path);
            }

            var bytes = File.ReadAllBytes(path);
            if (bytes.Length > maximumManifestBytes)
            {
                throw new InvalidDataException("Manifest file exceeds the 64 MiB safety limit: " + path);
            }
            using (var sha = SHA256.Create())
            {
                hash = BitConverter.ToString(sha.ComputeHash(bytes)).Replace("-", string.Empty).ToLowerInvariant();
            }

            using (var stream = new MemoryStream(bytes))
            {
                var settings = new XmlReaderSettings
                {
                    DtdProcessing = DtdProcessing.Prohibit,
                    XmlResolver = null,
                    MaxCharactersInDocument = maximumManifestBytes,
                };

                using (var reader = XmlReader.Create(stream, settings))
                {
                    var serializer = new instrumentationManifestSerializer();
                    return (instrumentationManifest)serializer.Deserialize(reader);
                }
            }
        }

        private IEventTraceOperand Build(instrumentationManifest manifest, EventKey key, string provenance)
        {
            return EventTraceOperandBuilder.BuildManifest(manifest, key, MetadataSource.ExternalManifest, provenance);
        }

        private sealed class ManifestEntry
        {
            private readonly string path;
            private readonly string hash;

            public ManifestEntry(string path, string hash, instrumentationManifest value)
            {
                this.path = path;
                this.hash = hash;
                this.Value = value;
            }

            public string Path => this.path;

            public instrumentationManifest Value { get; }

            public string Provenance()
            {
                return "man:" + this.path + ";sha256:" + this.hash;
            }
        }
    }
}
