namespace ETWDeserializer
{
    using System;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Security.Cryptography;
    using System.Xml;

    /// <summary>
    /// Reads the XML publisher-information output of `wevtutil gp ... /f:xml`.
    /// This data is useful for collection guidance but is not a payload schema.
    /// </summary>
    public sealed class ExportedProviderResolver
    {
        private const int MaxExportSize = 16 * 1024 * 1024;
        private readonly Dictionary<Guid, ExportedProviderInfo> providers = new Dictionary<Guid, ExportedProviderInfo>();

        public void AddFile(string path)
        {
            if (path == null)
            {
                throw new ArgumentNullException(nameof(path));
            }

            var file = new FileInfo(path);
            if (!file.Exists || file.Length > MaxExportSize)
            {
                throw new InvalidDataException("The provider-info XML is missing or exceeds the 16 MiB safety limit.");
            }

            byte[] bytes = File.ReadAllBytes(path);
            if (bytes.Length > MaxExportSize)
            {
                throw new InvalidDataException("The provider-info XML exceeds the 16 MiB safety limit.");
            }

            string hash;
            using (var sha = SHA256.Create())
            {
                hash = ToHex(sha.ComputeHash(bytes));
            }

            var settings = new XmlReaderSettings
            {
                DtdProcessing = DtdProcessing.Prohibit,
                XmlResolver = null,
                MaxCharactersInDocument = MaxExportSize,
                MaxCharactersFromEntities = 0,
            };

            using (var input = new MemoryStream(bytes, writable: false))
            using (var reader = XmlReader.Create(input, settings))
            {
                while (reader.Read() && !(reader.NodeType == XmlNodeType.Element && reader.LocalName == "provider"))
                {
                }

                if (reader.NodeType != XmlNodeType.Element || reader.LocalName != "provider")
                {
                    throw new InvalidDataException("The XML does not contain a provider-info element.");
                }

                string guidText = GetAttribute(reader, "guid");
                if (!Guid.TryParse(guidText, out Guid guid))
                {
                    throw new InvalidDataException("The provider-info XML has no valid provider GUID.");
                }

                var info = new ExportedProviderInfo(
                    guid,
                    GetAttribute(reader, "name"),
                    GetAttribute(reader, "resourceFileName"),
                    GetAttribute(reader, "messageFileName"),
                    GetAttribute(reader, "parameterFileName"),
                    path,
                    hash);
                this.providers[guid] = info;
            }
        }

        public bool TryGetProvider(Guid providerGuid, out ExportedProviderInfo info)
        {
            return this.providers.TryGetValue(providerGuid, out info);
        }

        public IReadOnlyDictionary<Guid, ExportedProviderInfo> Providers => this.providers;

        private static string GetAttribute(XmlReader reader, string name)
        {
            return reader.GetAttribute(name) ?? reader.GetAttribute(name, "http://schemas.microsoft.com/win/2004/08/events");
        }

        private static string ToHex(byte[] hash)
        {
            var result = new System.Text.StringBuilder(hash.Length * 2);
            foreach (byte value in hash)
            {
                result.Append(value.ToString("x2", CultureInfo.InvariantCulture));
            }

            return result.ToString();
        }
    }

    public sealed class ExportedProviderInfo
    {
        internal ExportedProviderInfo(Guid providerGuid, string name, string resourceFileName, string messageFileName, string parameterFileName, string sourcePath, string sha256)
        {
            this.ProviderGuid = providerGuid;
            this.Name = name;
            this.ResourceFileName = resourceFileName;
            this.MessageFileName = messageFileName;
            this.ParameterFileName = parameterFileName;
            this.SourcePath = sourcePath;
            this.Sha256 = sha256;
        }

        public Guid ProviderGuid { get; }

        public string Name { get; }

        public string ResourceFileName { get; }

        public string MessageFileName { get; }

        public string ParameterFileName { get; }

        public string SourcePath { get; }

        public string Sha256 { get; }

        public bool ProvidesPayloadSchema => false;
    }
}
