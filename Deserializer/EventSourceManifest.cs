namespace ETWDeserializer
{
    using System;
    using System.IO;
    using System.Collections.Generic;
    using System.Text;
    using System.Xml;
    using System.Xml.Serialization;

    internal sealed class EventSourceManifest
    {
        private readonly SortedDictionary<ushort, byte[]> chunks = new SortedDictionary<ushort, byte[]>();

        private readonly Guid providerGuid;

        private readonly byte format;

        private readonly byte majorVersion;

        private readonly byte minorVersion;

        private readonly byte magic;

        private readonly ushort totalChunks;

        private instrumentationManifest manifest;

        private const ushort MaximumChunks = 1024;

        public EventSourceManifest(Guid providerGuid, byte format, byte majorVersion, byte minorVersion, byte magic, ushort totalChunks)
        {
            this.providerGuid = providerGuid;
            this.format = format;
            this.majorVersion = majorVersion;
            this.minorVersion = minorVersion;
            this.magic = magic;
            if (totalChunks == 0 || totalChunks > MaximumChunks)
            {
                throw new InvalidOperationException("EventSource manifest chunk count is invalid or exceeds the safety limit.");
            }
            this.totalChunks = totalChunks;
        }

        public bool IsComplete => this.chunks.Count == this.totalChunks;

        public bool HasChunk(ushort chunkNumber) => this.chunks.ContainsKey(chunkNumber);

        public instrumentationManifest Schema
        {
            get
            {
                if (!this.IsComplete)
                {
                    throw new Exception("Schema is incomplete as not all chunks have been received");
                }

                if (this.manifest == null)
                {
                    int totalBytes = 0;
                    foreach (var chunk in this.chunks.Values) totalBytes = checked(totalBytes + chunk.Length);
                    if (totalBytes > 16 * 1024 * 1024)
                    {
                        throw new InvalidOperationException("EventSource manifest exceeds the safety size limit.");
                    }

                    var bytes = new byte[totalBytes];
                    int offset = 0;
                    foreach (var chunk in this.chunks.Values)
                    {
                        Buffer.BlockCopy(chunk, 0, bytes, offset, chunk.Length);
                        offset += chunk.Length;
                    }

                    using (var ms = new MemoryStream(bytes, false))
                    {
                        var serializer = new Microsoft.Xml.Serialization.GeneratedAssembly.instrumentationManifestSerializer();
                        var settings = new XmlReaderSettings
                        {
                            DtdProcessing = DtdProcessing.Prohibit,
                            XmlResolver = null,
                            MaxCharactersInDocument = 16 * 1024 * 1024,
                        };
                        using (var reader = XmlReader.Create(ms, settings))
                        {
                            this.manifest = (instrumentationManifest)serializer.Deserialize(reader);
                        }
                    }
                }

                return this.manifest;
            }
        }

        public Guid ProviderGuid => this.providerGuid;

        public byte Format => this.format;

        public byte MajorVersion => this.majorVersion;

        public byte MinorVersion => this.minorVersion;

        public byte Magic => this.magic;

        public ushort TotalChunks => this.totalChunks;

        public void AddChunk(ushort chunkNumber, byte[] schemaChunk)
        {
            if (chunkNumber >= this.totalChunks || schemaChunk == null || schemaChunk.Length == 0)
            {
                throw new InvalidOperationException("EventSource manifest chunk index or data is invalid.");
            }

            if (this.chunks.TryGetValue(chunkNumber, out var existing))
            {
                if (existing.Length != schemaChunk.Length)
                {
                    throw new InvalidOperationException("Conflicting duplicate EventSource manifest chunk.");
                }
                for (int i = 0; i < existing.Length; i++)
                {
                    if (existing[i] != schemaChunk[i]) throw new InvalidOperationException("Conflicting duplicate EventSource manifest chunk.");
                }
            }
            else
            {
                this.chunks.Add(chunkNumber, (byte[])schemaChunk.Clone());
            }
        }

        public override bool Equals(object obj)
        {
            var other = obj as EventSourceManifest;
            return other != null && this.Equals(other);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = this.providerGuid.GetHashCode();
                hashCode = (hashCode * 397) ^ this.format.GetHashCode();
                hashCode = (hashCode * 397) ^ this.majorVersion.GetHashCode();
                hashCode = (hashCode * 397) ^ this.minorVersion.GetHashCode();
                hashCode = (hashCode * 397) ^ this.magic.GetHashCode();
                hashCode = (hashCode * 397) ^ this.totalChunks.GetHashCode();

                return hashCode;
            }
        }

        public bool Equals(EventSourceManifest other)
        {
            return this.providerGuid.Equals(other.providerGuid)
                   && this.format == other.format
                   && this.majorVersion == other.majorVersion
                   && this.minorVersion == other.minorVersion
                   && this.magic == other.magic
                   && this.totalChunks == other.totalChunks;
        }
    }
}
