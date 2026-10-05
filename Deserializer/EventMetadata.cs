namespace ETWDeserializer
{
    using System;

    public sealed class EventMetadata
    {
        internal EventMetadata(Guid providerGuid, ushort id, byte version, string name, PropertyMetadata[] properties)
            : this(providerGuid, id, version, name, properties, null, MetadataSource.Unknown, DecodeStatus.Decoded, null)
        {
        }

        internal EventMetadata(
            Guid providerGuid,
            ushort id,
            byte version,
            string name,
            PropertyMetadata[] properties,
            string providerName,
            MetadataSource metadataSource,
            DecodeStatus decodeStatus,
            string provenance)
            : this(providerGuid, id, version, name, properties, providerName, metadataSource, decodeStatus, provenance, null)
        {
        }

        internal EventMetadata(
            Guid providerGuid,
            ushort id,
            byte version,
            string name,
            PropertyMetadata[] properties,
            string providerName,
            MetadataSource metadataSource,
            DecodeStatus decodeStatus,
            string provenance,
            string decodeReason)
            : this(providerGuid, id, version, name, properties, providerName, metadataSource, decodeStatus, provenance, decodeReason, null)
        {
        }

        internal EventMetadata(
            Guid providerGuid,
            ushort id,
            byte version,
            string name,
            PropertyMetadata[] properties,
            string providerName,
            MetadataSource metadataSource,
            DecodeStatus decodeStatus,
            string provenance,
            string decodeReason,
            ResolutionStatus? resolutionStatus)
        {
            this.ProviderGuid = providerGuid;
            this.Id = id;
            this.Version = version;
            this.Name = name;
            this.Properties = properties;
            this.ProviderName = providerName;
            this.MetadataSource = metadataSource;
            this.DecodeStatus = decodeStatus;
            this.Provenance = provenance;
            this.DecodeReason = decodeReason;
            this.ResolutionStatus = resolutionStatus ?? (decodeStatus == DecodeStatus.Unsupported
                ? ETWDeserializer.ResolutionStatus.Unsupported
                : decodeStatus == DecodeStatus.DecodeError
                    ? ETWDeserializer.ResolutionStatus.Invalid
                    : metadataSource == MetadataSource.Unknown
                        ? ETWDeserializer.ResolutionStatus.Missing
                        : ETWDeserializer.ResolutionStatus.Resolved);
        }

        public Guid ProviderGuid { get; private set; }

        public ushort Id { get; private set; }

        public byte Version { get; private set; }

        public string Name { get; private set; }

        public PropertyMetadata[] Properties { get; private set; }

        /// <summary>Provider name when known, otherwise null. The full <see cref="Name"/> is Task/Opcode decorated.</summary>
        public string ProviderName { get; private set; }

        /// <summary>Where this schema came from. See <see cref="MetadataSource"/>.</summary>
        public MetadataSource MetadataSource { get; private set; }

        /// <summary>How completely the event was decoded. See <see cref="DecodeStatus"/>.</summary>
        public DecodeStatus DecodeStatus { get; private set; }

        /// <summary>Free-form provenance detail (file path, hash, key/value, ...). Null when not applicable.</summary>
        public string Provenance { get; private set; }

        public string DecodeReason { get; private set; }

        public ResolutionStatus ResolutionStatus { get; private set; }
    }
}
