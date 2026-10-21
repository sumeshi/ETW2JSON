namespace ETWDeserializer
{
    using System;

    /// <summary>Identity of an event schema: provider + event id + version.</summary>
    public readonly struct EventKey : IEquatable<EventKey>
    {
        public EventKey(Guid providerGuid, ushort eventId, byte version, byte? classicOpcode = null)
        {
            this.ProviderGuid = providerGuid;
            this.EventId = eventId;
            this.Version = version;
            this.ClassicOpcode = classicOpcode;
        }

        public Guid ProviderGuid { get; }

        public ushort EventId { get; }

        public byte Version { get; }

        /// <summary>MOF event type; absent for manifest and TraceLogging events.</summary>
        public byte? ClassicOpcode { get; }

        public bool Equals(EventKey other)
        {
            return this.ProviderGuid.Equals(other.ProviderGuid)
                && this.EventId == other.EventId
                && this.Version == other.Version
                && this.ClassicOpcode == other.ClassicOpcode;
        }

        public override bool Equals(object obj)
        {
            return obj is EventKey other && this.Equals(other);
        }

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = this.ProviderGuid.GetHashCode();
                hashCode = (hashCode * 397) ^ this.EventId.GetHashCode();
                hashCode = (hashCode * 397) ^ this.Version.GetHashCode();
                if (this.ClassicOpcode.HasValue) hashCode = (hashCode * 397) ^ (256 + this.ClassicOpcode.Value);
                return hashCode;
            }
        }

        public override string ToString()
        {
            return "{" + this.ProviderGuid.ToString("D") + "}:" + this.EventId + ":" + this.Version
                + (this.ClassicOpcode.HasValue ? ":classic_opcode=" + this.ClassicOpcode.Value : string.Empty);
        }
    }

    /// <summary>Result of asking a single resolver for a schema.</summary>
    public sealed class ResolutionResult
    {
        public ResolutionResult(IEventTraceOperand operand, MetadataSource source, string provenance)
            : this(operand, source, provenance, operand == null ? ResolutionStatus.Missing : ResolutionStatus.Resolved, null)
        {
        }

        public ResolutionResult(IEventTraceOperand operand, MetadataSource source, string provenance, ResolutionStatus status, string reason)
        {
            this.Operand = operand;
            this.Source = source;
            this.Provenance = provenance;
            this.Status = operand == null ? status : (status == ResolutionStatus.Resolved ? operand.Metadata.ResolutionStatus : status);
            this.Reason = reason;
        }

        public IEventTraceOperand Operand { get; }

        public MetadataSource Source { get; }

        public string Provenance { get; }

        public ResolutionStatus Status { get; }

        public string Reason { get; }

        public bool Resolved => this.Operand != null && (this.Status == ResolutionStatus.Resolved || this.Status == ResolutionStatus.Unsupported);

        public static ResolutionResult Unresolved { get; } =
            new ResolutionResult(null, MetadataSource.Unknown, null, ResolutionStatus.Missing, "No matching metadata source was found.");

        public static ResolutionResult UnresolvedResult(ResolutionStatus status, MetadataSource source, string provenance, string reason)
        {
            return new ResolutionResult(null, source, provenance, status, reason);
        }
    }

    public enum ResolutionStatus
    {
        Resolved = 0,
        Missing,
        Unsupported,
        Invalid,
        Conflict,
    }

    /// <summary>
    /// A source of ETW event schemas. Resolvers must never load or execute
    /// evidence binaries; PE resources are parsed statically as data.
    /// </summary>
    public interface IMetadataResolver
    {
        MetadataSource Source { get; }

        /// <summary>Returns <see cref="ResolutionResult.Unresolved"/> when this source cannot decode the key.</summary>
        ResolutionResult Resolve(EventKey key);
    }

    /// <summary>Ordered set of resolvers, queried in priority order.</summary>
    public interface IMetadataResolverChain
    {
        ResolutionResult Resolve(EventKey key);
    }

    public interface ISourceScopedMetadataResolver
    {
        void SetCurrentSource(string sourceFile);
    }
}
