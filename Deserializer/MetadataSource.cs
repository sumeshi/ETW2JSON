namespace ETWDeserializer
{
    /// <summary>
    /// Where the schema used to decode an event came from. This is recorded per
    /// event so a forensic examiner can trace the provenance of the decode.
    /// </summary>
    public enum MetadataSource
    {
        /// <summary>Provenance could not be established.</summary>
        Unknown = 0,

        /// <summary>Schema embedded in the ETL/event itself (EventSource manifest chunks, KernelTraceControl metadata).</summary>
        Embedded,

        /// <summary>Self-describing TraceLogging metadata carried inside the event.</summary>
        TraceLogging,

        /// <summary>Schema read from an explicitly supplied .man file.</summary>
        ExternalManifest,

        /// <summary>Schema extracted statically from an explicitly supplied PE resource.</summary>
        ExternalPeResource,

        /// <summary>Schema resolved from an offline SOFTWARE hive and evidence Windows root.</summary>
        OfflineRegistryResolved,

        /// <summary>Schema obtained from the analysis host's provider registration. Disabled by default.</summary>
        LocalCache,
    }

    /// <summary>Outcome of decoding a single event.</summary>
    public enum DecodeStatus
    {
        /// <summary>All properties were decoded from a trusted schema.</summary>
        Decoded = 0,

        /// <summary>No schema was available; header and raw payload are preserved.</summary>
        MetadataMissing,

        /// <summary>A schema was found but uses a form this decoder does not support (for example WPP).</summary>
        Unsupported,

        /// <summary>Some properties decoded before the payload could not be interpreted.</summary>
        Partial,

        /// <summary>A schema was found but reading the payload failed.</summary>
        DecodeError,
    }

    internal static class MetadataSourceNames
    {
        public static string ToJson(MetadataSource source)
        {
            switch (source)
            {
                case MetadataSource.Embedded:
                    return "embedded";
                case MetadataSource.TraceLogging:
                    return "trace_logging";
                case MetadataSource.ExternalManifest:
                    return "external_manifest";
                case MetadataSource.ExternalPeResource:
                    return "external_pe_resource";
                case MetadataSource.OfflineRegistryResolved:
                    return "offline_registry_resolved";
                case MetadataSource.LocalCache:
                    return "local_cache";
                default:
                    return "unknown";
            }
        }

        public static string ToJson(DecodeStatus status)
        {
            switch (status)
            {
                case DecodeStatus.Decoded:
                    return "decoded";
                case DecodeStatus.MetadataMissing:
                    return "metadata_missing";
                case DecodeStatus.Unsupported:
                    return "unsupported";
                case DecodeStatus.Partial:
                    return "partial";
                default:
                    return "decode_error";
            }
        }
    }
}
