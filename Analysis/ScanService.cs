namespace ETW2JSON.Analysis
{
    using System;
    using System.Collections.Generic;
    using System.IO;
    using System.Linq;
    using System.Text.Json;
    using ETWDeserializer;

    /// <summary>
    /// Streaming analysis pass: enumerates ETL records exactly once, resolves their
    /// schema through the same resolver chain as conversion, and accumulates counts
    /// and metadata-status per provider / event id / version. It does not retain
    /// decoded events, only aggregate counters.
    /// </summary>
    public sealed class ScanService
    {
        private readonly Dictionary<ScanKey, ScanEntry> entries = new Dictionary<ScanKey, ScanEntry>();
        private readonly Dictionary<ScanKey, HashSet<string>> sourceFiles = new Dictionary<ScanKey, HashSet<string>>();
        private readonly Dictionary<ScanKey, Dictionary<string, SourceObservation>> observations = new Dictionary<ScanKey, Dictionary<string, SourceObservation>>();

        public ScanService(IMetadataResolverChain chain)
        {
        }

        public IReadOnlyDictionary<ScanKey, ScanEntry> Entries => this.entries;

        public void Observe(EventKey key, bool hasSchema, MetadataSource source, DecodeStatus status)
        {
            var resolutionStatus = hasSchema ? ResolutionStatus.Resolved : status switch
            {
                DecodeStatus.Unsupported => ResolutionStatus.Unsupported,
                DecodeStatus.DecodeError => ResolutionStatus.Invalid,
                _ => ResolutionStatus.Missing,
            };
            this.Observe(key, null, source, resolutionStatus, null);
        }

        public void Observe(EventKey key, IEventTraceOperand operand)
        {
            var metadata = operand?.Metadata;
            this.Observe(key, metadata?.ProviderName,
                metadata?.MetadataSource ?? MetadataSource.Unknown,
                metadata?.ResolutionStatus ?? ResolutionStatus.Missing,
                metadata?.DecodeReason);
        }

        public void Observe(string source, EventKey key, IEventTraceOperand operand)
        {
            this.Observe(key, operand);
            var scanKey = new ScanKey(key.ProviderGuid, key.EventId, key.Version);
            string sourceKey = source ?? string.Empty;
            if (!this.sourceFiles.TryGetValue(scanKey, out var sources))
            {
                sources = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                this.sourceFiles.Add(scanKey, sources);
            }
            sources.Add(sourceKey);
            if (!this.observations.TryGetValue(scanKey, out var bySource))
            {
                bySource = new Dictionary<string, SourceObservation>(StringComparer.OrdinalIgnoreCase);
                this.observations.Add(scanKey, bySource);
            }
            var metadata = operand?.Metadata;
            var observation = new SourceObservation(metadata?.ProviderName, metadata?.MetadataSource ?? MetadataSource.Unknown,
                metadata?.ResolutionStatus ?? ResolutionStatus.Missing, metadata?.DecodeReason, metadata);
            if (!bySource.TryGetValue(sourceKey, out var existing) || IsBetterObservation(observation.Status, existing.Status))
            {
                bySource[sourceKey] = observation;
            }
        }

        public void Refresh(PreflightMetadata resolver)
        {
            foreach (var pair in this.entries)
            {
                if (!this.sourceFiles.TryGetValue(pair.Key, out var sources) || sources.Count == 0) continue;
                var resolvedBySource = new List<SourceObservation>();
                bool conflicting = false;
                bool missing = false;
                foreach (string source in sources)
                {
                    resolver.SetCurrentSource(source);
                    SourceObservation observed = null;
                    if (this.observations.TryGetValue(pair.Key, out var bySource)) bySource.TryGetValue(source, out observed);
                    if (observed != null && (observed.Source == MetadataSource.TraceLogging || IsHeaderUnsupported(observed.Metadata)))
                    {
                        resolvedBySource.Add(observed);
                        continue;
                    }

                    var result = resolver.Resolve(new EventKey(pair.Key.ProviderGuid, pair.Key.EventId, pair.Key.Version));
                    if (result.Status == ResolutionStatus.Conflict)
                    {
                        resolvedBySource.Add(new SourceObservation(null, result.Source, result.Status, result.Reason, null));
                    }
                    else if (result.Resolved && (observed == null || observed.Status == ResolutionStatus.Missing
                        || SourcePriority(result.Source) >= SourcePriority(observed.Source)))
                    {
                        resolvedBySource.Add(new SourceObservation(result.Operand.Metadata.ProviderName, result.Source, result.Status,
                            result.Reason ?? result.Operand.Metadata.DecodeReason, result.Operand.Metadata));
                    }
                    else if (observed != null && observed.Status != ResolutionStatus.Missing)
                    {
                        resolvedBySource.Add(observed);
                    }
                    else
                    {
                        missing = true;
                    }
                }

                if (resolvedBySource.Count == 0) continue;
                var first = resolvedBySource[0];
                foreach (var other in resolvedBySource.Skip(1))
                {
                    if (first.Status == ResolutionStatus.Conflict || other.Status == ResolutionStatus.Conflict)
                    {
                        conflicting = true;
                        break;
                    }
                    if ((first.Metadata != null && other.Metadata != null && !Equivalent(first.Metadata, other.Metadata))
                        || first.Status != other.Status)
                    {
                        conflicting = true;
                        break;
                    }
                }

                if (conflicting)
                {
                    pair.Value.RefreshMetadata(null, first.Source, ResolutionStatus.Conflict,
                        "Conflicting or different metadata outcomes were found across input ETL sources.");
                }
                else if (missing)
                {
                    pair.Value.RefreshStatus("Mixed", first.Source,
                        "Metadata was available for only some input ETL sources; per-source decoding remains available.");
                }
                else
                {
                    pair.Value.RefreshMetadata(first.ProviderName, first.Source, first.Status, first.Reason);
                }
            }
        }

        private static bool IsBetterObservation(ResolutionStatus candidate, ResolutionStatus current)
        {
            int Rank(ResolutionStatus status) => status switch
            {
                ResolutionStatus.Conflict => 5,
                ResolutionStatus.Resolved => 4,
                ResolutionStatus.Unsupported => 3,
                ResolutionStatus.Invalid => 2,
                _ => 1,
            };
            return Rank(candidate) > Rank(current);
        }

        private static int SourcePriority(MetadataSource source) => source switch
        {
            MetadataSource.Embedded => 7,
            MetadataSource.TraceLogging => 8,
            MetadataSource.ExternalManifest => 6,
            MetadataSource.ExternalPeResource => 5,
            MetadataSource.OfflineRegistryResolved => 5,
            MetadataSource.LocalCache => 1,
            _ => 0,
        };

        private static bool IsHeaderUnsupported(EventMetadata metadata)
        {
            if (metadata?.ResolutionStatus != ResolutionStatus.Unsupported || metadata.DecodeReason == null) return false;
            return metadata.DecodeReason.StartsWith("WPP/TraceMessage", StringComparison.Ordinal)
                || metadata.DecodeReason.StartsWith("String-only", StringComparison.Ordinal);
        }

        private sealed class SourceObservation
        {
            public SourceObservation(string providerName, MetadataSource source, ResolutionStatus status, string reason, EventMetadata metadata)
            {
                this.ProviderName = providerName;
                this.Source = source;
                this.Status = status;
                this.Reason = reason;
                this.Metadata = metadata;
            }
            public string ProviderName { get; }
            public MetadataSource Source { get; }
            public ResolutionStatus Status { get; }
            public string Reason { get; }
            public EventMetadata Metadata { get; }
        }

        private static bool Equivalent(EventMetadata left, EventMetadata right)
        {
            if (left == null || right == null || left.Name != right.Name || left.Properties.Length != right.Properties.Length) return false;
            for (int i = 0; i < left.Properties.Length; i++)
            {
                var a = left.Properties[i];
                var b = right.Properties[i];
                if (a.Name != b.Name || a.InType != b.InType || a.OutType != b.OutType) return false;
            }
            return true;
        }

        private void Observe(EventKey key, string providerName, MetadataSource source, ResolutionStatus status, string reason)
        {
            var scanned = new ScanKey(key.ProviderGuid, key.EventId, key.Version);
            if (!this.entries.TryGetValue(scanned, out var entry))
            {
                entry = new ScanEntry(scanned);
                this.entries.Add(scanned, entry);
            }

            entry.Increment();
            entry.Observe(providerName, source, status, reason);
        }

        public void WriteText(TextWriter writer)
        {
            this.WriteText(writer, null);
        }

        public void WriteText(TextWriter writer, ExportedProviderResolver providerInfo)
        {
            foreach (var entry in this.entries.Values)
            {
                writer.WriteLine("Provider: " + (GetProviderName(entry, providerInfo) ?? "{unknown}"));
                writer.WriteLine("GUID: {" + entry.Key.ProviderGuid.ToString("D") + "}");
                writer.WriteLine();
                writer.WriteLine("Events:");
                writer.WriteLine("  ID " + entry.Key.EventId + " Version " + entry.Key.Version + ": " + entry.Count);
                writer.WriteLine();
                writer.WriteLine("Metadata:");
                writer.WriteLine("  Status: " + entry.MetadataStatus);
                if (!string.IsNullOrEmpty(entry.Reason))
                {
                    writer.WriteLine("  Reason: " + entry.Reason);
                }
                if (entry.MetadataSource != MetadataSource.Unknown)
                {
                    writer.WriteLine("  Source: " + MetadataSourceNames.ToJson(entry.MetadataSource));
                }

                writer.WriteLine();
            }
        }

        public void WriteJson(Stream stream)
        {
            this.WriteJson(stream, null);
        }

        public void WriteJson(Stream stream, ExportedProviderResolver providerInfo)
        {
            using (var writer = new Utf8JsonWriter(stream, new JsonWriterOptions { Indented = true }))
            {
                writer.WriteStartObject();
                writer.WritePropertyName("Providers");
                writer.WriteStartArray();
                foreach (var entry in this.entries.Values)
                {
                    writer.WriteStartObject();
                    writer.WriteString("provider_guid", entry.Key.ProviderGuid.ToString("D"));
                    string providerName = GetProviderName(entry, providerInfo);
                    if (providerName != null)
                    {
                        writer.WriteString("provider_name", providerName);
                    }

                    writer.WritePropertyName("events");
                    writer.WriteStartArray();
                    writer.WriteStartObject();
                    writer.WriteNumber("event_id", entry.Key.EventId);
                    writer.WriteNumber("version", entry.Key.Version);
                    writer.WriteNumber("count", entry.Count);
                    writer.WriteString("metadata_status", entry.MetadataStatus);
                    if (!string.IsNullOrEmpty(entry.Reason))
                    {
                        writer.WriteString("metadata_reason", entry.Reason);
                    }
                    writer.WriteString("metadata_source", MetadataSourceNames.ToJson(entry.MetadataSource));
                    writer.WriteEndObject();
                    writer.WriteEndArray();
                    writer.WriteEndObject();
                }

                writer.WriteEndArray();
                writer.WriteEndObject();
                writer.Flush();
            }
        }

        private static string GetProviderName(ScanEntry entry, ExportedProviderResolver providerInfo)
        {
            if (entry.ProviderName != null)
            {
                return entry.ProviderName;
            }

            if (providerInfo != null && providerInfo.TryGetProvider(entry.Key.ProviderGuid, out ExportedProviderInfo exported))
            {
                return exported.Name;
            }

            return null;
        }
    }

    /// <summary>Identity used by the scan for one provider/event/version tuple.</summary>
    public readonly struct ScanKey : IEquatable<ScanKey>
    {
        public ScanKey(Guid providerGuid, ushort eventId, byte version)
        {
            this.ProviderGuid = providerGuid;
            this.EventId = eventId;
            this.Version = version;
        }

        public Guid ProviderGuid { get; }

        public ushort EventId { get; }

        public byte Version { get; }

        public bool Equals(ScanKey other)
        {
            return this.ProviderGuid.Equals(other.ProviderGuid) && this.EventId == other.EventId && this.Version == other.Version;
        }

        public override bool Equals(object obj) => obj is ScanKey other && this.Equals(other);

        public override int GetHashCode()
        {
            unchecked
            {
                var hashCode = this.ProviderGuid.GetHashCode();
                hashCode = (hashCode * 397) ^ this.EventId.GetHashCode();
                hashCode = (hashCode * 397) ^ this.Version.GetHashCode();
                return hashCode;
            }
        }
    }

    /// <summary>Aggregated scan information for a single <see cref="ScanKey"/>.</summary>
    public sealed class ScanEntry
    {
        public ScanEntry(ScanKey key)
        {
            this.Key = key;
        }

        public ScanKey Key { get; }

        public long Count { get; private set; }

        public void Increment() => this.Count++;

        public string ProviderName { get; private set; }

        public MetadataSource MetadataSource { get; private set; } = MetadataSource.Unknown;

        public string MetadataStatus { get; private set; } = "Missing";

        public string Reason { get; private set; }

        public void Observe(string providerName, MetadataSource source, ResolutionStatus status, string reason)
        {
            if (this.ProviderName == null && providerName != null)
            {
                this.ProviderName = providerName;
            }

            string statusText = status.ToString();
            if (StatusRank(statusText) > StatusRank(this.MetadataStatus))
            {
                this.MetadataStatus = statusText;
                this.MetadataSource = source;
                this.Reason = reason;
            }
            else if (this.Reason == null && reason != null)
            {
                this.Reason = reason;
            }
        }

        public void RefreshMetadata(string providerName, MetadataSource source, ResolutionStatus status, string reason)
        {
            if (providerName != null) this.ProviderName = providerName;
            this.MetadataSource = source;
            this.MetadataStatus = status.ToString();
            this.Reason = reason;
        }

        public void RefreshStatus(string status, MetadataSource source, string reason)
        {
            this.MetadataStatus = status;
            this.MetadataSource = source;
            this.Reason = reason;
        }

        private static int StatusRank(string status)
        {
            return status switch
            {
                "Resolved" => 5,
                "Conflict" => 4,
                "Invalid" => 3,
                "Unsupported" => 2,
                _ => 1,
            };
        }
    }
}
