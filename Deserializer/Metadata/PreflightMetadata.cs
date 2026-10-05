namespace ETWDeserializer
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// A resolver that is populated during a preflight pass and reused during
    /// conversion. This lets schema metadata that appears later in the trace
    /// (for example EventSource manifest chunks) decode earlier events, without
    /// buffering the events themselves.
    /// </summary>
    public sealed class CachedSchemaResolver : IMetadataResolver
    {
        private readonly Dictionary<EventKey, ResolutionResult> cache = new Dictionary<EventKey, ResolutionResult>();

        public MetadataSource Source => MetadataSource.Embedded;

        public void Store(EventKey key, ResolutionResult result)
        {
            if (result == null) return;
            if (this.cache.TryGetValue(key, out var existing))
            {
                if (existing.Status == ResolutionStatus.Conflict) return;
                if (!existing.Resolved || !result.Resolved || !Equivalent(existing.Operand.Metadata, result.Operand.Metadata))
                {
                    this.cache[key] = ResolutionResult.UnresolvedResult(ResolutionStatus.Conflict, MetadataSource.Embedded, existing.Provenance + ";" + result.Provenance, "Embedded schemas from different ETL sources conflict for " + key + ".");
                    return;
                }

                string provenance = existing.Provenance;
                if (!string.IsNullOrEmpty(result.Provenance) && provenance.IndexOf(result.Provenance, StringComparison.Ordinal) < 0)
                {
                    provenance += ";" + result.Provenance;
                }
                this.cache[key] = new ResolutionResult(result.Operand, MetadataSource.Embedded, provenance);
                return;
            }

            this.cache[key] = result;
        }

        public ResolutionResult Resolve(EventKey key)
        {
            return this.cache.TryGetValue(key, out var result) ? result : ResolutionResult.Unresolved;
        }

        public bool Contains(EventKey key) => this.cache.ContainsKey(key);

        private static bool Equivalent(EventMetadata left, EventMetadata right)
        {
            if (left.Name != right.Name || left.ResolutionStatus != right.ResolutionStatus || left.Properties.Length != right.Properties.Length) return false;
            for (int i = 0; i < left.Properties.Length; i++)
            {
                var a = left.Properties[i];
                var b = right.Properties[i];
                if (a.Name != b.Name || a.InType != b.InType || a.OutType != b.OutType || a.IsStruct != b.IsStruct || a.ChildrenCount != b.ChildrenCount) return false;
            }
            return true;
        }
    }

    /// <summary>
    /// Preflight resolver: solves schemas for every header key seen, by leveraging
    /// the existing resolver chain and the deserializer's embedded/TDH discovery.
    /// It records which keys were resolvable so later passes can report missing
    /// metadata even without a second decode.
    /// </summary>
    public sealed class PreflightMetadata : IMetadataResolverChain, ISourceScopedMetadataResolver
    {
        private readonly MetadataResolver chain;
        private readonly Dictionary<string, Dictionary<EventKey, ResolutionResult>> sources = new Dictionary<string, Dictionary<EventKey, ResolutionResult>>(StringComparer.OrdinalIgnoreCase);
        private readonly HashSet<EventKey> seen = new HashSet<EventKey>();
        private string currentSource;

        public PreflightMetadata(MetadataResolver chain)
        {
            this.chain = chain;
        }

        public IReadOnlyDictionary<EventKey, ResolutionResult> Known
        {
            get => this.GetCurrentSourceCache();
        }

        public IEnumerable<EventKey> Seen => this.seen;

        public void SetCurrentSource(string sourceFile) => this.currentSource = sourceFile;

        public void Observe(EventKey key, ResolutionResult result)
        {
            this.seen.Add(key);
            if (result == null || (!result.Resolved && result.Status == ResolutionStatus.Missing)) return;
            var cache = this.GetCurrentSourceCache();
            if (cache.TryGetValue(key, out var previous))
            {
                if (previous.Status == ResolutionStatus.Conflict) return;
                if (!previous.Resolved || !result.Resolved || !CachedSchemaResolverEquivalent(previous.Operand.Metadata, result.Operand.Metadata))
                {
                    cache[key] = ResolutionResult.UnresolvedResult(ResolutionStatus.Conflict, MetadataSource.Embedded,
                        previous.Provenance + ";" + result.Provenance,
                        "Conflicting embedded schemas for " + key + " in source '" + (this.currentSource ?? "<unspecified>") + "'.");
                    return;
                }
            }
            cache[key] = result;
        }

        /// <summary>Stores an embedded schema discovered during the first pass for use during output.</summary>
        public void Store(EventKey key, ResolutionResult result)
        {
            this.Observe(key, result);
        }

        public void InvalidateProvider(Guid providerGuid)
        {
            RemoveProvider(this.GetCurrentSourceCache(), providerGuid);
        }

        private static void RemoveProvider(Dictionary<EventKey, ResolutionResult> values, Guid providerGuid)
        {
            var keys = new List<EventKey>();
            foreach (var key in values.Keys)
            {
                if (key.ProviderGuid == providerGuid) keys.Add(key);
            }
            foreach (var key in keys) values.Remove(key);
        }

        public ResolutionResult Resolve(EventKey key)
        {
            if (this.GetCurrentSourceCache().TryGetValue(key, out var result))
            {
                return result;
            }

            return this.chain.Resolve(key);
        }

        private Dictionary<EventKey, ResolutionResult> GetCurrentSourceCache()
        {
            string source = this.currentSource ?? string.Empty;
            if (!this.sources.TryGetValue(source, out var cache))
            {
                cache = new Dictionary<EventKey, ResolutionResult>();
                this.sources.Add(source, cache);
            }
            return cache;
        }

        private static bool CachedSchemaResolverEquivalent(EventMetadata left, EventMetadata right)
        {
            if (left.Name != right.Name || left.Properties.Length != right.Properties.Length) return false;
            for (int i = 0; i < left.Properties.Length; i++)
            {
                var a = left.Properties[i];
                var b = right.Properties[i];
                if (a.Name != b.Name || a.InType != b.InType || a.OutType != b.OutType || a.IsStruct != b.IsStruct || a.ChildrenCount != b.ChildrenCount) return false;
            }
            return true;
        }
    }
}
