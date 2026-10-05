namespace ETWDeserializer
{
    using System;
    using System.Collections.Generic;

    /// <summary>
    /// Queries resolvers in the order required by the forensic contract:
    /// embedded / TraceLogging, explicit manifest, explicit resource, offline
    /// registry, then (optionally) host local cache. Host local cache is never
    /// consulted implicitly.
    /// </summary>
    public sealed class MetadataResolver : IMetadataResolverChain
    {
        private readonly List<IMetadataResolver> resolvers = new List<IMetadataResolver>();

        public void Add(IMetadataResolver resolver)
        {
            if (resolver != null)
            {
                this.resolvers.Add(resolver);
            }
        }

        public void StoreEmbeddedSchema(EventKey key, ResolutionResult result)
        {
            foreach (var resolver in this.resolvers)
            {
                if (resolver is CachedSchemaResolver cache) cache.Store(key, result);
            }
        }

        public ResolutionResult Resolve(EventKey key)
        {
            ResolutionResult bestDiagnostic = null;
            foreach (var resolver in this.resolvers)
            {
                ResolutionResult result;
                try
                {
                    result = resolver.Resolve(key);
                }
                catch (Exception ex)
                {
                    // A broken metadata source must not abort the whole trace.
                    System.Diagnostics.Trace.WriteLine("resolver " + resolver.GetType().Name + " failed: " + ex.Message);
                    var failed = ResolutionResult.UnresolvedResult(ResolutionStatus.Invalid, resolver.Source, resolver.GetType().Name, ex.GetType().Name + ": " + ex.Message);
                    if (IsMoreRelevant(failed, bestDiagnostic)) bestDiagnostic = failed;
                    continue;
                }

                if (result != null && result.Resolved)
                {
                    return result;
                }

                if (result != null && result.Status == ResolutionStatus.Conflict)
                {
                    return result;
                }

                if (IsMoreRelevant(result, bestDiagnostic))
                {
                    bestDiagnostic = result;
                }
            }

            return bestDiagnostic ?? ResolutionResult.Unresolved;
        }

        private static bool IsMoreRelevant(ResolutionResult candidate, ResolutionResult current)
        {
            if (candidate == null) return false;
            if (current == null) return true;
            return Rank(candidate.Status) > Rank(current.Status);
        }

        private static int Rank(ResolutionStatus status)
        {
            switch (status)
            {
                case ResolutionStatus.Conflict: return 5;
                case ResolutionStatus.Invalid: return 4;
                case ResolutionStatus.Unsupported: return 3;
                case ResolutionStatus.Missing: return 2;
                default: return 0;
            }
        }
    }
}
