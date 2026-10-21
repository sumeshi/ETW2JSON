namespace ETWDeserializer.CustomParsers
{
    /// <summary>Version-limited fallbacks for classic investigation event classes.</summary>
    internal static class KernelInvestigationParsers
    {
        public static bool Supports(EventKey key)
        {
            if (!key.ClassicOpcode.HasValue) return false;
            byte opcode = key.ClassicOpcode.Value;
            return key.ProviderGuid == CustomParserGuids.KernelProcessGuid && KernelProcessV4Parser.Supports(key.Version, opcode)
                || key.ProviderGuid == CustomParserGuids.KernelImageLoadGuid && KernelImageLoadV2Parser.Supports(key.Version, opcode)
                || key.ProviderGuid == CustomParserGuids.KernelFileIoGuid && KernelFileNameV2Parser.Supports(key.Version, opcode);
        }
    }
}
