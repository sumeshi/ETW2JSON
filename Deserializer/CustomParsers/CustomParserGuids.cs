namespace ETWDeserializer.CustomParsers
{
    using System;

    /// <summary>
    /// Much of this knowledge has been acquired thanks to:
    /// https://github.com/Microsoft/perfview/blob/master/src/TraceEvent/Parsers/kerneltraceeventparser.cs.base
    /// https://github.com/Microsoft/perfview/blob/master/src/TraceEvent/Parsers/SymbolTraceEventParser.cs
    /// </summary>

    internal static class CustomParserGuids
    {
        public static Guid KernelTraceControlImageIdGuid = new Guid("b3e675d7-2554-4f18-830b-2762732560de");

        public static Guid KernelTraceControlMetaDataGuid = new Guid("bbccf6c1-6cd1-48c4-80ff-839482e37671");

        public static Guid KernelStackWalkGuid = new Guid("def2fe46-7bd6-4b80-bd94-f57fe20d0ce3");

        public static readonly Guid KernelProcessGuid = new Guid("3d6fa8d0-fe05-11d0-9dda-00c04fd7ba7c");

        public static readonly Guid KernelImageLoadGuid = new Guid("2cb15d1d-5fc1-11d2-abe1-00a0c911f518");

        public static readonly Guid KernelFileIoGuid = new Guid("90cbdc39-4a3e-11d1-84f4-0000f80464e3");
    }
}
