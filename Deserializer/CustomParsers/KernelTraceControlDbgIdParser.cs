namespace ETWDeserializer.CustomParsers
{
    using System;

    internal sealed class KernelTraceControlDbgIdParser
    {
        private static readonly EventMetadata EventMetadata;

        private static readonly PropertyMetadata ImageBase;

        private static readonly PropertyMetadata ProcessId;

        private static readonly PropertyMetadata GuidSig;

        private static readonly PropertyMetadata Age;

        private static readonly PropertyMetadata PdbFileName;

        static KernelTraceControlDbgIdParser()
        {
            ImageBase = new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_POINTER, TDH_OUT_TYPE.TDH_OUTTYPE_HEXINT64, "ImageBase", false, false, 0, null);
            ProcessId = new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_UINT32, TDH_OUT_TYPE.TDH_OUTTYPE_UNSIGNEDINT, "ProcessID", false, false, 0, null);
            GuidSig = new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_GUID, TDH_OUT_TYPE.TDH_OUTTYPE_GUID, "GuidSig", false, false, 0, null);
            Age = new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_UINT32, TDH_OUT_TYPE.TDH_OUTTYPE_UNSIGNEDINT, "Age", false, false, 0, null);
            PdbFileName = new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_ANSISTRING, TDH_OUT_TYPE.TDH_OUTTYPE_STRING, "PdbFileName", false, false, 0, null);
            EventMetadata = CustomParserMetadata.Create(
                new Guid("b3e675d7-2554-4f18-830b-2762732560de"),
                36,
                "KernelTraceControl/ImageID/DbgID_RSDS",
                new[] { ImageBase, ProcessId, GuidSig, Age, PdbFileName }, "pointer,uint32,guid,uint32,utf8z");
        }

        internal static EventMetadata SchemaMetadata => EventMetadata;

        public void Parse<T>(EventRecordReader reader, T writer, EventMetadata[] metadataArray, RuntimeEventMetadata runtimeMetadata)
            where T : IEtwWriter
        {
            CustomParserMetadata.PointerSize(runtimeMetadata);
            writer.WriteEventBegin(CustomParserMetadata.Bind(EventMetadata, runtimeMetadata), runtimeMetadata);

            writer.WritePropertyBegin(ImageBase);
            writer.WritePointer(reader.ReadPointer());
            writer.WritePropertyEnd();

            writer.WritePropertyBegin(ProcessId);
            writer.WriteUInt32(reader.ReadUInt32());
            writer.WritePropertyEnd();

            writer.WritePropertyBegin(GuidSig);
            writer.WriteGuid(reader.ReadGuid());
            writer.WritePropertyEnd();

            writer.WritePropertyBegin(Age);
            writer.WriteUInt32(reader.ReadUInt32());
            writer.WritePropertyEnd();

            writer.WritePropertyBegin(PdbFileName);
            writer.WriteAnsiString(CustomParserMetadata.ReadUtf8String(reader));
            writer.WritePropertyEnd();

            reader.EnsurePayloadConsumed();
            writer.WriteEventEnd();
        }
    }
}
