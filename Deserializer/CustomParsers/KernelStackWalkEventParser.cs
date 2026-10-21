namespace ETWDeserializer.CustomParsers
{
    using System;

    internal sealed class KernelStackWalkEventParser
    {
        private static readonly EventMetadata EventMetadata;

        private static readonly PropertyMetadata StacksPropertyMetadata;

        private static readonly PropertyMetadata StackProcessMetadata;

        private static readonly PropertyMetadata StackThreadMetadata;

        private static readonly PropertyMetadata EventTimeStampMetadata;

        static KernelStackWalkEventParser()
        {
            EventTimeStampMetadata = new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_INT64, TDH_OUT_TYPE.TDH_OUTTYPE_UNSIGNEDLONG, "EventTimeStamp", false, false, 0, null);
            StackProcessMetadata = new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_UINT32, TDH_OUT_TYPE.TDH_OUTTYPE_UNSIGNEDINT, "StackProcess", false, false, 0, null);
            StackThreadMetadata = new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_UINT32, TDH_OUT_TYPE.TDH_OUTTYPE_UNSIGNEDINT, "StackThread", false, false, 0, null);
            StacksPropertyMetadata = new PropertyMetadata(TDH_IN_TYPE.TDH_INTYPE_POINTER, TDH_OUT_TYPE.TDH_OUTTYPE_HEXINT64, "Stacks", false, false, 0, null);
            EventMetadata = CustomParserMetadata.Create(
                new Guid("def2fe46-7bd6-4b80-bd94-f57fe20d0ce3"),
                32,
                "Kernel/Stack/StackWalk",
                new[] { EventTimeStampMetadata, StackProcessMetadata, StackThreadMetadata, StacksPropertyMetadata }, "uint64,uint32,uint32,pointer[]");
        }

        internal static EventMetadata SchemaMetadata => EventMetadata;

        public void Parse<T>(EventRecordReader reader, T writer, EventMetadata[] metadataArray, RuntimeEventMetadata runtimeMetadata)
            where T : IEtwWriter
        {
            int pointerSize = CustomParserMetadata.PointerSize(runtimeMetadata);
            if (runtimeMetadata.UserDataLength < 16 || (runtimeMetadata.UserDataLength - 16) % pointerSize != 0)
                throw new InvalidOperationException("StackWalk payload does not contain a complete header and pointer array.");
            int numberOfStacks = (runtimeMetadata.UserDataLength - 16) / pointerSize;
            reader.ReserveArrayElements((ulong)numberOfStacks);
            writer.WriteEventBegin(CustomParserMetadata.Bind(EventMetadata, runtimeMetadata), runtimeMetadata);

            writer.WritePropertyBegin(EventTimeStampMetadata);
            writer.WriteUInt64(reader.ReadUInt64());
            writer.WritePropertyEnd();

            writer.WritePropertyBegin(StackProcessMetadata);
            writer.WriteUInt32(reader.ReadUInt32());
            writer.WritePropertyEnd();

            writer.WritePropertyBegin(StackThreadMetadata);
            writer.WriteUInt32(reader.ReadUInt32());
            writer.WritePropertyEnd();

            writer.WritePropertyBegin(StacksPropertyMetadata);

            writer.WriteArrayBegin();

            for (int i = 0; i < numberOfStacks; ++i)
            {
                writer.WritePointer(reader.ReadPointer());
            }

            writer.WriteArrayEnd();

            writer.WritePropertyEnd();
            reader.EnsurePayloadConsumed();
            writer.WriteEventEnd();
        }
    }
}
