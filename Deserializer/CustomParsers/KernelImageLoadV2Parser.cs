namespace ETWDeserializer.CustomParsers
{
    internal sealed class KernelImageLoadV2Parser
    {
        private static readonly PropertyMetadata[] Properties =
        {
            CustomParserMetadata.Property("ImageBase", TDH_IN_TYPE.TDH_INTYPE_POINTER),
            CustomParserMetadata.Property("ImageSize", TDH_IN_TYPE.TDH_INTYPE_POINTER),
            CustomParserMetadata.Property("ProcessId", TDH_IN_TYPE.TDH_INTYPE_UINT32),
            CustomParserMetadata.Property("ImageChecksum", TDH_IN_TYPE.TDH_INTYPE_UINT32),
            CustomParserMetadata.Property("TimeDateStamp", TDH_IN_TYPE.TDH_INTYPE_UINT32),
            CustomParserMetadata.Property("Reserved0", TDH_IN_TYPE.TDH_INTYPE_UINT32),
            CustomParserMetadata.Property("DefaultBase", TDH_IN_TYPE.TDH_INTYPE_POINTER),
            CustomParserMetadata.Property("Reserved1", TDH_IN_TYPE.TDH_INTYPE_UINT32),
            CustomParserMetadata.Property("Reserved2", TDH_IN_TYPE.TDH_INTYPE_UINT32),
            CustomParserMetadata.Property("Reserved3", TDH_IN_TYPE.TDH_INTYPE_UINT32),
            CustomParserMetadata.Property("Reserved4", TDH_IN_TYPE.TDH_INTYPE_UINT32),
            CustomParserMetadata.Property("FileName", TDH_IN_TYPE.TDH_INTYPE_UNICODESTRING),
        };

        public KernelImageLoadV2Parser(byte opcode)
        {
            string action = opcode switch { 10 => "Load", 2 => "Unload", 3 => "DCStart", 4 => "DCStop", _ => throw new System.ArgumentOutOfRangeException(nameof(opcode)) };
            this.SchemaMetadata = CustomParserMetadata.Create(CustomParserGuids.KernelImageLoadGuid, 0, "Kernel/Image/" + action,
                Properties, "image-load-v2:2*pointer,4*uint32,pointer,4*uint32,utf16z");
        }

        public EventMetadata SchemaMetadata { get; }

        public static bool Supports(byte version, byte opcode) => version == 2 && opcode is 10 or 2 or 3 or 4;

        public void Parse<T>(EventRecordReader reader, T writer, EventMetadata[] metadataArray, RuntimeEventMetadata runtime) where T : IEtwWriter
        {
            CustomParserMetadata.PointerSize(runtime);
            var output = new BuiltinEventWriter<T>(writer, this.SchemaMetadata, runtime);
            output.Pointer(reader.ReadPointer());
            output.Pointer(reader.ReadPointer());
            for (int i = 0; i < 4; i++) output.UInt32(reader.ReadUInt32());
            output.Pointer(reader.ReadPointer());
            for (int i = 0; i < 4; i++) output.UInt32(reader.ReadUInt32());
            output.Unicode(reader.ReadUnicodeString());
            output.Complete(reader);
        }
    }
}
