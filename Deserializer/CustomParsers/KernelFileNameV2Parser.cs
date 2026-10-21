namespace ETWDeserializer.CustomParsers
{
    internal sealed class KernelFileNameV2Parser
    {
        private static readonly PropertyMetadata[] Properties =
        {
            CustomParserMetadata.Property("FileKey", TDH_IN_TYPE.TDH_INTYPE_POINTER),
            CustomParserMetadata.Property("FileName", TDH_IN_TYPE.TDH_INTYPE_UNICODESTRING),
        };

        public KernelFileNameV2Parser(byte opcode)
        {
            string action = opcode switch { 0 => "Name", 32 => "FileCreate", 35 => "FileDelete", 36 => "FileRundown", _ => throw new System.ArgumentOutOfRangeException(nameof(opcode)) };
            this.SchemaMetadata = CustomParserMetadata.Create(CustomParserGuids.KernelFileIoGuid, 0, "Kernel/FileIO/" + action,
                Properties, "file-name-v2:pointer,utf16z;pointer_semantics:FileKey-not-open-FileObject");
        }

        public EventMetadata SchemaMetadata { get; }

        public static bool Supports(byte version, byte opcode) => version == 2 && opcode is 0 or 32 or 35 or 36;

        public void Parse<T>(EventRecordReader reader, T writer, EventMetadata[] metadataArray, RuntimeEventMetadata runtime) where T : IEtwWriter
        {
            CustomParserMetadata.PointerSize(runtime);
            var output = new BuiltinEventWriter<T>(writer, this.SchemaMetadata, runtime);
            output.Pointer(reader.ReadPointer());
            output.Unicode(reader.ReadUnicodeString());
            output.Complete(reader);
        }
    }
}
