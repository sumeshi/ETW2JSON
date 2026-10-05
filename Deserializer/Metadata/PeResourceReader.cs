namespace ETWDeserializer
{
    using System;
    using System.Buffers.Binary;
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using System.Reflection.PortableExecutable;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// A single resource entry read out of a PE image. The raw bytes are never
    /// interpreted here.
    /// </summary>
    public sealed class PeResourceEntry
    {
        internal PeResourceEntry(ushort typeId, string typeName, string name, ushort language, byte[] data, uint rva, uint dataSize)
        {
            this.TypeId = typeId;
            this.TypeName = typeName;
            this.Name = name;
            this.Language = language;
            this.Data = data;
            this.Rva = rva;
            this.DataSize = dataSize;
        }

        /// <summary>Numeric resource type id (for example 23 for RT_MANIFEST); zero when the type is named.</summary>
        public ushort TypeId { get; }

        /// <summary>Named resource type, or null when the type is numeric.</summary>
        public string TypeName { get; }

        /// <summary>Resource name; numeric names are rendered as invariant decimal strings.</summary>
        public string Name { get; }

        /// <summary>Language id of the leaf entry.</summary>
        public ushort Language { get; }

        /// <summary>Raw resource bytes exactly as stored in the image.</summary>
        public byte[] Data { get; }

        /// <summary>RVA of the raw resource bytes.</summary>
        public uint Rva { get; }

        /// <summary>Declared size of the raw resource bytes.</summary>
        public uint DataSize { get; }
    }

    /// <summary>
    /// Result of reading the resource directory of a PE image: the file identity,
    /// every parsed resource entry, and a lookup helper.
    /// </summary>
    public sealed class PeResourceData
    {
        internal PeResourceData(string path, string sha256, IReadOnlyList<PeResourceEntry> resources)
        {
            this.Path = path;
            this.Sha256 = sha256;
            this.Resources = resources;
        }

        /// <summary>The path passed to <see cref="PeResourceReader.Read"/>.</summary>
        public string Path { get; }

        /// <summary>Lowercase hex SHA-256 of the whole file.</summary>
        public string Sha256 { get; }

        /// <summary>All resource entries, in directory order.</summary>
        public IReadOnlyList<PeResourceEntry> Resources { get; }

        /// <summary>
        /// Returns the first entry with the given type id whose name matches
        /// <paramref name="name"/>, or null. Pass a null name to match any name.
        /// </summary>
        public PeResourceEntry Find(ushort typeId, string name)
        {
            foreach (var entry in this.Resources)
            {
                if (entry.TypeId == typeId && (name == null || string.Equals(entry.Name, name, StringComparison.Ordinal)))
                {
                    return entry;
                }
            }

            return null;
        }
    }

    /// <summary>
    /// Reads the resource directory of a PE image without loading or executing it.
    /// Only bytes on disk are parsed; no LoadLibrary, Assembly.Load or
    /// NativeLibrary.Load is used.
    /// </summary>
    public static class PeResourceReader
    {
        private const int DirectoryHeaderSize = 16;
        private const int DirectoryEntrySize = 8;
        private const int DataEntrySize = 16;
        private const uint NameIsStringFlag = 0x80000000;
        private const uint OffsetIsSubdirectoryFlag = 0x80000000;
        private const int MaxDepth = 4;
        private const int MaxResources = 100000;
        private const int MaxImageSize = 512 * 1024 * 1024;
        private const long MaxTotalResourceData = 128L * 1024 * 1024;

        /// <summary>
        /// Parses the PE resource directory at <paramref name="path"/> and returns
        /// the raw resource bytes. Throws <see cref="InvalidDataException"/> when
        /// the image or resource directory is malformed.
        /// </summary>
        public static PeResourceData Read(string path)
        {
            if (path == null)
            {
                throw new ArgumentNullException(nameof(path));
            }

            var fileInfo = new FileInfo(path);
            if (!fileInfo.Exists || fileInfo.Length > MaxImageSize)
            {
                throw new InvalidDataException("The PE image is missing or exceeds the 512 MiB safety limit.");
            }

            byte[] bytes = File.ReadAllBytes(path);
            if (bytes.Length > MaxImageSize)
            {
                throw new InvalidDataException("The PE image exceeds the 512 MiB safety limit.");
            }

            string sha256;
            using (var sha = SHA256.Create())
            {
                sha256 = ToHex(sha.ComputeHash(bytes));
            }

            var resources = new List<PeResourceEntry>();

            PEHeaders headers;
            using (var stream = new MemoryStream(bytes, writable: false))
            {
                headers = ReadHeaders(stream);
            }

            if (headers.PEHeader == null)
            {
                throw new InvalidDataException("The PE image has no COFF/optional header.");
            }

            var directory = headers.PEHeader.ResourceTableDirectory;
            uint directoryRva = (uint)directory.RelativeVirtualAddress;
            if (directoryRva != 0)
            {
                if (directory.Size == 0 || directory.Size > bytes.Length)
                {
                    throw new InvalidDataException("The PE resource directory has an invalid size.");
                }

                int resourceBase = RvaToOffset(headers, directoryRva);
                if (resourceBase < 0 || resourceBase > bytes.Length - (long)directory.Size)
                {
                    throw new InvalidDataException("The PE resource directory RVA cannot be mapped to a file offset.");
                }

                var visitedDirectories = new HashSet<int>();
                long totalResourceData = 0;
                WalkDirectory(bytes, headers, resourceBase, resourceBase, resourceBase + (long)directory.Size,
                    0, 0, null, null, 0, resources, visitedDirectories, ref totalResourceData);
            }

            return new PeResourceData(path, sha256, resources);
        }

        private static PEHeaders ReadHeaders(Stream stream)
        {
            try
            {
                using (var peReader = new PEReader(stream))
                {
                    return peReader.PEHeaders;
                }
            }
            catch (BadImageFormatException ex)
            {
                throw new InvalidDataException("The file is not a valid PE image.", ex);
            }
        }

        private static void WalkDirectory(
            byte[] bytes,
            PEHeaders headers,
            int resourceBase,
            int directoryOffset,
            long resourceLimit,
            int depth,
            ushort typeId,
            string typeName,
            string name,
            ushort language,
            List<PeResourceEntry> resources,
            HashSet<int> visitedDirectories,
            ref long totalResourceData)
        {
            if (depth > MaxDepth)
            {
                throw new InvalidDataException("PE resource directory nesting exceeds the supported depth.");
            }

            EnsureResourceRange(bytes, directoryOffset, DirectoryHeaderSize, resourceBase, resourceLimit);
            if (!visitedDirectories.Add(directoryOffset))
            {
                throw new InvalidDataException("The PE resource directory contains a cycle or shared subdirectory.");
            }

            ushort namedCount = ReadUInt16(bytes, directoryOffset + 12L);
            ushort idCount = ReadUInt16(bytes, directoryOffset + 14L);
            int entryCount = namedCount + idCount;
            if (entryCount < 0 || entryCount > MaxResources)
            {
                throw new InvalidDataException("PE resource directory declares an implausible number of entries.");
            }

            long entriesStart = directoryOffset + (long)DirectoryHeaderSize;
            EnsureResourceRange(bytes, entriesStart, (long)entryCount * DirectoryEntrySize, resourceBase, resourceLimit);

            for (int i = 0; i < entryCount; i++)
            {
                if (resources.Count >= MaxResources)
                {
                    throw new InvalidDataException("The PE image declares more resources than the reader will accept.");
                }

                long entryOffset = entriesStart + ((long)i * DirectoryEntrySize);
                uint nameField = ReadUInt32(bytes, entryOffset);
                uint offsetField = ReadUInt32(bytes, entryOffset + 4L);

                bool nameIsString = (nameField & NameIsStringFlag) != 0;
                uint nameValue = nameField & ~NameIsStringFlag;
                bool isSubdirectory = (offsetField & OffsetIsSubdirectoryFlag) != 0;
                uint childOffset = offsetField & ~OffsetIsSubdirectoryFlag;

                string entryName = nameIsString ? ReadString(bytes, resourceBase, resourceLimit, nameValue) : null;
                ushort entryId = nameIsString ? (ushort)0 : (ushort)nameValue;

                if (isSubdirectory)
                {
                    if (depth >= MaxDepth)
                    {
                        throw new InvalidDataException("PE resource directory nesting exceeds the supported depth.");
                    }

                    long childDirectory = resourceBase + (long)childOffset;
                    if (childDirectory < resourceBase || childDirectory >= resourceLimit)
                    {
                        throw new InvalidDataException("A PE resource subdirectory offset points outside the image.");
                    }

                    ushort childTypeId = typeId;
                    string childTypeName = typeName;
                    string childName = name;
                    ushort childLanguage = language;

                    if (depth == 0)
                    {
                        childTypeId = entryId;
                        childTypeName = entryName;
                    }
                    else if (depth == 1)
                    {
                        childName = entryName ?? nameValue.ToString(CultureInfo.InvariantCulture);
                    }
                    else if (depth >= 2)
                    {
                        childLanguage = entryId;
                    }

                    WalkDirectory(bytes, headers, resourceBase, (int)childDirectory, resourceLimit, depth + 1, childTypeId, childTypeName, childName, childLanguage, resources, visitedDirectories, ref totalResourceData);
                }
                else
                {
                    if (depth == 0)
                    {
                        typeId = entryId;
                        typeName = entryName;
                    }
                    else if (depth == 1)
                    {
                        name = entryName ?? nameValue.ToString(CultureInfo.InvariantCulture);
                    }
                    else if (depth >= 2)
                    {
                        language = entryId;
                    }

                    long dataEntryOffset = resourceBase + (long)childOffset;
                    EnsureResourceRange(bytes, dataEntryOffset, DataEntrySize, resourceBase, resourceLimit);

                    uint dataRva = ReadUInt32(bytes, dataEntryOffset);
                    uint dataSize = ReadUInt32(bytes, dataEntryOffset + 4L);

                    totalResourceData += dataSize;
                    if (totalResourceData > MaxTotalResourceData)
                    {
                        throw new InvalidDataException("PE resource data exceeds the 128 MiB safety limit.");
                    }

                    byte[] data = ReadResourceBytes(bytes, headers, dataRva, dataSize);
                    resources.Add(new PeResourceEntry(typeId, typeName, name, language, data, dataRva, dataSize));
                }
            }
        }

        private static byte[] ReadResourceBytes(byte[] bytes, PEHeaders headers, uint dataRva, uint dataSize)
        {
            if (dataSize == 0)
            {
                return Array.Empty<byte>();
            }

            if (dataSize > (uint)bytes.Length)
            {
                throw new InvalidDataException("A PE resource declares a size larger than the image.");
            }

            int offset = RvaToOffset(headers, dataRva);
            if (offset < 0)
            {
                throw new InvalidDataException("A PE resource data RVA cannot be mapped to a file offset.");
            }

            EnsureRange(bytes, offset, dataSize);
            var result = new byte[dataSize];
            Array.Copy(bytes, offset, result, 0, (int)dataSize);
            return result;
        }

        private static int RvaToOffset(PEHeaders headers, uint rva)
        {
            if (headers == null)
            {
                return -1;
            }

            foreach (var section in headers.SectionHeaders)
            {
                long va = (uint)section.VirtualAddress;
                long rawSize = (uint)section.SizeOfRawData;
                long virtualSize = (uint)section.VirtualSize;
                long span = Math.Max(virtualSize, rawSize);
                if (rva >= va && rva < va + span)
                {
                    long delta = rva - va;
                    if (delta >= rawSize)
                    {
                        return -1;
                    }

                    long offset = (uint)section.PointerToRawData + delta;
                    return offset <= int.MaxValue ? (int)offset : -1;
                }
            }

            return -1;
        }

        private static string ReadString(byte[] bytes, int resourceBase, long resourceLimit, uint stringOffset)
        {
            long stringPosition = resourceBase + (long)stringOffset;
            EnsureResourceRange(bytes, stringPosition, 2, resourceBase, resourceLimit);
            int lengthInCharacters = ReadUInt16(bytes, stringPosition);
            long byteCount = (long)lengthInCharacters * 2;
            EnsureResourceRange(bytes, stringPosition + 2, byteCount, resourceBase, resourceLimit);
            return Encoding.Unicode.GetString(bytes, (int)stringPosition + 2, (int)byteCount);
        }

        private static void EnsureResourceRange(byte[] bytes, long offset, long size, int resourceBase, long resourceLimit)
        {
            EnsureRange(bytes, offset, size);
            if (offset < resourceBase || size > resourceLimit - offset)
            {
                throw new InvalidDataException("A PE resource directory structure points outside the declared resource directory.");
            }
        }

        private static ushort ReadUInt16(byte[] bytes, long offset)
        {
            EnsureRange(bytes, offset, 2);
            return BinaryPrimitives.ReadUInt16LittleEndian(new ReadOnlySpan<byte>(bytes, (int)offset, 2));
        }

        private static uint ReadUInt32(byte[] bytes, long offset)
        {
            EnsureRange(bytes, offset, 4);
            return BinaryPrimitives.ReadUInt32LittleEndian(new ReadOnlySpan<byte>(bytes, (int)offset, 4));
        }

        private static void EnsureRange(byte[] bytes, long offset, long size)
        {
            if (offset < 0 || size < 0 || offset > bytes.Length - size)
            {
                throw new InvalidDataException("A PE structure points outside the bounds of the image.");
            }
        }

        private static string ToHex(byte[] hash)
        {
            var builder = new StringBuilder(hash.Length * 2);
            foreach (byte value in hash)
            {
                builder.Append(value.ToString("x2", CultureInfo.InvariantCulture));
            }

            return builder.ToString();
        }
    }
}
