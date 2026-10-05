namespace ETW2JSON.IO
{
    using System.IO;

    /// <summary>Creates a new output file without replacing or truncating an existing path.</summary>
    internal static class OutputFile
    {
        public static FileStream OpenNew(string path)
        {
            return new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.Read);
        }
    }
}
