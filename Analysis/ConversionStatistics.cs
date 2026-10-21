namespace ETW2JSON.Analysis
{
    using System.Collections.Generic;
    using System.Globalization;
    using System.IO;
    using ETWDeserializer;

    /// <summary>Record-level interpretation outcomes from the conversion pass.</summary>
    internal sealed class ConversionStatistics
    {
        private readonly Dictionary<DecodeStatus, long> counts = new Dictionary<DecodeStatus, long>();

        public long Total { get; private set; }

        public void Observe(EventKey key, IEventTraceOperand operand)
        {
            var status = operand?.Metadata.DecodeStatus ?? DecodeStatus.MetadataMissing;
            this.counts.TryGetValue(status, out long count);
            this.counts[status] = count + 1;
            this.Total++;
        }

        public long Count(DecodeStatus status) => this.counts.TryGetValue(status, out long count) ? count : 0;

        public void WriteText(TextWriter writer)
        {
            writer.WriteLine(string.Format(CultureInfo.InvariantCulture,
                "Event decode outcomes: total={0}; decoded={1}; metadata_missing={2}; unsupported={3}; partial={4}; decode_error={5}",
                this.Total, this.Count(DecodeStatus.Decoded), this.Count(DecodeStatus.MetadataMissing),
                this.Count(DecodeStatus.Unsupported), this.Count(DecodeStatus.Partial), this.Count(DecodeStatus.DecodeError)));
        }
    }
}
