namespace ETWDeserializer
{
    using System;
    using System.Collections.Generic;

    /// <summary>Compares the schema fields that control payload traversal and output.</summary>
    internal static class SchemaEquivalence
    {
        public static bool AreEquivalent(IEventTraceOperand left, IEventTraceOperand right)
        {
            if (ReferenceEquals(left, right)) return true;
            if (left == null || right == null) return false;

            var a = left.Metadata;
            var b = right.Metadata;
            if (a.ProviderGuid != b.ProviderGuid || a.Id != b.Id || a.Version != b.Version
                || !string.Equals(a.Name, b.Name, StringComparison.Ordinal)
                || !string.Equals(a.ProviderName, b.ProviderName, StringComparison.Ordinal)
                || a.ResolutionStatus != b.ResolutionStatus || a.DecodeStatus != b.DecodeStatus
                || a.Properties.Length != b.Properties.Length) return false;

            for (int i = 0; i < a.Properties.Length; i++)
            {
                if (!EquivalentMetadata(a.Properties[i], b.Properties[i])) return false;
            }

            // Names and primitive types alone do not describe an event layout.
            // Array counts, byte lengths and their reference targets also decide
            // which payload bytes are interpreted as each property.
            return EquivalentProperties(left.EventPropertyOperands, right.EventPropertyOperands);
        }

        private static bool EquivalentProperties(IEnumerable<IEventTracePropertyOperand> left, IEnumerable<IEventTracePropertyOperand> right)
        {
            using var leftItems = left.GetEnumerator();
            using var rightItems = right.GetEnumerator();
            while (true)
            {
                bool hasLeft = leftItems.MoveNext();
                bool hasRight = rightItems.MoveNext();
                if (hasLeft != hasRight) return false;
                if (!hasLeft) return true;

                var a = leftItems.Current;
                var b = rightItems.Current;
                if (!EquivalentMetadata(a.Metadata, b.Metadata)
                    || a.PropertyIndex != b.PropertyIndex
                    || a.IsVariableArray != b.IsVariableArray || a.IsFixedArray != b.IsFixedArray
                    || a.FixedArraySize != b.FixedArraySize
                    || !EquivalentReference(a.VariableArraySize, b.VariableArraySize)
                    || a.IsVariableLength != b.IsVariableLength || a.IsFixedLength != b.IsFixedLength
                    || a.FixedLengthSize != b.FixedLengthSize
                    || !EquivalentReference(a.VariableLengthSize, b.VariableLengthSize)
                    || a.IsWbemXMLFragment != b.IsWbemXMLFragment
                    || a.IsReferencedByOtherProperties != b.IsReferencedByOtherProperties
                    || !EquivalentProperties(a.Children, b.Children)) return false;
            }
        }

        private static bool EquivalentReference(IEventTracePropertyOperand left, IEventTracePropertyOperand right)
        {
            if (left == null || right == null) return left == right;
            return left.PropertyIndex == right.PropertyIndex && EquivalentMetadata(left.Metadata, right.Metadata);
        }

        private static bool EquivalentMetadata(PropertyMetadata left, PropertyMetadata right)
        {
            return string.Equals(left.Name, right.Name, StringComparison.Ordinal)
                && left.InType == right.InType && left.OutType == right.OutType
                && left.IsMapValue == right.IsMapValue && left.IsStruct == right.IsStruct
                && left.ChildrenCount == right.ChildrenCount
                // Event maps are currently unsupported. Distinct map objects must
                // not be assumed equivalent if a caller supplies one.
                && ReferenceEquals(left.Map, right.Map);
        }
    }
}
