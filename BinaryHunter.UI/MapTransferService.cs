using BinaryHunter.Core.Projects;

namespace BinaryHunter.UI;

public enum MapTransferMode { DefinitionsOnly, AbsoluteValues, RelativeChanges }

public sealed record MapTransferCandidate(
    EcuProjectMapDefinition SourceMap, long TargetOffset, EcuProjectMapDefinition? TargetMap,
    double Confidence, string MatchMethod, bool SourceChanged, int ByteLength)
{
    public string SourceAddress => $"0x{SourceMap.StartOffset:X8}";
    public string TargetAddress => TargetOffset < 0 ? "not found" : $"0x{TargetOffset:X8}";
    public string Dimensions => $"{SourceMap.Width} × {SourceMap.Height}";
    public string ConfidenceText => $"{Confidence:P0}";
    public bool IsValid => TargetOffset >= 0;
}

internal static class MapTransferService
{
    public static IReadOnlyList<MapTransferCandidate> Discover(
        byte[] source, byte[]? sourceOriginal, IReadOnlyList<EcuProjectMapDefinition> sourceMaps,
        byte[] target, IReadOnlyList<EcuProjectMapDefinition> targetMaps, double tolerancePercent)
    {
        var result = new List<MapTransferCandidate>();
        tolerancePercent = Math.Clamp(tolerancePercent, 0, 40);
        foreach (var sourceMap in sourceMaps)
        {
            var length = ByteLength(sourceMap);
            if (length <= 0 || sourceMap.StartOffset < 0 || sourceMap.StartOffset + length > source.LongLength)
                continue;
            var changed = IsChanged(source, sourceOriginal, sourceMap.StartOffset, length);
            var targetMap = FindDefinitionMatch(sourceMap, targetMaps);
            long targetOffset;
            double confidence;
            string method;
            if (targetMap is not null && targetMap.StartOffset >= 0 && targetMap.StartOffset + length <= target.LongLength)
            {
                targetOffset = targetMap.StartOffset;
                var sameId = string.Equals(sourceMap.Id, targetMap.Id, StringComparison.OrdinalIgnoreCase);
                confidence = sameId ? 1 : 0.96;
                method = sameId ? "Map ID" : "Name + dimensions";
            }
            else
            {
                var slice = source.AsSpan((int)sourceMap.StartOffset, length);
                var exact = target.AsSpan().IndexOf(slice);
                if (exact >= 0)
                {
                    targetOffset = exact; confidence = 0.99; method = "Exact content";
                }
                else
                {
                    var fuzzy = FindFuzzy(target, slice, tolerancePercent);
                    targetOffset = fuzzy.Offset;
                    confidence = fuzzy.Score;
                    method = fuzzy.Offset >= 0 ? "Content signature" : "No reliable match";
                }
            }
            result.Add(new MapTransferCandidate(EcuMapTools.Clone(sourceMap), targetOffset,
                targetMap is null ? null : EcuMapTools.Clone(targetMap), confidence, method, changed, length));
        }
        return result.OrderByDescending(item => item.SourceChanged).ThenByDescending(item => item.Confidence)
            .ThenBy(item => item.SourceMap.StartOffset).ToList();
    }

    public static byte[] Apply(byte[] target, byte[] source, byte[]? sourceOriginal,
        IEnumerable<MapTransferCandidate> candidates, MapTransferMode mode,
        IReadOnlyList<ChecksumBlockDefinition> checksumBlocks, bool skipChecksumRanges)
    {
        var result = target.ToArray();
        foreach (var candidate in candidates.Where(item => item.IsValid))
        {
            var sourceOffset = checked((int)candidate.SourceMap.StartOffset);
            var targetOffset = checked((int)candidate.TargetOffset);
            var length = Math.Min(candidate.ByteLength,
                Math.Min(source.Length - sourceOffset, result.Length - targetOffset));
            if (length <= 0 || mode == MapTransferMode.DefinitionsOnly) continue;
            if (mode == MapTransferMode.AbsoluteValues)
            {
                for (var index = 0; index < length; index++)
                {
                    var destination = targetOffset + index;
                    if (!skipChecksumRanges || !IsChecksumAddress(destination, checksumBlocks))
                        result[destination] = source[sourceOffset + index];
                }
                continue;
            }
            if (sourceOriginal is null || sourceOffset + length > sourceOriginal.Length) continue;
            ApplyRelative(result, targetOffset, source, sourceOriginal, sourceOffset, length,
                candidate.SourceMap, checksumBlocks, skipChecksumRanges);
        }
        return result;
    }

    public static EcuProjectMapDefinition RelocateDefinition(MapTransferCandidate candidate)
    {
        var map = EcuMapTools.Clone(candidate.SourceMap);
        var delta = candidate.TargetOffset - candidate.SourceMap.StartOffset;
        map.Id = candidate.TargetMap?.Id ?? Guid.NewGuid().ToString("N");
        map.StartOffset = candidate.TargetOffset;
        if (map.XAxis.Offset >= 0) map.XAxis.Offset += delta;
        if (map.YAxis.Offset >= 0) map.YAxis.Offset += delta;
        map.Comment = string.IsNullOrWhiteSpace(map.Comment)
            ? $"Imported by map relocation ({candidate.MatchMethod}, {candidate.Confidence:P0})."
            : map.Comment + $" Imported by map relocation ({candidate.MatchMethod}, {candidate.Confidence:P0}).";
        return map;
    }

    private static void ApplyRelative(byte[] target, int targetOffset, byte[] source, byte[] original,
        int sourceOffset, int length, EcuProjectMapDefinition map,
        IReadOnlyList<ChecksumBlockDefinition> checksumBlocks, bool skipChecksumRanges)
    {
        var valueSize = EcuMapTools.ValueSize(map.ValueType);
        var values = length / valueSize;
        for (var index = 0; index < values; index++)
        {
            var sourceValueOffset = sourceOffset + index * valueSize;
            var targetValueOffset = targetOffset + index * valueSize;
            if (skipChecksumRanges && Enumerable.Range(0, valueSize)
                    .Any(part => IsChecksumAddress(targetValueOffset + part, checksumBlocks))) continue;
            try
            {
                var current = EcuMapTools.Decode(source, sourceValueOffset, map.ValueType, map.LittleEndian);
                var baseline = EcuMapTools.Decode(original, sourceValueOffset, map.ValueType, map.LittleEndian);
                var targetValue = EcuMapTools.Decode(target, targetValueOffset, map.ValueType, map.LittleEndian);
                var encoded = EcuMapTools.Encode(targetValue + current - baseline, map.ValueType, map.LittleEndian);
                encoded.CopyTo(target, targetValueOffset);
            }
            catch (OverflowException)
            {
                // Preserve the target value when the relative change exceeds its data type.
            }
        }
    }

    private static EcuProjectMapDefinition? FindDefinitionMatch(EcuProjectMapDefinition source,
        IReadOnlyList<EcuProjectMapDefinition> targets)
    {
        var byId = targets.FirstOrDefault(target => !string.IsNullOrWhiteSpace(source.Id) &&
            string.Equals(source.Id, target.Id, StringComparison.OrdinalIgnoreCase));
        if (byId is not null) return byId;
        return targets.FirstOrDefault(target =>
            string.Equals(source.Name, target.Name, StringComparison.OrdinalIgnoreCase) &&
            source.Width == target.Width && source.Height == target.Height &&
            source.ValueType == target.ValueType);
    }

    private static bool IsChanged(byte[] source, byte[]? original, long offset, int length)
    {
        if (original is null || offset < 0 || offset + length > original.LongLength) return true;
        return !source.AsSpan((int)offset, length).SequenceEqual(original.AsSpan((int)offset, length));
    }

    private static (long Offset, double Score) FindFuzzy(byte[] target, ReadOnlySpan<byte> source, double tolerancePercent)
    {
        if (source.Length < 8 || target.Length < source.Length) return (-1, 0);
        var sourceBytes = source.ToArray();
        var anchors = new[] { 0, sourceBytes.Length / 3, sourceBytes.Length * 2 / 3, sourceBytes.Length - 8 }
            .Select(value => Math.Clamp(value, 0, sourceBytes.Length - 8)).Distinct()
            .OrderByDescending(offset => AnchorDiversity(sourceBytes, offset)).ToList();
        var required = 1 - tolerancePercent / 100d;
        long bestOffset = -1; var bestScore = 0d; var examined = 0;
        foreach (var anchorOffset in anchors)
        {
            var anchor = sourceBytes.AsSpan(anchorOffset, 8);
            var searchStart = 0;
            while (searchStart <= target.Length - anchor.Length && examined < 4096)
            {
                var found = target.AsSpan(searchStart).IndexOf(anchor);
                if (found < 0) break;
                found += searchStart;
                var candidate = found - anchorOffset;
                searchStart = found + 1;
                if (candidate < 0 || candidate + sourceBytes.Length > target.Length) continue;
                examined++;
                var score = Similarity(sourceBytes, target.AsSpan(candidate, sourceBytes.Length));
                if (score > bestScore) { bestScore = score; bestOffset = candidate; }
                if (score >= 0.999) return (candidate, score);
            }
        }
        return bestScore >= required ? (bestOffset, bestScore) : (-1, bestScore);
    }

    private static int AnchorDiversity(byte[] bytes, int offset)
    {
        Span<bool> seen = stackalloc bool[256];
        var count = 0;
        for (var index = offset; index < offset + 8; index++)
        {
            if (seen[bytes[index]]) continue;
            seen[bytes[index]] = true;
            count++;
        }
        return count;
    }

    private static double Similarity(ReadOnlySpan<byte> left, ReadOnlySpan<byte> right)
    {
        var step = Math.Max(1, left.Length / 4096);
        var equal = 0; var count = 0;
        for (var index = 0; index < left.Length; index += step)
        {
            if (left[index] == right[index]) equal++;
            count++;
        }
        return count == 0 ? 0 : equal / (double)count;
    }

    private static bool IsChecksumAddress(long address, IEnumerable<ChecksumBlockDefinition> blocks) =>
        blocks.Any(block => address >= block.StoreOffset && address < block.StoreOffset + block.StoredByteCount);

    private static int ByteLength(EcuProjectMapDefinition map)
    {
        var length = (long)Math.Max(0, map.Width) * Math.Max(0, map.Height) * EcuMapTools.ValueSize(map.ValueType);
        return length is > 0 and <= int.MaxValue ? (int)length : 0;
    }
}
