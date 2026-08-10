using System.Globalization;
using System.IO;
using System.Text;
using System.Text.Json;
using BinaryHunter.Core.Projects;

namespace BinaryHunter.UI;

public sealed record BinaryDifferenceRow(
    int Number, long Offset, byte? ReferenceValue, byte? CurrentValue, int? Delta,
    string Scope, string MapName)
{
    public string HexOffset => $"0x{Offset:X8}";
    public string ReferenceHex => ReferenceValue is byte value ? value.ToString("X2") : "--";
    public string CurrentHex => CurrentValue is byte value ? value.ToString("X2") : "--";
    public string DeltaText => Delta is int value ? value.ToString("+0;-0;0", CultureInfo.InvariantCulture) : "--";
    public string PercentText => ReferenceValue is > 0 && CurrentValue is byte current
        ? $"{(current - ReferenceValue.Value) * 100d / ReferenceValue.Value:+0.##;-0.##;0}%"
        : "--";
}

public sealed record MapDifferenceRow(
    string Name, string Category, long Offset, int Size, long ChangedBytes)
{
    public string HexOffset => $"0x{Offset:X8}";
    public string ChangedPercent => Size == 0 ? "0%" : $"{ChangedBytes * 100d / Size:0.##}%";
}

public sealed record BinaryDifferenceReport(
    IReadOnlyList<BinaryDifferenceRow> Rows,
    IReadOnlyList<MapDifferenceRow> Maps,
    long TotalChangedBytes, long CurrentOnlyBytes, long ReferenceOnlyBytes,
    int ChangedBlocks, bool IsTruncated);

internal static class BinaryDifferenceService
{
    public static BinaryDifferenceReport Analyze(
        byte[] current, byte[] reference, IReadOnlyList<EcuProjectMapDefinition> maps,
        IReadOnlyList<ChecksumBlockDefinition> checksums, long fromOffset = 0, int maximumRows = 5000)
    {
        fromOffset = Math.Max(0, fromOffset);
        maximumRows = Math.Clamp(maximumRows, 100, 100_000);
        var rows = new List<BinaryDifferenceRow>(Math.Min(maximumRows, 20_000));
        var mapCounts = new Dictionary<string, long>(StringComparer.OrdinalIgnoreCase);
        var mapRanges = maps.OrderBy(map => map.StartOffset)
            .Select(map => (Map: map, End: map.StartOffset + MapSize(map))).ToArray();
        var checksumRanges = checksums.SelectMany(block => new[]
        {
            (Start: block.RangeStart, End: block.RangeStart + block.RangeLength),
            (Start: block.StoreOffset, End: block.StoreOffset + block.StoredByteCount)
        }).OrderBy(range => range.Start).ToArray();
        var limit = Math.Max(current.LongLength, reference.LongLength);
        long changed = 0;
        long currentOnly = 0;
        long referenceOnly = 0;
        var blocks = 0;
        var insideBlock = false;

        for (long offset = fromOffset; offset < limit; offset++)
        {
            byte? currentValue = offset < current.LongLength ? current[(int)offset] : null;
            byte? referenceValue = offset < reference.LongLength ? reference[(int)offset] : null;
            var different = currentValue != referenceValue;
            if (!different)
            {
                insideBlock = false;
                continue;
            }

            changed++;
            if (!insideBlock) blocks++;
            insideBlock = true;
            if (currentValue is null) referenceOnly++;
            else if (referenceValue is null) currentOnly++;

            var map = FindMap(mapRanges, offset);
            if (map is not null)
                mapCounts[map.Id] = mapCounts.GetValueOrDefault(map.Id) + 1;
            var scope = map is not null ? "Map" : Contains(checksumRanges, offset) ? "Checksum" : "Binary";
            if (rows.Count < maximumRows)
                rows.Add(new BinaryDifferenceRow(rows.Count + 1, offset, referenceValue, currentValue,
                    referenceValue is byte oldValue && currentValue is byte newValue ? newValue - oldValue : null,
                    scope, map?.Name ?? string.Empty));
        }

        var mapRows = maps
            .Select(map => new { Map = map, Size = MapSize(map), Count = mapCounts.GetValueOrDefault(map.Id) })
            .Where(item => item.Count > 0)
            .OrderByDescending(item => item.Count)
            .ThenBy(item => item.Map.StartOffset)
            .Select(item => new MapDifferenceRow(item.Map.Name, item.Map.Category, item.Map.StartOffset,
                item.Size, item.Count))
            .ToList();
        return new BinaryDifferenceReport(rows, mapRows, changed, currentOnly, referenceOnly,
            blocks, changed > rows.Count);
    }

    public static IReadOnlyList<int> BuildDifferenceBlockIndex(byte[] current, byte[] reference, out long changedBytes)
    {
        var starts = new List<int>();
        var shared = Math.Min(current.Length, reference.Length);
        var inside = false;
        long count = 0;
        for (var offset = 0; offset < shared; offset++)
        {
            var different = current[offset] != reference[offset];
            if (different)
            {
                count++;
                if (!inside) starts.Add(offset);
            }
            inside = different;
        }
        if (current.Length > shared)
        {
            if (!inside) starts.Add(shared);
            count += current.Length - shared;
        }
        count += Math.Max(0, reference.Length - current.Length);
        changedBytes = count;
        return starts;
    }

    public static void ExportReport(string path, BinaryDifferenceReport report)
    {
        switch (Path.GetExtension(path).ToLowerInvariant())
        {
            case ".json":
                File.WriteAllText(path, JsonSerializer.Serialize(report, new JsonSerializerOptions { WriteIndented = true }));
                break;
            case ".txt":
                using (var writer = new StreamWriter(path, false, Encoding.UTF8))
                {
                    writer.WriteLine($"Changed bytes: {report.TotalChangedBytes:N0}");
                    writer.WriteLine($"Changed blocks: {report.ChangedBlocks:N0}");
                    writer.WriteLine($"Changed maps: {report.Maps.Count:N0}");
                    writer.WriteLine();
                    foreach (var row in report.Rows)
                        writer.WriteLine($"{row.HexOffset}\t{row.ReferenceHex}\t{row.CurrentHex}\t{row.DeltaText}\t{row.PercentText}\t{row.Scope}\t{row.MapName}");
                }
                break;
            default:
                using (var writer = new StreamWriter(path, false, new UTF8Encoding(true)))
                {
                    writer.WriteLine("Number,Offset,Reference,Current,Delta,Percent,Scope,Map");
                    foreach (var row in report.Rows)
                        writer.WriteLine(string.Join(',', row.Number, Csv(row.HexOffset), row.ReferenceHex,
                            row.CurrentHex, row.DeltaText, row.PercentText, Csv(row.Scope), Csv(row.MapName)));
                }
                break;
        }
    }

    public static void ExportMaps(string path, IEnumerable<EcuProjectMapDefinition> maps)
    {
        var list = maps.OrderBy(map => map.StartOffset).ToList();
        if (Path.GetExtension(path).Equals(".json", StringComparison.OrdinalIgnoreCase))
        {
            File.WriteAllText(path, JsonSerializer.Serialize(list, new JsonSerializerOptions { WriteIndented = true }));
            return;
        }
        using var writer = new StreamWriter(path, false, new UTF8Encoding(true));
        writer.WriteLine("Address,Size,Width,Height,Name,Category,Type,Endian,Factor,Offset,Unit,Comment");
        foreach (var map in list)
            writer.WriteLine(string.Join(',', Csv($"0x{map.StartOffset:X8}"), MapSize(map), map.Width, map.Height,
                Csv(map.Name), Csv(map.Category), map.ValueType, map.LittleEndian ? "Intel" : "Motorola",
                map.Factor.ToString("G17", CultureInfo.InvariantCulture),
                map.Offset.ToString("G17", CultureInfo.InvariantCulture), Csv(map.Unit), Csv(map.Comment)));
    }

    private static EcuProjectMapDefinition? FindMap((EcuProjectMapDefinition Map, long End)[] ranges, long offset)
    {
        var low = 0; var high = ranges.Length - 1; var candidate = -1;
        while (low <= high)
        {
            var middle = low + (high - low) / 2;
            if (ranges[middle].Map.StartOffset <= offset) { candidate = middle; low = middle + 1; }
            else high = middle - 1;
        }
        for (var index = candidate; index >= 0 && ranges[index].Map.StartOffset <= offset; index--)
        {
            if (offset < ranges[index].End) return ranges[index].Map;
            if (candidate - index > 16) break;
        }
        return null;
    }

    private static bool Contains((long Start, long End)[] ranges, long offset)
    {
        var low = 0; var high = ranges.Length - 1;
        while (low <= high)
        {
            var middle = low + (high - low) / 2;
            var range = ranges[middle];
            if (offset < range.Start) high = middle - 1;
            else if (offset >= range.End) low = middle + 1;
            else return true;
        }
        return false;
    }

    private static int MapSize(EcuProjectMapDefinition map)
    {
        var valueSize = map.ValueType is EcuMapValueType.Unsigned8 or EcuMapValueType.Signed8 ? 1 :
            map.ValueType is EcuMapValueType.Unsigned24 or EcuMapValueType.Signed24 ? 3 :
            map.ValueType is EcuMapValueType.Unsigned32 or EcuMapValueType.Signed32 or EcuMapValueType.Float32 ? 4 : 2;
        return Math.Max(0, map.Width) * Math.Max(0, map.Height) * valueSize;
    }

    private static string Csv(string value) => $"\"{value.Replace("\"", "\"\"")}\"";
}
