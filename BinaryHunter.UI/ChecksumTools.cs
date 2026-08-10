using BinaryHunter.Core.Plugins;

namespace BinaryHunter.UI;

public enum BinaryChecksumAlgorithm { Additive8, Additive16, Additive32, Xor8, Crc16Ccitt, Crc32 }

public sealed class ChecksumBlockDefinition
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string Name { get; set; } = "Manual checksum";
    public long RangeStart { get; set; }
    public long RangeLength { get; set; }
    public long StoreOffset { get; set; }
    public int StoredByteCount { get; set; } = 2;
    public bool LittleEndian { get; set; } = true;
    public BinaryChecksumAlgorithm Algorithm { get; set; } = BinaryChecksumAlgorithm.Additive16;
    public bool AutomaticCorrection { get; set; }
    public string PluginId { get; set; } = string.Empty;
    public string Description { get; set; } = string.Empty;
}

internal static class ChecksumTools
{
    public static byte[] Calculate(byte[] bytes, ChecksumBlockDefinition definition)
    {
        Validate(bytes, definition);
        if (!string.IsNullOrWhiteSpace(definition.PluginId))
        {
            var plugin = PluginCatalog.ChecksumPlugins().FirstOrDefault(item => item.Id == definition.PluginId)
                ?? throw new InvalidOperationException($"Checksum plugin '{definition.PluginId}' is not loaded.");
            var candidate = new ChecksumPluginCandidate(definition.Name, definition.RangeStart,
                definition.RangeLength, definition.StoreOffset, definition.StoredByteCount,
                definition.LittleEndian, definition.Description);
            return Normalize(plugin.Calculate(bytes, candidate), definition.StoredByteCount, definition.LittleEndian);
        }

        var data = new byte[checked((int)definition.RangeLength)];
        Buffer.BlockCopy(bytes, checked((int)definition.RangeStart), data, 0, data.Length);
        for (var index = 0; index < definition.StoredByteCount; index++)
        {
            var absolute = definition.StoreOffset + index;
            if (absolute >= definition.RangeStart && absolute < definition.RangeStart + definition.RangeLength)
                data[checked((int)(absolute - definition.RangeStart))] = 0;
        }
        ulong value = definition.Algorithm switch
        {
            BinaryChecksumAlgorithm.Additive8 => data.Aggregate(0UL, (sum, item) => (sum + item) & 0xFF),
            BinaryChecksumAlgorithm.Additive16 => AddWords(data, 2, definition.LittleEndian) & 0xFFFF,
            BinaryChecksumAlgorithm.Additive32 => AddWords(data, 4, definition.LittleEndian) & 0xFFFFFFFF,
            BinaryChecksumAlgorithm.Xor8 => data.Aggregate(0UL, (sum, item) => sum ^ item),
            BinaryChecksumAlgorithm.Crc16Ccitt => Crc16(data),
            BinaryChecksumAlgorithm.Crc32 => Crc32(data),
            _ => 0
        };
        var result = new byte[definition.StoredByteCount];
        for (var index = 0; index < result.Length; index++)
        {
            var destination = definition.LittleEndian ? index : result.Length - index - 1;
            result[destination] = (byte)(value >> (index * 8));
        }
        return result;
    }

    public static string Status(byte[] bytes, ChecksumBlockDefinition definition)
    {
        try
        {
            var expected = Calculate(bytes, definition);
            var actual = bytes.AsSpan(checked((int)definition.StoreOffset), definition.StoredByteCount);
            return actual.SequenceEqual(expected) ? "Valid" : $"Mismatch · expected {Convert.ToHexString(expected)}";
        }
        catch (Exception exception) { return "Invalid · " + exception.Message; }
    }

    public static void Apply(byte[] bytes, ChecksumBlockDefinition definition)
    {
        var result = Calculate(bytes, definition);
        Buffer.BlockCopy(result, 0, bytes, checked((int)definition.StoreOffset), result.Length);
    }

    private static void Validate(byte[] bytes, ChecksumBlockDefinition definition)
    {
        if (definition.RangeStart < 0 || definition.RangeLength <= 0 ||
            definition.RangeStart + definition.RangeLength > bytes.LongLength)
            throw new ArgumentOutOfRangeException(nameof(definition), "Checksum range is outside the file.");
        if (definition.RangeLength > int.MaxValue) throw new InvalidOperationException("Checksum range is too large.");
        if (definition.StoreOffset < 0 || definition.StoredByteCount is < 1 or > 8 ||
            definition.StoreOffset + definition.StoredByteCount > bytes.LongLength)
            throw new ArgumentOutOfRangeException(nameof(definition), "Checksum storage is outside the file.");
    }

    private static ulong AddWords(byte[] data, int width, bool littleEndian)
    {
        ulong sum = 0;
        for (var offset = 0; offset < data.Length; offset += width)
        {
            ulong word = 0; var count = Math.Min(width, data.Length - offset);
            for (var index = 0; index < count; index++)
                word |= (ulong)data[offset + (littleEndian ? index : count - index - 1)] << (index * 8);
            sum += word;
        }
        return sum;
    }
    private static ushort Crc16(ReadOnlySpan<byte> data)
    {
        ushort crc = 0xFFFF;
        foreach (var item in data) { crc ^= (ushort)(item << 8); for (var bit = 0; bit < 8; bit++) crc = (ushort)((crc & 0x8000) != 0 ? crc << 1 ^ 0x1021 : crc << 1); }
        return crc;
    }
    private static uint Crc32(ReadOnlySpan<byte> data)
    {
        var crc = 0xFFFFFFFFu;
        foreach (var item in data) { crc ^= item; for (var bit = 0; bit < 8; bit++) crc = (crc & 1) != 0 ? crc >> 1 ^ 0xEDB88320u : crc >> 1; }
        return ~crc;
    }
    private static byte[] Normalize(byte[] value, int count, bool littleEndian)
    {
        if (value.Length == count) return value;
        var result = new byte[count]; Array.Copy(value, 0, result, 0, Math.Min(value.Length, count));
        if (!littleEndian) Array.Reverse(result); return result;
    }
}
