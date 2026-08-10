using BinaryHunter.Core.Projects;

namespace BinaryHunter.UI;

internal static class EcuMapTools
{
    public static int ValueSize(EcuMapValueType type) => type switch
    {
        EcuMapValueType.Unsigned8 or EcuMapValueType.Signed8 => 1,
        EcuMapValueType.Unsigned16 or EcuMapValueType.Signed16 => 2,
        EcuMapValueType.Unsigned24 or EcuMapValueType.Signed24 => 3,
        _ => 4
    };

    public static bool IsSigned(EcuMapValueType type) => type is
        EcuMapValueType.Signed8 or EcuMapValueType.Signed16 or
        EcuMapValueType.Signed24 or EcuMapValueType.Signed32;

    public static double Decode(byte[] bytes, long offset, EcuMapValueType type, bool littleEndian)
    {
        var size = ValueSize(type);
        if (offset < 0 || offset + size > bytes.LongLength) throw new ArgumentOutOfRangeException(nameof(offset));
        ulong raw = 0;
        for (var index = 0; index < size; index++)
        {
            var source = littleEndian ? offset + index : offset + size - index - 1;
            raw |= (ulong)bytes[(int)source] << (index * 8);
        }
        if (type == EcuMapValueType.Float32)
            return BitConverter.Int32BitsToSingle(unchecked((int)raw));
        if (!IsSigned(type)) return raw;
        var bits = size * 8;
        var mask = (1UL << bits) - 1;
        var sign = 1UL << (bits - 1);
        return (raw & sign) == 0 ? (long)raw : unchecked((long)(raw | ~mask));
    }

    public static byte[] Encode(double value, EcuMapValueType type, bool littleEndian)
    {
        var size = ValueSize(type);
        ulong raw;
        if (type == EcuMapValueType.Float32)
        {
            if (!double.IsFinite(value) || value < -float.MaxValue || value > float.MaxValue)
                throw new OverflowException("Value is outside the Float32 range.");
            raw = unchecked((uint)BitConverter.SingleToInt32Bits((float)value));
        }
        else if (IsSigned(type))
        {
            var bits = size * 8;
            var minimum = -(1L << (bits - 1));
            var maximum = (1L << (bits - 1)) - 1;
            var signed = checked((long)Math.Round(value, MidpointRounding.AwayFromZero));
            if (signed < minimum || signed > maximum)
                throw new OverflowException($"Value is outside the signed {bits}-bit range.");
            raw = unchecked((ulong)signed) & ((1UL << bits) - 1);
        }
        else
        {
            var bits = size * 8;
            var maximum = (1UL << bits) - 1;
            if (!double.IsFinite(value) || value < 0 || value > maximum)
                throw new OverflowException($"Value is outside the unsigned {bits}-bit range.");
            raw = checked((ulong)Math.Round(value, MidpointRounding.AwayFromZero));
        }
        var result = new byte[size];
        for (var index = 0; index < size; index++)
        {
            var destination = littleEndian ? index : size - index - 1;
            result[destination] = (byte)(raw >> (index * 8));
        }
        return result;
    }

    public static EcuProjectMapDefinition Clone(EcuProjectMapDefinition map) => new()
    {
        Id = map.Id, Name = map.Name, Category = map.Category, StartOffset = map.StartOffset,
        Width = map.Width, Height = map.Height, ValueType = map.ValueType,
        LittleEndian = map.LittleEndian, Factor = map.Factor, Offset = map.Offset,
        Unit = map.Unit, Comment = map.Comment, XAxis = Clone(map.XAxis), YAxis = Clone(map.YAxis)
    };

    public static EcuProjectAxisDefinition Clone(EcuProjectAxisDefinition axis) => new()
    {
        Name = axis.Name, Offset = axis.Offset, Count = axis.Count, ValueType = axis.ValueType,
        LittleEndian = axis.LittleEndian, Factor = axis.Factor, ValueOffset = axis.ValueOffset,
        Unit = axis.Unit, Confidence = axis.Confidence
    };
}

internal static class AxisCandidateFinder
{
    public static (EcuProjectAxisDefinition? X, EcuProjectAxisDefinition? Y) Find(
        byte[] bytes, EcuProjectMapDefinition map)
    {
        var x = FindBest(bytes, map.StartOffset, map.Width, map.ValueType, map.LittleEndian);
        var ySearchEnd = x?.Offset ?? map.StartOffset;
        var y = FindBest(bytes, ySearchEnd, map.Height, map.ValueType, map.LittleEndian);
        if (x is not null) x.Name = "X axis";
        if (y is not null) y.Name = "Y axis";
        return (x, y);
    }

    private static EcuProjectAxisDefinition? FindBest(byte[] bytes, long beforeOffset, int count,
        EcuMapValueType type, bool littleEndian)
    {
        count = Math.Clamp(count, 2, 256);
        var size = EcuMapTools.ValueSize(type);
        var byteLength = count * size;
        var last = Math.Min(beforeOffset - byteLength, bytes.LongLength - byteLength);
        if (last < 0) return null;
        var first = Math.Max(0, beforeOffset - 16384);
        EcuProjectAxisDefinition? best = null;
        var bestScore = 0d;

        for (var candidate = first; candidate <= last; candidate++)
        {
            var values = new double[count];
            var valid = true;
            for (var index = 0; index < count; index++)
            {
                values[index] = EcuMapTools.Decode(bytes, candidate + index * size, type, littleEndian);
                if (!double.IsFinite(values[index]) || Math.Abs(values[index]) > 1e12)
                {
                    valid = false;
                    break;
                }
            }
            if (!valid) continue;
            var score = Score(values, beforeOffset - (candidate + byteLength));
            if (score <= bestScore) continue;
            bestScore = score;
            best = new EcuProjectAxisDefinition
            {
                Offset = candidate, Count = count, ValueType = type, LittleEndian = littleEndian,
                Factor = 1, Confidence = Math.Min(0.99, score / 100d)
            };
        }
        return bestScore >= 62 ? best : null;
    }

    private static double Score(IReadOnlyList<double> values, long distance)
    {
        var nonZeroDiffs = new List<double>();
        var increasing = 0;
        var decreasing = 0;
        for (var index = 1; index < values.Count; index++)
        {
            var difference = values[index] - values[index - 1];
            if (difference > 0) increasing++;
            else if (difference < 0) decreasing++;
            if (difference != 0) nonZeroDiffs.Add(Math.Abs(difference));
        }
        if (nonZeroDiffs.Count < Math.Max(1, values.Count / 2)) return 0;
        var monotonic = Math.Max(increasing, decreasing) / (double)(values.Count - 1);
        if (monotonic < 0.8) return 0;
        var distinctRatio = values.Distinct().Count() / (double)values.Count;
        var averageStep = nonZeroDiffs.Average();
        var deviation = nonZeroDiffs.Average(step => Math.Abs(step - averageStep));
        var consistency = averageStep == 0 ? 0 : Math.Max(0, 1 - deviation / averageStep);
        var distancePenalty = Math.Min(18, distance / 512d);
        return monotonic * 58 + distinctRatio * 22 + consistency * 20 - distancePenalty;
    }
}
