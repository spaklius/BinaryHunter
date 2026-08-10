using BinaryHunter.Core.Projects;
using System.Text;

namespace BinaryHunter.UI;

public sealed record AutomaticMapScanProgress(double Percent, string Stage, int AxisCandidates, int MapCandidates);

public sealed record AutomaticMapCandidate(EcuProjectMapDefinition Map, double Confidence, string Evidence);

internal static class AutomaticMapDiscoveryService
{
    private sealed record AxisSeed(long Offset, int Count, bool LittleEndian, double Confidence);
    private sealed record SurfaceScore(double Confidence, double Smoothness, double Plateau,
        double HorizontalDirection, double VerticalDirection, double DynamicRange);

    private static readonly int[] CommonDimensions = [8, 10, 12, 16, 20, 24, 32];

    public static Task<IReadOnlyList<AutomaticMapCandidate>> ScanAsync(byte[] bytes,
        IProgress<AutomaticMapScanProgress>? progress, CancellationToken cancellationToken) =>
        Task.Run(() => Scan(bytes, progress, cancellationToken), cancellationToken);

    private static IReadOnlyList<AutomaticMapCandidate> Scan(byte[] bytes,
        IProgress<AutomaticMapScanProgress>? progress, CancellationToken cancellationToken)
    {
        if (bytes.Length < 128) return [];
        var ranges = GetScanRanges(bytes.Length);
        var axes = new List<AxisSeed>();
        for (var endianIndex = 0; endianIndex < 2; endianIndex++)
        {
            var littleEndian = endianIndex == 0;
            for (var rangeIndex = 0; rangeIndex < ranges.Count; rangeIndex++)
            {
                cancellationToken.ThrowIfCancellationRequested();
                ScanAxisRange(bytes, ranges[rangeIndex].Start, ranges[rangeIndex].End,
                    littleEndian, axes, cancellationToken);
                var completed = (endianIndex * ranges.Count + rangeIndex + 1d) / (ranges.Count * 2d);
                progress?.Report(new AutomaticMapScanProgress(completed * 42,
                    littleEndian ? "Scanning Intel axis structures" : "Scanning Motorola axis structures",
                    axes.Count, 0));
            }
        }

        axes = axes.OrderByDescending(axis => axis.Confidence)
            .GroupBy(axis => (axis.Offset / 4, axis.Count, axis.LittleEndian))
            .Select(group => group.First()).Take(4500).ToList();

        var candidates = new List<AutomaticMapCandidate>();
        for (var index = 0; index < axes.Count; index++)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var axis = axes[index];
            foreach (var height in CommonDimensions)
            {
                TryAddSurface(bytes, axis, axis.Offset + axis.Count * 2L, axis.Count, height,
                    candidates, cancellationToken);
                var preceding = axis.Offset - axis.Count * (long)height * 2;
                if (preceding >= 0)
                    TryAddSurface(bytes, axis, preceding, axis.Count, height, candidates, cancellationToken);
            }
            if (index % 32 == 0 || index == axes.Count - 1)
                progress?.Report(new AutomaticMapScanProgress(42 + 54d * (index + 1) / Math.Max(1, axes.Count),
                    "Scoring map surfaces", axes.Count, candidates.Count));
        }

        var result = Deduplicate(candidates, 300);

        progress?.Report(new AutomaticMapScanProgress(100, "Automatic scan complete", axes.Count, result.Count));
        return result;
    }

    private static List<AutomaticMapCandidate> Deduplicate(
        IEnumerable<AutomaticMapCandidate> candidates, int maximum)
    {
        var result = new List<AutomaticMapCandidate>(maximum);
        var exactKeys = new HashSet<(long Region, int Width, int Height)>();
        foreach (var candidate in candidates.OrderByDescending(item => item.Confidence))
        {
            if (candidate.Confidence < 0.58) break;
            var key = (candidate.Map.StartOffset / 16, candidate.Map.Width, candidate.Map.Height);
            if (!exactKeys.Add(key)) continue;
            if (result.Any(existing => Overlap(candidate.Map, existing.Map) > 0.88)) continue;
            result.Add(candidate);
            if (result.Count >= maximum) break;
        }
        return result;
    }

    private static List<(int Start, int End)> GetScanRanges(int length)
    {
        const int maximumBytes = 32 * 1024 * 1024;
        if (length <= maximumBytes) return [(0, length - (length % 2))];
        var firstEnd = 4 * 1024 * 1024;
        var lastStart = Math.Max(firstEnd, length - 28 * 1024 * 1024);
        lastStart -= lastStart % 2;
        return [(0, firstEnd), (lastStart, length - (length % 2))];
    }

    private static void ScanAxisRange(byte[] bytes, int start, int end, bool littleEndian,
        List<AxisSeed> output, CancellationToken cancellationToken)
    {
        var runStart = start;
        var runDirection = 0;
        var runCount = 1;
        var previous = ReadU16(bytes, start, littleEndian);
        for (var offset = start + 2; offset + 1 < end; offset += 2)
        {
            if ((offset & 0x3FFFF) == 0) cancellationToken.ThrowIfCancellationRequested();
            var current = ReadU16(bytes, offset, littleEndian);
            var difference = current - previous;
            var direction = difference > 0 ? 1 : difference < 0 ? -1 : 0;
            var plausibleStep = difference != 0 && Math.Abs(difference) <= 16384;
            if (plausibleStep && (runDirection == 0 || direction == runDirection))
            {
                if (runDirection == 0) runDirection = direction;
                runCount++;
            }
            else
            {
                EmitAxisSeeds(bytes, runStart, runCount, littleEndian, output);
                runStart = offset - 2;
                runCount = plausibleStep ? 2 : 1;
                runDirection = plausibleStep ? direction : 0;
            }
            previous = current;
        }
        EmitAxisSeeds(bytes, runStart, runCount, littleEndian, output);
    }

    private static void EmitAxisSeeds(byte[] bytes, int runStart, int runCount, bool littleEndian,
        List<AxisSeed> output)
    {
        if (runCount < 6) return;
        foreach (var count in CommonDimensions.Where(value => value <= Math.Min(64, runCount)))
        {
            var start = runStart + (runCount - count) * 2L;
            var first = ReadU16(bytes, (int)start, littleEndian);
            var last = ReadU16(bytes, (int)(start + (count - 1L) * 2), littleEndian);
            var range = Math.Abs(last - first);
            if (range < count - 1 || range > 65000) continue;
            var confidence = Math.Clamp(0.54 + Math.Min(0.24, count / 100d) +
                Math.Min(0.18, Math.Log10(range + 1) / 20d), 0, 0.96);
            output.Add(new AxisSeed(start, count, littleEndian, confidence));
        }
    }

    private static void TryAddSurface(byte[] bytes, AxisSeed axis, long start, int width, int height,
        List<AutomaticMapCandidate> output, CancellationToken cancellationToken)
    {
        if (output.Count >= 12000) return;
        var byteLength = width * (long)height * 2;
        if (start < 0 || start + byteLength > bytes.LongLength) return;
        cancellationToken.ThrowIfCancellationRequested();
        var score = ScoreSurface(bytes, start, width, height, axis.LittleEndian);
        if (score.Confidence < 0.58) return;

        var nearbyText = ReadNearbyAscii(bytes, start, (int)Math.Min(byteLength, int.MaxValue));
        var (category, reason) = Classify(score, nearbyText);
        var confidence = Math.Clamp(score.Confidence * 0.78 + axis.Confidence * 0.22, 0, 0.98);
        var map = new EcuProjectMapDefinition
        {
            Name = $"{category} candidate @ 0x{start:X8}",
            Category = category,
            StartOffset = start,
            Width = width,
            Height = height,
            ValueType = EcuMapValueType.Unsigned16,
            LittleEndian = axis.LittleEndian,
            Comment = $"Automatic structural candidate; confidence {confidence:P0}. {reason}",
            XAxis = new EcuProjectAxisDefinition
            {
                Name = "X axis", Offset = axis.Offset, Count = width,
                ValueType = EcuMapValueType.Unsigned16, LittleEndian = axis.LittleEndian,
                Confidence = axis.Confidence
            },
            YAxis = new EcuProjectAxisDefinition { Name = "Y axis", Count = height }
        };
        if (confidence >= 0.74)
        {
            var foundAxes = AxisCandidateFinder.Find(bytes, map);
            if (foundAxes.X is not null && foundAxes.X.Confidence > map.XAxis.Confidence) map.XAxis = foundAxes.X;
            if (foundAxes.Y is not null) map.YAxis = foundAxes.Y;
        }
        var evidence = $"{reason}; smooth {score.Smoothness:P0}; plateau {score.Plateau:P0}; range {score.DynamicRange:G6}";
        output.Add(new AutomaticMapCandidate(map, confidence, evidence));
    }

    private static SurfaceScore ScoreSurface(byte[] bytes, long start, int width, int height, bool littleEndian)
    {
        var count = width * height;
        var values = new double[count];
        for (var index = 0; index < count; index++)
            values[index] = ReadU16(bytes, checked((int)(start + index * 2L)), littleEndian);
        var minimum = values.Min();
        var maximum = values.Max();
        var range = maximum - minimum;
        if (range < 4 || values.Distinct().Take(Math.Min(12, count)).Count() < 5)
            return new SurfaceScore(0, 0, 0, 0, 0, range);

        double horizontalDifference = 0, verticalDifference = 0;
        var horizontalCount = 0; var verticalCount = 0;
        var horizontalPositive = 0; var horizontalNegative = 0;
        var verticalPositive = 0; var verticalNegative = 0;
        var plateau = 0;
        for (var row = 0; row < height; row++)
        for (var column = 0; column < width; column++)
        {
            var index = row * width + column;
            if (column + 1 < width)
            {
                var difference = values[index + 1] - values[index];
                horizontalDifference += Math.Abs(difference); horizontalCount++;
                if (difference > 0) horizontalPositive++; else if (difference < 0) horizontalNegative++; else plateau++;
            }
            if (row + 1 < height)
            {
                var difference = values[index + width] - values[index];
                verticalDifference += Math.Abs(difference); verticalCount++;
                if (difference > 0) verticalPositive++; else if (difference < 0) verticalNegative++; else plateau++;
            }
        }
        var averageDifference = (horizontalDifference + verticalDifference) / Math.Max(1, horizontalCount + verticalCount);
        var normalizedRoughness = averageDifference / Math.Max(1, range);
        var smoothness = Math.Clamp(1 - normalizedRoughness * 7, 0, 1);
        var distinctRatio = values.Distinct().Count() / (double)count;
        var plateauRatio = plateau / (double)Math.Max(1, horizontalCount + verticalCount);
        var hDirection = Math.Max(horizontalPositive, horizontalNegative) / (double)Math.Max(1, horizontalCount);
        var vDirection = Math.Max(verticalPositive, verticalNegative) / (double)Math.Max(1, verticalCount);
        var confidence = smoothness * 0.48 + Math.Min(1, distinctRatio * 2.2) * 0.22 +
            Math.Max(hDirection, vDirection) * 0.20 + (range >= 32 ? 0.10 : 0.04);
        if (plateauRatio > 0.92 || normalizedRoughness > 0.35) confidence *= 0.55;
        return new SurfaceScore(confidence, smoothness, plateauRatio, hDirection, vDirection, range);
    }

    private static (string Category, string Reason) Classify(SurfaceScore score, string nearbyText)
    {
        var markers = new (string[] Words, string Category)[]
        {
            (["DRIVER", "PEDAL", "WISH"], "Driver wish"), (["SMOKE"], "Smoke limiter"),
            (["BOOST", "TURBO"], "Boost"), (["N75"], "N75"),
            (["RAIL", "PRESSURE"], "Rail pressure"), (["TORQUE", "LIMITER"], "Torque limiter"),
            (["DURATION", "INJECTION"], "Duration"), (["LAMBDA", "AFR"], "Lambda"),
            (["IGNITION", "SPARK"], "Ignition"), (["VVT", "CAMSHAFT"], "VVT"),
            (["EGR"], "EGR"), (["DPF"], "DPF"), (["SCR", "ADBLUE"], "SCR / AdBlue"),
            (["FUEL", "INJECT"], "Fuel")
        };
        foreach (var marker in markers)
            if (marker.Words.Any(word => nearbyText.Contains(word, StringComparison.Ordinal)))
                return (marker.Category, $"Nearby calibration marker suggests {marker.Category}");
        if (score.Plateau > 0.30 && score.Smoothness > 0.66)
            return ("Limiter", "Smooth surface with a repeated limiting plateau");
        if (score.HorizontalDirection > 0.80 && score.VerticalDirection > 0.72)
            return ("Driver wish / torque", "Strong directional gradients on both axes");
        if (score.HorizontalDirection > 0.78)
            return ("Duration / fuel", "Smooth predominantly directional rows");
        if (score.VerticalDirection > 0.78)
            return ("Boost / pressure", "Smooth predominantly directional columns");
        return ("Unclassified calibration", "Map-like smooth surface and adjacent monotonic axis");
    }

    private static string ReadNearbyAscii(byte[] bytes, long start, int length)
    {
        var first = (int)Math.Max(0, start - 768);
        var last = (int)Math.Min(bytes.LongLength, start + length + 768L);
        var builder = new StringBuilder(Math.Min(1536, last - first));
        for (var index = first; index < last; index++)
        {
            var value = bytes[index];
            builder.Append(value is >= 32 and <= 126 ? char.ToUpperInvariant((char)value) : ' ');
        }
        return builder.ToString();
    }

    private static int ReadU16(byte[] bytes, int offset, bool littleEndian) => littleEndian
        ? bytes[offset] | bytes[offset + 1] << 8
        : bytes[offset] << 8 | bytes[offset + 1];

    private static double Overlap(EcuProjectMapDefinition left, EcuProjectMapDefinition right)
    {
        var leftEnd = left.StartOffset + (long)left.Width * left.Height * EcuMapTools.ValueSize(left.ValueType);
        var rightEnd = right.StartOffset + (long)right.Width * right.Height * EcuMapTools.ValueSize(right.ValueType);
        var intersection = Math.Max(0, Math.Min(leftEnd, rightEnd) - Math.Max(left.StartOffset, right.StartOffset));
        var smaller = Math.Min(leftEnd - left.StartOffset, rightEnd - right.StartOffset);
        return smaller <= 0 ? 0 : intersection / (double)smaller;
    }
}
