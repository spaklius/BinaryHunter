namespace BinaryHunter.UI;

public enum SignalProcessingOperation
{
    HorizontalSmooth,
    VerticalSmooth,
    SurfaceSmooth,
    NoiseReduction,
    LinearInterpolation,
    HorizontalInterpolation,
    VerticalInterpolation,
    MultiPointInterpolation
}

public sealed record SignalPeak(int Index, int Row, int Column, double Value, double Prominence, bool IsMaximum);

public sealed record SignalAnalysisReport(
    int Count, double Minimum, double Maximum, double Mean, double StandardDeviation,
    double NoiseSigma, double SignalToNoiseDb, double Roughness, IReadOnlyList<SignalPeak> Peaks);

public static class SignalProcessingEngine
{
    public static SignalAnalysisReport Analyze(IReadOnlyList<double> values, int width, int height)
    {
        if (values.Count == 0) return new(0, 0, 0, 0, 0, 0, 0, 0, []);
        var finite = values.Where(double.IsFinite).ToArray();
        if (finite.Length == 0) return new(values.Count, 0, 0, 0, 0, 0, 0, 0, []);
        var mean = finite.Average();
        var variance = finite.Average(value => Math.Pow(value - mean, 2));
        var differences = new List<double>();
        for (var row = 0; row < height; row++)
            for (var column = 1; column < width; column++)
            {
                var index = row * width + column;
                if (index < values.Count && double.IsFinite(values[index]) && double.IsFinite(values[index - 1]))
                    differences.Add(values[index] - values[index - 1]);
            }
        var noise = differences.Count == 0 ? 0 : MedianAbsoluteDeviation(differences) / Math.Sqrt(2);
        var standardDeviation = Math.Sqrt(variance);
        var snr = noise <= 1e-15 ? double.PositiveInfinity : 20 * Math.Log10(Math.Max(1e-15, standardDeviation) / noise);
        var roughness = differences.Count == 0 ? 0 : differences.Average(Math.Abs);
        var peaks = FindPeaks(values, width, height, Math.Max(noise * 2.5, (finite.Max() - finite.Min()) * 0.01));
        return new(values.Count, finite.Min(), finite.Max(), mean, standardDeviation, noise, snr, roughness, peaks);
    }

    public static double[] Process(IReadOnlyList<double> values, int width, int height,
        SignalProcessingOperation operation, int radius, int iterations, double strength)
    {
        var current = values.ToArray();
        radius = Math.Clamp(radius, 1, 12);
        iterations = Math.Clamp(iterations, 1, 20);
        strength = Math.Clamp(strength, 0, 1);
        for (var iteration = 0; iteration < iterations; iteration++)
        {
            current = operation switch
            {
                SignalProcessingOperation.HorizontalSmooth => Smooth(current, width, height, radius, true, false, strength),
                SignalProcessingOperation.VerticalSmooth => Smooth(current, width, height, radius, false, true, strength),
                SignalProcessingOperation.SurfaceSmooth => Smooth(current, width, height, radius, true, true, strength),
                SignalProcessingOperation.NoiseReduction => ReduceNoise(current, width, height, radius, strength),
                SignalProcessingOperation.LinearInterpolation => InterpolateLinear(current),
                SignalProcessingOperation.HorizontalInterpolation => InterpolateHorizontal(current, width, height),
                SignalProcessingOperation.VerticalInterpolation => InterpolateVertical(current, width, height),
                SignalProcessingOperation.MultiPointInterpolation => InterpolateSurface(current, width, height),
                _ => current
            };
        }
        return current;
    }

    private static double[] Smooth(double[] source, int width, int height, int radius,
        bool horizontal, bool vertical, double strength)
    {
        var result = source.ToArray();
        for (var row = 0; row < height; row++)
            for (var column = 0; column < width; column++)
            {
                var index = row * width + column;
                if (index >= source.Length) continue;
                double sum = 0, weightSum = 0;
                var rowRadius = vertical ? radius : 0;
                var columnRadius = horizontal ? radius : 0;
                for (var y = Math.Max(0, row - rowRadius); y <= Math.Min(height - 1, row + rowRadius); y++)
                    for (var x = Math.Max(0, column - columnRadius); x <= Math.Min(width - 1, column + columnRadius); x++)
                    {
                        var sample = y * width + x;
                        if (sample >= source.Length || !double.IsFinite(source[sample])) continue;
                        var distance = Math.Abs(y - row) + Math.Abs(x - column);
                        var weight = radius + 1 - Math.Min(radius, distance);
                        sum += source[sample] * weight;
                        weightSum += weight;
                    }
                if (weightSum > 0) result[index] = source[index] * (1 - strength) + sum / weightSum * strength;
            }
        return result;
    }

    private static double[] ReduceNoise(double[] source, int width, int height, int radius, double strength)
    {
        var smoothed = Smooth(source, width, height, radius, true, true, 1);
        var report = Analyze(source, width, height);
        var threshold = Math.Max(report.NoiseSigma * 3, 1e-12);
        var result = new double[source.Length];
        for (var index = 0; index < source.Length; index++)
        {
            var residual = source[index] - smoothed[index];
            var preservation = Math.Clamp(Math.Abs(residual) / threshold, 0, 1);
            var filtered = smoothed[index] + residual * preservation;
            result[index] = source[index] * (1 - strength) + filtered * strength;
        }
        return result;
    }

    private static double[] InterpolateLinear(double[] source)
    {
        if (source.Length < 2) return source.ToArray();
        var result = new double[source.Length];
        for (var index = 0; index < result.Length; index++)
            result[index] = source[0] + (source[^1] - source[0]) * index / Math.Max(1d, result.Length - 1);
        return result;
    }

    private static double[] InterpolateHorizontal(double[] source, int width, int height)
    {
        var result = source.ToArray();
        for (var row = 0; row < height; row++)
        {
            var start = row * width;
            var end = Math.Min(source.Length - 1, start + width - 1);
            if (start >= source.Length || end <= start) continue;
            for (var column = 0; start + column <= end; column++)
                result[start + column] = source[start] + (source[end] - source[start]) * column / Math.Max(1d, end - start);
        }
        return result;
    }

    private static double[] InterpolateVertical(double[] source, int width, int height)
    {
        var result = source.ToArray();
        for (var column = 0; column < width; column++)
        {
            var top = column;
            var bottom = Math.Min(source.Length - 1, (height - 1) * width + column);
            if (top >= source.Length || bottom <= top) continue;
            for (var row = 0; row < height && row * width + column < source.Length; row++)
                result[row * width + column] = source[top] + (source[bottom] - source[top]) * row / Math.Max(1d, height - 1);
        }
        return result;
    }

    private static double[] InterpolateSurface(double[] source, int width, int height)
    {
        if (source.Length < 2 || width < 2 || height < 2) return InterpolateLinear(source);
        var topLeft = source[0];
        var topRight = source[Math.Min(source.Length - 1, width - 1)];
        var bottomLeft = source[Math.Min(source.Length - 1, (height - 1) * width)];
        var bottomRight = source[^1];
        var result = source.ToArray();
        for (var row = 0; row < height; row++)
            for (var column = 0; column < width; column++)
            {
                var index = row * width + column;
                if (index >= result.Length) continue;
                var tx = column / Math.Max(1d, width - 1);
                var ty = row / Math.Max(1d, height - 1);
                var top = topLeft + (topRight - topLeft) * tx;
                var bottom = bottomLeft + (bottomRight - bottomLeft) * tx;
                result[index] = top + (bottom - top) * ty;
            }
        return result;
    }

    private static IReadOnlyList<SignalPeak> FindPeaks(IReadOnlyList<double> values, int width, int height, double threshold)
    {
        var result = new List<SignalPeak>();
        for (var row = 0; row < height; row++)
            for (var column = 0; column < width; column++)
            {
                var index = row * width + column;
                if (index >= values.Count) continue;
                var neighbors = new List<double>(4);
                if (column > 0) neighbors.Add(values[index - 1]);
                if (column + 1 < width && index + 1 < values.Count) neighbors.Add(values[index + 1]);
                if (row > 0) neighbors.Add(values[index - width]);
                if (row + 1 < height && index + width < values.Count) neighbors.Add(values[index + width]);
                if (neighbors.Count < 2) continue;
                var value = values[index];
                var isMaximum = neighbors.All(neighbor => value > neighbor);
                var isMinimum = neighbors.All(neighbor => value < neighbor);
                if (!isMaximum && !isMinimum) continue;
                var prominence = isMaximum ? value - neighbors.Max() : neighbors.Min() - value;
                if (prominence >= threshold)
                    result.Add(new SignalPeak(index, row, column, value, prominence, isMaximum));
            }
        return result.OrderByDescending(peak => peak.Prominence).Take(256).ToList();
    }

    private static double MedianAbsoluteDeviation(IReadOnlyList<double> values)
    {
        var median = Median(values);
        return Median(values.Select(value => Math.Abs(value - median)).ToArray()) * 1.4826;
    }

    private static double Median(IReadOnlyList<double> values)
    {
        if (values.Count == 0) return 0;
        var sorted = values.OrderBy(value => value).ToArray();
        var middle = sorted.Length / 2;
        return sorted.Length % 2 == 0 ? (sorted[middle - 1] + sorted[middle]) / 2 : sorted[middle];
    }
}
