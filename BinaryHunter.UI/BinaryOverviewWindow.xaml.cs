using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using BinaryHunter.Core.Projects;
using WpfCanvas = System.Windows.Controls.Canvas;
using WpfBrush = System.Windows.Media.Brush;
using WpfColor = System.Windows.Media.Color;
using WpfMouseEventArgs = System.Windows.Input.MouseEventArgs;
using WpfPoint = System.Windows.Point;
using WpfRectangle = System.Windows.Shapes.Rectangle;

namespace BinaryHunter.UI;

public partial class BinaryOverviewWindow : Window
{
    private const int BucketCount = 512;
    private readonly byte[] _bytes;
    private readonly byte[]? _reference;
    private readonly IReadOnlyList<EcuProjectMapDefinition> _maps;
    private readonly Action<long> _navigate;
    private OverviewBucket[] _buckets = [];

    public BinaryOverviewWindow(byte[] bytes, IReadOnlyList<EcuProjectMapDefinition> maps,
        byte[]? reference, Action<long> navigate)
    {
        InitializeComponent();
        _bytes = bytes;
        _maps = maps;
        _reference = reference;
        _navigate = navigate;
        HeaderText.Text = $"{bytes.LongLength:N0} bytes  •  {maps.Count:N0} saved map(s)";
        Loaded += async (_, _) => await RebuildAsync();
    }

    private async Task RebuildAsync()
    {
        StatusText.Text = "Classifying binary regions…";
        var bytes = _bytes;
        var reference = _reference;
        var maps = _maps.ToArray();
        _buckets = await Task.Run(() => BuildBuckets(bytes, reference, maps));
        DrawOverview();
        StatusText.Text = $"{_buckets.Length:N0} overview region(s)  •  1 pixel ≈ {Math.Max(1, bytes.Length / Math.Max(1, _buckets.Length)):N0} bytes";
    }

    private static OverviewBucket[] BuildBuckets(byte[] bytes, byte[]? reference,
        IReadOnlyList<EcuProjectMapDefinition> maps)
    {
        if (bytes.Length == 0) return [];
        var count = Math.Min(BucketCount, bytes.Length);
        var result = new OverviewBucket[count];
        for (var bucket = 0; bucket < count; bucket++)
        {
            var start = (int)((long)bucket * bytes.Length / count);
            var end = (int)((long)(bucket + 1) * bytes.Length / count);
            end = Math.Max(start + 1, end);
            var empty = 0; var printable = 0; var differences = 0;
            for (var offset = start; offset < end; offset++)
            {
                var value = bytes[offset];
                if (value is 0x00 or 0xFF) empty++;
                if (value is >= 0x20 and <= 0x7E) printable++;
                if (reference is not null && (offset >= reference.Length || reference[offset] != value)) differences++;
            }
            var map = maps.Any(item => item.StartOffset < end && MapEnd(item) > start);
            var length = end - start;
            var kind = differences > 0 ? OverviewKind.Difference : map ? OverviewKind.Map :
                empty >= length * 0.85 ? OverviewKind.Empty :
                printable >= length * 0.35 ? OverviewKind.Text : OverviewKind.Binary;
            result[bucket] = new OverviewBucket(start, end, kind, differences);
        }
        return result;
    }

    private void DrawOverview()
    {
        OverviewCanvas.Children.Clear();
        if (_buckets.Length == 0 || OverviewCanvas.ActualHeight <= 0) return;
        var height = OverviewCanvas.ActualHeight / _buckets.Length;
        for (var index = 0; index < _buckets.Length; index++)
        {
            var rectangle = new WpfRectangle
            {
                Width = Math.Max(1, OverviewCanvas.ActualWidth),
                Height = Math.Max(1, height + 0.5),
                Fill = BrushFor(_buckets[index].Kind),
                IsHitTestVisible = false
            };
            WpfCanvas.SetTop(rectangle, index * height);
            OverviewCanvas.Children.Add(rectangle);
        }
    }

    private void NavigateFromPoint(WpfPoint point, bool commit)
    {
        if (_buckets.Length == 0 || OverviewCanvas.ActualHeight <= 0) return;
        var index = Math.Clamp((int)(point.Y / OverviewCanvas.ActualHeight * _buckets.Length), 0, _buckets.Length - 1);
        var bucket = _buckets[index];
        RegionText.Text = $"0x{bucket.Start:X8} - 0x{bucket.End - 1:X8}\n{bucket.Kind} region" +
                          (bucket.DifferenceCount > 0 ? $"\n{bucket.DifferenceCount:N0} changed byte(s)" : string.Empty);
        if (commit) _navigate(bucket.Start);
    }

    private void OverviewCanvas_MouseLeftButtonDown(object sender, MouseButtonEventArgs e) =>
        NavigateFromPoint(e.GetPosition(OverviewCanvas), true);

    private void OverviewCanvas_MouseMove(object sender, WpfMouseEventArgs e) =>
        NavigateFromPoint(e.GetPosition(OverviewCanvas), e.LeftButton == MouseButtonState.Pressed);

    private async void RebuildButton_Click(object sender, RoutedEventArgs e) => await RebuildAsync();
    private void OverviewCanvas_SizeChanged(object sender, SizeChangedEventArgs e) => DrawOverview();
    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();

    private static long MapEnd(EcuProjectMapDefinition map) => map.StartOffset +
        (long)Math.Max(1, map.Width) * Math.Max(1, map.Height) * EcuMapTools.ValueSize(map.ValueType);

    private static WpfBrush BrushFor(OverviewKind kind) => kind switch
    {
        OverviewKind.Empty => new SolidColorBrush(WpfColor.FromRgb(39, 39, 42)),
        OverviewKind.Text => new SolidColorBrush(WpfColor.FromRgb(14, 116, 144)),
        OverviewKind.Map => new SolidColorBrush(WpfColor.FromRgb(202, 138, 4)),
        OverviewKind.Difference => new SolidColorBrush(WpfColor.FromRgb(220, 38, 56)),
        _ => new SolidColorBrush(WpfColor.FromRgb(51, 65, 85))
    };

    private sealed record OverviewBucket(int Start, int End, OverviewKind Kind, int DifferenceCount);
    private enum OverviewKind { Empty, Text, Binary, Map, Difference }
}
