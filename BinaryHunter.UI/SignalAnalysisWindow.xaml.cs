using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows;

namespace BinaryHunter.UI;

public sealed class SignalPeakRow
{
    public required SignalPeak Peak { get; init; }
    public required long Offset { get; init; }
    public string TypeLabel => Peak.IsMaximum ? "Peak" : "Valley";
    public int Row => Peak.Row;
    public int Column => Peak.Column;
    public string HexOffset => $"0x{Offset:X8}";
    public string ValueText => Peak.Value.ToString("G10", CultureInfo.InvariantCulture);
    public string ProminenceText => Peak.Prominence.ToString("G8", CultureInfo.InvariantCulture);
}

public partial class SignalAnalysisWindow : Window
{
    public ObservableCollection<SignalPeakRow> Peaks { get; } = [];
    public long? NavigateOffset { get; private set; }

    public SignalAnalysisWindow(SignalAnalysisReport report, long startOffset, int valueSize, int width, int height, string scopeName)
    {
        InitializeComponent();
        ScopeText.Text = $"{scopeName}  •  0x{startOffset:X8}  •  {width} × {height}  •  {report.Count:N0} values";
        RangeText.Text = $"{report.Minimum:G8} … {report.Maximum:G8}";
        MeanText.Text = $"{report.Mean:G8} / {report.StandardDeviation:G7}";
        NoiseText.Text = $"σn {report.NoiseSigma:G7} / {(double.IsPositiveInfinity(report.SignalToNoiseDb) ? "∞" : report.SignalToNoiseDb.ToString("F1", CultureInfo.InvariantCulture))} dB";
        PeakText.Text = $"{report.Roughness:G7} / {report.Peaks.Count:N0}";
        foreach (var peak in report.Peaks)
            Peaks.Add(new SignalPeakRow { Peak = peak, Offset = startOffset + (long)peak.Index * valueSize });
        DataContext = this;
    }

    private void GoButton_Click(object sender, RoutedEventArgs e)
    {
        if (PeaksGrid.SelectedItem is not SignalPeakRow row) return;
        NavigateOffset = row.Offset;
        DialogResult = true;
    }
    private void CloseButton_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
