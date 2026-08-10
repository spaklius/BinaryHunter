using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Input;
using BinaryHunter.Core.Projects;
using MessageBox = System.Windows.MessageBox;
using SaveFileDialog = Microsoft.Win32.SaveFileDialog;

namespace BinaryHunter.UI;

public partial class DifferencesWindow : Window
{
    private readonly Func<byte[]> _currentProvider;
    private readonly byte[] _reference;
    private readonly IReadOnlyList<EcuProjectMapDefinition> _maps;
    private readonly IReadOnlyList<ChecksumBlockDefinition> _checksums;
    private readonly Action<long> _navigate;
    private readonly Action<IReadOnlyList<long>> _restore;
    private BinaryDifferenceReport? _report;
    public ObservableCollection<BinaryDifferenceRow> Rows { get; } = [];
    public ObservableCollection<MapDifferenceRow> Maps { get; } = [];

    public DifferencesWindow(string currentName, string referenceName, Func<byte[]> currentProvider,
        byte[] reference, IReadOnlyList<EcuProjectMapDefinition> maps,
        IReadOnlyList<ChecksumBlockDefinition> checksums, Action<long> navigate,
        Action<IReadOnlyList<long>> restore)
    {
        InitializeComponent();
        DataContext = this;
        SourceText.Text = $"{currentName}  ↔  {referenceName}";
        _currentProvider = currentProvider;
        _reference = reference;
        _maps = maps;
        _checksums = checksums;
        _navigate = navigate;
        _restore = restore;
        Loaded += async (_, _) => await RefreshAsync();
    }

    private async Task RefreshAsync()
    {
        if (!TryOffset(FromTextBox.Text, out var from))
        {
            MessageBox.Show("Enter a decimal address or a hexadecimal address such as 0x1A20.",
                "Invalid offset", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var limit = LimitComboBox.SelectedItem is ComboBoxItem { Tag: string tag } && int.TryParse(tag, out var value) ? value : 5000;
        StatusText.Text = "Analyzing differences…";
        IsEnabled = false;
        try
        {
            var current = _currentProvider();
            _report = await Task.Run(() => BinaryDifferenceService.Analyze(current, _reference, _maps, _checksums, from, limit));
            Rows.Clear(); foreach (var row in _report.Rows) Rows.Add(row);
            Maps.Clear(); foreach (var map in _report.Maps) Maps.Add(map);
            SummaryText.Text = $"{_report.TotalChangedBytes:N0} BYTES  •  {_report.ChangedBlocks:N0} BLOCKS  •  {_report.Maps.Count:N0} MAPS";
            StatusText.Text = _report.IsTruncated
                ? $"Showing first {_report.Rows.Count:N0} rows. Change the row limit or starting offset to inspect more."
                : $"{_report.Rows.Count:N0} byte difference row(s).";
        }
        finally { IsEnabled = true; }
    }

    private async void RefreshButton_Click(object sender, RoutedEventArgs e) => await RefreshAsync();
    private void GoToButton_Click(object sender, RoutedEventArgs e) { if (DifferencesGrid.SelectedItem is BinaryDifferenceRow row) _navigate(row.Offset); }
    private void DifferencesGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e) => GoToButton_Click(sender, e);

    private async void RestoreButton_Click(object sender, RoutedEventArgs e)
    {
        var offsets = DifferencesGrid.SelectedItems.Cast<BinaryDifferenceRow>()
            .Where(row => row.ReferenceValue is not null).Select(row => row.Offset).Distinct().ToList();
        if (offsets.Count == 0) return;
        _restore(offsets);
        await RefreshAsync();
    }

    private void ExportButton_Click(object sender, RoutedEventArgs e)
    {
        if (_report is null) return;
        var dialog = new SaveFileDialog { Title = "Export difference report", FileName = "difference-report.csv",
            Filter = "CSV report|*.csv|JSON report|*.json|Text report|*.txt", AddExtension = true };
        if (dialog.ShowDialog(this) != true) return;
        BinaryDifferenceService.ExportReport(dialog.FileName, _report);
        StatusText.Text = $"Exported: {dialog.FileName}";
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();

    private static bool TryOffset(string text, out long value)
    {
        text = text.Trim();
        return text.StartsWith("0x", StringComparison.OrdinalIgnoreCase)
            ? long.TryParse(text[2..], NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value)
            : long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }
}
