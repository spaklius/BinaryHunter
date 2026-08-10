using BinaryHunter.Core.Projects;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using MessageBox = System.Windows.MessageBox;
using OpenFileDialog = Microsoft.Win32.OpenFileDialog;

namespace BinaryHunter.UI;

public sealed class AutomaticMapCandidateRow : INotifyPropertyChanged
{
    private bool _isSelected;
    public required AutomaticMapCandidate Candidate { get; init; }
    public bool IsSelected
    {
        get => _isSelected;
        set { if (_isSelected == value) return; _isSelected = value; PropertyChanged?.Invoke(this, new(nameof(IsSelected))); }
    }
    public string Category => Candidate.Map.Category;
    public string ConfidenceText => Candidate.Confidence.ToString("P0");
    public string HexOffset => $"0x{Candidate.Map.StartOffset:X8}";
    public string Dimensions => $"{Candidate.Map.Width} × {Candidate.Map.Height}";
    public string Format => $"{Candidate.Map.ValueType} {(Candidate.Map.LittleEndian ? "Intel" : "Motorola")}";
    public string Axes => $"X {AxisText(Candidate.Map.XAxis)} / Y {AxisText(Candidate.Map.YAxis)}";
    public string Evidence => Candidate.Evidence;
    public event PropertyChangedEventHandler? PropertyChanged;
    private static string AxisText(EcuProjectAxisDefinition axis) => axis.Offset < 0
        ? "not found" : $"0x{axis.Offset:X} ({axis.Confidence:P0})";
}

public partial class AutomaticMapDiscoveryWindow : Window
{
    private readonly byte[] _bytes;
    private readonly IReadOnlyList<EcuProjectMapDefinition> _existingMaps;
    private readonly CancellationTokenSource _cancellation = new();
    private bool _scanFinished;

    public ObservableCollection<AutomaticMapCandidateRow> Rows { get; } = [];
    public IReadOnlyList<EcuProjectMapDefinition> ImportedMaps { get; private set; } = [];

    public AutomaticMapDiscoveryWindow(byte[] bytes, IEnumerable<EcuProjectMapDefinition> existingMaps)
    {
        InitializeComponent();
        _bytes = bytes;
        _existingMaps = existingMaps.Select(EcuMapTools.Clone).ToList();
        DataContext = this;
        Loaded += Window_Loaded;
        Closing += Window_Closing;
    }

    private async void Window_Loaded(object sender, RoutedEventArgs e)
    {
        Loaded -= Window_Loaded;
        var progress = new Progress<AutomaticMapScanProgress>(value =>
        {
            ScanProgress.Value = value.Percent;
            StatusText.Text = $"{value.Stage} · {value.AxisCandidates:N0} axes · {value.MapCandidates:N0} maps";
        });
        try
        {
            var candidates = await AutomaticMapDiscoveryService.ScanAsync(_bytes, progress, _cancellation.Token);
            foreach (var candidate in candidates.Where(candidate => !OverlapsExisting(candidate.Map)))
            {
                var row = new AutomaticMapCandidateRow { Candidate = candidate, IsSelected = candidate.Confidence >= 0.78 };
                row.PropertyChanged += Row_PropertyChanged;
                Rows.Add(row);
            }
            StatusText.Text = Rows.Count == 0
                ? "No reliable heuristic candidates. Load the matching XDF/A2L definition for this firmware."
                : "Scan complete. Review the selected candidates before import.";
        }
        catch (OperationCanceledException)
        {
            StatusText.Text = "Scan cancelled. Partial candidates were not imported.";
        }
        catch (Exception exception)
        {
            StatusText.Text = $"Scan failed: {exception.Message}";
        }
        finally
        {
            _scanFinished = true;
            CancelScanButton.IsEnabled = false;
            ScanProgress.Value = 100;
            RefreshSelectionState();
        }
    }

    private bool OverlapsExisting(EcuProjectMapDefinition candidate)
    {
        var candidateEnd = candidate.StartOffset + (long)candidate.Width * candidate.Height * EcuMapTools.ValueSize(candidate.ValueType);
        return _existingMaps.Any(existing =>
        {
            var existingEnd = existing.StartOffset + (long)existing.Width * existing.Height * EcuMapTools.ValueSize(existing.ValueType);
            var intersection = Math.Max(0, Math.Min(candidateEnd, existingEnd) - Math.Max(candidate.StartOffset, existing.StartOffset));
            var smaller = Math.Min(candidateEnd - candidate.StartOffset, existingEnd - existing.StartOffset);
            return smaller > 0 && intersection / (double)smaller > 0.88;
        });
    }

    private void Row_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(AutomaticMapCandidateRow.IsSelected)) RefreshSelectionState();
    }

    private void RefreshSelectionState()
    {
        var selected = Rows.Count(row => row.IsSelected);
        CountText.Text = $"{Rows.Count:N0} candidates · {selected:N0} selected";
        ImportButton.IsEnabled = _scanFinished && selected > 0;
    }

    private void SelectStrongButton_Click(object sender, RoutedEventArgs e)
    {
        foreach (var row in Rows) row.IsSelected = row.Candidate.Confidence >= 0.75;
        RefreshSelectionState();
    }

    private void LoadDefinitionsButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Load calibration definition",
            Filter = "Calibration definitions|*.xdf;*.a2l;*.damos;*.dam;*.json;*.bhmap;*.xml;*.csv;*.tsv|" +
                     "TunerPro XDF|*.xdf|ASAM A2L / DAMOS|*.a2l;*.damos;*.dam|All files|*.*"
        };
        if (dialog.ShowDialog(this) != true) return;
        MapDefinitionImportResult result;
        try { result = MapDefinitionImportService.Import(dialog.FileName); }
        catch (Exception exception)
        {
            MessageBox.Show(exception.Message, "Could not load calibration definition",
                MessageBoxButton.OK, MessageBoxImage.Warning);
            return;
        }
        var preview = new MapDefinitionImportWindow(dialog.FileName, _bytes.LongLength, result) { Owner = this };
        if (preview.ShowDialog() != true) return;
        var added = 0;
        foreach (var map in preview.ImportedMaps)
        {
            if (OverlapsExisting(map) || Rows.Any(row =>
                    row.Candidate.Map.StartOffset == map.StartOffset &&
                    row.Candidate.Map.Width == map.Width && row.Candidate.Map.Height == map.Height)) continue;
            var candidate = new AutomaticMapCandidate(EcuMapTools.Clone(map), 1,
                $"Definition-driven map imported from {result.Format}.");
            var row = new AutomaticMapCandidateRow { Candidate = candidate, IsSelected = true };
            row.PropertyChanged += Row_PropertyChanged;
            Rows.Add(row); added++;
        }
        _scanFinished = true;
        StatusText.Text = $"Loaded {added:N0} verified definition map(s) from {result.Format}.";
        RefreshSelectionState();
    }

    private void SelectAllButton_Click(object sender, RoutedEventArgs e)
    {
        foreach (var row in Rows) row.IsSelected = true;
        RefreshSelectionState();
    }

    private void ClearButton_Click(object sender, RoutedEventArgs e)
    {
        foreach (var row in Rows) row.IsSelected = false;
        RefreshSelectionState();
    }

    private void CancelScanButton_Click(object sender, RoutedEventArgs e)
    {
        _cancellation.Cancel();
        CancelScanButton.IsEnabled = false;
        StatusText.Text = "Cancelling scan...";
    }

    private void ImportButton_Click(object sender, RoutedEventArgs e)
    {
        ImportedMaps = Rows.Where(row => row.IsSelected)
            .Select(row => EcuMapTools.Clone(row.Candidate.Map)).ToList();
        DialogResult = ImportedMaps.Count > 0;
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e)
    {
        _cancellation.Cancel();
        DialogResult = false;
    }

    private void Window_Closing(object? sender, CancelEventArgs e) => _cancellation.Cancel();
}
