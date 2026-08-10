using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using BinaryHunter.Core.Projects;
using MessageBox = System.Windows.MessageBox;
using OpenFileDialog = Microsoft.Win32.OpenFileDialog;

namespace BinaryHunter.UI;

public sealed class MapTransferRow : INotifyPropertyChanged
{
    private bool _isSelected;
    public required MapTransferCandidate Candidate { get; init; }
    public bool IsSelected
    {
        get => _isSelected;
        set { if (_isSelected == value) return; _isSelected = value; PropertyChanged?.Invoke(this, new(nameof(IsSelected))); }
    }
    public event PropertyChangedEventHandler? PropertyChanged;
}

public partial class ImportChangesWindow : Window
{
    private readonly byte[] _target;
    private readonly IReadOnlyList<EcuProjectMapDefinition> _targetMaps;
    private readonly IReadOnlyList<ChecksumBlockDefinition> _checksums;
    private readonly EcuProjectService _projectService = new();
    private EcuProjectSession? _sourceProject;
    private byte[] _source = [];
    private byte[]? _sourceOriginal;
    public ObservableCollection<MapTransferRow> Rows { get; } = [];
    public byte[] ResultBytes { get; private set; } = [];
    public IReadOnlyList<EcuProjectMapDefinition> ImportedMaps { get; private set; } = [];

    public ImportChangesWindow(byte[] target, IReadOnlyList<EcuProjectMapDefinition> targetMaps,
        IReadOnlyList<ChecksumBlockDefinition> checksums)
    {
        InitializeComponent();
        _target = target;
        _targetMaps = targetMaps;
        _checksums = checksums;
        ResultBytes = target.ToArray();
        DataContext = this;
        StatusText.Text = "Choose a BinaryHunter source project";
    }

    private void ChooseSourceButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog
        {
            Title = "Select source project for change import",
            Filter = $"BinaryHunter project|*{EcuProjectService.ProjectExtension}|All files|*.*"
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            _sourceProject = _projectService.Open(dialog.FileName);
            _source = File.ReadAllBytes(_projectService.GetActiveVersionPath(_sourceProject));
            var originalVersion = _sourceProject.Manifest.Versions.OrderBy(version => version.Number).FirstOrDefault();
            _sourceOriginal = originalVersion is null ? null :
                File.ReadAllBytes(_projectService.GetVersionPath(_sourceProject, originalVersion));
            SourceProjectTextBox.Text = dialog.FileName;
            SourceInfoText.Text = $"{_sourceProject.Manifest.Maps.Count:N0} map(s)  •  {_source.Length:N0} bytes  •  active V{_sourceProject.ActiveVersion?.Number ?? 0:D4}";
            StatusText.Text = "Source loaded. Run map matching.";
            Rows.Clear();
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or InvalidDataException)
        {
            MessageBox.Show(exception.Message, "Could not open source project",
                MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private async void AnalyzeButton_Click(object sender, RoutedEventArgs e)
    {
        if (_sourceProject is null)
        {
            MessageBox.Show("Choose a source project first.", "Import changes",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        if (!double.TryParse(ToleranceTextBox.Text, NumberStyles.Float, CultureInfo.InvariantCulture, out var tolerance))
            tolerance = 5;
        tolerance = Math.Clamp(tolerance, 0, 40);
        ToleranceTextBox.Text = tolerance.ToString("G", CultureInfo.InvariantCulture);
        StatusText.Text = "Matching map definitions and content signatures…";
        IsEnabled = false;
        try
        {
            var found = await Task.Run(() => MapTransferService.Discover(_source, _sourceOriginal,
                _sourceProject.Manifest.Maps, _target, _targetMaps, tolerance));
            Rows.Clear();
            var changedOnly = ChangedOnlyCheckBox.IsChecked == true;
            foreach (var candidate in found.Where(item => !changedOnly || item.SourceChanged))
            {
                var row = new MapTransferRow { Candidate = candidate,
                    IsSelected = candidate.IsValid && candidate.Confidence >= 1 - tolerance / 100d };
                row.PropertyChanged += (_, _) => RefreshStatus();
                Rows.Add(row);
            }
            RefreshStatus();
        }
        finally { IsEnabled = true; }
    }

    private void SelectReadyButton_Click(object sender, RoutedEventArgs e)
    {
        foreach (var row in Rows) row.IsSelected = row.Candidate.IsValid;
        RefreshStatus();
    }

    private void ClearSelectionButton_Click(object sender, RoutedEventArgs e)
    {
        foreach (var row in Rows) row.IsSelected = false;
        RefreshStatus();
    }

    private void RefreshStatus()
    {
        var ready = Rows.Count(row => row.Candidate.IsValid);
        var selected = Rows.Count(row => row.IsSelected && row.Candidate.IsValid);
        var moved = Rows.Count(row => row.Candidate.IsValid && row.Candidate.TargetOffset != row.Candidate.SourceMap.StartOffset);
        StatusText.Text = $"{Rows.Count:N0} candidate(s)  •  {ready:N0} matched  •  {moved:N0} relocated  •  {selected:N0} selected";
    }

    private void ApplyButton_Click(object sender, RoutedEventArgs e)
    {
        var selected = Rows.Where(row => row.IsSelected && row.Candidate.IsValid)
            .Select(row => row.Candidate).ToList();
        if (selected.Count == 0)
        {
            MessageBox.Show("Select at least one matched map.", "Import changes",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var mode = TransferModeComboBox.SelectedItem is ComboBoxItem { Tag: string tag } &&
                   Enum.TryParse<MapTransferMode>(tag, out var parsed) ? parsed : MapTransferMode.RelativeChanges;
        if (mode == MapTransferMode.RelativeChanges && _sourceOriginal is null)
        {
            MessageBox.Show("The source project does not have an original version for relative transfer.",
                "Import changes", MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        ResultBytes = MapTransferService.Apply(_target, _source, _sourceOriginal, selected, mode,
            _checksums, SkipChecksumsCheckBox.IsChecked == true);
        ImportedMaps = ImportDefinitionsCheckBox.IsChecked == true
            ? selected.Select(MapTransferService.RelocateDefinition).ToList()
            : [];
        DialogResult = true;
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
