using BinaryHunter.Core.Projects;
using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Windows;
using WpfControl = System.Windows.Controls.Control;
using WpfTextChangedEventArgs = System.Windows.Controls.TextChangedEventArgs;

namespace BinaryHunter.UI;

public sealed class MapDefinitionImportRow : INotifyPropertyChanged
{
    private bool _isSelected;
    private long _baseAddress;
    private readonly long _fileLength;
    public required EcuProjectMapDefinition Source { get; init; }

    public MapDefinitionImportRow(long fileLength) => _fileLength = fileLength;
    public bool IsSelected
    {
        get => _isSelected;
        set { if (_isSelected == value) return; _isSelected = value; Changed(nameof(IsSelected)); }
    }
    public long BaseAddress
    {
        get => _baseAddress;
        set { _baseAddress = value; Changed(string.Empty); }
    }
    public string Name => Source.Name;
    public string Category => Source.Category;
    public string SourceAddress => $"0x{Source.StartOffset:X8}";
    public long AdjustedOffset => Source.StartOffset - BaseAddress;
    public string FileOffset => AdjustedOffset < 0 ? "outside file" : $"0x{AdjustedOffset:X8}";
    public string Dimensions => $"{Source.Width} × {Source.Height}";
    public string TypeLabel => $"{Source.ValueType} / {(Source.LittleEndian ? "Intel" : "Motorola")}";
    public string Scaling => $"x × {Source.Factor:G7} + {Source.Offset:G7}";
    public string Unit => Source.Unit;
    public long ByteLength => (long)Source.Width * Source.Height * EcuMapTools.ValueSize(Source.ValueType);
    public bool IsValid => AdjustedOffset >= 0 && AdjustedOffset + ByteLength <= _fileLength;
    public string Status => IsValid ? "Ready" : "Adjusted map range is outside file";
    public event PropertyChangedEventHandler? PropertyChanged;
    private void Changed(string propertyName) => PropertyChanged?.Invoke(this,
        string.IsNullOrEmpty(propertyName) ? new PropertyChangedEventArgs(null) : new PropertyChangedEventArgs(propertyName));

    public EcuProjectMapDefinition CreateAdjustedMap()
    {
        var map = EcuMapTools.Clone(Source);
        map.Id = Guid.NewGuid().ToString("N");
        map.StartOffset -= BaseAddress;
        if (map.XAxis.Offset >= 0) map.XAxis.Offset -= BaseAddress;
        if (map.YAxis.Offset >= 0) map.YAxis.Offset -= BaseAddress;
        NormalizeAxis(map.XAxis);
        NormalizeAxis(map.YAxis);
        return map;
    }

    private void NormalizeAxis(EcuProjectAxisDefinition axis)
    {
        var byteLength = (long)Math.Max(1, axis.Count) * EcuMapTools.ValueSize(axis.ValueType);
        if (axis.Offset >= 0 && axis.Offset + byteLength <= _fileLength) return;
        axis.Offset = -1; axis.Confidence = 0;
    }
}

public partial class MapDefinitionImportWindow : Window
{
    private readonly long _fileLength;
    private long _suggestedBase;
    private bool _updatingBase;
    public ObservableCollection<MapDefinitionImportRow> Rows { get; } = [];
    public IReadOnlyList<EcuProjectMapDefinition> ImportedMaps { get; private set; } = [];

    public MapDefinitionImportWindow(string path, long fileLength, MapDefinitionImportResult result)
    {
        InitializeComponent();
        _fileLength = fileLength;
        SourceText.Text = $"{result.Format} · {System.IO.Path.GetFileName(path)}";
        WarningText.Text = string.Join("  ", result.Warnings.Take(4));
        _suggestedBase = SuggestBase(result.Maps, fileLength);
        foreach (var map in result.Maps)
        {
            var row = new MapDefinitionImportRow(fileLength) { Source = EcuMapTools.Clone(map), BaseAddress = _suggestedBase };
            row.IsSelected = row.IsValid;
            row.PropertyChanged += Row_PropertyChanged;
            Rows.Add(row);
        }
        DataContext = this;
        SetBaseText(_suggestedBase);
        RefreshStatus();
    }

    private static long SuggestBase(IReadOnlyList<EcuProjectMapDefinition> maps, long fileLength)
    {
        if (maps.Count == 0 || maps.Any(map => map.StartOffset < fileLength)) return 0;
        var minimum = maps.Min(map => map.StartOffset);
        var maximum = maps.Max(map => map.StartOffset);
        if (maximum - minimum >= fileLength) return 0;
        long alignment = 1;
        while (alignment < fileLength && alignment < 1L << 30) alignment <<= 1;
        var candidate = minimum & ~(alignment - 1);
        return maps.All(map => map.StartOffset - candidate >= 0 && map.StartOffset - candidate < fileLength)
            ? candidate : 0;
    }

    private void SetBaseText(long value)
    {
        _updatingBase = true; BaseAddressTextBox.Text = $"0x{value:X}"; _updatingBase = false;
        ApplyBase(value);
    }

    private void BaseAddressTextBox_TextChanged(object sender, WpfTextChangedEventArgs e)
    {
        if (_updatingBase) return;
        if (MapDefinitionWindow.TryParseOffset(BaseAddressTextBox.Text, out var value) && value >= 0)
        {
            BaseAddressTextBox.ClearValue(WpfControl.BorderBrushProperty);
            ApplyBase(value);
        }
        else BaseAddressTextBox.BorderBrush = System.Windows.Media.Brushes.OrangeRed;
    }

    private void ApplyBase(long value)
    {
        foreach (var row in Rows)
        {
            row.BaseAddress = value;
            if (!row.IsValid) row.IsSelected = false;
        }
        MapsGrid.Items.Refresh(); RefreshStatus();
    }

    private void AutoBaseButton_Click(object sender, RoutedEventArgs e) => SetBaseText(_suggestedBase);
    private void SelectValidButton_Click(object sender, RoutedEventArgs e)
    {
        foreach (var row in Rows) row.IsSelected = row.IsValid;
        RefreshStatus();
    }
    private void ClearButton_Click(object sender, RoutedEventArgs e)
    {
        foreach (var row in Rows) row.IsSelected = false;
        RefreshStatus();
    }
    private void Row_PropertyChanged(object? sender, PropertyChangedEventArgs e)
    {
        if (e.PropertyName == nameof(MapDefinitionImportRow.IsSelected)) RefreshStatus();
    }
    private void RefreshStatus()
    {
        var valid = Rows.Count(row => row.IsValid); var selected = Rows.Count(row => row.IsSelected && row.IsValid);
        CountText.Text = $"{Rows.Count:N0} maps · {valid:N0} valid · {selected:N0} selected";
        ImportButton.IsEnabled = selected > 0;
    }
    private void ImportButton_Click(object sender, RoutedEventArgs e)
    {
        ImportedMaps = Rows.Where(row => row.IsSelected && row.IsValid).Select(row => row.CreateAdjustedMap()).ToList();
        DialogResult = ImportedMaps.Count > 0;
    }
    private void CancelButton_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
