using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Windows;
using System.Windows.Data;
using BinaryHunter.Core.Projects;
using OpenFileDialog = Microsoft.Win32.OpenFileDialog;
using SaveFileDialog = Microsoft.Win32.SaveFileDialog;
using MessageBox = System.Windows.MessageBox;

namespace BinaryHunter.UI;

public sealed class MapManagerRow(EcuProjectMapDefinition definition)
{
    public EcuProjectMapDefinition Definition { get; set; } = definition;
    public string Name => Definition.Name;
    public string Category => Definition.Category;
    public string StartHex => $"0x{Definition.StartOffset:X8}";
    public string Dimensions => $"{Definition.Width} × {Definition.Height}";
    public string TypeLabel => $"{Definition.ValueType} / {(Definition.LittleEndian ? "LE" : "BE")}";
    public string XAxisLabel => AxisLabel(Definition.XAxis);
    public string YAxisLabel => AxisLabel(Definition.YAxis);
    public string Unit => Definition.Unit;
    private static string AxisLabel(EcuProjectAxisDefinition axis) => axis.Offset < 0
        ? "Not assigned"
        : $"0x{axis.Offset:X8} ({axis.Confidence:P0})";
}

public partial class MapManagerWindow : Window
{
    private readonly long _fileLength;
    private readonly long _suggestedOffset;
    private readonly int _suggestedWidth;
    private readonly int _suggestedHeight;
    private readonly EcuMapValueType _suggestedType;
    private readonly bool _suggestedLittleEndian;
    public ObservableCollection<MapManagerRow> Rows { get; } = [];
    public byte[] WorkingBytes { get; private set; }
    public IReadOnlyList<EcuProjectMapDefinition> Maps => Rows.Select(row => EcuMapTools.Clone(row.Definition)).ToList();
    public long? NavigateOffset { get; private set; }
    public int NavigateLength { get; private set; } = 1;

    public MapManagerWindow(byte[] bytes, IEnumerable<EcuProjectMapDefinition> maps,
        long suggestedOffset, int selectedByteLength, EcuMapValueType suggestedType, bool littleEndian)
    {
        InitializeComponent();
        _fileLength = bytes.LongLength;
        WorkingBytes = bytes.ToArray();
        _suggestedOffset = suggestedOffset;
        _suggestedType = suggestedType;
        _suggestedLittleEndian = littleEndian;
        var valueCount = Math.Max(1, selectedByteLength / EcuMapTools.ValueSize(suggestedType));
        _suggestedWidth = Math.Clamp((int)Math.Sqrt(valueCount), 1, 64);
        _suggestedHeight = Math.Max(1, (int)Math.Ceiling(valueCount / (double)_suggestedWidth));
        foreach (var map in maps) Rows.Add(new MapManagerRow(EcuMapTools.Clone(map)));
        DataContext = this;
        CollectionViewSource.GetDefaultView(Rows).GroupDescriptions.Add(
            new PropertyGroupDescription(nameof(MapManagerRow.Category)));
    }

    private MapManagerRow? Selected => MapsGrid.SelectedItem as MapManagerRow;

    private void AddButton_Click(object sender, RoutedEventArgs e)
    {
        var seed = new EcuProjectMapDefinition
        {
            StartOffset = _suggestedOffset, Width = _suggestedWidth, Height = _suggestedHeight,
            ValueType = _suggestedType, LittleEndian = _suggestedLittleEndian,
            XAxis = new EcuProjectAxisDefinition { Name = "X axis", Count = _suggestedWidth, ValueType = _suggestedType, LittleEndian = _suggestedLittleEndian },
            YAxis = new EcuProjectAxisDefinition { Name = "Y axis", Count = _suggestedHeight, ValueType = _suggestedType, LittleEndian = _suggestedLittleEndian }
        };
        var dialog = new MapDefinitionWindow(seed, _suggestedOffset, _suggestedWidth, _suggestedHeight, _fileLength) { Owner = this };
        if (dialog.ShowDialog() != true) return;
        var row = new MapManagerRow(dialog.Result);
        Rows.Add(row); MapsGrid.SelectedItem = row; MapsGrid.ScrollIntoView(row);
    }

    private void EditButton_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } row) return;
        var map = row.Definition;
        var dialog = new MapDefinitionWindow(map, map.StartOffset, map.Width, map.Height, _fileLength) { Owner = this };
        if (dialog.ShowDialog() != true) return;
        row.Definition = dialog.Result;
        MapsGrid.Items.Refresh();
    }

    private void DeleteButton_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is { } row) Rows.Remove(row);
    }

    private void ImportDefinitionsButton_Click(object sender, RoutedEventArgs e)
    {
        var fileDialog = new OpenFileDialog
        {
            Title = "Import DAMOS, A2L, Driver or Map Pack",
            Filter = "Calibration definitions|*.xdf;*.a2l;*.damos;*.dam;*.csv;*.tsv;*.txt;*.map;*.drv;*.json;*.bhmap;*.xml|" +
                     "TunerPro XDF|*.xdf|ASAM A2L / DAMOS|*.a2l;*.damos;*.dam|Driver / Map Pack|*.csv;*.tsv;*.txt;*.map;*.drv;*.json;*.bhmap;*.xml|All files|*.*"
        };
        if (fileDialog.ShowDialog(this) != true) return;
        MapDefinitionImportResult result;
        try { result = MapDefinitionImportService.Import(fileDialog.FileName); }
        catch (Exception exception)
        {
            MessageBox.Show(exception.Message, "Could not import calibration definitions",
                MessageBoxButton.OK, MessageBoxImage.Warning); return;
        }

        var preview = new MapDefinitionImportWindow(fileDialog.FileName, _fileLength, result) { Owner = this };
        if (preview.ShowDialog() != true) return;
        var imported = 0; var duplicates = 0;
        foreach (var map in preview.ImportedMaps)
        {
            if (Rows.Any(row => IsDuplicate(row.Definition, map))) { duplicates++; continue; }
            Rows.Add(new MapManagerRow(EcuMapTools.Clone(map))); imported++;
        }
        MapsGrid.Items.Refresh();
        StatusText.Text = $"Imported {imported:N0} {result.Format} map(s)" +
                          (duplicates == 0 ? "." : $"; skipped {duplicates:N0} duplicate(s).");
    }

    private static bool IsDuplicate(EcuProjectMapDefinition left, EcuProjectMapDefinition right) =>
        left.StartOffset == right.StartOffset && left.Width == right.Width && left.Height == right.Height &&
        left.ValueType == right.ValueType;

    private void ExportMapPackButton_Click(object sender, RoutedEventArgs e)
    {
        if (Rows.Count == 0) { StatusText.Text = "There are no maps to export."; return; }
        var dialog = new SaveFileDialog
        {
            Title = "Export BinaryHunter Map Pack", Filter = "BinaryHunter Map Pack|*.bhmap.json|JSON|*.json",
            DefaultExt = ".bhmap.json", FileName = "BinaryHunter-map-pack.bhmap.json"
        };
        if (dialog.ShowDialog(this) != true) return;
        try
        {
            MapDefinitionImportService.ExportJson(dialog.FileName, Rows.Select(row => row.Definition));
            StatusText.Text = $"Exported {Rows.Count:N0} map(s) to {System.IO.Path.GetFileName(dialog.FileName)}.";
        }
        catch (Exception exception)
        {
            MessageBox.Show(exception.Message, "Could not export map pack", MessageBoxButton.OK, MessageBoxImage.Warning);
        }
    }

    private void AutoGroupButton_Click(object sender, RoutedEventArgs e)
    {
        var changed = 0;
        foreach (var row in Rows)
        {
            if (!string.IsNullOrWhiteSpace(row.Definition.Category) &&
                !row.Definition.Category.Equals("Unclassified", StringComparison.OrdinalIgnoreCase)) continue;
            var category = MapCategoryClassifier.Classify(row.Definition.Name + " " + row.Definition.Comment);
            if (category == "Unclassified") continue;
            row.Definition.Category = category; changed++;
        }
        MapsGrid.Items.Refresh(); StatusText.Text = $"Automatically grouped {changed:N0} map(s).";
    }

    private void FindAxesButton_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } row) return;
        var result = AxisCandidateFinder.Find(WorkingBytes, row.Definition);
        if (result.X is not null) row.Definition.XAxis = result.X;
        if (result.Y is not null) row.Definition.YAxis = result.Y;
        MapsGrid.Items.Refresh();
        StatusText.Text = $"Axis search: X {(result.X is null ? "not found" : $"{result.X.Confidence:P0}")}, Y {(result.Y is null ? "not found" : $"{result.Y.Confidence:P0}")}.";
    }

    private void EditXAxisButton_Click(object sender, RoutedEventArgs e) => EditAxis(isXAxis: true);
    private void EditYAxisButton_Click(object sender, RoutedEventArgs e) => EditAxis(isXAxis: false);

    private void EditAxis(bool isXAxis)
    {
        if (Selected is not { } row) return;
        var axis = isXAxis ? row.Definition.XAxis : row.Definition.YAxis;
        if (axis.Offset < 0 || axis.Count <= 0)
        {
            StatusText.Text = "Assign the axis manually or run axis search first.";
            return;
        }
        var dialog = new AxisEditorWindow(WorkingBytes, axis) { Owner = this };
        if (dialog.ShowDialog() != true) return;
        WorkingBytes = dialog.ResultBytes;
        if (isXAxis) row.Definition.XAxis = dialog.ResultAxis; else row.Definition.YAxis = dialog.ResultAxis;
        MapsGrid.Items.Refresh();
        StatusText.Text = $"{axis.Name} values updated in the working document.";
    }

    private void GoZButton_Click(object sender, RoutedEventArgs e)
    {
        if (Selected is not { } row) return;
        NavigateOffset = row.Definition.StartOffset;
        NavigateLength = checked(row.Definition.Width * row.Definition.Height * EcuMapTools.ValueSize(row.Definition.ValueType));
        DialogResult = true;
    }
    private void GoXButton_Click(object sender, RoutedEventArgs e) => GoAxis(Selected?.Definition.XAxis);
    private void GoYButton_Click(object sender, RoutedEventArgs e) => GoAxis(Selected?.Definition.YAxis);
    private void GoAxis(EcuProjectAxisDefinition? axis)
    {
        if (axis is null || axis.Offset < 0) return;
        NavigateOffset = axis.Offset;
        NavigateLength = axis.Count * EcuMapTools.ValueSize(axis.ValueType);
        DialogResult = true;
    }

    private void SaveButton_Click(object sender, RoutedEventArgs e) => DialogResult = true;
    private void CancelButton_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
