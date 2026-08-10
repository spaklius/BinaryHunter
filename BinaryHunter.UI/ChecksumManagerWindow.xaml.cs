using BinaryHunter.Core.Plugins;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows;

namespace BinaryHunter.UI;

public sealed class ChecksumBlockRow
{
    public required ChecksumBlockDefinition Definition { get; init; }
    public string Name { get => Definition.Name; set => Definition.Name = value; }
    public string Algorithm { get => Definition.PluginId.Length > 0 ? "Plugin" : Definition.Algorithm.ToString(); set { if (Enum.TryParse<BinaryChecksumAlgorithm>(value, true, out var parsed)) { Definition.Algorithm = parsed; Definition.PluginId = string.Empty; } } }
    public string RangeStartText { get => $"0x{Definition.RangeStart:X}"; set { if (TryNumber(value, out var parsed)) Definition.RangeStart = parsed; } }
    public string RangeLengthText { get => $"0x{Definition.RangeLength:X}"; set { if (TryNumber(value, out var parsed)) Definition.RangeLength = parsed; } }
    public string StoreOffsetText { get => $"0x{Definition.StoreOffset:X}"; set { if (TryNumber(value, out var parsed)) Definition.StoreOffset = parsed; } }
    public int StoredByteCount { get => Definition.StoredByteCount; set => Definition.StoredByteCount = Math.Clamp(value, 1, 8); }
    public bool LittleEndian { get => Definition.LittleEndian; set => Definition.LittleEndian = value; }
    public bool AutomaticCorrection { get => Definition.AutomaticCorrection; set => Definition.AutomaticCorrection = value; }
    public string Status { get; set; } = "Not checked";
    private static bool TryNumber(string text, out long value) => MapDefinitionWindow.TryParseOffset(text, out value);
}

public partial class ChecksumManagerWindow : Window
{
    public ObservableCollection<ChecksumBlockRow> Rows { get; } = [];
    public byte[] WorkingBytes { get; private set; }
    public IReadOnlyList<ChecksumBlockDefinition> Definitions => Rows.Select(row => Clone(row.Definition)).ToList();
    private ChecksumBlockRow? Selected => BlocksGrid.SelectedItem as ChecksumBlockRow;

    public ChecksumManagerWindow(byte[] bytes, IEnumerable<ChecksumBlockDefinition> definitions)
    {
        InitializeComponent(); WorkingBytes = bytes.ToArray();
        foreach (var definition in definitions) Rows.Add(new ChecksumBlockRow { Definition = Clone(definition) });
        DataContext = this; RefreshStatuses();
    }

    private void AddButton_Click(object sender, RoutedEventArgs e)
    {
        var bytes = WorkingBytes.LongLength >= 2 ? 2 : 1;
        var definition = new ChecksumBlockDefinition
        {
            Name = "Manual additive checksum", RangeStart = 0,
            RangeLength = Math.Max(1, WorkingBytes.LongLength - bytes),
            StoreOffset = Math.Max(0, WorkingBytes.LongLength - bytes), StoredByteCount = bytes,
            Algorithm = bytes == 1 ? BinaryChecksumAlgorithm.Additive8 : BinaryChecksumAlgorithm.Additive16
        };
        var row = new ChecksumBlockRow { Definition = definition }; Rows.Add(row); BlocksGrid.SelectedItem = row; RefreshStatuses();
    }
    private void DeleteButton_Click(object sender, RoutedEventArgs e) { if (Selected is { } row) Rows.Remove(row); }
    private async void SearchPluginsButton_Click(object sender, RoutedEventArgs e)
    {
        StatusText.Text = "Searching checksum plugins...";
        var snapshot = WorkingBytes.ToArray();
        List<(IChecksumPlugin plugin, ChecksumPluginCandidate candidate)> found;
        try
        {
            found = await Task.Run(() => PluginCatalog.ChecksumPlugins()
                .SelectMany(plugin => plugin.Detect(snapshot, CancellationToken.None)
                    .Select(candidate => (plugin, candidate))).ToList());
        }
        catch (Exception exception)
        {
            StatusText.Text = "Plugin search failed: " + exception.Message; return;
        }
        var added = 0;
        foreach (var (plugin, candidate) in found)
        {
            if (Rows.Any(row => row.Definition.PluginId == plugin.Id && row.Definition.StoreOffset == candidate.StoreOffset)) continue;
            Rows.Add(new ChecksumBlockRow { Definition = new ChecksumBlockDefinition
            {
                Name = candidate.Name, PluginId = plugin.Id, RangeStart = candidate.RangeStart,
                RangeLength = candidate.RangeLength, StoreOffset = candidate.StoreOffset,
                StoredByteCount = candidate.StoredByteCount, LittleEndian = candidate.LittleEndian,
                Description = candidate.Description
            }}); added++;
        }
        RefreshStatuses(); StatusText.Text = $"Checksum plugin search found {added:N0} new block(s).";
    }
    private void ApplySelectedButton_Click(object sender, RoutedEventArgs e) { if (Selected is { } row) Apply(row); }
    private void ApplyAllButton_Click(object sender, RoutedEventArgs e)
    {
        var applied = 0; foreach (var row in Rows) { if (Apply(row, false)) applied++; }
        RefreshStatuses(); StatusText.Text = $"Applied {applied:N0} checksum block(s) to the working copy.";
    }
    private bool Apply(ChecksumBlockRow row, bool refresh = true)
    {
        try { ChecksumTools.Apply(WorkingBytes, row.Definition); if (refresh) { RefreshStatuses(); StatusText.Text = $"Applied {row.Name}."; } return true; }
        catch (Exception exception) { row.Status = "Invalid · " + exception.Message; BlocksGrid.Items.Refresh(); return false; }
    }
    private void RefreshStatuses() { foreach (var row in Rows) row.Status = ChecksumTools.Status(WorkingBytes, row.Definition); BlocksGrid.Items.Refresh(); StatusText.Text = $"{Rows.Count:N0} checksum block(s)."; }
    private void PluginInfoButton_Click(object sender, RoutedEventArgs e) => new PluginInfoWindow { Owner = this }.ShowDialog();
    private void SaveButton_Click(object sender, RoutedEventArgs e) => DialogResult = true;
    private void CancelButton_Click(object sender, RoutedEventArgs e) => DialogResult = false;
    private static ChecksumBlockDefinition Clone(ChecksumBlockDefinition value) => new()
    {
        Id = value.Id, Name = value.Name, RangeStart = value.RangeStart, RangeLength = value.RangeLength,
        StoreOffset = value.StoreOffset, StoredByteCount = value.StoredByteCount, LittleEndian = value.LittleEndian,
        Algorithm = value.Algorithm, AutomaticCorrection = value.AutomaticCorrection,
        PluginId = value.PluginId, Description = value.Description
    };
}
