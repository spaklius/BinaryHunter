using System.Globalization;
using System.Windows;
using BinaryHunter.Core.Projects;

namespace BinaryHunter.UI;

public partial class MapDefinitionWindow : Window
{
    private readonly long _fileLength;
    private readonly EcuProjectMapDefinition _source;
    public EcuProjectMapDefinition Result { get; private set; }

    public MapDefinitionWindow(EcuProjectMapDefinition? source, long suggestedOffset,
        int suggestedWidth, int suggestedHeight, long fileLength)
    {
        InitializeComponent();
        _fileLength = fileLength;
        _source = source is null ? new EcuProjectMapDefinition
        {
            StartOffset = suggestedOffset,
            Width = suggestedWidth,
            Height = suggestedHeight,
            XAxis = new EcuProjectAxisDefinition { Name = "X axis", Count = suggestedWidth },
            YAxis = new EcuProjectAxisDefinition { Name = "Y axis", Count = suggestedHeight }
        } : EcuMapTools.Clone(source);
        Result = EcuMapTools.Clone(_source);
        ValueTypeComboBox.ItemsSource = Enum.GetValues<EcuMapValueType>();
        Populate();
    }

    private void Populate()
    {
        NameTextBox.Text = _source.Name;
        CategoryTextBox.Text = _source.Category;
        StartTextBox.Text = $"0x{_source.StartOffset:X}";
        WidthTextBox.Text = _source.Width.ToString(CultureInfo.InvariantCulture);
        HeightTextBox.Text = _source.Height.ToString(CultureInfo.InvariantCulture);
        ValueTypeComboBox.SelectedItem = _source.ValueType;
        EndianComboBox.SelectedIndex = _source.LittleEndian ? 0 : 1;
        FactorTextBox.Text = _source.Factor.ToString("G17", CultureInfo.InvariantCulture);
        ValueOffsetTextBox.Text = _source.Offset.ToString("G17", CultureInfo.InvariantCulture);
        UnitTextBox.Text = _source.Unit;
        XAxisTextBox.Text = _source.XAxis.Offset < 0 ? string.Empty : $"0x{_source.XAxis.Offset:X}";
        YAxisTextBox.Text = _source.YAxis.Offset < 0 ? string.Empty : $"0x{_source.YAxis.Offset:X}";
        XCountTextBox.Text = _source.XAxis.Count.ToString(CultureInfo.InvariantCulture);
        YCountTextBox.Text = _source.YAxis.Count.ToString(CultureInfo.InvariantCulture);
        CommentTextBox.Text = _source.Comment;
    }

    private void SaveButton_Click(object sender, RoutedEventArgs e)
    {
        if (!TryParseOffset(StartTextBox.Text, out var start) || start < 0 || start >= _fileLength)
        {
            ValidationText.Text = "Z start offset is outside the file.";
            return;
        }
        if (!int.TryParse(WidthTextBox.Text, out var width) || width is < 1 or > 4096 ||
            !int.TryParse(HeightTextBox.Text, out var height) || height is < 1 or > 4096)
        {
            ValidationText.Text = "Width and height must be between 1 and 4096.";
            return;
        }
        if (ValueTypeComboBox.SelectedItem is not EcuMapValueType valueType)
        {
            ValidationText.Text = "Choose a data type.";
            return;
        }
        var byteLength = (long)width * height * EcuMapTools.ValueSize(valueType);
        if (start + byteLength > _fileLength)
        {
            ValidationText.Text = "The configured Z map extends beyond the file.";
            return;
        }
        if (!double.TryParse(FactorTextBox.Text, NumberStyles.Float, CultureInfo.InvariantCulture, out var factor) || factor == 0 || !double.IsFinite(factor) ||
            !double.TryParse(ValueOffsetTextBox.Text, NumberStyles.Float, CultureInfo.InvariantCulture, out var valueOffset) || !double.IsFinite(valueOffset))
        {
            ValidationText.Text = "Factor must be non-zero and factor/offset must be finite numbers.";
            return;
        }
        if (!TryParseOptionalAxis(XAxisTextBox.Text, XCountTextBox.Text, out var xOffset, out var xCount) ||
            !TryParseOptionalAxis(YAxisTextBox.Text, YCountTextBox.Text, out var yOffset, out var yCount))
        {
            ValidationText.Text = "Axis offset/count is invalid.";
            return;
        }

        Result = EcuMapTools.Clone(_source);
        Result.Name = string.IsNullOrWhiteSpace(NameTextBox.Text) ? "Unnamed map" : NameTextBox.Text.Trim();
        Result.Category = string.IsNullOrWhiteSpace(CategoryTextBox.Text) ? "Unclassified" : CategoryTextBox.Text.Trim();
        Result.StartOffset = start; Result.Width = width; Result.Height = height;
        Result.ValueType = valueType; Result.LittleEndian = EndianComboBox.SelectedIndex == 0;
        Result.Factor = factor; Result.Offset = valueOffset; Result.Unit = UnitTextBox.Text.Trim();
        Result.Comment = CommentTextBox.Text.Trim();
        Result.XAxis.Offset = xOffset; Result.XAxis.Count = xCount; Result.XAxis.ValueType = valueType; Result.XAxis.LittleEndian = Result.LittleEndian;
        Result.YAxis.Offset = yOffset; Result.YAxis.Count = yCount; Result.YAxis.ValueType = valueType; Result.YAxis.LittleEndian = Result.LittleEndian;
        DialogResult = true;
    }

    private bool TryParseOptionalAxis(string offsetText, string countText, out long offset, out int count)
    {
        offset = -1;
        count = 0;
        if (string.IsNullOrWhiteSpace(offsetText)) return true;
        return TryParseOffset(offsetText, out offset) && offset >= 0 && offset < _fileLength &&
               int.TryParse(countText, out count) && count is >= 1 and <= 4096;
    }

    internal static bool TryParseOffset(string text, out long value)
    {
        text = text.Trim();
        if (text.StartsWith("0x", StringComparison.OrdinalIgnoreCase))
            return long.TryParse(text.AsSpan(2), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out value);
        return long.TryParse(text, NumberStyles.Integer, CultureInfo.InvariantCulture, out value);
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
