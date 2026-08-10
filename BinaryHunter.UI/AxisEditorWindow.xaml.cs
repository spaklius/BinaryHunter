using System.Collections.ObjectModel;
using System.Globalization;
using System.Windows;
using BinaryHunter.Core.Projects;

namespace BinaryHunter.UI;

public sealed class AxisValueRow
{
    public int Index { get; init; }
    public long Offset { get; init; }
    public string HexOffset => $"0x{Offset:X8}";
    public string RawText { get; init; } = string.Empty;
    public string EngineeringText { get; set; } = string.Empty;
}

public partial class AxisEditorWindow : Window
{
    private readonly byte[] _sourceBytes;
    private readonly EcuProjectAxisDefinition _sourceAxis;
    public ObservableCollection<AxisValueRow> Values { get; } = [];
    public byte[] ResultBytes { get; private set; }
    public EcuProjectAxisDefinition ResultAxis { get; private set; }

    public AxisEditorWindow(byte[] bytes, EcuProjectAxisDefinition axis)
    {
        InitializeComponent();
        _sourceBytes = bytes;
        ResultBytes = bytes;
        _sourceAxis = EcuMapTools.Clone(axis);
        ResultAxis = EcuMapTools.Clone(axis);
        DataContext = this;
        FactorTextBox.Text = axis.Factor.ToString("G17", CultureInfo.InvariantCulture);
        OffsetTextBox.Text = axis.ValueOffset.ToString("G17", CultureInfo.InvariantCulture);
        UnitTextBox.Text = axis.Unit;
        AxisInfoText.Text = $"{axis.Name}  •  0x{axis.Offset:X8}  •  {axis.Count} × {axis.ValueType}  •  {(axis.LittleEndian ? "Intel LE" : "Motorola BE")}";
        LoadValues();
    }

    private void LoadValues()
    {
        var size = EcuMapTools.ValueSize(_sourceAxis.ValueType);
        for (var index = 0; index < _sourceAxis.Count; index++)
        {
            var offset = _sourceAxis.Offset + index * size;
            if (offset < 0 || offset + size > _sourceBytes.LongLength) break;
            var raw = EcuMapTools.Decode(_sourceBytes, offset, _sourceAxis.ValueType, _sourceAxis.LittleEndian);
            var engineering = raw * _sourceAxis.Factor + _sourceAxis.ValueOffset;
            Values.Add(new AxisValueRow
            {
                Index = index, Offset = offset, RawText = raw.ToString("G12", CultureInfo.InvariantCulture),
                EngineeringText = engineering.ToString("G12", CultureInfo.InvariantCulture)
            });
        }
    }

    private void SaveButton_Click(object sender, RoutedEventArgs e)
    {
        if (!double.TryParse(FactorTextBox.Text, NumberStyles.Float, CultureInfo.InvariantCulture, out var factor) ||
            !double.IsFinite(factor) || factor == 0 ||
            !double.TryParse(OffsetTextBox.Text, NumberStyles.Float, CultureInfo.InvariantCulture, out var valueOffset) ||
            !double.IsFinite(valueOffset))
        {
            ValidationText.Text = "Factor must be non-zero and factor/offset must be finite.";
            return;
        }
        var result = _sourceBytes.ToArray();
        try
        {
            foreach (var row in Values)
            {
                if (!double.TryParse(row.EngineeringText, NumberStyles.Float, CultureInfo.InvariantCulture, out var engineering) || !double.IsFinite(engineering))
                    throw new FormatException($"Row {row.Index}: invalid engineering value.");
                var raw = (engineering - valueOffset) / factor;
                var encoded = EcuMapTools.Encode(raw, _sourceAxis.ValueType, _sourceAxis.LittleEndian);
                Buffer.BlockCopy(encoded, 0, result, (int)row.Offset, encoded.Length);
            }
        }
        catch (Exception exception) when (exception is FormatException or OverflowException)
        {
            ValidationText.Text = exception.Message;
            return;
        }
        ResultAxis = EcuMapTools.Clone(_sourceAxis);
        ResultAxis.Factor = factor;
        ResultAxis.ValueOffset = valueOffset;
        ResultAxis.Unit = UnitTextBox.Text.Trim();
        ResultBytes = result;
        DialogResult = true;
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
