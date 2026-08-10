using System.Globalization;
using System.Windows;
using System.Windows.Controls;

namespace BinaryHunter.UI;

public partial class DataProcessingWindow : Window
{
    private readonly double[] _values;
    private readonly int _width;
    private readonly int _height;
    public double[] ResultValues { get; private set; }

    public DataProcessingWindow(double[] values, int width, int height, string scopeName)
    {
        InitializeComponent();
        _values = values;
        _width = width;
        _height = height;
        ResultValues = values;
        OperationComboBox.ItemsSource = Enum.GetValues<SignalProcessingOperation>();
        OperationComboBox.SelectedIndex = 0;
        ScopeText.Text = $"{scopeName}  •  {width} × {height}  •  {values.Length:N0} values";
        UpdatePreview();
    }

    private bool TryProcess(out double[] result)
    {
        result = _values;
        if (OperationComboBox.SelectedItem is not SignalProcessingOperation operation ||
            !int.TryParse(RadiusTextBox.Text, out var radius) || radius is < 1 or > 12 ||
            !int.TryParse(IterationsTextBox.Text, out var iterations) || iterations is < 1 or > 20)
        {
            ValidationText.Text = "Radius must be 1–12 and iterations 1–20.";
            return false;
        }
        result = SignalProcessingEngine.Process(_values, _width, _height, operation, radius, iterations, StrengthSlider.Value);
        ValidationText.Text = string.Empty;
        return true;
    }

    private void UpdatePreview()
    {
        if (BeforeText is null || !TryProcess(out var result)) return;
        var before = SignalProcessingEngine.Analyze(_values, _width, _height);
        var after = SignalProcessingEngine.Analyze(result, _width, _height);
        BeforeText.Text = $"Before  Min/Max {before.Minimum:G7}/{before.Maximum:G7}  •  Noise {before.NoiseSigma:G6}  •  Roughness {before.Roughness:G6}  •  Peaks {before.Peaks.Count}";
        AfterText.Text = $"After   Min/Max {after.Minimum:G7}/{after.Maximum:G7}  •  Noise {after.NoiseSigma:G6}  •  Roughness {after.Roughness:G6}  •  Peaks {after.Peaks.Count}";
        StrengthText.Text = StrengthSlider.Value.ToString("P0", CultureInfo.InvariantCulture);
    }

    private void ApplyButton_Click(object sender, RoutedEventArgs e)
    {
        if (!TryProcess(out var result)) return;
        ResultValues = result;
        DialogResult = true;
    }
    private void Input_Changed(object sender, SelectionChangedEventArgs e) => UpdatePreview();
    private void Input_TextChanged(object sender, TextChangedEventArgs e) => UpdatePreview();
    private void Input_ValueChanged(object sender, RoutedPropertyChangedEventArgs<double> e) => UpdatePreview();
    private void CancelButton_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
