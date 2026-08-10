using System.Globalization;
using System.Windows;
using System.Windows.Controls;

namespace BinaryHunter.UI;

public enum NumericConversionAction { DisplayOnly, TransformSelection }

public partial class NumericConversionWindow : Window
{
    private readonly double _sample;
    public NumericConversionProfile ResultProfile { get; private set; } = NumericConversionProfile.Default;
    public NumericConversionAction ResultAction { get; private set; }

    public NumericConversionWindow(NumericConversionProfile profile, double sample)
    {
        InitializeComponent();
        _sample = sample;
        FactorTextBox.Text = profile.Factor.ToString("G17", CultureInfo.InvariantCulture);
        OffsetTextBox.Text = profile.Offset.ToString("G17", CultureInfo.InvariantCulture);
        FormulaTextBox.Text = profile.Formula;
        UnitTextBox.Text = profile.Unit;
        UpdatePreview();
    }

    private bool TryCreateProfile(out NumericConversionProfile profile)
    {
        profile = NumericConversionProfile.Default;
        if (!double.TryParse(FactorTextBox.Text, NumberStyles.Float, CultureInfo.InvariantCulture, out var factor) || !double.IsFinite(factor))
        {
            ValidationText.Text = "Factor must be a finite number using a decimal point.";
            return false;
        }
        if (!double.TryParse(OffsetTextBox.Text, NumberStyles.Float, CultureInfo.InvariantCulture, out var offset) || !double.IsFinite(offset))
        {
            ValidationText.Text = "Offset must be a finite number using a decimal point.";
            return false;
        }
        if (!NumericFormula.TryEvaluate(FormulaTextBox.Text, _sample, out _, out var error))
        {
            ValidationText.Text = error;
            return false;
        }
        profile = new NumericConversionProfile(factor, offset,
            string.IsNullOrWhiteSpace(FormulaTextBox.Text) ? "x" : FormulaTextBox.Text.Trim(), UnitTextBox.Text.Trim());
        ValidationText.Text = string.Empty;
        return true;
    }

    private void UpdatePreview()
    {
        if (PreviewText is null || !TryCreateProfile(out var profile))
        {
            if (PreviewText is not null) PreviewText.Text = "Preview unavailable";
            return;
        }
        var result = profile.Convert(_sample);
        PreviewText.Text = $"Sample: {_sample:G9}  →  {result:G9}{(string.IsNullOrWhiteSpace(profile.Unit) ? string.Empty : " " + profile.Unit)}";
    }

    private void Input_TextChanged(object sender, TextChangedEventArgs e) => UpdatePreview();
    private void DisplayButton_Click(object sender, RoutedEventArgs e) => Complete(NumericConversionAction.DisplayOnly);
    private void TransformButton_Click(object sender, RoutedEventArgs e) => Complete(NumericConversionAction.TransformSelection);

    private void Complete(NumericConversionAction action)
    {
        if (!TryCreateProfile(out var profile)) return;
        ResultProfile = profile;
        ResultAction = action;
        DialogResult = true;
    }

    private void ResetButton_Click(object sender, RoutedEventArgs e)
    {
        FactorTextBox.Text = "1";
        OffsetTextBox.Text = "0";
        FormulaTextBox.Text = "x";
        UnitTextBox.Text = string.Empty;
    }

    private void CancelButton_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
