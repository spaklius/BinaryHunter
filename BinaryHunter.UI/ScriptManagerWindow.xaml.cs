using BinaryHunter.Core.Projects;
using System.IO;
using System.Windows;
using OpenFileDialog = Microsoft.Win32.OpenFileDialog;
using SaveFileDialog = Microsoft.Win32.SaveFileDialog;

namespace BinaryHunter.UI;

public partial class ScriptManagerWindow : Window
{
    private readonly byte[] _source;
    private BinaryHunterScriptResult? _preview;
    public byte[] ResultBytes { get; private set; }
    public IReadOnlyList<EcuProjectMapDefinition> ResultMaps { get; private set; } = [];
    public ScriptManagerWindow(byte[] bytes)
    {
        InitializeComponent(); _source = bytes; ResultBytes = bytes.ToArray(); TemplateButton_Click(this, new RoutedEventArgs());
    }
    private void OpenButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFileDialog { Title = "Open BinaryHunter script", Filter = "BinaryHunter scripts|*.bhscript;*.txt|All files|*.*" };
        if (dialog.ShowDialog(this) == true) ScriptTextBox.Text = File.ReadAllText(dialog.FileName);
    }
    private void SaveButton_Click(object sender, RoutedEventArgs e)
    {
        var dialog = new SaveFileDialog { Title = "Save BinaryHunter script", Filter = "BinaryHunter script|*.bhscript|Text file|*.txt", DefaultExt = ".bhscript" };
        if (dialog.ShowDialog(this) == true) File.WriteAllText(dialog.FileName, ScriptTextBox.Text);
    }
    private void TemplateButton_Click(object sender, RoutedEventArgs e) => ScriptTextBox.Text =
        "// BinaryHunter safe automation script\n" +
        $"require_size 0x{_source.Length:X} 0x{_source.Length:X}\n" +
        "// assert 0x100 \"01 02 03 04\"\n// set 0x100 \"01 02 03 04\"\n" +
        "// replace_all \"AA BB CC\" \"11 22 33\"\n// fill 0x200 0x10 FF\n" +
        "// map \"Boost target\" 0x1000 16 16 Unsigned16 intel \"Boost\"\n";
    private void PreviewButton_Click(object sender, RoutedEventArgs e)
    {
        _preview = BinaryHunterScriptEngine.Preview(ScriptTextBox.Text, _source);
        LogTextBox.Text = string.Join(Environment.NewLine, _preview.Log); ApplyButton.IsEnabled = _preview.Success;
        StatusText.Text = _preview.Success ? $"Ready · {_preview.ChangedBytes:N0} byte(s) · {_preview.Maps.Count:N0} map(s)" : "Preview failed";
    }
    private void ApplyButton_Click(object sender, RoutedEventArgs e)
    {
        if (_preview is not { Success: true }) return; ResultBytes = _preview.Bytes; ResultMaps = _preview.Maps; DialogResult = true;
    }
    private void CloseButton_Click(object sender, RoutedEventArgs e) => DialogResult = false;
}
