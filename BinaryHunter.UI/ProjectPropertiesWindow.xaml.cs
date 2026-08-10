using System.Windows;
using BinaryHunter.Core.Projects;
using MessageBox = System.Windows.MessageBox;

namespace BinaryHunter.UI;

public partial class ProjectPropertiesWindow : Window
{
    private readonly EcuProjectSession _session;
    private readonly EcuProjectService _service;
    public event EventHandler? ProjectSaved;

    public ProjectPropertiesWindow(EcuProjectSession session, EcuProjectService service, int selectedTab = 0)
    {
        InitializeComponent();
        _session = session;
        _service = service;
        PropertiesTabs.SelectedIndex = Math.Clamp(selectedTab, 0, PropertiesTabs.Items.Count - 1);
        LoadValues();
    }

    public void SelectTab(int index)
    {
        PropertiesTabs.SelectedIndex = Math.Clamp(index, 0, PropertiesTabs.Items.Count - 1);
        Activate();
    }

    private void LoadValues()
    {
        var manifest = _session.Manifest;
        var version = _session.ActiveVersion;
        ProjectPathText.Text = _session.ManifestPath;
        ProjectNameTextBox.Text = manifest.Name;
        ProjectCommentTextBox.Text = manifest.Description;
        ProjectIdText.Text = manifest.ProjectId.ToString();
        CreatedText.Text = manifest.CreatedUtc.ToLocalTime().ToString("g");
        UpdatedText.Text = manifest.UpdatedUtc.ToLocalTime().ToString("g");
        SourcesText.Text = $"{manifest.Sources.Count:N0} imported source file(s)";
        VersionsText.Text = $"{manifest.Versions.Count:N0} stored version(s)";
        VersionNameTextBox.Text = version?.Name ?? string.Empty;
        VersionCommentTextBox.Text = version?.Comment ?? string.Empty;
        VersionHashTextBox.Text = version?.Sha256 ?? string.Empty;
        MetadataGrid.ItemsSource = manifest.Metadata.OrderBy(item => item.Key).ToList();
        HistoryGrid.ItemsSource = manifest.History.OrderByDescending(item => item.TimestampUtc).ToList();
        StatusText.Text = version is null ? "Project has no active version" : $"Active version V{version.Number:D4}";
    }

    private void SaveButton_Click(object sender, RoutedEventArgs e)
    {
        var name = ProjectNameTextBox.Text.Trim();
        if (name.Length == 0)
        {
            MessageBox.Show("Project name cannot be empty.", "Project properties",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }
        var manifest = _session.Manifest;
        var oldComment = manifest.Description;
        manifest.Name = name;
        manifest.Description = ProjectCommentTextBox.Text.Trim();
        if (_session.ActiveVersion is { } version)
        {
            version.Name = string.IsNullOrWhiteSpace(VersionNameTextBox.Text)
                ? version.Name : VersionNameTextBox.Text.Trim();
            version.Comment = VersionCommentTextBox.Text.Trim();
        }
        if (!string.Equals(oldComment, manifest.Description, StringComparison.Ordinal))
            manifest.History.Insert(0, new EcuProjectHistoryEntry
            {
                Kind = EcuProjectHistoryKind.Note,
                Title = "Project comment updated",
                Details = manifest.Description,
                VersionId = manifest.ActiveVersionId
            });
        _service.SaveManifest(_session);
        LoadValues();
        ProjectSaved?.Invoke(this, EventArgs.Empty);
        StatusText.Text = "Project properties saved";
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();
}
