using System.Windows;
using System.Windows.Input;
using BinaryHunter.Core.Projects;

namespace BinaryHunter.UI;

public partial class ProjectHistoryWindow : Window
{
    public EcuProjectVersion? SelectedVersion { get; private set; }

    public ProjectHistoryWindow(EcuProjectSession session)
    {
        InitializeComponent();
        ProjectNameText.Text = session.Manifest.Name;
        ProjectPathText.Text = session.ManifestPath;
        VersionsGrid.ItemsSource = session.Manifest.Versions.OrderByDescending(version => version.Number).ToList();
        HistoryGrid.ItemsSource = session.Manifest.History.OrderByDescending(entry => entry.TimestampUtc).ToList();
        SummaryText.Text = $"{session.Manifest.Versions.Count:N0} version(s)  /  {session.Manifest.Sources.Count:N0} source file(s)";
        VersionsGrid.SelectedItem = session.ActiveVersion;
    }

    private void OpenVersionButton_Click(object sender, RoutedEventArgs e) => OpenSelectedVersion();

    private void VersionsGrid_MouseDoubleClick(object sender, MouseButtonEventArgs e) => OpenSelectedVersion();

    private void OpenSelectedVersion()
    {
        if (VersionsGrid.SelectedItem is not EcuProjectVersion version) return;
        SelectedVersion = version;
        DialogResult = true;
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();
}