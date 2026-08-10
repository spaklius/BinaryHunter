using System.Windows;

namespace BinaryHunter.UI;

public partial class PluginInfoWindow : Window
{
    public PluginInfoWindow() { InitializeComponent(); Refresh(false); }
    private void Refresh(bool force)
    {
        var items = PluginCatalog.Load(force); PluginsGrid.ItemsSource = items;
        StatusText.Text = $"{items.Count:N0} module(s) · {items.Count(item => item.Status == "Ready" || item.Status == "Loaded"):N0} available";
    }
    private void RefreshButton_Click(object sender, RoutedEventArgs e) => Refresh(true);
    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();
}
