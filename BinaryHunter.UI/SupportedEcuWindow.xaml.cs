using System.Windows;
using BinaryHunter.UI.Models;
using BinaryHunter.UI.Services;

namespace BinaryHunter.UI;

public partial class SupportedEcuWindow : Window
{
    private readonly IReadOnlyList<SupportedEcuGroup> _groups;

    public SupportedEcuWindow(IReadOnlyList<SupportedEcuGroup> groups)
    {
        _groups = groups;
        InitializeComponent();
        WindowSizing.Configure(this, preferredWidth: 960, preferredHeight: 760);
        ProfileCountText.Text = $"{groups.Count} vehicle groups • {groups.Sum(group => group.Count)} automatic profiles";
        ApplyFilter();
    }

    private void FilterTextBox_TextChanged(object sender, System.Windows.Controls.TextChangedEventArgs e) => ApplyFilter();

    private void FilterCheckBox_Changed(object sender, RoutedEventArgs e) => ApplyFilter();

    private void ApplyFilter()
    {
        if (GroupsControl is null) return;
        var filter = FilterTextBox?.Text?.Trim() ?? string.Empty;
        var hideBase = HideBaseCheckBox?.IsChecked == true;
        GroupsControl.ItemsSource = _groups
            .Select(group => new SupportedEcuGroup(
                group.VehicleBrand,
                group.BrandCode,
                group.Profiles.Where(profile =>
                    (filter.Length == 0 ||
                     profile.Name.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                     profile.ImageSize.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                     group.VehicleBrand.Contains(filter, StringComparison.OrdinalIgnoreCase) ||
                     group.BrandCode.Contains(filter, StringComparison.OrdinalIgnoreCase)) &&
                    (!hideBase || !profile.IsDraft)).ToArray()))
            .Where(group => group.Count > 0)
            .ToArray();
    }

    private void CloseButton_Click(object sender, RoutedEventArgs e) => Close();
}
