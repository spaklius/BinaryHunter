using System;
using System.Globalization;
using System.Windows.Data;

namespace BinaryHunter.UI;

public sealed class SelectedDetectorConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var detectorName = value as string;
        return string.Equals(detectorName, MainWindow.Instance?._selectedDetectorName, StringComparison.OrdinalIgnoreCase);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture)
    {
        throw new NotSupportedException();
    }
}
