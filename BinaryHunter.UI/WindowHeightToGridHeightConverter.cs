using System.Globalization;
using System.Windows.Data;

namespace BinaryHunter.UI;

public sealed class WindowHeightToGridHeightConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var windowHeight = value is double height ? height : 800d;
        var reservedHeight = double.TryParse(
            parameter?.ToString(),
            NumberStyles.Float,
            CultureInfo.InvariantCulture,
            out var reserved)
            ? reserved
            : 610d;
        return Math.Clamp(windowHeight - reservedHeight, 190d, 430d);
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        throw new NotSupportedException();
}
