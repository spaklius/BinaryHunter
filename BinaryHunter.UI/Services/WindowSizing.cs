using System.Windows;
using System.Windows.Interop;
using System.Windows.Media;
using Forms = System.Windows.Forms;

namespace BinaryHunter.UI.Services;

public static class WindowSizing
{
    public static void Configure(
        Window window,
        double preferredWidth,
        double preferredHeight,
        double maximumWidthRatio = 0.94,
        double maximumHeightRatio = 0.92)
    {
        window.SourceInitialized += (_, _) =>
        {
            var screen = Forms.Screen.FromHandle(new WindowInteropHelper(window).Handle);
            var source = PresentationSource.FromVisual(window);
            var fromDevice = source?.CompositionTarget?.TransformFromDevice ?? Matrix.Identity;
            var topLeft = fromDevice.Transform(new System.Windows.Point(screen.WorkingArea.Left, screen.WorkingArea.Top));
            var bottomRight = fromDevice.Transform(new System.Windows.Point(screen.WorkingArea.Right, screen.WorkingArea.Bottom));
            var workWidth = Math.Max(640, bottomRight.X - topLeft.X);
            var workHeight = Math.Max(480, bottomRight.Y - topLeft.Y);

            window.MaxWidth = workWidth;
            window.MaxHeight = workHeight;
            window.MinWidth = Math.Min(window.MinWidth, workWidth);
            window.MinHeight = Math.Min(window.MinHeight, workHeight);

            if (window.WindowState != WindowState.Normal) return;
            window.Width = Math.Min(preferredWidth, workWidth * maximumWidthRatio);
            window.Height = Math.Min(preferredHeight, workHeight * maximumHeightRatio);
        };
    }
}
