using System.Windows;
using System.Windows.Threading;

namespace BinaryHunter.UI
{
    /// <summary>
    /// Interaction logic for App.xaml
    /// </summary>
    public partial class App : System.Windows.Application
    {
        protected override void OnStartup(StartupEventArgs e)
        {
            base.OnStartup(e);

            DispatcherUnhandledException += OnDispatcherUnhandledException;
            AppDomain.CurrentDomain.UnhandledException += OnDomainUnhandledException;
            TaskScheduler.UnobservedTaskException += OnUnobservedTaskException;
        }

        private static void OnDispatcherUnhandledException(object sender, DispatcherUnhandledExceptionEventArgs e)
        {
            System.Windows.MessageBox.Show(
                $"BinaryHunter hit an unexpected error and cannot continue:\n\n{e.Exception.Message}",
                "BinaryHunter", MessageBoxButton.OK, MessageBoxImage.Error);
            e.Handled = true;
        }

        private static void OnDomainUnhandledException(object sender, UnhandledExceptionEventArgs e)
        {
            if (e.ExceptionObject is Exception exception)
            {
                System.Windows.MessageBox.Show(
                    $"BinaryHunter hit an unrecoverable error:\n\n{exception.Message}",
                    "BinaryHunter", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        private static void OnUnobservedTaskException(object? sender, UnobservedTaskExceptionEventArgs e)
        {
            System.Windows.MessageBox.Show(
                $"BinaryHunter hit an unobserved task error:\n\n{e.Exception.Message}",
                "BinaryHunter", MessageBoxButton.OK, MessageBoxImage.Error);
            e.SetObserved();
        }
    }
}