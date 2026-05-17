using System.Windows;

namespace SyslogPusher.UI;

public partial class App : Application
{
    private void OnStartup(object sender, StartupEventArgs e)
    {
        Current.MainWindow = StartupRouter.CreateMainWindow(e.Args);
        Current.MainWindow.Show();
    }
}
