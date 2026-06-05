using System.Windows;

namespace SyslogPusher.UI;

public static class UiLauncher
{
    [STAThread]
    public static void Run(string[] args)
    {
        var app = new App();
        app.InitializeComponent();
        app.Run();
    }
}
