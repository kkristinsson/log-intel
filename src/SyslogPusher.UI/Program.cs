using System.Windows;
using SyslogPusher.Core;

namespace SyslogPusher.UI;

public static class Program
{
    [STAThread]
    public static void Main(string[] args)
    {
        if (args.Contains(AppPaths.ServiceModeArgument, StringComparer.OrdinalIgnoreCase))
        {
            ServiceHost.RunAsync(args).GetAwaiter().GetResult();
            return;
        }

        var app = new App();
        app.InitializeComponent();
        app.Run();
    }
}
