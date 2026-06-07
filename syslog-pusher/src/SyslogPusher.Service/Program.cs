using Microsoft.Extensions.Hosting.WindowsServices;
using SyslogPusher.Core;
using SyslogPusher.UI;

if (ShouldRunAsService(args))
{
    await ServiceHost.RunAsync(args);
    return;
}

RunUserInterface(args);

static bool ShouldRunAsService(string[] args) =>
    args.Contains("--service", StringComparer.OrdinalIgnoreCase)
    || (OperatingSystem.IsWindows() && WindowsServiceHelpers.IsWindowsService());

static void RunUserInterface(string[] args)
{
    // Worker entry point is MTA; WPF requires STA.
    var thread = new Thread(() => UiLauncher.Run(args))
    {
        Name = "SyslogPusher.UI"
    };
    thread.SetApartmentState(ApartmentState.STA);
    thread.Start();
    thread.Join();
}
