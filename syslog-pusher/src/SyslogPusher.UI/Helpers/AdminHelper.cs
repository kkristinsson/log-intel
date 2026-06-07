using System.Security.Principal;

namespace SyslogPusher.UI.Helpers;

public static class AdminHelper
{
    public static bool IsRunningAsAdministrator()
    {
        using var identity = WindowsIdentity.GetCurrent();
        var principal = new WindowsPrincipal(identity);
        return principal.IsInRole(WindowsBuiltInRole.Administrator);
    }

    public static void RelaunchAsAdministrator(string[] args)
    {
        var argumentList = string.Join(" ", args.Select(a => $"\"{a}\""));
        var startInfo = new System.Diagnostics.ProcessStartInfo
        {
            FileName = Environment.ProcessPath ?? AppContext.BaseDirectory,
            Arguments = argumentList,
            UseShellExecute = true,
            Verb = "runas"
        };
        System.Diagnostics.Process.Start(startInfo);
    }
}
