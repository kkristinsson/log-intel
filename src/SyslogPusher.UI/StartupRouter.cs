using System.Windows;
using SyslogPusher.Core.Configuration;
using SyslogPusher.Core.ServiceManagement;
using SyslogPusher.UI.Helpers;
using SyslogPusher.UI.Views;

namespace SyslogPusher.UI;

public static class StartupRouter
{
    public static Window CreateMainWindow(string[] args)
    {
        var forceConfigure = HasArg(args, "--configure");
        var forceWizard = HasArg(args, "--wizard");
        var forceMaintenance = HasArg(args, "--maintenance")
            || HasArg(args, "--uninstall");
        var isAdmin = AdminHelper.IsRunningAsAdministrator();
        var isInstalled = WindowsServiceManager.IsInstalled();

        if (forceConfigure)
            return new MainConfigWindow();

        if (forceWizard)
            return new InstallWizardWindow();

        if (forceMaintenance || (isAdmin && isInstalled))
            return new MaintenanceWindow();

        if (!ConfigurationStore.Exists())
            return new InstallWizardWindow();

        return new MainConfigWindow();
    }

    private static bool HasArg(string[] args, string flag) =>
        args.Contains(flag, StringComparer.OrdinalIgnoreCase);
}
