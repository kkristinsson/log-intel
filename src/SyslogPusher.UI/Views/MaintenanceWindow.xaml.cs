using System.Windows;
using SyslogPusher.Core;
using SyslogPusher.Core.ServiceManagement;
using SyslogPusher.UI.Helpers;

namespace SyslogPusher.UI.Views;

public partial class MaintenanceWindow : Window
{
    public MaintenanceWindow()
    {
        InitializeComponent();
        RefreshStatus();
    }

    private void RefreshStatus()
    {
        if (!AdminHelper.IsRunningAsAdministrator())
        {
            StatusText.Text =
                "Administrator privileges are required. Close and run SyslogPusher.exe as Administrator.";
            UpgradeButton.IsEnabled = false;
            UninstallButton.IsEnabled = false;
            return;
        }

        if (!WindowsServiceManager.IsInstalled())
        {
            StatusText.Text = "Syslog Pusher is not installed. Run setup without administrator privileges.";
            UpgradeButton.IsEnabled = false;
            UninstallButton.IsEnabled = false;
            return;
        }

        var status = WindowsServiceManager.GetStatus();
        var currentPath = WindowsServiceManager.GetConfiguredBinaryPath() ?? "(unknown)";
        var newPath = AppPaths.GetServiceBinaryPath();

        StatusText.Text =
            $"Service status: {status}{Environment.NewLine}" +
            $"Current service command: {currentPath}{Environment.NewLine}" +
            $"This executable: {newPath}";

        UpgradeButton.IsEnabled = true;
        UninstallButton.IsEnabled = true;
    }

    private void OnUpgrade(object sender, RoutedEventArgs e)
    {
        if (!EnsureAdministrator())
            return;

        if (MessageBox.Show(
                "Upgrade the installed service to use this executable and restart it?",
                Branding.ProductName,
                MessageBoxButton.YesNo,
                MessageBoxImage.Question) != MessageBoxResult.Yes)
            return;

        try
        {
            WindowsServiceManager.Upgrade();
            MessageBox.Show(
                "Service upgraded and restarted.",
                Branding.ProductName,
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            RefreshStatus();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Upgrade failed", MessageBoxButton.OK, MessageBoxImage.Error);
            RefreshStatus();
        }
    }

    private void OnUninstall(object sender, RoutedEventArgs e)
    {
        if (!EnsureAdministrator())
            return;

        var removeConfig = RemoveConfigCheckBox.IsChecked == true;
        var prompt = removeConfig
            ? "Uninstall Syslog Pusher and delete all configuration?"
            : "Uninstall the Syslog Pusher Windows service? Configuration will be kept.";

        if (MessageBox.Show(
                prompt,
                "Confirm uninstall",
                MessageBoxButton.YesNo,
                MessageBoxImage.Warning) != MessageBoxResult.Yes)
            return;

        try
        {
            WindowsServiceManager.Uninstall(removeConfiguration: removeConfig);
            MessageBox.Show(
                removeConfig
                    ? "Syslog Pusher has been uninstalled and configuration removed."
                    : "Syslog Pusher service has been uninstalled. Configuration was kept.",
                Branding.ProductName,
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            Close();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Uninstall failed", MessageBoxButton.OK, MessageBoxImage.Error);
            RefreshStatus();
        }
    }

    private bool EnsureAdministrator()
    {
        if (AdminHelper.IsRunningAsAdministrator())
            return true;

        var result = MessageBox.Show(
            "This action requires Administrator privileges. Relaunch elevated now?",
            Branding.ProductName,
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);
        if (result == MessageBoxResult.Yes)
        {
            AdminHelper.RelaunchAsAdministrator(["--maintenance"]);
            Close();
        }

        return false;
    }

    private void OnOpenConfiguration(object sender, RoutedEventArgs e)
    {
        var config = new MainConfigWindow();
        config.Owner = this;
        config.ShowDialog();
    }

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
