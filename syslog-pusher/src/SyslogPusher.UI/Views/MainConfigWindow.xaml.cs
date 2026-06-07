using System.Collections.ObjectModel;
using System.Windows;
using Microsoft.Win32;
using SyslogPusher.Core;
using SyslogPusher.Core.Configuration;
using SyslogPusher.Core.ServiceManagement;
using SyslogPusher.UI.Helpers;
using SyslogPusher.UI.ViewModels;

namespace SyslogPusher.UI.Views;

public partial class MainConfigWindow : Window
{
    private readonly AppConfiguration _configuration;
    private readonly ObservableCollection<EventSourceRow> _eventRows = [];
    private readonly ObservableCollection<DirectoryWatchRow> _directoryRows = [];

    public MainConfigWindow()
    {
        InitializeComponent();
        _configuration = ConfigurationStore.Load();
        LoadUi();
        RefreshStatus();
    }

    private void LoadUi()
    {
        ConfigBinder.BindDestination(
            _configuration,
            HostTextBox,
            PortTextBox,
            ProtocolComboBox,
            HostnameTextBox);
        ConfigBinder.BindFileHandling(_configuration, IgnoreBinaryCheckBox, BinarySampleTextBox);

        _eventRows.Clear();
        foreach (var row in _configuration.EventSources.Select(EventSourceRow.FromConfig))
            _eventRows.Add(row);

        if (_eventRows.Count == 0)
            _eventRows.Add(new EventSourceRow());

        _directoryRows.Clear();
        foreach (var row in _configuration.DirectoryWatches.Select(DirectoryWatchRow.FromConfig))
            _directoryRows.Add(row);

        EventSourcesGrid.ItemsSource = _eventRows;
        DirectoryWatchesGrid.ItemsSource = _directoryRows;
    }

    private void RefreshStatus()
    {
        if (!WindowsServiceManager.IsInstalled())
        {
            StatusText.Text =
                "Service is not installed (configuration was saved). Click Install service as Administrator.";
            InstallServiceButton.Visibility = Visibility.Visible;
            InstallServiceButton.IsEnabled = AdminHelper.IsRunningAsAdministrator();
            RestartServiceButton.IsEnabled = false;
            RestartServiceButton.Visibility = Visibility.Collapsed;
            return;
        }

        InstallServiceButton.Visibility = Visibility.Collapsed;
        MaintenanceButton.Visibility = Visibility.Visible;
        RestartServiceButton.Visibility = Visibility.Visible;

        var status = WindowsServiceManager.GetStatus();
        StatusText.Text = $"Service status: {status}. Configuration file: {AppPaths.ConfigFilePath}";
        RestartServiceButton.IsEnabled = status == System.ServiceProcess.ServiceControllerStatus.Running
            && AdminHelper.IsRunningAsAdministrator();
    }

    private void OnOpenMaintenance(object sender, RoutedEventArgs e)
    {
        var maintenance = new MaintenanceWindow { Owner = this };
        maintenance.ShowDialog();
        RefreshStatus();
    }

    private void OnInstallService(object sender, RoutedEventArgs e)
    {
        if (!AdminHelper.IsRunningAsAdministrator())
        {
            MessageBox.Show(
                "Installing the service requires Administrator privileges.",
                Branding.ProductName,
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        try
        {
            SaveConfiguration();
            WindowsServiceManager.InstallAndStart();
            MessageBox.Show(
                "Service installed and started.",
                Branding.ProductName,
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            RefreshStatus();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Install failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnAddEventSource(object sender, RoutedEventArgs e) =>
        _eventRows.Add(new EventSourceRow());

    private void OnRemoveEventSource(object sender, RoutedEventArgs e)
    {
        if (EventSourcesGrid.SelectedItem is EventSourceRow row)
            _eventRows.Remove(row);
    }

    private void OnAddDirectoryWatch(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Select directory to watch" };
        if (dialog.ShowDialog() != true)
            return;

        _directoryRows.Add(new DirectoryWatchRow { Path = dialog.FolderName });
    }

    private void OnRemoveDirectoryWatch(object sender, RoutedEventArgs e)
    {
        if (DirectoryWatchesGrid.SelectedItem is DirectoryWatchRow row)
            _directoryRows.Remove(row);
    }

    private void SaveConfiguration()
    {
        ConfigBinder.ReadDestination(
            _configuration,
            HostTextBox,
            PortTextBox,
            ProtocolComboBox,
            HostnameTextBox);
        ConfigBinder.ReadFileHandling(_configuration, IgnoreBinaryCheckBox, BinarySampleTextBox);

        _configuration.EventSources = _eventRows
            .Where(r => !string.IsNullOrWhiteSpace(r.LogName))
            .Select(r => r.ToConfig())
            .ToList();
        _configuration.DirectoryWatches = _directoryRows
            .Where(r => !string.IsNullOrWhiteSpace(r.Path))
            .Select(r => r.ToConfig())
            .ToList();

        ConfigurationStore.Save(_configuration);
    }

    private void OnSave(object sender, RoutedEventArgs e)
    {
        try
        {
            SaveConfiguration();
            MessageBox.Show(
                "Configuration saved. Restart the service to apply changes.",
                Branding.ProductName,
                MessageBoxButton.OK,
                MessageBoxImage.Information);
            RefreshStatus();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Save failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnRestartService(object sender, RoutedEventArgs e)
    {
        if (!AdminHelper.IsRunningAsAdministrator())
        {
            MessageBox.Show(
                "Restarting the service requires Administrator privileges.",
                "Syslog Pusher",
                MessageBoxButton.OK,
                MessageBoxImage.Warning);
            return;
        }

        try
        {
            WindowsServiceManager.Restart();
            RefreshStatus();
            MessageBox.Show("Service restarted.", "Syslog Pusher", MessageBoxButton.OK, MessageBoxImage.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Restart failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnClose(object sender, RoutedEventArgs e) => Close();
}
