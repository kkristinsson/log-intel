using System.IO;
using System.Windows;
using System.Windows.Controls;
using SyslogPusher.Core;
using SyslogPusher.Core.Configuration;
using SyslogPusher.Core.ServiceManagement;
using SyslogPusher.UI.Helpers;
using SyslogPusher.UI.ViewModels;
using SyslogPusher.UI.WizardPages;

namespace SyslogPusher.UI.Views;

public partial class InstallWizardWindow : Window
{
    private readonly AppConfiguration _configuration = ConfigurationStore.CreateDefault();
    private readonly List<Page> _pages = [];
    private int _stepIndex;

    private DestinationPage? _destinationPage;
    private EventsPage? _eventsPage;
    private DirectoriesPage? _directoriesPage;
    private FileHandlingPage? _fileHandlingPage;

    public InstallWizardWindow()
    {
        InitializeComponent();
        BuildPages();
        ShowStep(0);
    }

    private void BuildPages()
    {
        _pages.Add(new WelcomePage());
        _destinationPage = new DestinationPage();
        _pages.Add(_destinationPage);
        _eventsPage = new EventsPage();
        _pages.Add(_eventsPage);
        _directoriesPage = new DirectoriesPage();
        _pages.Add(_directoriesPage);
        _fileHandlingPage = new FileHandlingPage();
        _pages.Add(_fileHandlingPage);
        _pages.Add(new SummaryPage());
    }

    private void ShowStep(int index)
    {
        _stepIndex = index;
        WizardFrame.Navigate(_pages[index]);
        BackButton.IsEnabled = index > 0;
        var isLast = index == _pages.Count - 1;
        NextButton.Visibility = isLast ? Visibility.Collapsed : Visibility.Visible;
        FinishButton.Visibility = isLast ? Visibility.Visible : Visibility.Collapsed;

        StepTitle.Text = index switch
        {
            0 => "Welcome",
            1 => "Syslog destination",
            2 => "Windows event logs",
            3 => "Log file directories",
            4 => "File handling",
            _ => "Install"
        };

        StepDescription.Text = index switch
        {
            0 => "This wizard installs the Syslog Pusher Windows service and creates the initial configuration.",
            1 => "Specify the remote syslog server and transport.",
            2 => "Choose which Windows event logs to forward.",
            3 => "Optionally watch folders for log file changes.",
            4 => "Control how files are inspected before forwarding.",
            _ => "Review settings and install the service. Administrator privileges are required."
        };

        if (isLast && WizardFrame.Content is SummaryPage summary)
            summary.SetSummary(BuildSummaryText());
    }

    private string BuildSummaryText()
    {
        ApplyCurrentPagesToConfig();
        var lines = new List<string>
        {
            $"Syslog: {_configuration.Destination.Host}:{_configuration.Destination.Port} ({_configuration.Destination.Protocol})",
            $"Event sources: {_configuration.EventSources.Count(s => s.Enabled)}",
            $"Directory watches: {_configuration.DirectoryWatches.Count(w => w.Enabled)}",
            $"Ignore binary files: {_configuration.FileHandling.IgnoreBinaryFiles}",
            $"Config path: {AppPaths.ConfigFilePath}",
            $"Service command: {AppPaths.GetServiceBinaryPath()}"
        };
        return string.Join(Environment.NewLine, lines);
    }

    private void ApplyCurrentPagesToConfig()
    {
        _destinationPage?.Apply(_configuration);
        _eventsPage?.Apply(_configuration);
        _directoriesPage?.Apply(_configuration);
        _fileHandlingPage?.Apply(_configuration);
    }

    private void OnBack(object sender, RoutedEventArgs e)
    {
        if (_stepIndex > 0)
            ShowStep(_stepIndex - 1);
    }

    private void OnNext(object sender, RoutedEventArgs e)
    {
        if (!ValidateCurrentStep())
            return;

        if (_stepIndex < _pages.Count - 1)
            ShowStep(_stepIndex + 1);
    }

    private bool ValidateCurrentStep()
    {
        if (WizardFrame.Content is DestinationPage destination && !destination.Validate(out var error))
        {
            MessageBox.Show(error, "Validation", MessageBoxButton.OK, MessageBoxImage.Warning);
            return false;
        }

        return true;
    }

    private void OnFinish(object sender, RoutedEventArgs e)
    {
        if (!AdminHelper.IsRunningAsAdministrator())
        {
            var result = MessageBox.Show(
                "Installing the Windows service requires Administrator privileges. Relaunch elevated now?",
                "Administrator required",
                MessageBoxButton.YesNo,
                MessageBoxImage.Question);
            if (result == MessageBoxResult.Yes)
            {
                AdminHelper.RelaunchAsAdministrator(["--wizard"]);
                Close();
            }

            return;
        }

        try
        {
            ApplyCurrentPagesToConfig();
            ConfigurationStore.Save(_configuration);

            var executablePath = AppPaths.ResolveExecutablePath();
            if (!File.Exists(executablePath))
                throw new FileNotFoundException(
                    "Could not find SyslogPusher.exe.",
                    executablePath);

            WindowsServiceManager.InstallAndStart();

            MessageBox.Show(
                "Syslog Pusher has been installed and started. You can reopen this application anytime to change settings.",
                "Installation complete",
                MessageBoxButton.OK,
                MessageBoxImage.Information);

            Application.Current.MainWindow = new MainConfigWindow();
            Application.Current.MainWindow.Show();
            Close();
        }
        catch (Exception ex)
        {
            MessageBox.Show(ex.Message, "Installation failed", MessageBoxButton.OK, MessageBoxImage.Error);
        }
    }

    private void OnCancel(object sender, RoutedEventArgs e) => Close();

    private void OnClosing(object sender, System.ComponentModel.CancelEventArgs e)
    {
        if (ConfigurationStore.Exists())
            return;

        var result = MessageBox.Show(
            "Exit setup without installing? The service will not be configured.",
            "Cancel setup",
            MessageBoxButton.YesNo,
            MessageBoxImage.Question);
        if (result != MessageBoxResult.Yes)
            e.Cancel = true;
    }
}
