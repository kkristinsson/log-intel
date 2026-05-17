using System.Windows.Controls;
using SyslogPusher.Core.Configuration;
using SyslogPusher.UI.Helpers;

namespace SyslogPusher.UI.WizardPages;

public partial class DestinationPage : Page
{
    public DestinationPage()
    {
        InitializeComponent();
        HostnameTextBox.Text = Environment.MachineName;
    }

    public bool Validate(out string error)
    {
        if (string.IsNullOrWhiteSpace(HostTextBox.Text))
        {
            error = "Host is required.";
            return false;
        }

        if (!int.TryParse(PortTextBox.Text, out var port) || port is < 1 or > 65535)
        {
            error = "Port must be between 1 and 65535.";
            return false;
        }

        error = string.Empty;
        return true;
    }

    public void Apply(AppConfiguration configuration) =>
        ConfigBinder.ReadDestination(
            configuration,
            HostTextBox,
            PortTextBox,
            ProtocolComboBox,
            HostnameTextBox,
            AppNameTextBox);
}
