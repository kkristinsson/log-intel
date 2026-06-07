using System.Windows.Controls;
using SyslogPusher.Core.Configuration;
using SyslogPusher.UI.Helpers;

namespace SyslogPusher.UI.WizardPages;

public partial class FileHandlingPage : Page
{
    public FileHandlingPage() => InitializeComponent();

    public void Apply(AppConfiguration configuration) =>
        ConfigBinder.ReadFileHandling(configuration, IgnoreBinaryCheckBox, BinarySampleTextBox);
}
