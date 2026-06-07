using System.Windows.Controls;

namespace SyslogPusher.UI.WizardPages;

public partial class SummaryPage : Page
{
    public SummaryPage() => InitializeComponent();

    public void SetSummary(string text) => SummaryText.Text = text;
}
