using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using SyslogPusher.Core.Configuration;
using SyslogPusher.UI.ViewModels;

namespace SyslogPusher.UI.WizardPages;

public partial class EventsPage : Page
{
    private readonly ObservableCollection<EventSourceRow> _rows =
    [
        new() { LogName = "Application" },
        new() { LogName = "System" }
    ];

    public EventsPage()
    {
        InitializeComponent();
        Grid.ItemsSource = _rows;
    }

    private void OnAdd(object sender, RoutedEventArgs e) => _rows.Add(new EventSourceRow());

    private void OnRemove(object sender, RoutedEventArgs e)
    {
        if (Grid.SelectedItem is EventSourceRow row)
            _rows.Remove(row);
    }

    public void Apply(AppConfiguration configuration) =>
        configuration.EventSources = _rows
            .Where(r => !string.IsNullOrWhiteSpace(r.LogName))
            .Select(r => r.ToConfig())
            .ToList();
}
