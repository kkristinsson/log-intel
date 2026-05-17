using System.Collections.ObjectModel;
using System.Windows;
using System.Windows.Controls;
using Microsoft.Win32;
using SyslogPusher.Core.Configuration;
using SyslogPusher.UI.ViewModels;

namespace SyslogPusher.UI.WizardPages;

public partial class DirectoriesPage : Page
{
    private readonly ObservableCollection<DirectoryWatchRow> _rows = [];

    public DirectoriesPage()
    {
        InitializeComponent();
        Grid.ItemsSource = _rows;
    }

    private void OnAdd(object sender, RoutedEventArgs e)
    {
        var dialog = new OpenFolderDialog { Title = "Select directory to watch" };
        if (dialog.ShowDialog() != true)
            return;

        _rows.Add(new DirectoryWatchRow { Path = dialog.FolderName });
    }

    private void OnRemove(object sender, RoutedEventArgs e)
    {
        if (Grid.SelectedItem is DirectoryWatchRow row)
            _rows.Remove(row);
    }

    public void Apply(AppConfiguration configuration) =>
        configuration.DirectoryWatches = _rows
            .Where(r => !string.IsNullOrWhiteSpace(r.Path))
            .Select(r => r.ToConfig())
            .ToList();
}
