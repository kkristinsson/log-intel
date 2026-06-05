using System.Collections.ObjectModel;
using System.Windows.Controls;
using SyslogPusher.Core.Configuration;

namespace SyslogPusher.UI.Helpers;

public static class ConfigBinder
{
    public static void BindDestination(
        AppConfiguration config,
        TextBox host,
        TextBox port,
        ComboBox protocol,
        TextBox hostname)
    {
        host.Text = config.Destination.Host;
        port.Text = config.Destination.Port.ToString();
        protocol.SelectedIndex = config.Destination.Protocol == SyslogProtocol.Tcp ? 1 : 0;
        hostname.Text = config.Destination.Hostname;
    }

    public static void ReadDestination(
        AppConfiguration config,
        TextBox host,
        TextBox port,
        ComboBox protocol,
        TextBox hostname)
    {
        config.Destination.Host = host.Text.Trim();
        config.Destination.Port = int.TryParse(port.Text, out var p) ? p : 514;
        config.Destination.Protocol = protocol.SelectedIndex == 1
            ? SyslogProtocol.Tcp
            : SyslogProtocol.Udp;
        config.Destination.Hostname = string.IsNullOrWhiteSpace(hostname.Text)
            ? Environment.MachineName
            : hostname.Text.Trim();
    }

    public static void BindFileHandling(AppConfiguration config, CheckBox ignoreBinary, TextBox sampleBytes)
    {
        ignoreBinary.IsChecked = config.FileHandling.IgnoreBinaryFiles;
        sampleBytes.Text = config.FileHandling.BinaryDetectionSampleBytes.ToString();
    }

    public static void ReadFileHandling(AppConfiguration config, CheckBox ignoreBinary, TextBox sampleBytes)
    {
        config.FileHandling.IgnoreBinaryFiles = ignoreBinary.IsChecked == true;
        config.FileHandling.BinaryDetectionSampleBytes = int.TryParse(sampleBytes.Text, out var bytes)
            ? Math.Max(256, bytes)
            : 8192;
    }

    public static ObservableCollection<EventLogSourceConfig> CloneEventSources(AppConfiguration config) =>
        new(config.EventSources.Select(s => new EventLogSourceConfig
        {
            Enabled = s.Enabled,
            LogName = s.LogName,
            ProviderNames = s.ProviderNames.ToList(),
            EventIds = s.EventIds.ToList(),
            Levels = s.Levels.ToList()
        }));

    public static ObservableCollection<DirectoryWatchConfig> CloneDirectoryWatches(AppConfiguration config) =>
        new(config.DirectoryWatches.Select(w => new DirectoryWatchConfig
        {
            Enabled = w.Enabled,
            Path = w.Path,
            Mode = w.Mode,
            FilePatterns = w.FilePatterns.ToList(),
            IncludeSubdirectories = w.IncludeSubdirectories,
            TailFromEndBytes = w.TailFromEndBytes
        }));
}
