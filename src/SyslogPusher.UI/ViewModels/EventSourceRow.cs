using SyslogPusher.Core.Configuration;

namespace SyslogPusher.UI.ViewModels;

public sealed class EventSourceRow
{
    public bool Enabled { get; set; } = true;
    public string LogName { get; set; } = "Application";
    public string ProvidersDisplay { get; set; } = string.Empty;
    public string EventIdsDisplay { get; set; } = string.Empty;

    public static EventSourceRow FromConfig(EventLogSourceConfig config) => new()
    {
        Enabled = config.Enabled,
        LogName = config.LogName,
        ProvidersDisplay = string.Join(", ", config.ProviderNames),
        EventIdsDisplay = string.Join(", ", config.EventIds)
    };

    public EventLogSourceConfig ToConfig() => new()
    {
        Enabled = Enabled,
        LogName = string.IsNullOrWhiteSpace(LogName) ? "Application" : LogName.Trim(),
        ProviderNames = SplitCsv(ProvidersDisplay),
        EventIds = SplitCsv(EventIdsDisplay)
            .Select(s => int.TryParse(s, out var id) ? id : (int?)null)
            .Where(id => id.HasValue)
            .Select(id => id!.Value)
            .ToList(),
        Levels = []
    };

    private static List<string> SplitCsv(string value) =>
        value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .ToList();
}
