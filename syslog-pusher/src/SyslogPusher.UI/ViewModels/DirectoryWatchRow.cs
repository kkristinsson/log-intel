using SyslogPusher.Core.Configuration;

namespace SyslogPusher.UI.ViewModels;

public sealed class DirectoryWatchRow
{
    public bool Enabled { get; set; } = true;
    public string Path { get; set; } = string.Empty;
    public string Mode { get; set; } = "All files";
    public string PatternsDisplay { get; set; } = "*.log, *.txt";
    public bool IncludeSubdirectories { get; set; }
    public bool OnlyPushNewEvents { get; set; } = true;

    public static DirectoryWatchRow FromConfig(DirectoryWatchConfig config) => new()
    {
        Enabled = config.Enabled,
        Path = config.Path,
        Mode = config.Mode == DirectoryWatchMode.AllFiles ? "All files" : "Matched files only",
        PatternsDisplay = string.Join(", ", config.FilePatterns),
        IncludeSubdirectories = config.IncludeSubdirectories,
        OnlyPushNewEvents = config.OnlyPushNewEvents
    };

    public DirectoryWatchConfig ToConfig() => new()
    {
        Enabled = Enabled,
        Path = Path.Trim(),
        Mode = Mode.StartsWith("Matched", StringComparison.OrdinalIgnoreCase)
            ? DirectoryWatchMode.MatchedFilesOnly
            : DirectoryWatchMode.AllFiles,
        FilePatterns = PatternsDisplay.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
            .Where(s => !string.IsNullOrWhiteSpace(s))
            .ToList(),
        IncludeSubdirectories = IncludeSubdirectories,
        OnlyPushNewEvents = OnlyPushNewEvents,
        TailFromEndBytes = 64 * 1024
    };
}
