namespace SyslogPusher.Core.Syslog;

public static class SyslogAppNames
{
    public const string WindowsEvents = "WindowsEvents";

    private static readonly string[] StripExtensions = [".log", ".txt"];

    public static string FromLogFilePath(string path)
    {
        var name = Path.GetFileName(path);
        foreach (var extension in StripExtensions)
        {
            if (name.EndsWith(extension, StringComparison.OrdinalIgnoreCase))
                return name[..^extension.Length];
        }

        return name;
    }
}
