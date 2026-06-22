using System.Reflection;

namespace SyslogPusher.UI;

public static class Branding
{
    public static string Version { get; } =
        typeof(Branding).Assembly.GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion
        ?? typeof(Branding).Assembly.GetName().Version?.ToString(3)
        ?? "unknown";

    public static string ProductName { get; } = $"Syslog Pusher v{Version}";
    public const string CompanyName = "Kristinsson Consulting AB";
    public const string CopyrightLine = "© 2026 Kristinsson Consulting AB";
    public const string WrittenByLine = "Written by Kristinsson Consulting AB";
    public static string FooterLine { get; } = $"v{Version} · Written by Kristinsson Consulting AB · © 2026 Kristinsson Consulting AB";
    public const string AboutText =
        "Forwards Windows events and log files to a remote syslog server.";
}
