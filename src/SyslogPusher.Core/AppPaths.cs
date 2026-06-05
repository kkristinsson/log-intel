namespace SyslogPusher.Core;

public static class AppPaths
{
    public const string ServiceName = "SyslogPusher";
    public const string ServiceDisplayName = "Syslog Pusher";
    public const string ServiceDescription =
        "Syslog Pusher by Kristinsson Consulting AB - forwards Windows events and log files to syslog.";
    public const string ExecutableFileName = "SyslogPusher.exe";

    public static string DataDirectory =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "SyslogPusher");

    public static string ConfigFilePath => Path.Combine(DataDirectory, "config.json");

    public static string ResolveExecutablePath() =>
        Environment.ProcessPath
        ?? Path.Combine(AppContext.BaseDirectory, ExecutableFileName);

    public static string GetServiceBinaryPath() =>
        $"\"{ResolveExecutablePath()}\"";

    public static string GetScCreateBinPathValue() =>
        $"\\\"{ResolveExecutablePath()}\\\"";
}
