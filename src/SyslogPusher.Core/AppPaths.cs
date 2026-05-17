namespace SyslogPusher.Core;

public static class AppPaths
{
    public const string ServiceName = "SyslogPusher";
    public const string ServiceDisplayName = "Syslog Pusher";
    public const string ServiceDescription =
        "Syslog Pusher by Kristinsson Consulting AB - forwards Windows events and log files to syslog.";
    public const string ExecutableFileName = "SyslogPusher.exe";
    public const string ServiceModeArgument = "--service";

    public static string DataDirectory =>
        Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "SyslogPusher");

    public static string ConfigFilePath => Path.Combine(DataDirectory, "config.json");

    public static string ResolveExecutablePath() =>
        Environment.ProcessPath
        ?? Path.Combine(AppContext.BaseDirectory, ExecutableFileName);

    /// <summary>Command line shown to users (executable plus service mode flag).</summary>
    public static string GetServiceBinaryPath() =>
        $"\"{ResolveExecutablePath()}\" {ServiceModeArgument}";

    /// <summary>
    /// Value for sc.exe create binPath= (entire executable + args as one quoted value).
    /// </summary>
    public static string GetScCreateBinPathValue() =>
        $"\\\"{ResolveExecutablePath()}\\\" {ServiceModeArgument}";
}
