namespace SyslogPusher.Core.Configuration;

public sealed class AppConfiguration
{
    public SyslogDestination Destination { get; set; } = new();
    public List<EventLogSourceConfig> EventSources { get; set; } = [];
    public List<DirectoryWatchConfig> DirectoryWatches { get; set; } = [];
    public FileHandlingOptions FileHandling { get; set; } = new();
}

public sealed class SyslogDestination
{
    public string Host { get; set; } = "127.0.0.1";
    public int Port { get; set; } = 514;
    public SyslogProtocol Protocol { get; set; } = SyslogProtocol.Udp;
    public string Hostname { get; set; } = Environment.MachineName;
    public string AppName { get; set; } = "SyslogPusher";
}

public enum SyslogProtocol
{
    Udp,
    Tcp
}

public sealed class EventLogSourceConfig
{
    public bool Enabled { get; set; } = true;
    public string LogName { get; set; } = "Application";
    public List<string> ProviderNames { get; set; } = [];
    public List<int> EventIds { get; set; } = [];
    public List<byte> Levels { get; set; } = [];
}

public sealed class DirectoryWatchConfig
{
    public bool Enabled { get; set; } = true;
    public string Path { get; set; } = string.Empty;
    public DirectoryWatchMode Mode { get; set; } = DirectoryWatchMode.AllFiles;
    public List<string> FilePatterns { get; set; } = ["*.log", "*.txt"];
    public bool IncludeSubdirectories { get; set; }
    public long TailFromEndBytes { get; set; } = 64 * 1024;
}

public enum DirectoryWatchMode
{
    AllFiles,
    MatchedFilesOnly
}

public sealed class FileHandlingOptions
{
    public bool IgnoreBinaryFiles { get; set; } = true;
    public int BinaryDetectionSampleBytes { get; set; } = 8192;
}
