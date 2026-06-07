using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using SyslogPusher.Core.Configuration;
using SyslogPusher.Core.Files;
using SyslogPusher.Core.Syslog;

namespace SyslogPusher.Core.Collectors;

public sealed class LogFileCollector : IAsyncDisposable
{
    private const int UserFacility = 1;
    private readonly AppConfiguration _configuration;
    private readonly SyslogSender _sender;
    private readonly ILogger<LogFileCollector> _logger;
    private readonly List<FileSystemWatcher> _watchers = [];
    private readonly ConcurrentDictionary<string, long> _filePositions = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, bool> _binarySkipped = new(StringComparer.OrdinalIgnoreCase);
    private readonly CancellationTokenSource _cts = new();

    public LogFileCollector(
        AppConfiguration configuration,
        SyslogSender sender,
        ILogger<LogFileCollector> logger)
    {
        _configuration = configuration;
        _sender = sender;
        _logger = logger;
    }

    public void Start()
    {
        foreach (var watch in _configuration.DirectoryWatches.Where(w => w.Enabled))
        {
            if (string.IsNullOrWhiteSpace(watch.Path) || !Directory.Exists(watch.Path))
            {
                _logger.LogWarning("Directory watch path does not exist: {Path}", watch.Path);
                continue;
            }

            SeedExistingFiles(watch);

            var watcher = new FileSystemWatcher(watch.Path)
            {
                IncludeSubdirectories = watch.IncludeSubdirectories,
                NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size,
                Filter = "*",
                EnableRaisingEvents = true
            };

            watcher.Changed += (_, args) => OnFileEvent(args.FullPath, watch);
            watcher.Created += (_, args) => OnFileEvent(args.FullPath, watch);
            watcher.Renamed += (_, args) => OnFileEvent(args.FullPath, watch);

            _watchers.Add(watcher);
            _logger.LogInformation("Watching directory {Path}", watch.Path);
        }
    }

    private void SeedExistingFiles(DirectoryWatchConfig watch)
    {
        var option = watch.IncludeSubdirectories ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        foreach (var file in Directory.EnumerateFiles(watch.Path, "*", option))
        {
            if (!ShouldWatchFile(file, watch))
                continue;

            TailFile(file, watch, initial: true);
        }
    }

    private void OnFileEvent(string? fullPath, DirectoryWatchConfig watch)
    {
        if (string.IsNullOrWhiteSpace(fullPath) || !ShouldWatchFile(fullPath, watch))
            return;

        TailFile(fullPath, watch, initial: false);
    }

    private bool ShouldWatchFile(string path, DirectoryWatchConfig watch)
    {
        if (!File.Exists(path))
            return false;

        if (watch.Mode == DirectoryWatchMode.MatchedFilesOnly &&
            !FilePatternMatcher.MatchesAny(Path.GetFileName(path), watch.FilePatterns))
            return false;

        if (_configuration.FileHandling.IgnoreBinaryFiles)
        {
            if (_binarySkipped.TryGetValue(path, out var skipped) && skipped)
                return false;

            if (BinaryFileDetector.LooksBinary(path, _configuration.FileHandling.BinaryDetectionSampleBytes))
            {
                _binarySkipped[path] = true;
                _logger.LogDebug("Skipping binary file {Path}", path);
                return false;
            }
        }

        return true;
    }

    private void TailFile(string path, DirectoryWatchConfig watch, bool initial)
    {
        try
        {
            using var stream = new FileStream(
                path,
                FileMode.Open,
                FileAccess.Read,
                FileShare.ReadWrite | FileShare.Delete);

            var startPosition = initial
                ? (watch.OnlyPushNewEvents
                    ? stream.Length
                    : Math.Max(0, stream.Length - watch.TailFromEndBytes))
                : _filePositions.GetOrAdd(path, stream.Length);

            if (startPosition > stream.Length)
                startPosition = 0;

            stream.Seek(startPosition, SeekOrigin.Begin);
            using var reader = new StreamReader(stream);
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                if (string.IsNullOrWhiteSpace(line))
                    continue;

                var message = new SyslogMessage(
                    UserFacility,
                    6,
                    _configuration.Destination.Hostname,
                    SyslogAppNames.FromLogFilePath(path),
                    line,
                    DateTimeOffset.UtcNow);

                _sender.Enqueue(message);
            }

            _filePositions[path] = stream.Position;
        }
        catch (IOException ex)
        {
            _logger.LogDebug(ex, "Could not read {Path} yet; will retry on next change", path);
        }
        catch (Exception ex)
        {
            _logger.LogWarning(ex, "Failed to tail file {Path}", path);
        }
    }

    public ValueTask DisposeAsync()
    {
        _cts.Cancel();
        foreach (var watcher in _watchers)
        {
            watcher.EnableRaisingEvents = false;
            watcher.Dispose();
        }

        _watchers.Clear();
        _cts.Dispose();
        return ValueTask.CompletedTask;
    }
}
