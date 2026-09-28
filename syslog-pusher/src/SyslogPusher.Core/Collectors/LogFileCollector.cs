using System.Collections.Concurrent;
using Microsoft.Extensions.Logging;
using SyslogPusher.Core.Configuration;
using SyslogPusher.Core.Files;
using SyslogPusher.Core.Syslog;

namespace SyslogPusher.Core.Collectors;

public sealed class LogFileCollector : IAsyncDisposable
{
    private const int UserFacility = 1;
    private const int PollIntervalMs = 2000;
    private const int WatcherBufferSize = 64 * 1024;

    private readonly AppConfiguration _configuration;
    private readonly SyslogSender _sender;
    private readonly ILogger<LogFileCollector> _logger;
    private readonly List<(FileSystemWatcher Watcher, DirectoryWatchConfig Watch)> _watchers = [];
    private readonly ConcurrentDictionary<string, long> _filePositions = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, bool> _binarySkipped = new(StringComparer.OrdinalIgnoreCase);
    private readonly ConcurrentDictionary<string, object> _fileLocks = new(StringComparer.OrdinalIgnoreCase);
    private readonly object _watcherLock = new();
    private readonly CancellationTokenSource _cts = new();
    private Task? _pollTask;

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
            AttachWatcher(watch);
            _logger.LogInformation("Watching directory {Path}", watch.Path);
        }

        _pollTask = Task.Run(() => PollLoopAsync(_cts.Token));
    }

    private void AttachWatcher(DirectoryWatchConfig watch)
    {
        var watcher = CreateWatcher(watch);
        lock (_watcherLock)
            _watchers.Add((watcher, watch));
    }

    private FileSystemWatcher CreateWatcher(DirectoryWatchConfig watch)
    {
        var watcher = new FileSystemWatcher(watch.Path)
        {
            IncludeSubdirectories = watch.IncludeSubdirectories,
            NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.CreationTime,
            Filter = "*",
            InternalBufferSize = WatcherBufferSize,
            EnableRaisingEvents = true
        };

        watcher.Changed += (_, args) => OnFileEvent(args.FullPath, watch);
        watcher.Created += (_, args) => OnFileEvent(args.FullPath, watch);
        watcher.Renamed += (_, args) =>
        {
            // Archive (new name) plus the replacement file that often appears at the old path (ip.log).
            OnFileEvent(args.FullPath, watch);
            OnFileEvent(args.OldFullPath, watch);
        };
        watcher.Error += (_, args) =>
        {
            _logger.LogWarning(args.GetException(),
                "File watcher overflow/error on {Path}; recreating watcher and scanning", watch.Path);
            RecreateWatcher(watcher, watch);
            ScanWatch(watch);
        };

        return watcher;
    }

    private void RecreateWatcher(FileSystemWatcher oldWatcher, DirectoryWatchConfig watch)
    {
        lock (_watcherLock)
        {
            _watchers.RemoveAll(entry => ReferenceEquals(entry.Watcher, oldWatcher));
            try
            {
                oldWatcher.EnableRaisingEvents = false;
                oldWatcher.Dispose();
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Failed disposing broken watcher for {Path}", watch.Path);
            }

            try
            {
                var replacement = CreateWatcher(watch);
                _watchers.Add((replacement, watch));
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Could not recreate file watcher for {Path}", watch.Path);
            }
        }
    }

    private async Task PollLoopAsync(CancellationToken cancellationToken)
    {
        while (!cancellationToken.IsCancellationRequested)
        {
            try
            {
                await Task.Delay(PollIntervalMs, cancellationToken).ConfigureAwait(false);
                foreach (var watch in _configuration.DirectoryWatches.Where(w => w.Enabled))
                    ScanWatch(watch);
            }
            catch (OperationCanceledException)
            {
                break;
            }
            catch (Exception ex)
            {
                _logger.LogDebug(ex, "Log directory poll failed; will retry");
            }
        }
    }

    private void ScanWatch(DirectoryWatchConfig watch)
    {
        if (string.IsNullOrWhiteSpace(watch.Path) || !Directory.Exists(watch.Path))
            return;

        var option = watch.IncludeSubdirectories ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        IEnumerable<string> files;
        try
        {
            files = Directory.EnumerateFiles(watch.Path, "*", option);
        }
        catch (Exception ex)
        {
            _logger.LogDebug(ex, "Could not enumerate {Path}", watch.Path);
            return;
        }

        foreach (var file in files)
        {
            if (!ShouldWatchFile(file, watch))
                continue;

            TailFile(file, watch, initial: false);
        }
    }

    private void SeedExistingFiles(DirectoryWatchConfig watch)
    {
        var option = watch.IncludeSubdirectories ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        foreach (var file in Directory.EnumerateFiles(watch.Path, "*", option))
        {
            if (!ShouldWatchFile(file, watch))
                continue;

            if (watch.OnlyPushNewEvents)
            {
                SeedFilePositionAtEnd(file);
                continue;
            }

            TailFile(file, watch, initial: true);
        }
    }

    private void SeedFilePositionAtEnd(string path)
    {
        try
        {
            _filePositions[path] = new FileInfo(path).Length;
        }
        catch (IOException ex)
        {
            _logger.LogDebug(ex, "Could not seed position for {Path}; will read from first observed change", path);
        }
        catch (UnauthorizedAccessException ex)
        {
            _logger.LogDebug(ex, "Could not seed position for {Path}; will read from first observed change", path);
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
        var gate = _fileLocks.GetOrAdd(path, static _ => new object());
        lock (gate)
        {
            try
            {
                using var stream = new FileStream(
                    path,
                    FileMode.Open,
                    FileAccess.Read,
                    FileShare.ReadWrite | FileShare.Delete);

                var startPosition = initial
                    ? Math.Max(0, stream.Length - watch.TailFromEndBytes)
                    : (_filePositions.TryGetValue(path, out var position) ? position : 0);

                // Truncation, log4j recreate, or a new file reused the old path after rotate.
                if (startPosition > stream.Length)
                    startPosition = 0;

                if (startPosition == stream.Length)
                {
                    _filePositions[path] = stream.Length;
                    return;
                }

                stream.Seek(startPosition, SeekOrigin.Begin);
                using var reader = new StreamReader(stream, detectEncodingFromByteOrderMarks: true);
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
    }

    public async ValueTask DisposeAsync()
    {
        _cts.Cancel();
        if (_pollTask is not null)
        {
            try
            {
                await _pollTask.ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
            }
        }

        lock (_watcherLock)
        {
            foreach (var (watcher, _) in _watchers)
            {
                watcher.EnableRaisingEvents = false;
                watcher.Dispose();
            }

            _watchers.Clear();
        }

        _cts.Dispose();
    }
}
