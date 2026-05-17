using System.Diagnostics.Eventing.Reader;
using Microsoft.Extensions.Logging;
using SyslogPusher.Core.Configuration;
using SyslogPusher.Core.Syslog;

namespace SyslogPusher.Core.Collectors;

public sealed class EventLogCollector : IAsyncDisposable
{
    private const int UserFacility = 1;
    private readonly AppConfiguration _configuration;
    private readonly SyslogSender _sender;
    private readonly ILogger<EventLogCollector> _logger;
    private readonly List<EventLogWatcher> _watchers = [];
    private readonly CancellationTokenSource _cts = new();

    public EventLogCollector(
        AppConfiguration configuration,
        SyslogSender sender,
        ILogger<EventLogCollector> logger)
    {
        _configuration = configuration;
        _sender = sender;
        _logger = logger;
    }

    public void Start()
    {
        foreach (var source in _configuration.EventSources.Where(s => s.Enabled))
        {
            try
            {
                var query = new EventLogQuery(source.LogName, PathType.LogName, "*");
                var watcher = new EventLogWatcher(query);
                watcher.EventRecordWritten += (_, args) =>
                {
                    if (args.EventRecord is null)
                        return;

                    try
                    {
                        OnEventRecord(args.EventRecord, source);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to process event from {LogName}", source.LogName);
                    }
                    finally
                    {
                        args.EventRecord.Dispose();
                    }
                };
                watcher.Enabled = true;
                _watchers.Add(watcher);
                _logger.LogInformation("Watching Windows event log {LogName}", source.LogName);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Unable to watch event log {LogName}", source.LogName);
            }
        }
    }

    private void OnEventRecord(EventRecord record, EventLogSourceConfig source)
    {
        if (source.ProviderNames.Count > 0 &&
            !source.ProviderNames.Contains(record.ProviderName ?? string.Empty, StringComparer.OrdinalIgnoreCase))
            return;

        if (source.EventIds.Count > 0 && !source.EventIds.Contains(record.Id))
            return;

        if (source.Levels.Count > 0)
        {
            var level = record.Level.HasValue ? (byte)record.Level.Value : (byte)4;
            if (!source.Levels.Contains(level))
                return;
        }

        var text = record.FormatDescription() ?? $"EventId={record.Id} Provider={record.ProviderName}";
        var severity = MapSeverity(record.Level);
        var message = new SyslogMessage(
            UserFacility,
            severity,
            _configuration.Destination.Hostname,
            SyslogAppNames.WindowsEvents,
            $"[{source.LogName}] {text}",
            record.TimeCreated ?? DateTimeOffset.UtcNow);

        _sender.Enqueue(message);
    }

    private static int MapSeverity(byte? level) => level switch
    {
        1 => 2,
        2 => 3,
        3 => 4,
        4 => 5,
        5 => 6,
        _ => 6
    };

    public ValueTask DisposeAsync()
    {
        _cts.Cancel();
        foreach (var watcher in _watchers)
            watcher.Dispose();
        _watchers.Clear();
        _cts.Dispose();
        return ValueTask.CompletedTask;
    }
}
