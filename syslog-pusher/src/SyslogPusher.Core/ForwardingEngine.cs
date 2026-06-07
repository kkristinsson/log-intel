using Microsoft.Extensions.Logging;
using SyslogPusher.Core.Collectors;
using SyslogPusher.Core.Configuration;
using SyslogPusher.Core.Syslog;

namespace SyslogPusher.Core;

public sealed class ForwardingEngine : IAsyncDisposable
{
    private readonly AppConfiguration _configuration;
    private readonly ILoggerFactory _loggerFactory;
    private SyslogSender? _sender;
    private EventLogCollector? _eventCollector;
    private LogFileCollector? _fileCollector;
    private readonly DateTimeOffset _serviceStartUtc = DateTimeOffset.UtcNow;

    public ForwardingEngine(AppConfiguration configuration, ILoggerFactory loggerFactory)
    {
        _configuration = configuration;
        _loggerFactory = loggerFactory;
    }

    public void Start()
    {
        _sender = new SyslogSender(_configuration, _loggerFactory.CreateLogger<SyslogSender>());
        _sender.Start();

        if (_configuration.EventSources.Any(s => s.Enabled))
        {
            _eventCollector = new EventLogCollector(
                _configuration,
                _sender,
                _loggerFactory.CreateLogger<EventLogCollector>(),
                _serviceStartUtc);
            _eventCollector.Start();
        }

        if (_configuration.DirectoryWatches.Any(w => w.Enabled))
        {
            _fileCollector = new LogFileCollector(
                _configuration,
                _sender,
                _loggerFactory.CreateLogger<LogFileCollector>());
            _fileCollector.Start();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_eventCollector is not null)
            await _eventCollector.DisposeAsync().ConfigureAwait(false);
        if (_fileCollector is not null)
            await _fileCollector.DisposeAsync().ConfigureAwait(false);
        if (_sender is not null)
            await _sender.DisposeAsync().ConfigureAwait(false);
    }
}
