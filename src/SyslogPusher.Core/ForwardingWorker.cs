using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SyslogPusher.Core.Configuration;

namespace SyslogPusher.Core;

internal sealed class ForwardingWorker : BackgroundService
{
    private readonly AppConfiguration _configuration;
    private readonly ILoggerFactory _loggerFactory;
    private readonly ILogger<ForwardingWorker> _logger;
    private ForwardingEngine? _engine;

    public ForwardingWorker(
        AppConfiguration configuration,
        ILoggerFactory loggerFactory,
        ILogger<ForwardingWorker> logger)
    {
        _configuration = configuration;
        _loggerFactory = loggerFactory;
        _logger = logger;
    }

    protected override Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!ConfigurationStore.Exists())
        {
            _logger.LogWarning(
                "Configuration file not found at {Path}. Service is idle until configured.",
                AppPaths.ConfigFilePath);
            return Task.Delay(Timeout.Infinite, stoppingToken);
        }

        _engine = new ForwardingEngine(_configuration, _loggerFactory);
        _engine.Start();
        _logger.LogInformation("Syslog Pusher forwarding started");
        return Task.Delay(Timeout.Infinite, stoppingToken);
    }

    public override async Task StopAsync(CancellationToken cancellationToken)
    {
        if (_engine is not null)
            await _engine.DisposeAsync().ConfigureAwait(false);

        await base.StopAsync(cancellationToken).ConfigureAwait(false);
    }
}
