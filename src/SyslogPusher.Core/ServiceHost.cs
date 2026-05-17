using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SyslogPusher.Core.Configuration;

namespace SyslogPusher.Core;

public static class ServiceHost
{
    public static Task RunAsync(string[] args)
    {
        var builder = Host.CreateApplicationBuilder(args);
        builder.Services.AddWindowsService(options =>
        {
            options.ServiceName = AppPaths.ServiceName;
        });
        builder.Services.AddLogging(logging =>
        {
            logging.AddEventLog(settings =>
            {
                settings.SourceName = AppPaths.ServiceDisplayName;
            });
        });
        builder.Services.AddSingleton(_ => ConfigurationStore.Load());
        builder.Services.AddHostedService<ForwardingWorker>();

        return builder.Build().RunAsync();
    }
}
