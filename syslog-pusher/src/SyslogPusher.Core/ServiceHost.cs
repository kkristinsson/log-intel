using System.Diagnostics;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using SyslogPusher.Core.Configuration;

namespace SyslogPusher.Core;

public static class ServiceHost
{
    public static Task RunAsync(string[] args)
    {
        AppDomain.CurrentDomain.UnhandledException += OnUnhandledException;

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

    private static void OnUnhandledException(object sender, UnhandledExceptionEventArgs e)
    {
        try
        {
            var message = e.ExceptionObject?.ToString() ?? "Unknown error";
            if (message.Length > 30000)
                message = message[..30000];

            EventLog.WriteEntry(
                AppPaths.ServiceDisplayName,
                message,
                EventLogEntryType.Error,
                5000);
        }
        catch
        {
            // Best effort only.
        }
    }
}
