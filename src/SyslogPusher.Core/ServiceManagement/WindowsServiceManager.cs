using System.Diagnostics;
using System.ServiceProcess;

namespace SyslogPusher.Core.ServiceManagement;

public static class WindowsServiceManager
{
    public static bool IsInstalled()
    {
        try
        {
            using var controller = new ServiceController(AppPaths.ServiceName);
            _ = controller.Status;
            return true;
        }
        catch
        {
            return false;
        }
    }

    public static ServiceControllerStatus? GetStatus()
    {
        try
        {
            using var controller = new ServiceController(AppPaths.ServiceName);
            return controller.Status;
        }
        catch
        {
            return null;
        }
    }

    public static void Install()
    {
        var executablePath = AppPaths.ResolveExecutablePath();
        if (!File.Exists(executablePath))
            throw new FileNotFoundException("Application executable not found.", executablePath);

        RunScCreate();
        RunSc($"description {AppPaths.ServiceName} \"{AppPaths.ServiceDescription}\"");
    }

    public static void InstallAndStart()
    {
        if (!IsInstalled())
            Install();

        Start();
    }

    public static void Uninstall(bool removeConfiguration = false)
    {
        if (!IsInstalled())
            return;

        if (GetStatus() is ServiceControllerStatus.Running or ServiceControllerStatus.StartPending)
            RunSc($"stop {AppPaths.ServiceName}");

        RunSc($"delete {AppPaths.ServiceName}");

        if (removeConfiguration && Directory.Exists(AppPaths.DataDirectory))
            Directory.Delete(AppPaths.DataDirectory, recursive: true);
    }

    public static void Start()
    {
        using var controller = new ServiceController(AppPaths.ServiceName);
        if (controller.Status == ServiceControllerStatus.Running)
            return;

        controller.Start();
        controller.WaitForStatus(ServiceControllerStatus.Running, TimeSpan.FromSeconds(30));
    }

    public static void Stop()
    {
        using var controller = new ServiceController(AppPaths.ServiceName);
        if (controller.Status == ServiceControllerStatus.Stopped)
            return;

        controller.Stop();
        controller.WaitForStatus(ServiceControllerStatus.Stopped, TimeSpan.FromSeconds(30));
    }

    public static void Restart()
    {
        Stop();
        Start();
    }

    public static void Upgrade()
    {
        if (!IsInstalled())
            throw new InvalidOperationException("Service is not installed.");

        var executablePath = AppPaths.ResolveExecutablePath();
        if (!File.Exists(executablePath))
            throw new FileNotFoundException("Application executable not found.", executablePath);

        var wasRunning = GetStatus() is ServiceControllerStatus.Running
            or ServiceControllerStatus.StartPending;

        if (wasRunning)
            Stop();

        RunSc(
            $"config {AppPaths.ServiceName} binPath= \"{AppPaths.GetScCreateBinPathValue()}\"");

        Start();
    }

    public static string? GetConfiguredBinaryPath()
    {
        try
        {
            var startInfo = new ProcessStartInfo
            {
                FileName = "sc.exe",
                Arguments = $"qc {AppPaths.ServiceName}",
                UseShellExecute = false,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                CreateNoWindow = true
            };

            using var process = Process.Start(startInfo);
            if (process is null)
                return null;

            var output = process.StandardOutput.ReadToEnd();
            process.WaitForExit();
            if (process.ExitCode != 0)
                return null;

            const string prefix = "BINARY_PATH_NAME";
            foreach (var line in output.Split('\n'))
            {
                var trimmed = line.Trim();
                if (!trimmed.StartsWith(prefix, StringComparison.OrdinalIgnoreCase))
                    continue;

                var colon = trimmed.IndexOf(':');
                if (colon >= 0 && colon < trimmed.Length - 1)
                    return trimmed[(colon + 1)..].Trim();
            }

            return null;
        }
        catch
        {
            return null;
        }
    }

    private static void RunScCreate()
    {
        // sc.exe parses one command line; ArgumentList splits "Syslog Pusher" and breaks start= auto.
        // Space after '=' is required. binPath must include --service inside its quotes.
        var arguments =
            $"create {AppPaths.ServiceName} " +
            $"binPath= \"{AppPaths.GetScCreateBinPathValue()}\" " +
            "start= auto " +
            $"DisplayName= \"{AppPaths.ServiceDisplayName}\"";

        RunSc(arguments);
    }

    private static void RunSc(string arguments)
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = "sc.exe",
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true
        };

        RunProcess(startInfo, $"sc.exe {arguments}");
    }

    private static void RunProcess(ProcessStartInfo startInfo, string commandLabel)
    {
        using var process = Process.Start(startInfo)
            ?? throw new InvalidOperationException("Failed to start sc.exe");

        process.WaitForExit();
        var stderr = process.StandardError.ReadToEnd();
        var stdout = process.StandardOutput.ReadToEnd();

        if (process.ExitCode != 0)
            throw new InvalidOperationException(
                $"{commandLabel} failed ({process.ExitCode}): {stderr} {stdout}".Trim());
    }
}
