# Syslog Pusher

Syslog Pusher is a Windows service that forwards **Windows event logs** and **log files from watched directories** to a remote **syslog** server over **UDP** or **TCP**. All setup and ongoing changes are done through a **graphical WPF application** — no manual editing of config files.

## Features

- Windows service (`SyslogPusher`) with automatic start
- Configurable Windows event log sources (log name, optional provider/event ID filters)
- Configurable directory watches:
  - **All files** in a folder, or **matched files only** (e.g. `*.log`, `*.txt`)
  - Optional subdirectory recursion
- Syslog destination: host, port, UDP/TCP, hostname, app name (RFC 5424)
- **Ignore binary files** by default (configurable sample size)
- First-run **install wizard** and later **configuration UI**
- Settings stored under `%ProgramData%\SyslogPusher\`

## Requirements

See [REQUIREMENTS.txt](REQUIREMENTS.txt) for supported Windows versions, .NET runtime, and privileges.

## Build

Requires [.NET 8 SDK](https://dotnet.microsoft.com/download/dotnet/8.0).

```powershell
cd syslogpusher
.\scripts\publish.ps1
```

Output is a **single file**: `dist\SyslogPusher.exe` (self-contained, win-x64). Target machines do not need a separate .NET install.

The same executable opens the configuration UI when run interactively, and runs as the Windows service when started by the Service Control Manager (no WPF loaded in service mode).

## Install

1. Copy **`dist\SyslogPusher.exe`** to the machine.
2. Run **`SyslogPusher.exe`** (first launch opens the setup wizard).
3. Complete the wizard and click **Install** (elevates to Administrator).
4. The service is registered, configuration is saved, and forwarding starts.

To change settings later, run `SyslogPusher.exe` again. Use **Restart service** after saving (Administrator).

To reopen the install wizard: `SyslogPusher.exe --wizard`

## Uninstall

From an elevated command prompt:

```text
sc stop SyslogPusher
sc delete SyslogPusher
```

Remove `%ProgramData%\SyslogPusher` if you no longer need the configuration.

## Project layout

```
src/
  SyslogPusher.Core/      Shared config, collectors, syslog client
  SyslogPusher.Service/   Windows service host
  SyslogPusher.UI/        WPF wizard + configuration app
```

## License

MIT (add your license file as needed).
