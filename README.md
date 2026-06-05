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
- **Only new** (per directory watch) — skip existing file content on service start; forward only lines appended after startup
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

## Only push new events (per directory)

On the **Log directories** tab, each watch has an **Only new** checkbox (default off).

When enabled for a directory:

- On service **start**, syslogpusher seeks to the **end** of each matching file in that watch (no replay of the last 64 KB).
- Only **new lines appended after startup** are forwarded.
- Other directory watches without the checkbox behave as before.

Use this for folders with large historical application logs (e.g. `Pri.log`) where the central collector should not receive a burst of old events after every service restart.

**Pair with syslogb:** on the syslog collector, syslogb includes a built-in **SMS Pri logs** timestamp parser for `Pri.log` so sort order and time-range filtering use the embedded event date in the message, not the rsyslog receive prefix. See the [syslogb README](https://github.com/kkristinsson/syslogb#timestamp-parsers-remote--syslogpusher-logs).

Windows **event logs** use a separate startup grace window (default 5 minutes) to ignore events older than service start minus grace.

## Project layout

```
src/
  SyslogPusher.Core/      Shared config, collectors, syslog client
  SyslogPusher.Service/   Windows service host
  SyslogPusher.UI/        WPF wizard + configuration app
```

## License

MIT (add your license file as needed).
