namespace SyslogPusher.Core.Syslog;

public readonly record struct SyslogMessage(
    int Facility,
    int Severity,
    string Hostname,
    string AppName,
    string Message,
    DateTimeOffset Timestamp);
