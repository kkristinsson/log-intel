using System.Globalization;
using System.Text;

namespace SyslogPusher.Core.Syslog;

public static class SyslogFormatter
{
    public static string FormatRfc5424(SyslogMessage message)
    {
        var priority = message.Facility * 8 + message.Severity;
        var timestamp = message.Timestamp.ToString("yyyy-MM-dd'T'HH:mm:ss.fffK", CultureInfo.InvariantCulture);
        var sanitized = Sanitize(message.Message);
        return $"<{priority}>1 {timestamp} {message.Hostname} {message.AppName} - - - {sanitized}";
    }

    public static byte[] FormatRfc5424Bytes(SyslogMessage message) =>
        Encoding.UTF8.GetBytes(FormatRfc5424(message) + "\n");

    private static string Sanitize(string value)
    {
        if (string.IsNullOrEmpty(value))
            return "-";

        var builder = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            if (ch is '\r' or '\n')
                builder.Append(' ');
            else if (ch < 32)
                builder.Append(' ');
            else
                builder.Append(ch);
        }

        return builder.ToString();
    }
}
