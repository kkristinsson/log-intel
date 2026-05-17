using System.Text.Json;
using System.Text.Json.Serialization;

namespace SyslogPusher.Core.Configuration;

public static class ConfigurationStore
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        WriteIndented = true,
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter(JsonNamingPolicy.CamelCase) }
    };

    public static AppConfiguration Load()
    {
        if (!File.Exists(AppPaths.ConfigFilePath))
            return CreateDefault();

        var json = File.ReadAllText(AppPaths.ConfigFilePath);
        var config = JsonSerializer.Deserialize<AppConfiguration>(json, JsonOptions);
        return config ?? CreateDefault();
    }

    public static void Save(AppConfiguration configuration)
    {
        Directory.CreateDirectory(AppPaths.DataDirectory);
        var json = JsonSerializer.Serialize(configuration, JsonOptions);
        var tempPath = AppPaths.ConfigFilePath + ".tmp";
        File.WriteAllText(tempPath, json);
        File.Move(tempPath, AppPaths.ConfigFilePath, overwrite: true);
    }

    public static bool Exists() => File.Exists(AppPaths.ConfigFilePath);

    public static AppConfiguration CreateDefault() => new();
}
