using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;

namespace RemoteRewrite;

internal sealed class AppConfig
{
    public static readonly AppConfig Empty = new AppConfig
    {
        Enable = true,
        AppPreference = 100,
        DefaultTtl = 300,
        RefreshSeconds = 300,
        Sources = Array.Empty<SourceConfig>(),
        SplitHorizon = SplitHorizonConfig.Disabled
    };

    public bool Enable { get; private set; }
    public byte AppPreference { get; private set; }
    public uint DefaultTtl { get; private set; }
    public int RefreshSeconds { get; private set; }
    public SourceConfig[] Sources { get; private set; }
    public SplitHorizonConfig SplitHorizon { get; private set; }

    public static AppConfig Parse(string config)
    {
        using JsonDocument document = JsonDocument.Parse(config);
        JsonElement root = document.RootElement;

        return new AppConfig
        {
            Enable = root.TryGetProperty("enable", out JsonElement enable) ? enable.GetBoolean() : true,
            AppPreference = root.TryGetProperty("appPreference", out JsonElement appPreference) ? appPreference.GetByte() : (byte)100,
            DefaultTtl = root.TryGetProperty("defaultTtl", out JsonElement defaultTtl) ? defaultTtl.GetUInt32() : 300u,
            RefreshSeconds = root.TryGetProperty("refreshSeconds", out JsonElement refreshSeconds) ? refreshSeconds.GetInt32() : 300,
            Sources = root.TryGetProperty("sources", out JsonElement sources)
                ? sources.EnumerateArray().Select(static item => SourceConfig.Parse(item)).ToArray()
                : Array.Empty<SourceConfig>(),
            SplitHorizon = root.TryGetProperty("splitHorizon", out JsonElement splitHorizon)
                ? SplitHorizonConfig.Parse(splitHorizon)
                : SplitHorizonConfig.Disabled
        };
    }

    public void LoadSplitHorizonIntegration(string applicationFolder)
    {
        SplitHorizon.LoadInstalledConfig(applicationFolder);
    }
}

internal sealed class SourceConfig
{
    public string Name { get; private set; }
    public bool Enable { get; private set; }
    public SourceFormat Format { get; private set; }
    public string Url { get; private set; }
    public string Text { get; private set; }
    public HashSet<string> GroupNames { get; private set; }

    public static SourceConfig Parse(JsonElement item, string defaultName = null)
    {
        return new SourceConfig
        {
            Name = item.TryGetProperty("name", out JsonElement name)
                ? name.GetString().Trim().ToLowerInvariant()
                : defaultName?.Trim().ToLowerInvariant(),
            Enable = item.TryGetProperty("enable", out JsonElement enable) ? enable.GetBoolean() : true,
            Format = item.TryGetProperty("format", out JsonElement format)
                ? ParseFormat(format.GetString())
                : SourceFormat.AdGuardFilter,
            Url = item.TryGetProperty("url", out JsonElement url) && (url.ValueKind == JsonValueKind.String)
                ? url.GetString()
                : null,
            Text = item.TryGetProperty("text", out JsonElement text) && (text.ValueKind == JsonValueKind.String)
                ? text.GetString()
                : null,
            GroupNames = item.TryGetProperty("groupNames", out JsonElement groupNames) && (groupNames.ValueKind == JsonValueKind.Array)
                ? new HashSet<string>(
                    groupNames.EnumerateArray()
                        .Where(static entry => entry.ValueKind == JsonValueKind.String)
                        .Select(static entry => entry.GetString()?.Trim().ToLowerInvariant())
                        .Where(static entry => !string.IsNullOrWhiteSpace(entry)),
                    StringComparer.OrdinalIgnoreCase
                )
                : new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        };
    }

    static SourceFormat ParseFormat(string value)
    {
        return value.ToLowerInvariant() switch
        {
            "adguard-filter" => SourceFormat.AdGuardFilter,
            "rewrite-rules-json" => SourceFormat.RewriteRulesJson,
            _ => throw new NotSupportedException("Unsupported source format: " + value),
        };
    }
}

internal enum SourceFormat
{
    AdGuardFilter,
    RewriteRulesJson
}
