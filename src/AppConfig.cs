using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.Json;

namespace RemoteRewrite;

internal sealed class AppConfig
{
    static readonly JsonDocumentOptions _jsonOptions = new JsonDocumentOptions
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip
    };

    public static readonly AppConfig Empty = new AppConfig
    {
        Enable = true,
        AppPreference = 100,
        GlobalMode = true,
        AllowInsecureHttp = false,
        DefaultTtl = 300,
        RefreshSeconds = 300,
        Sources = Array.Empty<SourceConfig>(),
        SplitHorizon = SplitHorizonConfig.Disabled
    };

    public bool Enable { get; private set; }
    public byte AppPreference { get; private set; }
    public bool GlobalMode { get; private set; }
    public bool AllowInsecureHttp { get; private set; }
    public uint DefaultTtl { get; private set; }
    public int RefreshSeconds { get; private set; }
    public SourceConfig[] Sources { get; private set; }
    public SplitHorizonConfig SplitHorizon { get; private set; }
    public int EnabledSourceCount => Sources.Count(static source => source.Enable);

    public static AppConfig Parse(string config)
    {
        if (string.IsNullOrWhiteSpace(config))
            throw new FormatException("Remote Rewrite App configuration cannot be empty.");

        using JsonDocument document = JsonDocument.Parse(config, _jsonOptions);
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new FormatException("Remote Rewrite App configuration must be a JSON object.");

        bool allowInsecureHttp = root.TryGetProperty("allowInsecureHttp", out JsonElement insecureHttp) && insecureHttp.GetBoolean();
        SourceConfig[] sources = root.TryGetProperty("sources", out JsonElement sourcesElement)
            ? ParseSources(sourcesElement, allowInsecureHttp)
            : Array.Empty<SourceConfig>();

        AppConfig result = new AppConfig
        {
            Enable = root.TryGetProperty("enable", out JsonElement enable) ? enable.GetBoolean() : true,
            AppPreference = root.TryGetProperty("appPreference", out JsonElement appPreference) ? appPreference.GetByte() : (byte)100,
            GlobalMode = root.TryGetProperty("globalMode", out JsonElement globalMode) ? globalMode.GetBoolean() : true,
            AllowInsecureHttp = allowInsecureHttp,
            DefaultTtl = root.TryGetProperty("defaultTtl", out JsonElement defaultTtl) ? defaultTtl.GetUInt32() : 300u,
            RefreshSeconds = root.TryGetProperty("refreshSeconds", out JsonElement refreshSeconds) ? refreshSeconds.GetInt32() : 300,
            Sources = sources,
            SplitHorizon = root.TryGetProperty("splitHorizon", out JsonElement splitHorizon)
                ? SplitHorizonConfig.Parse(splitHorizon)
                : SplitHorizonConfig.Disabled
        };

        result.Validate();
        return result;
    }

    public void LoadSplitHorizonIntegration(string applicationFolder)
    {
        SplitHorizon.LoadInstalledConfig(applicationFolder);
    }

    void Validate()
    {
        if (DefaultTtl == 0 || DefaultTtl > AppLimits.MaximumTtl)
            throw new FormatException($"defaultTtl must be between 1 and {AppLimits.MaximumTtl} seconds.");

        if (RefreshSeconds != 0 && (RefreshSeconds < AppLimits.MinimumRetrySeconds || RefreshSeconds > AppLimits.MaximumRefreshSeconds))
            throw new FormatException($"refreshSeconds must be 0 (disabled) or between {AppLimits.MinimumRetrySeconds} and {AppLimits.MaximumRefreshSeconds} seconds.");

        if (Sources.Length > AppLimits.MaxSources)
            throw new FormatException($"At most {AppLimits.MaxSources} sources may be configured.");

        string duplicateName = Sources
            .GroupBy(static source => source.Name, StringComparer.OrdinalIgnoreCase)
            .FirstOrDefault(static group => group.Count() > 1)
            ?.Key;
        if (duplicateName is not null)
            throw new FormatException("Duplicate source name: " + duplicateName);
    }

    static SourceConfig[] ParseSources(JsonElement value, bool allowInsecureHttp)
    {
        if (value.ValueKind != JsonValueKind.Array)
            throw new FormatException("sources must be a JSON array.");

        return value.EnumerateArray().Select(item => SourceConfig.Parse(item, allowInsecureHttp: allowInsecureHttp)).ToArray();
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

    public static SourceConfig Parse(JsonElement item, string defaultName = null, bool allowInsecureHttp = true)
    {
        if (item.ValueKind != JsonValueKind.Object)
            throw new FormatException("Each source must be a JSON object.");

        string name = item.TryGetProperty("name", out JsonElement nameElement) && nameElement.ValueKind == JsonValueKind.String
            ? nameElement.GetString()?.Trim().ToLowerInvariant()
            : defaultName?.Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(name))
            throw new FormatException("Each source must have a non-empty name.");

        string url = item.TryGetProperty("url", out JsonElement urlElement) && urlElement.ValueKind == JsonValueKind.String
            ? urlElement.GetString()?.Trim()
            : null;
        string text = item.TryGetProperty("text", out JsonElement textElement) && textElement.ValueKind == JsonValueKind.String
            ? textElement.GetString()
            : null;

        bool enable = item.TryGetProperty("enable", out JsonElement enableElement) ? enableElement.GetBoolean() : true;
        if (enable && string.IsNullOrWhiteSpace(url) && string.IsNullOrWhiteSpace(text))
            throw new FormatException($"Source '{name}' must define either url or text.");

        if (!string.IsNullOrWhiteSpace(url))
            ValidateUrl(name, url, allowInsecureHttp);

        return new SourceConfig
        {
            Name = name,
            Enable = enable,
            Format = item.TryGetProperty("format", out JsonElement format) && format.ValueKind == JsonValueKind.String
                ? ParseFormat(format.GetString())
                : SourceFormat.AdGuardFilter,
            Url = url,
            Text = text,
            GroupNames = item.TryGetProperty("groupNames", out JsonElement groupNames) && groupNames.ValueKind == JsonValueKind.Array
                ? new HashSet<string>(
                    groupNames.EnumerateArray()
                        .Where(static entry => entry.ValueKind == JsonValueKind.String)
                        .Select(static entry => entry.GetString()?.Trim().ToLowerInvariant())
                        .Where(static entry => !string.IsNullOrWhiteSpace(entry)),
                    StringComparer.OrdinalIgnoreCase)
                : new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        };
    }

    static SourceFormat ParseFormat(string value)
    {
        return value?.Trim().ToLowerInvariant() switch
        {
            "adguard-filter" => SourceFormat.AdGuardFilter,
            "rewrite-rules-json" => SourceFormat.RewriteRulesJson,
            _ => throw new NotSupportedException("Unsupported source format: " + value)
        };
    }

    static void ValidateUrl(string sourceName, string value, bool allowInsecureHttp)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out Uri uri))
            throw new FormatException($"Source '{sourceName}' URL must be absolute.");

        if (uri.Scheme == Uri.UriSchemeHttps)
            return;

        if (uri.Scheme == Uri.UriSchemeHttp)
        {
            bool isLoopback = uri.IsLoopback
                || (IPAddress.TryParse(uri.Host, out IPAddress address) && IPAddress.IsLoopback(address));
            if (allowInsecureHttp || isLoopback)
                return;
        }

        throw new FormatException($"Source '{sourceName}' URL must use HTTPS. Set allowInsecureHttp to true only for trusted local HTTP sources.");
    }
}

internal enum SourceFormat
{
    AdGuardFilter,
    RewriteRulesJson
}
