using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
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
        AllowPrivateNetworkSources = false,
        DefaultTtl = 300,
        RefreshSeconds = 300,
        Sources = Array.Empty<SourceConfig>(),
        SplitHorizon = SplitHorizonConfig.Disabled
    };

    public bool Enable { get; private set; }
    public byte AppPreference { get; private set; }
    public bool GlobalMode { get; private set; }
    public bool AllowInsecureHttp { get; private set; }
    public bool AllowPrivateNetworkSources { get; private set; }
    public uint DefaultTtl { get; private set; }
    public int RefreshSeconds { get; private set; }
    public SourceConfig[] Sources { get; private set; }
    public SplitHorizonConfig SplitHorizon { get; private set; }
    public int EnabledSourceCount => Sources.Count(static source => source.Enable);

    public static AppConfig Parse(string config)
    {
        if (string.IsNullOrWhiteSpace(config))
            throw new FormatException("Remote Rewrite App configuration cannot be empty.");

        if (Encoding.UTF8.GetByteCount(config) > AppLimits.MaxConfigBytes)
            throw new FormatException($"Remote Rewrite App configuration exceeds the {AppLimits.MaxConfigBytes}-byte limit.");

        using JsonDocument document = JsonDocument.Parse(config, _jsonOptions);
        JsonElement root = document.RootElement;
        if (root.ValueKind != JsonValueKind.Object)
            throw new FormatException("Remote Rewrite App configuration must be a JSON object.");
        JsonObjectValidation.RequireUniqueProperties(root, "Remote Rewrite App configuration");

        bool allowInsecureHttp = root.TryGetProperty("allowInsecureHttp", out JsonElement insecureHttp) && insecureHttp.GetBoolean();
        bool allowPrivateNetworkSources = root.TryGetProperty("allowPrivateNetworkSources", out JsonElement privateNetworkSources)
            && privateNetworkSources.GetBoolean();
        SourceConfig[] sources = root.TryGetProperty("sources", out JsonElement sourcesElement)
            ? ParseSources(sourcesElement, allowInsecureHttp, allowPrivateNetworkSources)
            : Array.Empty<SourceConfig>();

        AppConfig result = new AppConfig
        {
            Enable = root.TryGetProperty("enable", out JsonElement enable) ? enable.GetBoolean() : true,
            AppPreference = root.TryGetProperty("appPreference", out JsonElement appPreference) ? appPreference.GetByte() : (byte)100,
            GlobalMode = root.TryGetProperty("globalMode", out JsonElement globalMode) ? globalMode.GetBoolean() : true,
            AllowInsecureHttp = allowInsecureHttp,
            AllowPrivateNetworkSources = allowPrivateNetworkSources,
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

    static SourceConfig[] ParseSources(JsonElement value, bool allowInsecureHttp, bool allowPrivateNetworkSources)
    {
        if (value.ValueKind != JsonValueKind.Array)
            throw new FormatException("sources must be a JSON array.");

        List<SourceConfig> sources = new List<SourceConfig>();
        foreach (JsonElement item in value.EnumerateArray())
        {
            if (sources.Count >= AppLimits.MaxSources)
                throw new FormatException($"At most {AppLimits.MaxSources} sources may be configured.");
            sources.Add(SourceConfig.Parse(
                item,
                allowInsecureHttp: allowInsecureHttp,
                allowPrivateNetworkSources: allowPrivateNetworkSources));
        }

        return sources.ToArray();
    }
}

internal sealed class SourceConfig
{
    const int MaxGroupNames = 64;
    const int MaxGroupNameLength = 128;

    public string Name { get; private set; }
    public bool Enable { get; private set; }
    public SourceFormat Format { get; private set; }
    public string Url { get; private set; }
    public string Text { get; private set; }
    public HashSet<string> GroupNames { get; private set; }

    public static SourceConfig Parse(
        JsonElement item,
        string defaultName = null,
        bool allowInsecureHttp = true,
        bool allowPrivateNetworkSources = false)
    {
        if (item.ValueKind != JsonValueKind.Object)
            throw new FormatException("Each source must be a JSON object.");
        JsonObjectValidation.RequireUniqueProperties(item, "Source configuration");

        string name = item.TryGetProperty("name", out JsonElement nameElement) && nameElement.ValueKind == JsonValueKind.String
            ? nameElement.GetString()?.Trim().ToLowerInvariant()
            : defaultName?.Trim().ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(name))
            throw new FormatException("Each source must have a non-empty name.");

        if (name.Length > 128)
            throw new FormatException("Source names cannot exceed 128 characters.");

        string url = item.TryGetProperty("url", out JsonElement urlElement) && urlElement.ValueKind == JsonValueKind.String
            ? urlElement.GetString()?.Trim()
            : null;
        string text = item.TryGetProperty("text", out JsonElement textElement) && textElement.ValueKind == JsonValueKind.String
            ? textElement.GetString()
            : null;

        bool enable = item.TryGetProperty("enable", out JsonElement enableElement) ? enableElement.GetBoolean() : true;
        if (enable && string.IsNullOrWhiteSpace(url) && string.IsNullOrWhiteSpace(text))
            throw new FormatException($"Source '{name}' must define either url or text.");

        if (!string.IsNullOrWhiteSpace(url) && !string.IsNullOrWhiteSpace(text))
            throw new FormatException($"Source '{name}' cannot define both url and text.");

        if (text is not null && Encoding.UTF8.GetByteCount(text) > AppLimits.MaxSourceBytes)
            throw new FormatException($"Source '{name}' inline text exceeds the {AppLimits.MaxSourceBytes}-byte limit.");

        if (!string.IsNullOrWhiteSpace(url))
            ValidateUrl(name, url, allowInsecureHttp, allowPrivateNetworkSources);

        HashSet<string> groupNames = ParseGroupNames(item, name);

        return new SourceConfig
        {
            Name = name,
            Enable = enable,
            Format = item.TryGetProperty("format", out JsonElement format) && format.ValueKind == JsonValueKind.String
                ? ParseFormat(format.GetString())
                : SourceFormat.AdGuardFilter,
            Url = url,
            Text = text,
            GroupNames = groupNames
        };
    }

    static HashSet<string> ParseGroupNames(JsonElement item, string sourceName)
    {
        if (!item.TryGetProperty("groupNames", out JsonElement groupNames))
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        if (groupNames.ValueKind != JsonValueKind.Array)
            throw new FormatException($"Source '{sourceName}' groupNames must be an array.");

        HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (JsonElement entry in groupNames.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(entry.GetString()))
                throw new FormatException($"Source '{sourceName}' groupNames must contain only non-empty strings.");

            string normalized = entry.GetString().Trim().ToLowerInvariant();
            if (normalized.Length > MaxGroupNameLength)
                throw new FormatException($"Source '{sourceName}' group names cannot exceed {MaxGroupNameLength} characters.");

            result.Add(normalized);
            if (result.Count > MaxGroupNames)
                throw new FormatException($"Source '{sourceName}' cannot contain more than {MaxGroupNames} distinct group names.");
        }

        return result;
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

    static void ValidateUrl(string sourceName, string value, bool allowInsecureHttp, bool allowPrivateNetworkSources)
    {
        if (!Uri.TryCreate(value, UriKind.Absolute, out Uri uri))
            throw new FormatException($"Source '{sourceName}' URL must be absolute.");

        if (!string.IsNullOrEmpty(uri.UserInfo) || !string.IsNullOrEmpty(uri.Fragment))
            throw new FormatException($"Source '{sourceName}' URL cannot contain credentials or a fragment.");

        if (string.IsNullOrWhiteSpace(uri.Host) || uri.Port <= 0)
            throw new FormatException($"Source '{sourceName}' URL must contain a valid host and port.");

        string host = uri.IdnHost.Trim('[', ']');
        if (!allowPrivateNetworkSources
            && IPAddress.TryParse(host, out IPAddress address)
            && SourceNetworkPolicy.IsBlockedByDefault(address))
        {
            throw new FormatException(
                $"Source '{sourceName}' URL targets a private or special-use address. "
                + "Set allowPrivateNetworkSources to true only for explicitly trusted internal sources.");
        }

        if (uri.Scheme == Uri.UriSchemeHttps)
            return;

        if (uri.Scheme == Uri.UriSchemeHttp)
        {
            if (allowInsecureHttp)
                return;
        }

        throw new FormatException($"Source '{sourceName}' URL must use HTTPS. Set allowInsecureHttp to true only for trusted local HTTP sources.");
    }
}

internal static class SourceNetworkPolicy
{
    public static bool IsBlockedByDefault(IPAddress address)
    {
        if (address is null)
            return true;

        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        if (IPAddress.IsLoopback(address)
            || address.Equals(IPAddress.Any)
            || address.Equals(IPAddress.None)
            || address.Equals(IPAddress.IPv6Any)
            || address.Equals(IPAddress.IPv6None)
            || address.Equals(IPAddress.IPv6Loopback))
        {
            return true;
        }

        byte[] bytes = address.GetAddressBytes();
        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            byte first = bytes[0];
            byte second = bytes[1];
            byte third = bytes[2];
            byte fourth = bytes[3];

            return first == 0
                || first == 10
                || first == 127
                || (first == 100 && (second & 0xc0) == 0x40) // RFC 6598 shared address space
                || (first == 169 && second == 254)
                || (first == 172 && second >= 16 && second <= 31)
                || (first == 192 && second == 0 && third == 0 && fourth != 9 && fourth != 10) // IETF protocol assignments except globally reachable PCP/TURN anycast
                || (first == 192 && second == 0 && third == 2)
                || (first == 192 && second == 88 && third == 99)
                || (first == 192 && second == 168)
                || (first == 198 && (second == 18 || second == 19))
                || (first == 198 && second == 51 && third == 100)
                || (first == 203 && second == 0 && third == 113)
                || first >= 224;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            return address.IsIPv6LinkLocal
                || address.IsIPv6Multicast
                || address.IsIPv6SiteLocal
                || HasPrefix(bytes, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 96) // IPv4-compatible
                || HasPrefix(bytes, [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00], 96) // IPv4-translated
                || HasPrefix(bytes, [0x00, 0x64, 0xff, 0x9b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 96) // NAT64 well-known prefix
                || HasPrefix(bytes, [0x00, 0x64, 0xff, 0x9b, 0x00, 0x01], 48) // NAT64 local-use prefix
                || HasPrefix(bytes, [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00], 64) // discard-only
                || HasPrefix(bytes, [0x20, 0x01, 0x00], 23) // IETF protocol assignments, including Teredo
                || HasPrefix(bytes, [0x20, 0x01, 0x0d, 0xb8], 32) // documentation prefix
                || HasPrefix(bytes, [0x20, 0x02], 16) // 6to4 embeds an IPv4 destination
                || HasPrefix(bytes, [0x3f, 0xfe], 16) // retired 6bone prefix
                || HasPrefix(bytes, [0x3f, 0xff, 0x00], 20) // documentation prefix
                || HasPrefix(bytes, [0x5f, 0x00], 16) // segment-routing SIDs
                || (bytes[0] & 0xfe) == 0xfc // RFC 4193 unique local addresses
                || IsIsatapAddress(bytes);
        }

        return true;
    }

    static bool HasPrefix(byte[] address, byte[] prefix, int prefixLength)
    {
        int wholeBytes = prefixLength / 8;
        for (int index = 0; index < wholeBytes; index++)
        {
            if (address[index] != prefix[index])
                return false;
        }

        int remainingBits = prefixLength % 8;
        if (remainingBits == 0)
            return true;

        int mask = 0xff << (8 - remainingBits);
        return (address[wholeBytes] & mask) == (prefix[wholeBytes] & mask);
    }

    static bool IsIsatapAddress(byte[] bytes)
    {
        return (bytes[8] == 0x00 || bytes[8] == 0x02)
            && bytes[9] == 0x00
            && bytes[10] == 0x5e
            && bytes[11] == 0xfe;
    }
}

internal enum SourceFormat
{
    AdGuardFilter,
    RewriteRulesJson
}
