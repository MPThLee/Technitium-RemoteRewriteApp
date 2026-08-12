using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;

namespace RemoteRewrite;

internal sealed class SplitHorizonConfig
{
    public static readonly SplitHorizonConfig Disabled = new SplitHorizonConfig
    {
        Enable = false,
        DefaultGroupName = null,
        PrivateGroupName = null,
        PublicGroupName = null,
        ImportInstalledApp = false,
        ConfigFile = null,
        DomainGroupRules = Array.Empty<DomainGroupRule>(),
        NetworkGroupRules = Array.Empty<NetworkGroupRule>()
    };

    public bool Enable { get; private set; }
    public string DefaultGroupName { get; private set; }
    public string PrivateGroupName { get; private set; }
    public string PublicGroupName { get; private set; }
    public bool ImportInstalledApp { get; private set; }
    public string ConfigFile { get; private set; }
    public DomainGroupRule[] DomainGroupRules { get; private set; }
    public NetworkGroupRule[] NetworkGroupRules { get; private set; }

    public static SplitHorizonConfig Parse(JsonElement value)
    {
        List<DomainGroupRule> domainRules = new List<DomainGroupRule>();
        List<NetworkGroupRule> networkRules = new List<NetworkGroupRule>();

        if (value.TryGetProperty("domainGroupMap", out JsonElement domainGroupMap) && (domainGroupMap.ValueKind == JsonValueKind.Object))
        {
            foreach (JsonProperty property in domainGroupMap.EnumerateObject())
            {
                if (property.Value.ValueKind != JsonValueKind.String)
                    continue;

                domainRules.Add(new DomainGroupRule(property.Name, property.Value.GetString()));
            }
        }

        if (value.TryGetProperty("networkGroupMap", out JsonElement networkGroupMap) && (networkGroupMap.ValueKind == JsonValueKind.Object))
        {
            foreach (JsonProperty property in networkGroupMap.EnumerateObject())
            {
                if (property.Value.ValueKind != JsonValueKind.String)
                    continue;

                networkRules.Add(NetworkGroupRule.Parse(property.Name, property.Value.GetString()));
            }
        }

        return new SplitHorizonConfig
        {
            Enable = value.TryGetProperty("enable", out JsonElement enable) ? enable.GetBoolean() : true,
            DefaultGroupName = value.TryGetProperty("defaultGroupName", out JsonElement defaultGroupName) ? NormalizeGroupName(defaultGroupName.GetString()) : "default",
            PrivateGroupName = value.TryGetProperty("privateGroupName", out JsonElement privateGroupName) ? NormalizeGroupName(privateGroupName.GetString()) : "private",
            PublicGroupName = value.TryGetProperty("publicGroupName", out JsonElement publicGroupName) ? NormalizeGroupName(publicGroupName.GetString()) : "public",
            ImportInstalledApp = value.TryGetProperty("importInstalledApp", out JsonElement importInstalledApp) ? importInstalledApp.GetBoolean() : false,
            ConfigFile = value.TryGetProperty("configFile", out JsonElement configFile) && (configFile.ValueKind == JsonValueKind.String)
                ? configFile.GetString()
                : null,
            DomainGroupRules = domainRules.OrderByDescending(static item => item.Pattern.Length).ToArray(),
            NetworkGroupRules = networkRules.OrderByDescending(static item => item.PrefixLength).ToArray()
        };
    }

    public void LoadInstalledConfig(string applicationFolder)
    {
        if (!Enable || !ImportInstalledApp || string.IsNullOrWhiteSpace(applicationFolder))
            return;

        string configFile = ConfigFile;
        if (string.IsNullOrWhiteSpace(configFile))
        {
            string appRoot = Directory.GetParent(applicationFolder)?.FullName;
            if (string.IsNullOrWhiteSpace(appRoot))
                return;

            string officialPath = Path.Combine(appRoot, "Split Horizon", "dnsApp.config");
            string legacyPath = Path.Combine(appRoot, "SplitHorizonApp", "dnsApp.config");
            configFile = File.Exists(officialPath) ? officialPath : legacyPath;
        }
        else if (!Path.IsPathRooted(configFile))
        {
            configFile = Path.Combine(applicationFolder, configFile);
        }

        if (!File.Exists(configFile))
            return;

        using JsonDocument document = JsonDocument.Parse(File.ReadAllText(configFile));
        JsonElement root = document.RootElement;

        List<DomainGroupRule> domainRules = new List<DomainGroupRule>();
        List<NetworkGroupRule> networkRules = new List<NetworkGroupRule>();
        HashSet<string> disabledGroups = ParseDisabledGroups(root);

        if (root.TryGetProperty("domainGroupMap", out JsonElement domainGroupMap) && (domainGroupMap.ValueKind == JsonValueKind.Object))
        {
            foreach (JsonProperty property in domainGroupMap.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.String && !disabledGroups.Contains(property.Value.GetString()))
                    domainRules.Add(new DomainGroupRule(property.Name, property.Value.GetString()));
            }
        }

        if (root.TryGetProperty("networkGroupMap", out JsonElement networkGroupMap) && (networkGroupMap.ValueKind == JsonValueKind.Object))
        {
            foreach (JsonProperty property in networkGroupMap.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.String && !disabledGroups.Contains(property.Value.GetString()))
                    networkRules.Add(NetworkGroupRule.Parse(property.Name, property.Value.GetString()));
            }
        }

        DomainGroupRules = DomainGroupRules.Concat(domainRules).OrderByDescending(static item => item.Pattern.Length).ToArray();
        NetworkGroupRules = NetworkGroupRules.Concat(networkRules).OrderByDescending(static item => item.PrefixLength).ToArray();
    }

    public HashSet<string> ResolveGroups(string qname, IPAddress address)
    {
        HashSet<string> groups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!Enable)
            return groups;

        AddGroup(groups, DefaultGroupName);
        AddGroup(groups, NetworkClassifier.IsPrivateOrSpecial(address) ? PrivateGroupName : PublicGroupName);

        DomainGroupRule domainRule = DomainGroupRules.FirstOrDefault(rule => rule.Matches(qname));
        if (domainRule is not null)
        {
            AddGroup(groups, domainRule.GroupName);
        }
        else
        {
            NetworkGroupRule networkRule = NetworkGroupRules.FirstOrDefault(rule => rule.Matches(address));
            if (networkRule is not null)
                AddGroup(groups, networkRule.GroupName);
        }

        return groups;
    }

    static void AddGroup(HashSet<string> groups, string name)
    {
        if (!string.IsNullOrWhiteSpace(name))
            groups.Add(name);
    }

    static string NormalizeGroupName(string value)
    {
        return string.IsNullOrWhiteSpace(value) ? null : value.Trim().ToLowerInvariant();
    }

    static HashSet<string> ParseDisabledGroups(JsonElement root)
    {
        HashSet<string> disabled = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!root.TryGetProperty("groups", out JsonElement groups) || groups.ValueKind != JsonValueKind.Array)
            return disabled;

        foreach (JsonElement group in groups.EnumerateArray())
        {
            if (group.ValueKind != JsonValueKind.Object)
                continue;

            bool enabled = !group.TryGetProperty("enabled", out JsonElement enabledElement) || enabledElement.GetBoolean();
            if (enabled)
                continue;

            if (group.TryGetProperty("name", out JsonElement name) && name.ValueKind == JsonValueKind.String && !string.IsNullOrWhiteSpace(name.GetString()))
                disabled.Add(name.GetString().Trim());
        }

        return disabled;
    }
}

internal static class NetworkClassifier
{
    public static bool IsPrivateOrSpecial(IPAddress address)
    {
        if (address is null)
            return false;

        if (address.IsIPv4MappedToIPv6)
            address = address.MapToIPv4();

        if (IPAddress.IsLoopback(address))
            return true;

        if (address.AddressFamily == AddressFamily.InterNetwork)
        {
            byte[] bytes = address.GetAddressBytes();
            return bytes[0] == 10
                || (bytes[0] == 172 && (bytes[1] >= 16) && (bytes[1] <= 31))
                || (bytes[0] == 192 && bytes[1] == 168)
                || (bytes[0] == 169 && bytes[1] == 254)
                || bytes[0] == 127;
        }

        if (address.AddressFamily == AddressFamily.InterNetworkV6)
        {
            if (address.Equals(IPAddress.IPv6Loopback))
                return true;

            byte[] bytes = address.GetAddressBytes();
            return (bytes[0] & 0xFE) == 0xFC || (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80);
        }

        return false;
    }
}

internal sealed class DomainGroupRule
{
    public DomainGroupRule(string pattern, string groupName)
    {
        if (string.IsNullOrWhiteSpace(pattern) || string.IsNullOrWhiteSpace(groupName))
            throw new FormatException("Split Horizon domain and group names cannot be empty.");

        Pattern = pattern.Trim().TrimStart('.').ToLowerInvariant();
        GroupName = groupName.Trim().ToLowerInvariant();
    }

    public string Pattern { get; }
    public string GroupName { get; }

    public bool Matches(string qname)
    {
        return qname.Equals(Pattern, StringComparison.OrdinalIgnoreCase) || qname.EndsWith("." + Pattern, StringComparison.OrdinalIgnoreCase);
    }
}

internal sealed class NetworkGroupRule
{
    NetworkGroupRule(IPAddress network, int prefixLength, string groupName)
    {
        Network = network;
        PrefixLength = prefixLength;
        GroupName = groupName.Trim().ToLowerInvariant();
    }

    public IPAddress Network { get; }
    public int PrefixLength { get; }
    public string GroupName { get; }

    public static NetworkGroupRule Parse(string pattern, string groupName)
    {
        if (string.IsNullOrWhiteSpace(groupName))
            throw new FormatException("Split Horizon network group name cannot be empty.");

        string trimmed = pattern.Trim();
        if (trimmed.Contains('/'))
        {
            string[] parts = trimmed.Split('/', 2);
            IPAddress network = IPAddress.Parse(parts[0]);
            int prefixLength = int.Parse(parts[1]);
            int maximumPrefixLength = network.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            if (prefixLength < 0 || prefixLength > maximumPrefixLength)
                throw new FormatException($"Invalid prefix length {prefixLength} for network '{pattern}'.");

            return new NetworkGroupRule(network, prefixLength, groupName);
        }

        IPAddress address = IPAddress.Parse(trimmed);
        int prefixLengthValue = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
        return new NetworkGroupRule(address, prefixLengthValue, groupName);
    }

    public bool Matches(IPAddress address)
    {
        if (address is null)
            return false;

        IPAddress candidate = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
        IPAddress network = Network.IsIPv4MappedToIPv6 ? Network.MapToIPv4() : Network;

        if (candidate.AddressFamily != network.AddressFamily)
            return false;

        byte[] left = candidate.GetAddressBytes();
        byte[] right = network.GetAddressBytes();
        int remainingBits = PrefixLength;

        for (int i = 0; i < left.Length && remainingBits > 0; i++)
        {
            int bitsToCompare = Math.Min(8, remainingBits);
            int mask = 0xFF << (8 - bitsToCompare);

            if ((left[i] & mask) != (right[i] & mask))
                return false;

            remainingBits -= bitsToCompare;
        }

        return true;
    }
}
