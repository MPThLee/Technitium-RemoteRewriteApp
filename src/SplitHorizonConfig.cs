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

            configFile = Path.Combine(appRoot, "SplitHorizonApp", "dnsApp.config");
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

        if (root.TryGetProperty("domainGroupMap", out JsonElement domainGroupMap) && (domainGroupMap.ValueKind == JsonValueKind.Object))
        {
            foreach (JsonProperty property in domainGroupMap.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.String)
                    domainRules.Add(new DomainGroupRule(property.Name, property.Value.GetString()));
            }
        }

        if (root.TryGetProperty("networkGroupMap", out JsonElement networkGroupMap) && (networkGroupMap.ValueKind == JsonValueKind.Object))
        {
            foreach (JsonProperty property in networkGroupMap.EnumerateObject())
            {
                if (property.Value.ValueKind == JsonValueKind.String)
                    networkRules.Add(NetworkGroupRule.Parse(property.Name, property.Value.GetString()));
            }
        }

        DomainGroupRules = domainRules.Concat(DomainGroupRules).OrderByDescending(static item => item.Pattern.Length).ToArray();
        NetworkGroupRules = networkRules.Concat(NetworkGroupRules).OrderByDescending(static item => item.PrefixLength).ToArray();
    }

    public HashSet<string> ResolveGroups(string qname, IPAddress address)
    {
        HashSet<string> groups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        if (!Enable)
            return groups;

        AddGroup(groups, DefaultGroupName);
        AddGroup(groups, NetworkClassifier.IsPrivateOrSpecial(address) ? PrivateGroupName : PublicGroupName);

        foreach (DomainGroupRule rule in DomainGroupRules)
        {
            if (rule.Matches(qname))
                AddGroup(groups, rule.GroupName);
        }

        foreach (NetworkGroupRule rule in NetworkGroupRules)
        {
            if (rule.Matches(address))
                AddGroup(groups, rule.GroupName);
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
        string trimmed = pattern.Trim();
        if (trimmed.Contains('/'))
        {
            string[] parts = trimmed.Split('/', 2);
            IPAddress network = IPAddress.Parse(parts[0]);
            int prefixLength = int.Parse(parts[1]);
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
