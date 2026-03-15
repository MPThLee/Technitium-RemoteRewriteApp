using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace RemoteRewrite;

internal static class RuleParser
{
    public static IEnumerable<RewriteRule> ParseAdGuardFilterSource(SourceConfig source, string content, ref int order)
    {
        List<RewriteRule> rules = new List<RewriteRule>();

        foreach (string rawLine in content.Split('\n'))
        {
            string line = rawLine.Trim();
            if ((line.Length == 0) || line.StartsWith("!") || line.StartsWith("#") || !line.Contains("$dnsrewrite="))
                continue;

            Match regexMatch = Regex.Match(line, @"^/(.+)/\$dnsrewrite=([^,$]+)(?:,(.*))?$");
            if (regexMatch.Success)
            {
                RewriteAnswer answer = ParseAnswer(regexMatch.Groups[2].Value);
                if (answer is not null)
                {
                    rules.Add(new RewriteRule(source.Name, order++, MatchType.Regex, regexMatch.Groups[1].Value, new[] { answer }, null, source.GroupNames));
                }
                continue;
            }

            Match hostMatch = Regex.Match(line, @"^(?:@@)?\|\|(.+?)\^\$dnsrewrite=([^,$]+)(?:,(.*))?$");
            if (!hostMatch.Success)
                continue;

            RewriteAnswer hostAnswer = ParseAnswer(hostMatch.Groups[2].Value);
            if (hostAnswer is null)
                continue;

            string pattern = hostMatch.Groups[1].Value.Trim().ToLowerInvariant();
            MatchType matchType = pattern.Contains('*') ? MatchType.Glob : MatchType.Suffix;

            rules.Add(new RewriteRule(source.Name, order++, matchType, pattern, new[] { hostAnswer }, null, source.GroupNames));
        }

        return rules;
    }

    public static IEnumerable<RewriteRule> ParseRewriteRulesJsonSource(SourceConfig source, string content, ref int order)
    {
        using JsonDocument document = JsonDocument.Parse(content);
        JsonElement root = document.RootElement;
        List<RewriteRule> rules = new List<RewriteRule>();

        foreach (JsonElement rule in root.GetProperty("rules").EnumerateArray())
        {
            RewriteAnswer[] answers = rule.GetProperty("answers").EnumerateArray().Select(static item => new RewriteAnswer(item)).ToArray();
            uint? ttl = null;

            if (rule.TryGetProperty("ttl", out JsonElement ttlElement) && (ttlElement.ValueKind == JsonValueKind.Number))
                ttl = ttlElement.GetUInt32();

            rules.Add(new RewriteRule(
                source.Name,
                order++,
                Enum.Parse<MatchType>(rule.GetProperty("matchType").GetString(), ignoreCase: true),
                rule.GetProperty("pattern").GetString(),
                answers,
                ttl,
                MergeGroupNames(source.GroupNames, ParseGroupNames(rule, "groupNames"))
            ));
        }

        return rules;
    }

    public static RewriteAnswer ParseAnswer(string value)
    {
        string target = value.Trim().ToLowerInvariant();

        if (IPAddress.TryParse(target, out IPAddress address))
        {
            if (address.AddressFamily == AddressFamily.InterNetwork)
                return new RewriteAnswer(DnsResourceRecordType.A, target);

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
                return new RewriteAnswer(DnsResourceRecordType.AAAA, target);

            return null;
        }

        return new RewriteAnswer(DnsResourceRecordType.CNAME, target);
    }

    public static bool GlobMatch(string qname, string pattern)
    {
        string regex = "^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$";
        return Regex.IsMatch(qname, regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, AppLimits.RegexTimeout);
    }

    static HashSet<string> ParseGroupNames(JsonElement item, string propertyName)
    {
        if (!item.TryGetProperty(propertyName, out JsonElement groupNames) || (groupNames.ValueKind != JsonValueKind.Array))
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        return new HashSet<string>(
            groupNames.EnumerateArray()
                .Where(static entry => entry.ValueKind == JsonValueKind.String)
                .Select(static entry => entry.GetString()?.Trim().ToLowerInvariant())
                .Where(static entry => !string.IsNullOrWhiteSpace(entry)),
            StringComparer.OrdinalIgnoreCase
        );
    }

    static HashSet<string> MergeGroupNames(HashSet<string> first, HashSet<string> second)
    {
        if ((first.Count == 0) && (second.Count == 0))
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        HashSet<string> merged = new HashSet<string>(first, StringComparer.OrdinalIgnoreCase);
        merged.UnionWith(second);
        return merged;
    }
}
