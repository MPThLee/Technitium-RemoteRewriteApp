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
    static readonly JsonDocumentOptions _jsonOptions = new JsonDocumentOptions
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip
    };

    public static IEnumerable<RewriteRule> ParseAdGuardFilterSource(SourceConfig source, string content, ref int order)
    {
        List<RewriteRule> rules = new List<RewriteRule>();

        foreach (string rawLine in content.Split('\n'))
        {
            string line = rawLine.Trim();
            if ((line.Length == 0) || line.StartsWith("!") || line.StartsWith("#"))
                continue;

            RewriteRule rule;
            try
            {
                rule = ParseAdGuardRule(source, line, order);
            }
            catch (Exception ex) when (ex is FormatException or NotSupportedException or ArgumentException)
            {
                continue;
            }
            if (rule is null)
                continue;

            rules.Add(rule);
            order++;
        }

        return rules;
    }

    public static IEnumerable<RewriteRule> ParseRewriteRulesJsonSource(SourceConfig source, string content, ref int order)
    {
        using JsonDocument document = JsonDocument.Parse(content, _jsonOptions);
        JsonElement root = document.RootElement;
        JsonElement rulesElement = root.ValueKind == JsonValueKind.Array ? root : root.GetProperty("rules");

        if (rulesElement.ValueKind != JsonValueKind.Array)
            throw new FormatException("Rewrite JSON must contain a 'rules' array or be a top-level array.");

        List<(int Priority, int Index, JsonElement Rule)> orderedRules = new List<(int, int, JsonElement)>();
        int index = 0;

        foreach (JsonElement rule in rulesElement.EnumerateArray())
        {
            int priority = rule.TryGetProperty("order", out JsonElement priorityElement) && priorityElement.ValueKind == JsonValueKind.Number
                ? priorityElement.GetInt32()
                : index;
            orderedRules.Add((priority, index++, rule));
        }

        List<RewriteRule> rules = new List<RewriteRule>();
        foreach ((int _, int _, JsonElement rule) in orderedRules.OrderBy(static item => item.Priority).ThenBy(static item => item.Index))
        {
            RewriteAnswer[] answers = rule.TryGetProperty("answers", out JsonElement answersElement) && answersElement.ValueKind == JsonValueKind.Array
                ? answersElement.EnumerateArray().Select(static item => new RewriteAnswer(item)).ToArray()
                : Array.Empty<RewriteAnswer>();

            uint? ttl = rule.TryGetProperty("ttl", out JsonElement ttlElement) && ttlElement.ValueKind == JsonValueKind.Number
                ? ttlElement.GetUInt32()
                : null;

            DnsResponseCode responseCode = rule.TryGetProperty("responseCode", out JsonElement responseCodeElement)
                ? ParseResponseCode(responseCodeElement.GetString())
                : DnsResponseCode.NoError;

            rules.Add(new RewriteRule(
                source.Name,
                order++,
                Enum.Parse<MatchType>(RequiredString(rule, "matchType"), ignoreCase: true),
                RequiredString(rule, "pattern"),
                answers,
                ttl,
                MergeGroupNames(source.GroupNames, ParseGroupNames(rule, "groupNames")),
                responseCode,
                ParseQueryTypes(rule, "queryTypes"),
                rule.TryGetProperty("exception", out JsonElement exception) && exception.ValueKind == JsonValueKind.True,
                rule.TryGetProperty("hasRewriteValue", out JsonElement hasRewriteValue) ? hasRewriteValue.GetBoolean() : true
            ));
        }

        return rules;
    }

    public static RewriteAnswer ParseAnswer(string value)
    {
        string target = value?.Trim().TrimEnd('.').ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(target))
            return null;

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

    static RewriteRule ParseAdGuardRule(SourceConfig source, string line, int order)
    {
        bool isException = line.StartsWith("@@", StringComparison.Ordinal);
        string body = isException ? line[2..] : line;
        int modifierStart = body.LastIndexOf('$');
        if (modifierStart < 1)
            return null;

        string patternText = body[..modifierStart];
        string[] modifiers = body[(modifierStart + 1)..].Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        string rewriteModifier = modifiers.FirstOrDefault(static item => item.Equals("dnsrewrite", StringComparison.OrdinalIgnoreCase) || item.StartsWith("dnsrewrite=", StringComparison.OrdinalIgnoreCase));
        if (rewriteModifier is null)
            return null;

        if (modifiers.Any(static item => IsUnsupportedTargetingModifier(item)))
            return null;

        if (!TryParsePattern(patternText, out MatchType matchType, out string pattern))
            return null;

        HashSet<DnsResourceRecordType> queryTypes = ParseDnsTypeModifier(modifiers);
        bool hasRewriteValue = rewriteModifier.Length > "dnsrewrite".Length && rewriteModifier["dnsrewrite".Length] == '=';
        DnsResponseCode responseCode = DnsResponseCode.NoError;
        RewriteAnswer[] answers = Array.Empty<RewriteAnswer>();

        if (hasRewriteValue)
        {
            string value = rewriteModifier[(rewriteModifier.IndexOf('=') + 1)..].Trim();
            if (!TryParseRewriteValue(value, out responseCode, out answers))
                return null;
        }
        else if (!isException)
        {
            return null;
        }

        return new RewriteRule(
            source.Name,
            order,
            matchType,
            pattern,
            answers,
            null,
            source.GroupNames,
            responseCode,
            queryTypes,
            isException,
            hasRewriteValue);
    }

    static bool TryParsePattern(string value, out MatchType matchType, out string pattern)
    {
        string candidate = value.Trim();
        matchType = MatchType.Suffix;
        pattern = null;

        if (candidate.StartsWith('/') && candidate.EndsWith('/') && candidate.Length > 2)
        {
            matchType = MatchType.Regex;
            pattern = candidate[1..^1];
            return true;
        }

        if (candidate.StartsWith("||", StringComparison.Ordinal))
        {
            candidate = candidate[2..];
            if (candidate.EndsWith('^'))
                candidate = candidate[..^1];
            matchType = candidate.Contains('*') ? MatchType.Glob : MatchType.Suffix;
        }
        else if (candidate.StartsWith('|') && candidate.EndsWith('|') && candidate.Length > 2)
        {
            candidate = candidate[1..^1];
            matchType = candidate.Contains('*') ? MatchType.Glob : MatchType.Exact;
        }
        else
        {
            if (candidate.EndsWith('^'))
                candidate = candidate[..^1];
            matchType = candidate.Contains('*') ? MatchType.Glob : MatchType.Suffix;
        }

        candidate = candidate.Trim().TrimEnd('.').ToLowerInvariant();
        if (candidate.Length == 0 || candidate.Any(char.IsWhiteSpace))
            return false;

        if ((matchType == MatchType.Exact || matchType == MatchType.Suffix) && !DnsClient.IsDomainNameValid(candidate))
            return false;

        pattern = candidate;
        return true;
    }

    static bool TryParseRewriteValue(string value, out DnsResponseCode responseCode, out RewriteAnswer[] answers)
    {
        responseCode = DnsResponseCode.NoError;
        answers = Array.Empty<RewriteAnswer>();

        if (string.IsNullOrWhiteSpace(value))
            return true;

        string[] full = value.Split(';', 3);
        if (full.Length == 3)
        {
            responseCode = ParseResponseCode(full[0]);
            if (string.IsNullOrWhiteSpace(full[1]) || string.IsNullOrWhiteSpace(full[2]))
                return true;

            if (!Enum.TryParse(full[1], ignoreCase: true, out DnsResourceRecordType type)
                || (type != DnsResourceRecordType.A && type != DnsResourceRecordType.AAAA && type != DnsResourceRecordType.CNAME))
                return false;

            answers = new[] { new RewriteAnswer(type, full[2]) };
            return true;
        }

        if (IsResponseCodeKeyword(value))
        {
            responseCode = ParseResponseCode(value);
            return true;
        }

        RewriteAnswer answer = ParseAnswer(value);
        if (answer is null)
            return false;

        answers = new[] { answer };
        return true;
    }

    static DnsResponseCode ParseResponseCode(string value)
    {
        return value?.Trim().ToUpperInvariant() switch
        {
            "NOERROR" => DnsResponseCode.NoError,
            "FORMERR" => DnsResponseCode.FormatError,
            "SERVFAIL" => DnsResponseCode.ServerFailure,
            "NXDOMAIN" => DnsResponseCode.NxDomain,
            "REFUSED" => DnsResponseCode.Refused,
            _ => throw new FormatException("Unsupported DNS rewrite response code: " + value)
        };
    }

    static bool IsResponseCodeKeyword(string value)
    {
        string keyword = value.Trim().ToUpperInvariant();
        return keyword is "NOERROR" or "FORMERR" or "SERVFAIL" or "NXDOMAIN" or "REFUSED";
    }

    static HashSet<DnsResourceRecordType> ParseDnsTypeModifier(IEnumerable<string> modifiers)
    {
        string modifier = modifiers.FirstOrDefault(static item => item.StartsWith("dnstype=", StringComparison.OrdinalIgnoreCase));
        if (modifier is null)
            return new HashSet<DnsResourceRecordType>();

        HashSet<DnsResourceRecordType> types = new HashSet<DnsResourceRecordType>();
        foreach (string value in modifier[(modifier.IndexOf('=') + 1)..].Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            if (value.StartsWith('~'))
                throw new NotSupportedException("Negated dnstype modifiers are not supported.");

            if (!Enum.TryParse(value, ignoreCase: true, out DnsResourceRecordType type))
                throw new FormatException("Unsupported DNS query type: " + value);

            types.Add(type);
        }

        return types;
    }

    static bool IsUnsupportedTargetingModifier(string modifier)
    {
        return modifier.StartsWith("client=", StringComparison.OrdinalIgnoreCase)
            || modifier.StartsWith("ctag=", StringComparison.OrdinalIgnoreCase)
            || modifier.StartsWith("denyallow=", StringComparison.OrdinalIgnoreCase);
    }

    static string RequiredString(JsonElement item, string propertyName)
    {
        if (!item.TryGetProperty(propertyName, out JsonElement value) || value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
            throw new FormatException($"Rewrite JSON property '{propertyName}' must be a non-empty string.");

        return value.GetString();
    }

    static HashSet<string> ParseGroupNames(JsonElement item, string propertyName)
    {
        if (!item.TryGetProperty(propertyName, out JsonElement groupNames) || groupNames.ValueKind != JsonValueKind.Array)
            return new HashSet<string>(StringComparer.OrdinalIgnoreCase);

        return new HashSet<string>(
            groupNames.EnumerateArray()
                .Where(static entry => entry.ValueKind == JsonValueKind.String)
                .Select(static entry => entry.GetString()?.Trim().ToLowerInvariant())
                .Where(static entry => !string.IsNullOrWhiteSpace(entry)),
            StringComparer.OrdinalIgnoreCase);
    }

    static HashSet<DnsResourceRecordType> ParseQueryTypes(JsonElement item, string propertyName)
    {
        if (!item.TryGetProperty(propertyName, out JsonElement queryTypes) || queryTypes.ValueKind != JsonValueKind.Array)
            return new HashSet<DnsResourceRecordType>();

        HashSet<DnsResourceRecordType> result = new HashSet<DnsResourceRecordType>();
        foreach (JsonElement entry in queryTypes.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.String || !Enum.TryParse(entry.GetString(), ignoreCase: true, out DnsResourceRecordType type))
                throw new FormatException("Rewrite JSON contains an invalid query type.");
            result.Add(type);
        }

        return result;
    }

    static HashSet<string> MergeGroupNames(HashSet<string> first, HashSet<string> second)
    {
        HashSet<string> merged = new HashSet<string>(first, StringComparer.OrdinalIgnoreCase);
        merged.UnionWith(second);
        return merged;
    }
}
