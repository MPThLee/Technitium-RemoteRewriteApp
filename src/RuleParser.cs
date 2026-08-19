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
    const int MaxGroupNamesPerRule = 64;
    const int MaxGroupNameLength = 128;

    static readonly JsonDocumentOptions _jsonOptions = new JsonDocumentOptions
    {
        AllowTrailingCommas = true,
        CommentHandling = JsonCommentHandling.Skip
    };

    public static IEnumerable<RewriteRule> ParseAdGuardFilterSource(SourceConfig source, string content, ref int order, RuleParseBudget budget = null)
    {
        List<RewriteRule> rules = new List<RewriteRule>();
        budget ??= new RuleParseBudget();

        foreach (string rawLine in content.Split('\n'))
        {
            string line = rawLine.Trim();
            if ((line.Length == 0) || line.StartsWith("!") || line.StartsWith("#"))
                continue;

            RewriteRule rule;
            try
            {
                rule = ParseAdGuardRule(source, line, order, budget);
            }
            catch (Exception ex) when (ex is not RuleLimitException
                && ex is not UnsupportedRegexConstructException
                && (ex is FormatException or NotSupportedException or ArgumentException))
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

    public static IEnumerable<RewriteRule> ParseRewriteRulesJsonSource(SourceConfig source, string content, ref int order, RuleParseBudget budget = null)
    {
        budget ??= new RuleParseBudget();
        using JsonDocument document = JsonDocument.Parse(content, _jsonOptions);
        JsonElement root = document.RootElement;
        if (root.ValueKind == JsonValueKind.Object)
            JsonObjectValidation.RequireUniqueProperties(root, "Rewrite JSON root");
        JsonElement rulesElement = root.ValueKind == JsonValueKind.Array ? root : root.GetProperty("rules");

        if (rulesElement.ValueKind != JsonValueKind.Array)
            throw new FormatException("Rewrite JSON must contain a 'rules' array or be a top-level array.");

        List<(int Priority, int Index, JsonElement Rule)> orderedRules = new List<(int, int, JsonElement)>();
        int index = 0;

        foreach (JsonElement rule in rulesElement.EnumerateArray())
        {
            if (index >= budget.RemainingRules)
                throw new RuleLimitException($"Configured sources exceed the {budget.MaxRules}-rule limit.");
            if (rule.ValueKind != JsonValueKind.Object)
                throw new FormatException("Each rewrite JSON rule must be an object.");
            JsonObjectValidation.RequireUniqueProperties(rule, "Rewrite JSON rule");

            int priority = rule.TryGetProperty("order", out JsonElement priorityElement) && priorityElement.ValueKind == JsonValueKind.Number
                ? priorityElement.GetInt32()
                : index;
            orderedRules.Add((priority, index++, rule));
        }

        List<RewriteRule> rules = new List<RewriteRule>();
        foreach ((int _, int _, JsonElement rule) in orderedRules.OrderBy(static item => item.Priority).ThenBy(static item => item.Index))
        {
            RewriteAnswer[] answers = ParseAnswers(rule);

            uint? ttl = ParseOptionalTtl(rule);

            DnsResponseCode responseCode = rule.TryGetProperty("responseCode", out JsonElement responseCodeElement)
                ? responseCodeElement.ValueKind == JsonValueKind.String
                    ? ParseResponseCode(responseCodeElement.GetString())
                    : throw new FormatException("Rewrite JSON responseCode must be a string.")
                : DnsResponseCode.NoError;

            MatchType matchType = ParseMatchType(RequiredString(rule, "matchType"));
            HashSet<string> ruleGroupNames = ParseGroupNames(rule, "groupNames");
            HashSet<DnsResourceRecordType> queryTypes = ParseQueryTypes(rule, "queryTypes");
            bool isException = OptionalBoolean(rule, "exception", false);
            bool hasRewriteValue = OptionalBoolean(rule, "hasRewriteValue", true);
            int groupMembershipCount = source.GroupNames.Count + (ruleGroupNames?.Count ?? 0);
            budget.EnsureCanAdd(matchType, answers.Length, groupMembershipCount, queryTypes?.Count ?? 0);

            RewriteRule parsedRule = new RewriteRule(
                source.Name,
                order,
                matchType,
                RequiredString(rule, "pattern"),
                answers,
                ttl,
                ruleGroupNames,
                responseCode,
                queryTypes,
                isException,
                hasRewriteValue,
                source.GroupNames
            );
            budget.Add(matchType, answers.Length, groupMembershipCount, queryTypes?.Count ?? 0);
            rules.Add(parsedRule);
            order++;
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

    static RewriteRule ParseAdGuardRule(SourceConfig source, string line, int order, RuleParseBudget budget)
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

        if (modifiers.Any(static item => !IsSupportedModifier(item)))
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

        budget.EnsureCanAdd(matchType, answers.Length, source.GroupNames.Count, queryTypes?.Count ?? 0);
        RewriteRule rule = new RewriteRule(
            source.Name,
            order,
            matchType,
            pattern,
            answers,
            null,
            null,
            responseCode,
            queryTypes,
            isException,
            hasRewriteValue,
            source.GroupNames);
        budget.Add(matchType, answers.Length, source.GroupNames.Count, queryTypes?.Count ?? 0);
        return rule;
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
            bool missingType = string.IsNullOrWhiteSpace(full[1]);
            bool missingValue = string.IsNullOrWhiteSpace(full[2]);
            if (missingType && missingValue)
                return true;
            if (missingType || missingValue)
                return false;

            if (!Enum.TryParse(full[1], ignoreCase: true, out DnsResourceRecordType type)
                || !Enum.IsDefined(type)
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
        string[] typeModifiers = modifiers
            .Where(static item => item.StartsWith("dnstype=", StringComparison.OrdinalIgnoreCase))
            .ToArray();
        if (typeModifiers.Length == 0)
            return null;
        if (typeModifiers.Length != 1)
            throw new FormatException("A rewrite rule may contain only one dnstype modifier.");

        HashSet<DnsResourceRecordType> types = new HashSet<DnsResourceRecordType>();
        string modifier = typeModifiers[0];
        string typeList = modifier[(modifier.IndexOf('=') + 1)..];
        if (string.IsNullOrWhiteSpace(typeList))
            throw new FormatException("The dnstype modifier cannot be empty.");

        foreach (string value in typeList.Split('|', StringSplitOptions.TrimEntries))
        {
            if (string.IsNullOrWhiteSpace(value))
                throw new FormatException("The dnstype modifier cannot contain empty query types.");
            if (value.StartsWith('~'))
                throw new NotSupportedException("Negated dnstype modifiers are not supported.");

            if (!Enum.TryParse(value, ignoreCase: true, out DnsResourceRecordType type) || !Enum.IsDefined(type))
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

    static bool IsSupportedModifier(string modifier)
    {
        return modifier.Equals("dnsrewrite", StringComparison.OrdinalIgnoreCase)
            || modifier.StartsWith("dnsrewrite=", StringComparison.OrdinalIgnoreCase)
            || modifier.StartsWith("dnstype=", StringComparison.OrdinalIgnoreCase)
            || modifier.Equals("important", StringComparison.OrdinalIgnoreCase);
    }

    static RewriteAnswer[] ParseAnswers(JsonElement rule)
    {
        if (!rule.TryGetProperty("answers", out JsonElement answersElement))
            return Array.Empty<RewriteAnswer>();

        if (answersElement.ValueKind != JsonValueKind.Array)
            throw new FormatException("Rewrite JSON answers must be an array.");

        List<RewriteAnswer> answers = new List<RewriteAnswer>();
        foreach (JsonElement answer in answersElement.EnumerateArray())
        {
            if (answers.Count >= AppLimits.MaxAnswersPerRule)
                throw new FormatException($"A rewrite rule cannot contain more than {AppLimits.MaxAnswersPerRule} answers.");
            if (answer.ValueKind != JsonValueKind.Object)
                throw new FormatException("Each rewrite answer must be an object.");
            JsonObjectValidation.RequireUniqueProperties(answer, "Rewrite JSON answer");
            answers.Add(new RewriteAnswer(answer));
        }

        return answers.ToArray();
    }

    static MatchType ParseMatchType(string value)
    {
        if (!Enum.TryParse(value, ignoreCase: true, out MatchType matchType) || !Enum.IsDefined(matchType))
            throw new FormatException("Unsupported rewrite match type: " + value);

        return matchType;
    }

    static bool OptionalBoolean(JsonElement item, string propertyName, bool defaultValue)
    {
        if (!item.TryGetProperty(propertyName, out JsonElement value))
            return defaultValue;
        if (value.ValueKind is not (JsonValueKind.True or JsonValueKind.False))
            throw new FormatException($"Rewrite JSON property '{propertyName}' must be a boolean.");
        return value.GetBoolean();
    }

    static uint? ParseOptionalTtl(JsonElement item)
    {
        if (!item.TryGetProperty("ttl", out JsonElement ttl) || ttl.ValueKind == JsonValueKind.Null)
            return null;
        if (ttl.ValueKind != JsonValueKind.Number || !ttl.TryGetUInt32(out uint value))
            throw new FormatException("Rewrite JSON ttl must be a non-negative integer or null.");
        if (value > AppLimits.MaximumTtl)
            throw new FormatException($"Rewrite JSON ttl cannot exceed {AppLimits.MaximumTtl} seconds.");
        return value;
    }

    static string RequiredString(JsonElement item, string propertyName)
    {
        if (!item.TryGetProperty(propertyName, out JsonElement value) || value.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(value.GetString()))
            throw new FormatException($"Rewrite JSON property '{propertyName}' must be a non-empty string.");

        return value.GetString();
    }

    static HashSet<string> ParseGroupNames(JsonElement item, string propertyName)
    {
        if (!item.TryGetProperty(propertyName, out JsonElement groupNames))
            return null;

        if (groupNames.ValueKind != JsonValueKind.Array)
            throw new FormatException($"Rewrite JSON property '{propertyName}' must be an array.");

        HashSet<string> result = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (JsonElement entry in groupNames.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.String || string.IsNullOrWhiteSpace(entry.GetString()))
                throw new FormatException($"Rewrite JSON property '{propertyName}' must contain only non-empty strings.");

            string normalized = entry.GetString().Trim().ToLowerInvariant();
            if (normalized.Length > MaxGroupNameLength)
                throw new FormatException($"Rewrite JSON group names cannot exceed {MaxGroupNameLength} characters.");

            result.Add(normalized);
            if (result.Count > MaxGroupNamesPerRule)
                throw new FormatException($"A rewrite rule cannot contain more than {MaxGroupNamesPerRule} distinct group names.");
        }

        return result.Count > 0 ? result : null;
    }

    static HashSet<DnsResourceRecordType> ParseQueryTypes(JsonElement item, string propertyName)
    {
        if (!item.TryGetProperty(propertyName, out JsonElement queryTypes))
            return null;

        if (queryTypes.ValueKind != JsonValueKind.Array)
            throw new FormatException($"Rewrite JSON property '{propertyName}' must be an array.");

        HashSet<DnsResourceRecordType> result = new HashSet<DnsResourceRecordType>();
        foreach (JsonElement entry in queryTypes.EnumerateArray())
        {
            if (entry.ValueKind != JsonValueKind.String
                || !Enum.TryParse(entry.GetString(), ignoreCase: true, out DnsResourceRecordType type)
                || !Enum.IsDefined(type))
                throw new FormatException("Rewrite JSON contains an invalid query type.");
            result.Add(type);
        }

        return result.Count > 0 ? result : null;
    }
}
