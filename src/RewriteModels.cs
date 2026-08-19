using System;
using System.Collections.Frozen;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text.Json;
using System.Text.RegularExpressions;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace RemoteRewrite;

internal sealed class RewriteRule
{
    static readonly IReadOnlySet<string> _emptyGroupNames = Array.Empty<string>().ToFrozenSet(StringComparer.OrdinalIgnoreCase);
    static readonly IReadOnlySet<DnsResourceRecordType> _emptyQueryTypes = Array.Empty<DnsResourceRecordType>().ToFrozenSet();
    readonly Regex _matcher;

    public RewriteRule(
        string sourceName,
        int order,
        MatchType matchType,
        string pattern,
        RewriteAnswer[] answers,
        uint? ttl,
        HashSet<string> groupNames,
        DnsResponseCode responseCode = DnsResponseCode.NoError,
        HashSet<DnsResourceRecordType> queryTypes = null,
        bool isException = false,
        bool hasRewriteValue = true,
        HashSet<string> sourceGroupNames = null)
    {
        string normalizedPattern = pattern?.Trim().TrimEnd('.').ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(normalizedPattern))
            throw new FormatException("Rewrite rule pattern cannot be empty.");

        if (pattern.Length > AppLimits.MaxPatternLength)
            throw new FormatException($"Rewrite rule pattern exceeds the {AppLimits.MaxPatternLength}-character limit.");

        if ((matchType is MatchType.Exact or MatchType.Suffix)
            && (normalizedPattern.Contains('*') || !DnsClient.IsDomainNameValid(normalizedPattern)))
            throw new FormatException($"Rewrite rule {matchType.ToString().ToLowerInvariant()} pattern must be a valid DNS name.");

        if (ttl > AppLimits.MaximumTtl)
            throw new FormatException($"Rewrite rule TTL cannot exceed {AppLimits.MaximumTtl} seconds.");

        if ((answers?.Length ?? 0) > AppLimits.MaxAnswersPerRule)
            throw new FormatException($"A rewrite rule cannot contain more than {AppLimits.MaxAnswersPerRule} answers.");

        if (responseCode != DnsResponseCode.NoError && (answers?.Length ?? 0) > 0)
            throw new FormatException("A rewrite rule with an error response code cannot also contain answers.");

        if ((answers?.Any(static answer => answer.Type == DnsResourceRecordType.CNAME) ?? false) && answers.Length > 1)
            throw new FormatException("A CNAME rewrite cannot coexist with other answers in the same rule.");

        SourceName = sourceName;
        Order = order;
        MatchType = matchType;
        Pattern = normalizedPattern;
        Answers = answers ?? Array.Empty<RewriteAnswer>();
        Ttl = ttl;
        RuleGroupNames = groupNames?.Count > 0 ? groupNames : _emptyGroupNames;
        SourceGroupNames = sourceGroupNames?.Count > 0 ? sourceGroupNames : _emptyGroupNames;
        ResponseCode = responseCode;
        QueryTypes = queryTypes?.Count > 0 ? queryTypes : _emptyQueryTypes;
        IsException = isException;
        HasRewriteValue = hasRewriteValue;

        if (matchType == MatchType.Regex)
        {
            _matcher = CreateNonBacktrackingRegex(pattern);
        }
        else if (matchType == MatchType.Glob)
        {
            string regexPattern = "^" + Regex.Escape(Pattern).Replace("\\*", ".*") + "$";
            _matcher = CreateNonBacktrackingRegex(regexPattern);
        }
    }

    public string SourceName { get; }
    public int Order { get; }
    public MatchType MatchType { get; }
    public string Pattern { get; }
    public RewriteAnswer[] Answers { get; }
    public uint? Ttl { get; }
    public IReadOnlySet<string> GroupNames
    {
        get
        {
            if (SourceGroupNames.Count == 0)
                return RuleGroupNames;
            if (RuleGroupNames.Count == 0)
                return SourceGroupNames;

            HashSet<string> combined = new HashSet<string>(SourceGroupNames, StringComparer.OrdinalIgnoreCase);
            combined.UnionWith(RuleGroupNames);
            return combined;
        }
    }
    public IReadOnlySet<string> RuleGroupNames { get; }
    public IReadOnlySet<string> SourceGroupNames { get; }
    public DnsResponseCode ResponseCode { get; }
    public IReadOnlySet<DnsResourceRecordType> QueryTypes { get; }
    public bool IsException { get; }
    public bool HasRewriteValue { get; }

    static Regex CreateNonBacktrackingRegex(string pattern)
    {
        try
        {
            return new Regex(
                pattern,
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.NonBacktracking,
                AppLimits.RegexTimeout);
        }
        catch (NotSupportedException ex)
        {
            throw new UnsupportedRegexConstructException(
                "Regex rules cannot use constructs that require backtracking, such as lookarounds or backreferences.",
                ex);
        }
    }

    public bool IsMatch(string qname)
    {
        return TryMatch(qname, out _);
    }

    public bool TryMatch(string qname, out bool timedOut)
    {
        timedOut = false;
        try
        {
            return MatchType switch
            {
                MatchType.Exact => qname.Equals(Pattern, StringComparison.OrdinalIgnoreCase),
                MatchType.Suffix => qname.Equals(Pattern, StringComparison.OrdinalIgnoreCase) || qname.EndsWith("." + Pattern, StringComparison.OrdinalIgnoreCase),
                MatchType.Glob or MatchType.Regex => _matcher.IsMatch(qname),
                _ => false
            };
        }
        catch (RegexMatchTimeoutException)
        {
            timedOut = true;
            return false;
        }
    }

    public bool AppliesTo(DnsResourceRecordType questionType)
    {
        return QueryTypes.Count == 0 || QueryTypes.Contains(questionType) || questionType == DnsResourceRecordType.ANY;
    }

    public bool AppliesToGroups(HashSet<string> resolvedGroups)
    {
        return (SourceGroupNames.Count == 0 || SourceGroupNames.Overlaps(resolvedGroups))
            && (RuleGroupNames.Count == 0 || RuleGroupNames.Overlaps(resolvedGroups));
    }

    public bool Disables(RewriteRule candidate)
    {
        if (!IsException || !HasRewriteValue)
            return IsException;

        if (ResponseCode != candidate.ResponseCode)
            return false;

        if (Answers.Length == 0)
            return candidate.Answers.Length == 0;

        return Answers.Any(exceptionAnswer => candidate.Answers.Any(exceptionAnswer.Equals));
    }
}

internal sealed class RewriteMatch
{
    public RewriteMatch(DnsResponseCode responseCode, IReadOnlyList<RewriteRule> rules)
    {
        ResponseCode = responseCode;
        Rules = rules;
    }

    public DnsResponseCode ResponseCode { get; }
    public IReadOnlyList<RewriteRule> Rules { get; }
}

internal sealed class RewriteAnswer
{
    public RewriteAnswer(DnsResourceRecordType type, string value)
    {
        if ((type != DnsResourceRecordType.A) && (type != DnsResourceRecordType.AAAA) && (type != DnsResourceRecordType.CNAME))
            throw new NotSupportedException("Only A, AAAA, and CNAME rewrite answers are supported.");

        string normalizedValue = value?.Trim().TrimEnd('.').ToLowerInvariant();
        if (string.IsNullOrWhiteSpace(normalizedValue))
            throw new FormatException("Rewrite answer value cannot be empty.");

        if ((type == DnsResourceRecordType.A) || (type == DnsResourceRecordType.AAAA))
        {
            if (!IPAddress.TryParse(normalizedValue, out IPAddress address))
                throw new FormatException($"Rewrite answer '{normalizedValue}' is not a valid IP address.");

            if ((type == DnsResourceRecordType.A) && (address.AddressFamily != AddressFamily.InterNetwork))
                throw new FormatException($"Rewrite answer '{normalizedValue}' is not an IPv4 address.");

            if ((type == DnsResourceRecordType.AAAA) && (address.AddressFamily != AddressFamily.InterNetworkV6))
                throw new FormatException($"Rewrite answer '{normalizedValue}' is not an IPv6 address.");
        }
        else if (!DnsClient.IsDomainNameValid(normalizedValue))
        {
            throw new FormatException($"Rewrite answer '{normalizedValue}' is not a valid CNAME target.");
        }

        Type = type;
        Value = normalizedValue;
    }

    public RewriteAnswer(JsonElement json)
        : this(
            ParseType(json.GetProperty("type")),
            json.GetProperty("value").GetString())
    {
    }

    public DnsResourceRecordType Type { get; }
    public string Value { get; }

    public bool Equals(RewriteAnswer other)
    {
        return other is not null
            && Type == other.Type
            && Value.Equals(other.Value, StringComparison.OrdinalIgnoreCase);
    }

    static DnsResourceRecordType ParseType(JsonElement value)
    {
        if (value.ValueKind != JsonValueKind.String
            || !Enum.TryParse(value.GetString(), ignoreCase: true, out DnsResourceRecordType type)
            || !Enum.IsDefined(type))
        {
            throw new FormatException("Rewrite answer type is invalid.");
        }

        return type;
    }
}

internal sealed class RuleParseBudget
{
    readonly int _maxRules;
    readonly int _maxRegexRules;
    readonly int _maxAnswerMemberships;
    readonly int _maxGroupIndexMemberships;
    readonly int _maxQueryTypeMemberships;
    int _rules;
    int _regexRules;
    int _answerMemberships;
    int _groupIndexMemberships;
    int _queryTypeMemberships;

    public RuleParseBudget(
        int maxRules = AppLimits.MaxRules,
        int maxRegexRules = AppLimits.MaxRegexRules,
        int maxAnswerMemberships = AppLimits.MaxAnswerMemberships,
        int maxGroupIndexMemberships = AppLimits.MaxGroupIndexMemberships,
        int maxQueryTypeMemberships = AppLimits.MaxQueryTypeMemberships)
    {
        _maxRules = maxRules;
        _maxRegexRules = maxRegexRules;
        _maxAnswerMemberships = maxAnswerMemberships;
        _maxGroupIndexMemberships = maxGroupIndexMemberships;
        _maxQueryTypeMemberships = maxQueryTypeMemberships;
    }

    public void EnsureCanAdd(MatchType matchType, int answerCount, int groupIndexCount, int queryTypeCount)
    {
        if (_rules >= _maxRules)
            throw new RuleLimitException($"Configured sources exceed the {_maxRules}-rule limit.");

        if ((matchType is MatchType.Glob or MatchType.Regex) && _regexRules >= _maxRegexRules)
            throw new RuleLimitException($"Configured sources exceed the {_maxRegexRules}-rule glob/regex limit.");

        if (answerCount > AppLimits.MaxAnswersPerRule)
            throw new FormatException($"A rewrite rule cannot contain more than {AppLimits.MaxAnswersPerRule} answers.");

        EnsureAggregateLimit(_answerMemberships, answerCount, _maxAnswerMemberships, "answer");
        EnsureAggregateLimit(_groupIndexMemberships, groupIndexCount, _maxGroupIndexMemberships, "group-index");
        EnsureAggregateLimit(_queryTypeMemberships, queryTypeCount, _maxQueryTypeMemberships, "query-type");
    }

    public void Add(MatchType matchType, int answerCount, int groupIndexCount, int queryTypeCount)
    {
        _rules++;
        if (matchType is MatchType.Glob or MatchType.Regex)
            _regexRules++;
        _answerMemberships += answerCount;
        _groupIndexMemberships += groupIndexCount;
        _queryTypeMemberships += queryTypeCount;
    }

    static void EnsureAggregateLimit(int current, int additional, int maximum, string label)
    {
        if (additional < 0 || current > maximum - additional)
            throw new RuleLimitException($"Configured sources exceed the {maximum} aggregate {label} membership limit.");
    }

    public int RuleCount => _rules;
    public int MaxRules => _maxRules;
    public int RemainingRules => _maxRules - _rules;
}

internal sealed class RuleLimitException : FormatException
{
    public RuleLimitException(string message) : base(message)
    {
    }
}

internal sealed class UnsupportedRegexConstructException : FormatException
{
    public UnsupportedRegexConstructException(string message, Exception innerException) : base(message, innerException)
    {
    }
}

internal enum MatchType
{
    Exact,
    Suffix,
    Glob,
    Regex
}
