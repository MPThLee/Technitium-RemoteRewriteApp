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

internal sealed class RewriteRule
{
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
        bool hasRewriteValue = true)
    {
        if (string.IsNullOrWhiteSpace(pattern))
            throw new FormatException("Rewrite rule pattern cannot be empty.");

        SourceName = sourceName;
        Order = order;
        MatchType = matchType;
        Pattern = pattern.Trim().TrimEnd('.').ToLowerInvariant();
        Answers = answers ?? Array.Empty<RewriteAnswer>();
        Ttl = ttl;
        GroupNames = groupNames?.Count > 0
            ? new HashSet<string>(groupNames, StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        ResponseCode = responseCode;
        QueryTypes = queryTypes?.Count > 0
            ? new HashSet<DnsResourceRecordType>(queryTypes)
            : new HashSet<DnsResourceRecordType>();
        IsException = isException;
        HasRewriteValue = hasRewriteValue;

        if (matchType == MatchType.Regex)
        {
            _matcher = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant, AppLimits.RegexTimeout);
        }
        else if (matchType == MatchType.Glob)
        {
            string regexPattern = "^" + Regex.Escape(Pattern).Replace("\\*", ".*") + "$";
            _matcher = new Regex(regexPattern, RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant, AppLimits.RegexTimeout);
        }
    }

    public string SourceName { get; }
    public int Order { get; }
    public MatchType MatchType { get; }
    public string Pattern { get; }
    public RewriteAnswer[] Answers { get; }
    public uint? Ttl { get; }
    public HashSet<string> GroupNames { get; }
    public DnsResponseCode ResponseCode { get; }
    public HashSet<DnsResourceRecordType> QueryTypes { get; }
    public bool IsException { get; }
    public bool HasRewriteValue { get; }

    public bool IsMatch(string qname)
    {
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
            return false;
        }
    }

    public bool AppliesTo(DnsResourceRecordType questionType)
    {
        return QueryTypes.Count == 0 || QueryTypes.Contains(questionType) || questionType == DnsResourceRecordType.ANY;
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
            Enum.Parse<DnsResourceRecordType>(json.GetProperty("type").GetString(), ignoreCase: true),
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
}

internal enum MatchType
{
    Exact,
    Suffix,
    Glob,
    Regex
}
