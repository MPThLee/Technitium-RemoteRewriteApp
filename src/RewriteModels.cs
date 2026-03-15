using System;
using System.Collections.Generic;
using System.Text.Json;
using System.Text.RegularExpressions;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace RemoteRewrite;

internal sealed class RewriteRule
{
    readonly Regex _regex;

    public RewriteRule(string sourceName, int order, MatchType matchType, string pattern, RewriteAnswer[] answers, uint? ttl, HashSet<string> groupNames)
    {
        SourceName = sourceName;
        Order = order;
        MatchType = matchType;
        Pattern = pattern.ToLowerInvariant();
        Answers = answers;
        Ttl = ttl;
        GroupNames = groupNames.Count == 0
            ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            : new HashSet<string>(groupNames, StringComparer.OrdinalIgnoreCase);

        if (matchType == MatchType.Regex)
            _regex = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant, AppLimits.RegexTimeout);
    }

    public string SourceName { get; }
    public int Order { get; }
    public MatchType MatchType { get; }
    public string Pattern { get; }
    public RewriteAnswer[] Answers { get; }
    public uint? Ttl { get; }
    public HashSet<string> GroupNames { get; }

    public bool IsMatch(string qname)
    {
        switch (MatchType)
        {
            case MatchType.Suffix:
                return qname.Equals(Pattern, StringComparison.OrdinalIgnoreCase) || qname.EndsWith("." + Pattern, StringComparison.OrdinalIgnoreCase);

            case MatchType.Glob:
                return RuleParser.GlobMatch(qname, Pattern);

            case MatchType.Regex:
                try
                {
                    return _regex.IsMatch(qname);
                }
                catch (RegexMatchTimeoutException)
                {
                    return false;
                }

            default:
                return false;
        }
    }
}

internal sealed class RewriteAnswer
{
    public RewriteAnswer(DnsResourceRecordType type, string value)
    {
        Type = type;
        Value = value;
    }

    public RewriteAnswer(JsonElement json)
    {
        Type = Enum.Parse<DnsResourceRecordType>(json.GetProperty("type").GetString(), ignoreCase: true);
        Value = json.GetProperty("value").GetString();
    }

    public DnsResourceRecordType Type { get; }
    public string Value { get; }
}

internal enum MatchType
{
    Suffix,
    Glob,
    Regex
}
