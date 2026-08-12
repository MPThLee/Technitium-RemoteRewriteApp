using System;
using System.Collections.Generic;
using System.Linq;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace RemoteRewrite;

internal static class RuleMatcher
{
    public static RewriteMatch Match(
        IEnumerable<RewriteRule> primaryRules,
        IEnumerable<RewriteRule> secondaryRules,
        string qname,
        DnsResourceRecordType questionType,
        HashSet<string> enabledSources,
        HashSet<string> requestedGroups,
        HashSet<string> resolvedGroups)
    {
        if ((requestedGroups.Count > 0) && !requestedGroups.Overlaps(resolvedGroups))
            return null;

        List<RewriteRule> primaryCandidates = new List<RewriteRule>();
        List<RewriteRule> exceptions = new List<RewriteRule>();

        Collect(primaryRules, qname, questionType, enabledSources, resolvedGroups, primaryCandidates, exceptions);
        RemoveDisabled(primaryCandidates, exceptions);
        if (primaryCandidates.Count > 0)
            return BuildMatch(primaryCandidates);

        List<RewriteRule> secondaryCandidates = new List<RewriteRule>();
        Collect(secondaryRules, qname, questionType, enabledSources, resolvedGroups, secondaryCandidates, exceptions);
        RemoveDisabled(secondaryCandidates, exceptions);
        if (secondaryCandidates.Count == 0)
            return null;

        return BuildMatch(secondaryCandidates);
    }

    static void RemoveDisabled(List<RewriteRule> candidates, List<RewriteRule> exceptions)
    {
        if (exceptions.Count > 0)
            candidates.RemoveAll(candidate => exceptions.Any(exception => exception.Disables(candidate)));
    }

    static RewriteMatch BuildMatch(List<RewriteRule> candidates)
    {
        RewriteRule emptyResponse = candidates.FirstOrDefault(static rule => rule.Answers.Length == 0);
        if (emptyResponse is not null)
            return new RewriteMatch(emptyResponse.ResponseCode, new[] { emptyResponse });

        RewriteRule cname = candidates.FirstOrDefault(static rule => rule.Answers.Any(static answer => answer.Type == DnsResourceRecordType.CNAME));
        if (cname is not null)
            return new RewriteMatch(cname.ResponseCode, new[] { cname });

        return new RewriteMatch(candidates[0].ResponseCode, candidates);
    }

    public static RewriteRule Match(
        IEnumerable<RewriteRule> rules,
        string qname,
        HashSet<string> enabledSources,
        HashSet<string> requestedGroups,
        HashSet<string> resolvedGroups)
    {
        return Match(rules, Array.Empty<RewriteRule>(), qname, DnsResourceRecordType.ANY, enabledSources, requestedGroups, resolvedGroups)?.Rules.FirstOrDefault();
    }

    static void Collect(
        IEnumerable<RewriteRule> rules,
        string qname,
        DnsResourceRecordType questionType,
        HashSet<string> enabledSources,
        HashSet<string> resolvedGroups,
        List<RewriteRule> candidates,
        List<RewriteRule> exceptions)
    {
        foreach (RewriteRule rule in rules)
        {
            if ((enabledSources.Count > 0) && !enabledSources.Contains(rule.SourceName))
                continue;

            if ((rule.GroupNames.Count > 0) && !rule.GroupNames.Overlaps(resolvedGroups))
                continue;

            if (!rule.AppliesTo(questionType) || !rule.IsMatch(qname))
                continue;

            if (rule.IsException)
                exceptions.Add(rule);
            else
                candidates.Add(rule);
        }
    }
}
