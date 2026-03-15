using System.Collections.Generic;

namespace RemoteRewrite;

internal static class RuleMatcher
{
    public static RewriteRule Match(IEnumerable<RewriteRule> rules, string qname, HashSet<string> enabledSources, HashSet<string> requestedGroups, HashSet<string> resolvedGroups)
    {
        foreach (RewriteRule rule in rules)
        {
            if ((enabledSources.Count > 0) && !enabledSources.Contains(rule.SourceName))
                continue;

            if ((requestedGroups.Count > 0) && !requestedGroups.Overlaps(resolvedGroups))
                continue;

            if ((rule.GroupNames.Count > 0) && !rule.GroupNames.Overlaps(resolvedGroups))
                continue;

            if (rule.IsMatch(qname))
                return rule;
        }

        return null;
    }
}
