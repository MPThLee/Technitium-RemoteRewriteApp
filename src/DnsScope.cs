using System;

namespace RemoteRewrite;

internal static class DnsScope
{
    public static bool IsInZone(string qname, string zoneName)
    {
        if (string.IsNullOrWhiteSpace(zoneName))
            return true;

        zoneName = zoneName.ToLowerInvariant();
        return qname.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || qname.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase);
    }

    public static bool MatchesAppRecordScope(string qname, string appRecordName)
    {
        if (string.IsNullOrWhiteSpace(appRecordName))
            return true;

        appRecordName = appRecordName.ToLowerInvariant();

        if (qname.Equals(appRecordName, StringComparison.OrdinalIgnoreCase))
            return true;

        if (appRecordName.Contains('*'))
            return RuleParser.GlobMatch(qname, appRecordName);

        return false;
    }
}
