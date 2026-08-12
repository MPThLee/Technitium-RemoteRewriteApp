using System.Collections.Generic;
using System.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace RemoteRewrite;

internal static class DnsResponseBuilder
{
    public static IReadOnlyList<DnsResourceRecord> BuildAnswers(
        DnsQuestionRecord question,
        uint appRecordTtl,
        uint? overrideTtl,
        uint defaultTtl,
        RewriteMatch match)
    {
        List<DnsResourceRecord> answers = new List<DnsResourceRecord>();
        HashSet<string> seen = new HashSet<string>(System.StringComparer.OrdinalIgnoreCase);

        foreach (RewriteRule rule in match.Rules)
        {
            uint ttl = overrideTtl ?? rule.Ttl ?? defaultTtl;
            if (ttl == 0)
                ttl = appRecordTtl;

            foreach (RewriteAnswer answer in rule.Answers)
            {
                if (!ShouldInclude(question.Type, answer.Type))
                    continue;

                string key = answer.Type + "\0" + answer.Value;
                if (!seen.Add(key))
                    continue;

                switch (answer.Type)
                {
                    case DnsResourceRecordType.A:
                        answers.Add(new DnsResourceRecord(question.Name, answer.Type, DnsClass.IN, ttl, new DnsARecordData(IPAddress.Parse(answer.Value))));
                        break;

                    case DnsResourceRecordType.AAAA:
                        answers.Add(new DnsResourceRecord(question.Name, answer.Type, DnsClass.IN, ttl, new DnsAAAARecordData(IPAddress.Parse(answer.Value))));
                        break;

                    case DnsResourceRecordType.CNAME:
                        answers.Add(new DnsResourceRecord(question.Name, answer.Type, DnsClass.IN, ttl, new DnsCNAMERecordData(answer.Value)));
                        break;
                }
            }
        }

        return answers;
    }

    static bool ShouldInclude(DnsResourceRecordType questionType, DnsResourceRecordType answerType)
    {
        if (questionType == DnsResourceRecordType.ANY)
            return true;

        if (answerType == DnsResourceRecordType.CNAME)
            return questionType is DnsResourceRecordType.A or DnsResourceRecordType.AAAA or DnsResourceRecordType.CNAME;

        return questionType == answerType;
    }
}
