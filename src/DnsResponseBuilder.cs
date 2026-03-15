using System.Collections.Generic;
using System.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace RemoteRewrite;

internal static class DnsResponseBuilder
{
    public static IReadOnlyList<DnsResourceRecord> BuildAnswers(DnsQuestionRecord question, uint appRecordTtl, uint? overrideTtl, uint defaultTtl, RewriteRule rule)
    {
        List<DnsResourceRecord> answers = new List<DnsResourceRecord>();
        uint ttl = overrideTtl ?? rule.Ttl ?? defaultTtl;
        if (ttl == 0)
            ttl = appRecordTtl;

        foreach (RewriteAnswer answer in rule.Answers)
        {
            switch (answer.Type)
            {
                case DnsResourceRecordType.A:
                    if (question.Type == DnsResourceRecordType.A)
                        answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.A, DnsClass.IN, ttl, new DnsARecordData(IPAddress.Parse(answer.Value))));
                    break;

                case DnsResourceRecordType.AAAA:
                    if (question.Type == DnsResourceRecordType.AAAA)
                        answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.AAAA, DnsClass.IN, ttl, new DnsAAAARecordData(IPAddress.Parse(answer.Value))));
                    break;

                case DnsResourceRecordType.CNAME:
                    if ((question.Type == DnsResourceRecordType.A) || (question.Type == DnsResourceRecordType.AAAA) || (question.Type == DnsResourceRecordType.CNAME))
                        answers.Add(new DnsResourceRecord(question.Name, DnsResourceRecordType.CNAME, DnsClass.IN, ttl, new DnsCNAMERecordData(answer.Value)));
                    break;
            }
        }

        return answers;
    }
}
