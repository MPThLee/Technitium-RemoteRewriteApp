using System.Net;
using System.Text.Json;
using RemoteRewrite;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace RemoteRewriteApp.Tests;

public sealed class AdGuardCompatibilityTests
{
    [Fact]
    public void ParserSupportsExactAndFullDnsRewriteSyntax()
    {
        RewriteRule[] rules = Parse("""
|exact.example|$dnsrewrite=NOERROR;A;192.0.2.10
||alias.example^$dnsrewrite=NOERROR;CNAME;target.example
||refused.example^$dnsrewrite=REFUSED
""");

        Assert.Equal(RemoteRewrite.MatchType.Exact, rules[0].MatchType);
        Assert.Equal(DnsResourceRecordType.A, Assert.Single(rules[0].Answers).Type);
        Assert.Equal(DnsResourceRecordType.CNAME, Assert.Single(rules[1].Answers).Type);
        Assert.Equal(DnsResponseCode.Refused, rules[2].ResponseCode);
        Assert.Empty(rules[2].Answers);
    }

    [Fact]
    public void ParserSupportsDnsTypeModifierInAnyModifierPosition()
    {
        RewriteRule rule = Assert.Single(Parse("||service.example^$dnstype=HTTPS,dnsrewrite=REFUSED,important"));

        Assert.Contains(DnsResourceRecordType.HTTPS, rule.QueryTypes);
        Assert.True(rule.AppliesTo(DnsResourceRecordType.HTTPS));
        Assert.False(rule.AppliesTo(DnsResourceRecordType.A));
    }

    [Fact]
    public void ParserSkipsUnsupportedClientTargetingInsteadOfApplyingGlobally()
    {
        RewriteRule[] rules = Parse("||service.example^$dnsrewrite=192.0.2.10,client=192.0.2.20");

        Assert.Empty(rules);
    }

    [Fact]
    public void ParserSkipsMalformedRemoteLinesWithoutDiscardingValidRules()
    {
        RewriteRule[] rules = Parse("""
||<!DOCTYPE html>^$dnsrewrite=not a domain
||valid.example^$dnsrewrite=192.0.2.10
""");

        RewriteRule rule = Assert.Single(rules);
        Assert.Equal("valid.example", rule.Pattern);
    }

    [Fact]
    public void GeneralExceptionDisablesMatchingRewrite()
    {
        RewriteRule[] rules = Parse("""
||service.example^$dnsrewrite=192.0.2.10
@@||service.example^$dnsrewrite
""");

        RewriteMatch match = Match(rules, "service.example", DnsResourceRecordType.A);

        Assert.Null(match);
    }

    [Fact]
    public void ValueSpecificExceptionLeavesOtherMatchingAnswers()
    {
        RewriteRule[] rules = Parse("""
||service.example^$dnsrewrite=192.0.2.10
||service.example^$dnsrewrite=192.0.2.11
@@||service.example^$dnsrewrite=192.0.2.10
""");

        RewriteMatch match = Match(rules, "service.example", DnsResourceRecordType.A);
        IReadOnlyList<DnsResourceRecord> answers = BuildAnswers(match, DnsResourceRecordType.A);

        DnsARecordData answer = Assert.IsType<DnsARecordData>(Assert.Single(answers).RDATA);
        Assert.Equal(IPAddress.Parse("192.0.2.11"), answer.Address);
    }

    [Fact]
    public void ScopedExceptionCanSuppressRemoteRewrite()
    {
        RewriteRule[] scoped = Parse("@@||service.example^$dnsrewrite");
        RewriteRule[] remote = Parse("||service.example^$dnsrewrite=192.0.2.10");

        RewriteMatch match = RuleMatcher.Match(
            scoped,
            remote,
            "service.example",
            DnsResourceRecordType.A,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase));

        Assert.Null(match);
    }

    [Fact]
    public void MultipleMatchingRulesProduceMultipleAnswers()
    {
        RewriteRule[] rules = Parse("""
||service.example^$dnsrewrite=192.0.2.10
||service.example^$dnsrewrite=192.0.2.11
""");

        RewriteMatch match = Match(rules, "service.example", DnsResourceRecordType.A);
        IReadOnlyList<DnsResourceRecord> answers = BuildAnswers(match, DnsResourceRecordType.A);

        Assert.Equal(2, answers.Count);
    }

    [Fact]
    public void CnameRewriteTakesPriorityOverAddressRewrites()
    {
        RewriteRule[] rules = Parse("""
||service.example^$dnsrewrite=192.0.2.10
||service.example^$dnsrewrite=target.example
""");

        RewriteMatch match = Match(rules, "service.example", DnsResourceRecordType.A);
        IReadOnlyList<DnsResourceRecord> answers = BuildAnswers(match, DnsResourceRecordType.A);

        DnsCNAMERecordData answer = Assert.IsType<DnsCNAMERecordData>(Assert.Single(answers).RDATA);
        Assert.Equal("target.example", answer.Domain);
    }

    [Fact]
    public void JsonParserSupportsTopLevelArrayAndExplicitOrder()
    {
        SourceConfig source = CreateSource("rewrite-rules-json");
        int order = 0;
        RewriteRule[] rules = RuleParser.ParseRewriteRulesJsonSource(source, """
[
  {
    "order": 20,
    "matchType": "suffix",
    "pattern": "second.example",
    "answers": [{ "type": "A", "value": "192.0.2.20" }]
  },
  {
    "order": 10,
    "matchType": "exact",
    "pattern": "first.example",
    "answers": [{ "type": "A", "value": "192.0.2.10" }]
  }
]
""", ref order).ToArray();

        Assert.Equal("first.example", rules[0].Pattern);
        Assert.Equal(RemoteRewrite.MatchType.Exact, rules[0].MatchType);
        Assert.Equal("second.example", rules[1].Pattern);
    }

    [Fact]
    public void ConfigRejectsDuplicateSourcesAndUnsafeHttp()
    {
        Assert.Throws<FormatException>(() => AppConfig.Parse("""
{
  "sources": [
    { "name": "same", "url": "https://example.invalid/a.txt" },
    { "name": "same", "url": "https://example.invalid/b.txt" }
  ]
}
"""));

        Assert.Throws<FormatException>(() => AppConfig.Parse("""
{
  "sources": [
    { "name": "remote", "url": "http://example.invalid/dns.txt" }
  ]
}
"""));
    }

    [Fact]
    public void ConfigRejectsUnsafeRefreshAndNetworkPrefixValues()
    {
        Assert.Throws<FormatException>(() => AppConfig.Parse("""{ "refreshSeconds": 1 }"""));
        Assert.Throws<FormatException>(() => SplitHorizonConfig.Parse(JsonDocument.Parse("""
{
  "enable": true,
  "networkGroupMap": { "192.0.2.0/33": "invalid" }
}
""").RootElement));
    }

    [Fact]
    public void SplitHorizonUsesDomainBeforeNetworkAndMostSpecificNetwork()
    {
        SplitHorizonConfig domainFirst = SplitHorizonConfig.Parse(JsonDocument.Parse("""
{
  "enable": true,
  "domainGroupMap": { "example": "domain" },
  "networkGroupMap": { "10.0.0.0/8": "network" }
}
""").RootElement);

        HashSet<string> domainGroups = domainFirst.ResolveGroups("service.example", IPAddress.Parse("10.1.2.3"));
        Assert.Contains("domain", domainGroups);
        Assert.DoesNotContain("network", domainGroups);

        SplitHorizonConfig networkSpecific = SplitHorizonConfig.Parse(JsonDocument.Parse("""
{
  "enable": true,
  "networkGroupMap": {
    "10.0.0.0/8": "broad",
    "10.1.0.0/16": "specific"
  }
}
""").RootElement);

        HashSet<string> networkGroups = networkSpecific.ResolveGroups("service.other", IPAddress.Parse("10.1.2.3"));
        Assert.Contains("specific", networkGroups);
        Assert.DoesNotContain("broad", networkGroups);
    }

    static RewriteRule[] Parse(string content)
    {
        SourceConfig source = CreateSource("adguard-filter");
        int order = 0;
        return RuleParser.ParseAdGuardFilterSource(source, content, ref order).ToArray();
    }

    static SourceConfig CreateSource(string format)
    {
        return SourceConfig.Parse(JsonDocument.Parse($$"""
{
  "name": "test",
  "enable": true,
  "format": "{{format}}",
  "text": "placeholder"
}
""").RootElement);
    }

    static RewriteMatch Match(RewriteRule[] rules, string qname, DnsResourceRecordType questionType)
    {
        return RuleMatcher.Match(
            rules,
            Array.Empty<RewriteRule>(),
            qname,
            questionType,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase));
    }

    static IReadOnlyList<DnsResourceRecord> BuildAnswers(RewriteMatch match, DnsResourceRecordType questionType)
    {
        return DnsResponseBuilder.BuildAnswers(
            new DnsQuestionRecord("service.example", questionType, DnsClass.IN),
            0,
            null,
            300,
            match);
    }
}
