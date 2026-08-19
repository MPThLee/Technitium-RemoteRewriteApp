using System.Net;
using System.Text.Json;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using RemoteRewrite;
using Xunit;

namespace RemoteRewriteApp.Tests;

public sealed class RewriteCoreTests
{
    [Fact]
    public void ParseAdGuardFilterSource_PreservesSuffixGlobAndRegexRules()
    {
        SourceConfig source = SourceConfig.Parse(JsonDocument.Parse("""
{
  "name": "remote-dns",
  "enable": true,
  "format": "adguard-filter",
  "url": "https://example.invalid/dns.txt",
  "groupNames": ["private"]
}
""").RootElement);

        int order = 0;
        RewriteRule[] rules = RuleParser.ParseAdGuardFilterSource(
            source,
            """
||exact.example^$dnsrewrite=192.0.2.10
||edge*.example^$dnsrewrite=192.0.2.20
/node\d+\.example/$dnsrewrite=192.0.2.30
""",
            ref order
        ).ToArray();

        Assert.Contains(rules, rule => rule.MatchType == RemoteRewrite.MatchType.Suffix && rule.Pattern == "exact.example");
        Assert.Contains(rules, rule => rule.MatchType == RemoteRewrite.MatchType.Glob && rule.Pattern == "edge*.example");
        Assert.Contains(rules, rule => rule.MatchType == RemoteRewrite.MatchType.Regex && rule.Pattern == @"node\d+\.example");
        Assert.All(rules, rule => Assert.Contains("private", rule.GroupNames));
    }

    [Fact]
    public void ParseRewriteRulesJsonSource_RequiresBothSourceAndRuleGroups()
    {
        SourceConfig source = SourceConfig.Parse(JsonDocument.Parse("""
{
  "name": "remote-manifest",
  "enable": true,
  "format": "rewrite-rules-json",
  "url": "https://example.invalid/rewrite.json",
  "groupNames": ["private"]
}
""").RootElement);

        int order = 0;
        RewriteRule rule = RuleParser.ParseRewriteRulesJsonSource(
            source,
            """
{
  "rules": [
    {
      "matchType": "regex",
      "pattern": "node\\d+\\.example",
      "answers": [{ "type": "A", "value": "192.0.2.55" }],
      "groupNames": ["edge"]
    }
  ]
}
""",
            ref order
        ).Single();

        Assert.True(rule.GroupNames.SetEquals(new[] { "private", "edge" }));
        Assert.Null(RuleMatcher.Match(
            new[] { rule },
            "node1.example",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(["private"], StringComparer.OrdinalIgnoreCase)));
        Assert.Null(RuleMatcher.Match(
            new[] { rule },
            "node1.example",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(["edge"], StringComparer.OrdinalIgnoreCase)));

        RewriteRule? bothGroups = RuleMatcher.Match(
            new[] { rule },
            "node1.example",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(["private", "edge"], StringComparer.OrdinalIgnoreCase));
        Assert.NotNull(bothGroups);
    }

    [Fact]
    public void SplitHorizonConfig_ResolvesPublicPrivateAndMappedGroups()
    {
        SplitHorizonConfig config = SplitHorizonConfig.Parse(JsonDocument.Parse("""
{
  "enable": true,
  "defaultGroupName": "default",
  "privateGroupName": "private",
  "publicGroupName": "public",
  "domainGroupMap": {
    "internal.example": "internal"
  },
  "networkGroupMap": {
    "10.0.0.0/8": "private",
    "198.51.100.0/24": "edge"
  }
}
""").RootElement);

        HashSet<string> privateGroups = config.ResolveGroups("service.internal.example", IPAddress.Parse("10.1.2.3"));
        HashSet<string> publicGroups = config.ResolveGroups("service.example", IPAddress.Parse("203.0.113.8"));

        Assert.True(privateGroups.SetEquals(new[] { "default", "private", "internal" }));
        Assert.True(publicGroups.SetEquals(new[] { "default", "public" }));
    }

    [Fact]
    public void RuleMatcher_UsesResolvedGroupsForConditionalRewriteSelection()
    {
        RewriteRule[] rules =
        [
            new RewriteRule(
                "remote-dns",
                0,
                RemoteRewrite.MatchType.Suffix,
                "service.example",
                [new RewriteAnswer(DnsResourceRecordType.A, "192.0.2.10")],
                null,
                new HashSet<string>(["public"], StringComparer.OrdinalIgnoreCase)
            ),
            new RewriteRule(
                "remote-dns",
                1,
                RemoteRewrite.MatchType.Suffix,
                "service.example",
                [new RewriteAnswer(DnsResourceRecordType.A, "198.51.100.10")],
                null,
                new HashSet<string>(["private"], StringComparer.OrdinalIgnoreCase)
            )
        ];

        RewriteRule privateRule = RuleMatcher.Match(
            rules,
            "service.example",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(["private"], StringComparer.OrdinalIgnoreCase)
        );

        RewriteRule publicRule = RuleMatcher.Match(
            rules,
            "service.example",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(["public"], StringComparer.OrdinalIgnoreCase)
        );

        Assert.Equal("198.51.100.10", privateRule!.Answers.Single().Value);
        Assert.Equal("192.0.2.10", publicRule!.Answers.Single().Value);
    }

    [Fact]
    public void AppRecordOptions_ParseSupportsGroupScoping()
    {
        AppRecordOptions options = AppRecordOptions.Parse("""
{
  "enable": true,
  "sourceNames": ["remote-dns"],
  "groupNames": ["private"],
  "overrideTtl": 120
}
""");

        Assert.Contains("remote-dns", options.SourceNames);
        Assert.Contains("private", options.GroupNames);
        Assert.Equal<uint>(120, options.OverrideTtl!.Value);
        Assert.True(options.MatchesGroups(new HashSet<string>(["private"], StringComparer.OrdinalIgnoreCase)));
        Assert.False(options.MatchesGroups(new HashSet<string>(["public"], StringComparer.OrdinalIgnoreCase)));
    }

    [Fact]
    public void AppRecordOptions_ParseEmptyUsesDefaults()
    {
        AppRecordOptions options = AppRecordOptions.Parse("");

        Assert.True(options.Enable);
        Assert.Empty(options.SourceNames);
        Assert.Empty(options.GroupNames);
        Assert.Null(options.OverrideTtl);
    }

    [Fact]
    public void DnsScope_IsInZoneMatchesExactAndSubdomain()
    {
        Assert.True(DnsScope.IsInZone("service.example", "example"));
        Assert.True(DnsScope.IsInZone("example", "example"));
        Assert.False(DnsScope.IsInZone("service.other", "example"));
    }

    [Fact]
    public void DnsScope_MatchesAppRecordScopeSupportsExactAndGlob()
    {
        Assert.True(DnsScope.MatchesAppRecordScope("service.example", "service.example"));
        Assert.True(DnsScope.MatchesAppRecordScope("edge01.example", "edge*.example"));
        Assert.False(DnsScope.MatchesAppRecordScope("service.example", "other.example"));
    }

    [Fact]
    public void RuleParser_ParseAnswerSupportsIpv4Ipv6AndCname()
    {
        Assert.Equal(DnsResourceRecordType.A, RuleParser.ParseAnswer("192.0.2.10")!.Type);
        Assert.Equal(DnsResourceRecordType.AAAA, RuleParser.ParseAnswer("2001:db8::10")!.Type);
        Assert.Equal(DnsResourceRecordType.CNAME, RuleParser.ParseAnswer("alias.example")!.Type);
    }

    [Fact]
    public void RuleParser_GlobMatchMatchesExpectedPatterns()
    {
        Assert.True(RuleParser.GlobMatch("edge01.example", "edge*.example"));
        Assert.True(RuleParser.GlobMatch("a.b.example", "*.example"));
        Assert.False(RuleParser.GlobMatch("service.other", "edge*.example"));
    }

    [Fact]
    public void RuleMatcher_RespectsSourceFilter()
    {
        RewriteRule[] rules =
        [
            new RewriteRule("source-a", 0, RemoteRewrite.MatchType.Suffix, "service.example", [new RewriteAnswer(DnsResourceRecordType.A, "192.0.2.10")], null, new HashSet<string>(StringComparer.OrdinalIgnoreCase)),
            new RewriteRule("source-b", 1, RemoteRewrite.MatchType.Suffix, "service.example", [new RewriteAnswer(DnsResourceRecordType.A, "198.51.100.10")], null, new HashSet<string>(StringComparer.OrdinalIgnoreCase))
        ];

        RewriteRule? rule = RuleMatcher.Match(
            rules,
            "service.example",
            new HashSet<string>(["source-b"], StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        );

        Assert.Equal("198.51.100.10", rule!.Answers.Single().Value);
    }

    [Fact]
    public void RuleMatcher_SourceFilterAppliesOnlyToConfiguredSecondaryRules()
    {
        RewriteRule[] inlineRules =
        [
            new RewriteRule("private-inline", 0, RemoteRewrite.MatchType.Suffix, "service.example", [new RewriteAnswer(DnsResourceRecordType.A, "10.0.0.10")], null, new HashSet<string>(StringComparer.OrdinalIgnoreCase))
        ];
        RewriteRule[] configuredRules =
        [
            new RewriteRule("remote-dns", 1, RemoteRewrite.MatchType.Suffix, "service.example", [new RewriteAnswer(DnsResourceRecordType.A, "192.0.2.10")], null, new HashSet<string>(StringComparer.OrdinalIgnoreCase))
        ];

        RewriteMatch? match = RuleMatcher.Match(
            inlineRules,
            configuredRules,
            "service.example",
            DnsResourceRecordType.A,
            new HashSet<string>(["remote-dns"], StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase));

        Assert.Equal("10.0.0.10", match!.Rules.Single().Answers.Single().Value);
    }

    [Fact]
    public void RuleMatcher_RespectsRequestedGroups()
    {
        RewriteRule[] rules =
        [
            new RewriteRule("remote", 0, RemoteRewrite.MatchType.Suffix, "service.example", [new RewriteAnswer(DnsResourceRecordType.A, "192.0.2.10")], null, new HashSet<string>(["private"], StringComparer.OrdinalIgnoreCase))
        ];

        RewriteRule? rule = RuleMatcher.Match(
            rules,
            "service.example",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(["public"], StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(["private"], StringComparer.OrdinalIgnoreCase)
        );

        Assert.Null(rule);
    }

    [Fact]
    public void RuleMatcher_ReturnsNullWhenRuleGroupsDoNotMatchResolvedGroups()
    {
        RewriteRule[] rules =
        [
            new RewriteRule("remote", 0, RemoteRewrite.MatchType.Suffix, "service.example", [new RewriteAnswer(DnsResourceRecordType.A, "192.0.2.10")], null, new HashSet<string>(["private"], StringComparer.OrdinalIgnoreCase))
        ];

        RewriteRule? rule = RuleMatcher.Match(
            rules,
            "service.example",
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(["public"], StringComparer.OrdinalIgnoreCase)
        );

        Assert.Null(rule);
    }

    [Fact]
    public void RuleMatcher_FailsClosedWhenSameSuffixCandidateWorkExceedsLimit()
    {
        RewriteRule[] rules = Enumerable.Range(0, AppLimits.MaxMatchingRulesPerRequest + 1)
            .Select(order => new RewriteRule(
                "remote",
                order,
                RemoteRewrite.MatchType.Suffix,
                "example",
                [new RewriteAnswer(DnsResourceRecordType.A, "192.0.2.1")],
                null,
                new HashSet<string>(StringComparer.OrdinalIgnoreCase)))
            .ToArray();
        RuleSet ruleSet = new RuleSet(rules);

        RewriteMatch match = RuleMatcher.Match(
            Array.Empty<RewriteRule>(),
            ruleSet.GetCandidates(
                "host.example",
                DnsResourceRecordType.A,
                new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                new HashSet<string>(StringComparer.OrdinalIgnoreCase)),
            "host.example",
            DnsResourceRecordType.A,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase));

        Assert.NotNull(match);
        Assert.Equal(DnsResponseCode.ServerFailure, match.ResponseCode);
        Assert.Empty(match.Rules);
    }

    [Fact]
    public void RuleMatcher_PrivateOnlyCandidateFanoutDoesNotAffectPublicQueries()
    {
        HashSet<string> privateOnly = new HashSet<string>(["private"], StringComparer.OrdinalIgnoreCase);
        RewriteRule[] rules = Enumerable.Range(0, AppLimits.MaxMatchingRulesPerRequest + 1)
            .Select(order => new RewriteRule(
                "remote",
                order,
                RemoteRewrite.MatchType.Suffix,
                "example",
                [new RewriteAnswer(DnsResourceRecordType.A, "192.0.2.1")],
                null,
                privateOnly))
            .ToArray();

        RewriteRule publicRule = new RewriteRule(
            "remote",
            rules.Length,
            RemoteRewrite.MatchType.Suffix,
            "example",
            [new RewriteAnswer(DnsResourceRecordType.A, "198.51.100.1")],
            null,
            new HashSet<string>(["public"], StringComparer.OrdinalIgnoreCase));
        RuleSet ruleSet = new RuleSet(rules.Append(publicRule));
        HashSet<string> publicGroups = new HashSet<string>(["public"], StringComparer.OrdinalIgnoreCase);
        RewriteRule indexedCandidate = Assert.Single(ruleSet.GetCandidates(
            "host.example",
            DnsResourceRecordType.A,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            publicGroups));
        Assert.Same(publicRule, indexedCandidate);

        RewriteMatch match = RuleMatcher.Match(
            Array.Empty<RewriteRule>(),
            ruleSet.GetCandidates(
                "host.example",
                DnsResourceRecordType.A,
                new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                publicGroups),
            "host.example",
            DnsResourceRecordType.A,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            publicGroups);

        Assert.NotNull(match);
        Assert.Same(publicRule, Assert.Single(match.Rules));
    }

    [Fact]
    public void RuleMatcher_WrongTypeCandidateFanoutDoesNotAffectOtherQueryTypes()
    {
        HashSet<DnsResourceRecordType> aaaaOnly = new HashSet<DnsResourceRecordType>([DnsResourceRecordType.AAAA]);
        RewriteRule[] rules = Enumerable.Range(0, AppLimits.MaxMatchingRulesPerRequest + 1)
            .Select(order => new RewriteRule(
                "remote",
                order,
                RemoteRewrite.MatchType.Suffix,
                "example",
                [new RewriteAnswer(DnsResourceRecordType.AAAA, "2001:db8::1")],
                null,
                new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                queryTypes: aaaaOnly))
            .ToArray();

        RewriteRule aRule = new RewriteRule(
            "remote",
            rules.Length,
            RemoteRewrite.MatchType.Suffix,
            "example",
            [new RewriteAnswer(DnsResourceRecordType.A, "198.51.100.1")],
            null,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            queryTypes: new HashSet<DnsResourceRecordType>([DnsResourceRecordType.A]));
        RuleSet ruleSet = new RuleSet(rules.Append(aRule));
        RewriteRule indexedCandidate = Assert.Single(ruleSet.GetCandidates(
            "host.example",
            DnsResourceRecordType.A,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)));
        Assert.Same(aRule, indexedCandidate);

        RewriteMatch match = RuleMatcher.Match(
            Array.Empty<RewriteRule>(),
            ruleSet.GetCandidates(
                "host.example",
                DnsResourceRecordType.A,
                new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                new HashSet<string>(StringComparer.OrdinalIgnoreCase)),
            "host.example",
            DnsResourceRecordType.A,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase));

        Assert.NotNull(match);
        Assert.Same(aRule, Assert.Single(match.Rules));
    }

    [Fact]
    public void RuleSet_SourceIndexFindsAllowedRuleAfterUnrelatedFlood()
    {
        RewriteRule[] unrelated = Enumerable.Range(0, AppLimits.MaxMatchingRulesPerRequest + 1)
            .Select(order => new RewriteRule(
                "source-a",
                order,
                RemoteRewrite.MatchType.Suffix,
                "example",
                [new RewriteAnswer(DnsResourceRecordType.A, "192.0.2.1")],
                null,
                new HashSet<string>(StringComparer.OrdinalIgnoreCase)))
            .ToArray();
        RewriteRule allowedRule = new RewriteRule(
            "source-b",
            unrelated.Length,
            RemoteRewrite.MatchType.Suffix,
            "example",
            [new RewriteAnswer(DnsResourceRecordType.A, "198.51.100.1")],
            null,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase));
        RuleSet ruleSet = new RuleSet(unrelated.Append(allowedRule));

        RewriteRule candidate = Assert.Single(ruleSet.GetCandidates(
            "host.example",
            DnsResourceRecordType.A,
            new HashSet<string>(["source-b"], StringComparer.OrdinalIgnoreCase),
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)));

        Assert.Same(allowedRule, candidate);
    }

    [Fact]
    public void RuleSet_BitsetIntersectsBroadDisjointImmutablePostings()
    {
        HashSet<DnsResourceRecordType> aOnly = new HashSet<DnsResourceRecordType>([DnsResourceRecordType.A]);
        HashSet<DnsResourceRecordType> aaaaOnly = new HashSet<DnsResourceRecordType>([DnsResourceRecordType.AAAA]);
        RewriteAnswer[] aAnswer = [new RewriteAnswer(DnsResourceRecordType.A, "192.0.2.1")];
        RewriteAnswer[] aaaaAnswer = [new RewriteAnswer(DnsResourceRecordType.AAAA, "2001:db8::1")];
        HashSet<string> privateOnly = new HashSet<string>(["private"], StringComparer.OrdinalIgnoreCase);
        HashSet<string> publicOnly = new HashSet<string>(["public"], StringComparer.OrdinalIgnoreCase);
        int half = AppLimits.MaxMatchingRulesPerRequest + 1;
        RewriteRule[] rules = Enumerable.Range(0, half)
            .Select(order => new RewriteRule(
                "source-a",
                order,
                RemoteRewrite.MatchType.Suffix,
                "example",
                aAnswer,
                null,
                privateOnly,
                queryTypes: aOnly))
            .Concat(Enumerable.Range(half, half).Select(order => new RewriteRule(
                "source-b",
                order,
                RemoteRewrite.MatchType.Suffix,
                "example",
                aaaaAnswer,
                null,
                publicOnly,
                queryTypes: aaaaOnly)))
            .ToArray();
        RuleSet ruleSet = new RuleSet(rules);

        RewriteRule[] candidates = ruleSet.GetCandidates(
            "host.example",
            DnsResourceRecordType.AAAA,
            new HashSet<string>(["source-a"], StringComparer.OrdinalIgnoreCase),
            privateOnly).ToArray();

        Assert.Empty(candidates);
    }

    [Fact]
    public void NetworkClassifier_DetectsPrivateIpv4()
    {
        Assert.True(NetworkClassifier.IsPrivateOrSpecial(IPAddress.Parse("10.0.0.10")));
        Assert.True(NetworkClassifier.IsPrivateOrSpecial(IPAddress.Parse("172.16.5.10")));
        Assert.True(NetworkClassifier.IsPrivateOrSpecial(IPAddress.Parse("192.168.1.20")));
        Assert.False(NetworkClassifier.IsPrivateOrSpecial(IPAddress.Parse("203.0.113.20")));
    }

    [Fact]
    public void NetworkClassifier_DetectsPrivateIpv6()
    {
        Assert.True(NetworkClassifier.IsPrivateOrSpecial(IPAddress.Parse("fd00::1")));
        Assert.True(NetworkClassifier.IsPrivateOrSpecial(IPAddress.Parse("fe80::1")));
        Assert.True(NetworkClassifier.IsPrivateOrSpecial(IPAddress.IPv6Loopback));
        Assert.False(NetworkClassifier.IsPrivateOrSpecial(IPAddress.Parse("2001:db8:ffff::1")));
    }

    [Fact]
    public void DomainGroupRule_MatchesExactAndSubdomain()
    {
        DomainGroupRule rule = new DomainGroupRule("internal.example", "private");

        Assert.True(rule.Matches("internal.example"));
        Assert.True(rule.Matches("service.internal.example"));
        Assert.False(rule.Matches("internal.other"));
    }

    [Fact]
    public void NetworkGroupRule_MatchesCidrAndSingleAddress()
    {
        NetworkGroupRule cidr = NetworkGroupRule.Parse("10.0.0.0/8", "private");
        NetworkGroupRule single = NetworkGroupRule.Parse("198.51.100.10", "edge");

        Assert.True(cidr.Matches(IPAddress.Parse("10.2.3.4")));
        Assert.False(cidr.Matches(IPAddress.Parse("192.0.2.10")));
        Assert.True(single.Matches(IPAddress.Parse("198.51.100.10")));
        Assert.False(single.Matches(IPAddress.Parse("198.51.100.11")));
    }

    [Fact]
    public void SplitHorizonConfig_DisabledReturnsNoGroups()
    {
        HashSet<string> groups = SplitHorizonConfig.Disabled.ResolveGroups("service.example", IPAddress.Parse("10.0.0.10"));

        Assert.Empty(groups);
    }

    [Fact]
    public void SplitHorizonConfig_DefaultsToPublicForPublicAddresses()
    {
        SplitHorizonConfig config = SplitHorizonConfig.Parse(JsonDocument.Parse("""
{
  "enable": true
}
""").RootElement);

        HashSet<string> groups = config.ResolveGroups("service.example", IPAddress.Parse("203.0.113.8"));

        Assert.True(groups.SetEquals(new[] { "default", "public" }));
    }

    [Fact]
    public void SplitHorizonConfig_AddsNetworkMappedGroup()
    {
        SplitHorizonConfig config = SplitHorizonConfig.Parse(JsonDocument.Parse("""
{
  "enable": true,
  "networkGroupMap": {
    "198.51.100.0/24": "edge"
  }
}
""").RootElement);

        HashSet<string> groups = config.ResolveGroups("service.example", IPAddress.Parse("198.51.100.20"));

        Assert.Contains("edge", groups);
    }

    [Fact]
    public void AppConfig_ParseSupportsSplitHorizonAndSourceGroups()
    {
        AppConfig config = AppConfig.Parse("""
{
  "enable": true,
  "defaultTtl": 123,
  "refreshSeconds": 456,
  "splitHorizon": {
    "enable": true,
    "domainGroupMap": {
      "internal.example": "private"
    }
  },
  "sources": [
    {
      "name": "remote-manifest",
      "enable": true,
      "format": "rewrite-rules-json",
      "url": "https://example.invalid/rewrite.json",
      "groupNames": ["private"]
    }
  ]
}
""");

        Assert.True(config.Enable);
        Assert.Equal<uint>(123, config.DefaultTtl);
        Assert.Equal(456, config.RefreshSeconds);
        Assert.True(config.SplitHorizon.Enable);
        Assert.Contains("private", config.Sources.Single().GroupNames);
    }

    [Fact]
    public void RewriteRule_SuffixMatchesExactAndSubdomain()
    {
        RewriteRule rule = new RewriteRule(
            "remote",
            0,
            RemoteRewrite.MatchType.Suffix,
            "example",
            [new RewriteAnswer(DnsResourceRecordType.A, "192.0.2.10")],
            null,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        );

        Assert.True(rule.IsMatch("example"));
        Assert.True(rule.IsMatch("service.example"));
        Assert.False(rule.IsMatch("service.other"));
    }

    [Fact]
    public void RewriteRule_GlobMatchesExpectedNames()
    {
        RewriteRule rule = new RewriteRule(
            "remote",
            0,
            RemoteRewrite.MatchType.Glob,
            "edge*.example",
            [new RewriteAnswer(DnsResourceRecordType.A, "192.0.2.10")],
            null,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        );

        Assert.True(rule.IsMatch("edge01.example"));
        Assert.False(rule.IsMatch("core01.example"));
    }

    [Fact]
    public void RewriteRule_RegexMatchesExpectedNames()
    {
        RewriteRule rule = new RewriteRule(
            "remote",
            0,
            RemoteRewrite.MatchType.Regex,
            @"node\d+\.example",
            [new RewriteAnswer(DnsResourceRecordType.A, "192.0.2.10")],
            null,
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        );

        Assert.True(rule.IsMatch("node12.example"));
        Assert.False(rule.IsMatch("nodea.example"));
    }
}
