using System.Net;
using System.Text.Json;
using RemoteRewrite;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace RemoteRewriteApp.Tests;

public sealed class ParserHardeningTests
{
    [Fact]
    public void AppConfigRejectsDuplicateSecurityProperties()
    {
        Assert.Throws<FormatException>(() => AppConfig.Parse("""
        {
          "allowPrivateNetworkSources": false,
          "allowPrivateNetworkSources": true,
          "sources": []
        }
        """));
    }

    [Fact]
    public void SourceConfigRejectsDuplicateProperties()
    {
        Assert.Throws<FormatException>(() => AppConfig.Parse("""
        {
          "sources": [{
            "name": "ambiguous",
            "enable": false,
            "enable": true,
            "text": "||service.example^$dnsrewrite=192.0.2.10"
          }]
        }
        """));
    }

    [Theory]
    [InlineData("{ \"enable\": false, \"enable\": true }")]
    [InlineData("{ \"splitHorizonMap\": { \"private\": { \"enable\": false, \"enable\": true } } }")]
    public void AppRecordRejectsDuplicatePolicyProperties(string data)
    {
        Assert.False(AppRecordOptions.TryParse(data, out _));
    }

    [Theory]
    [InlineData("{ \"rules\": [], \"rules\": [] }")]
    [InlineData("[{ \"matchType\": \"suffix\", \"pattern\": \"one.example\", \"pattern\": \"two.example\", \"answers\": [] }]")]
    [InlineData("[{ \"matchType\": \"suffix\", \"pattern\": \"one.example\", \"answers\": [{ \"type\": \"A\", \"value\": \"192.0.2.1\", \"value\": \"192.0.2.2\" }] }]")]
    public void RewriteJsonRejectsDuplicateProperties(string content)
    {
        SourceConfig source = CreateJsonSource();
        int order = 0;

        Assert.Throws<FormatException>(() => RuleParser.ParseRewriteRulesJsonSource(source, content, ref order).ToArray());
    }

    [Fact]
    public void AppRecordTryParseRejectsStructurallyIncompleteInlineJson()
    {
        string appRecordData = CreateIncompleteAppRecordData();

        bool parsed = AppRecordOptions.TryParse(appRecordData, out _);

        Assert.False(parsed);
    }

    [Fact]
    public async Task StructurallyIncompleteAppRecordFailsClosedOnRequestPath()
    {
        App app = new App();
        await app.InitializeAsync(null!, """{ "enable": true, "globalMode": false, "sources": [] }""");

        try
        {
            DnsDatagram? response = await app.ProcessRequestAsync(
                CreateRequest("service.example", DnsResourceRecordType.A),
                new IPEndPoint(IPAddress.Loopback, 5300),
                DnsTransportProtocol.Udp,
                true,
                "example",
                "*.example",
                120,
                CreateIncompleteAppRecordData());

            Assert.NotNull(response);
            Assert.Equal(DnsResponseCode.ServerFailure, response!.RCODE);
        }
        finally
        {
            app.Dispose();
        }
    }

    [Theory]
    [InlineData("exact")]
    [InlineData("suffix")]
    public void JsonParserRejectsInvalidDnsPatternsBeforeCountingThem(string matchType)
    {
        SourceConfig source = CreateJsonSource();
        RuleParseBudget budget = new RuleParseBudget();
        int order = 0;

        Assert.Throws<FormatException>(() => RuleParser.ParseRewriteRulesJsonSource(source, $$"""
{
  "rules": [{
    "matchType": "{{matchType}}",
    "pattern": "bad name.example",
    "answers": [{ "type": "A", "value": "192.0.2.10" }]
  }]
}
""", ref order, budget).ToArray());

        Assert.Equal(0, budget.RuleCount);
        Assert.Equal(0, order);
    }

    [Theory]
    [InlineData("exact")]
    [InlineData("suffix")]
    public void JsonParserRejectsWildcardInLiteralDnsPatterns(string matchType)
    {
        SourceConfig source = CreateJsonSource();
        int order = 0;

        Assert.Throws<FormatException>(() => RuleParser.ParseRewriteRulesJsonSource(source, $$"""
        [{
          "matchType": "{{matchType}}",
          "pattern": "*.example",
          "answers": [{ "type": "A", "value": "192.0.2.10" }]
        }]
        """, ref order).ToArray());
    }

    [Theory]
    [InlineData("exact")]
    [InlineData("suffix")]
    public void JsonParserNormalizesValidDnsPatterns(string matchType)
    {
        SourceConfig source = CreateJsonSource();
        int order = 0;

        RewriteRule rule = Assert.Single(RuleParser.ParseRewriteRulesJsonSource(source, $$"""
{
  "rules": [{
    "matchType": "{{matchType}}",
    "pattern": " Service.Example. ",
    "answers": [{ "type": "A", "value": "192.0.2.10" }]
  }]
}
""", ref order));

        Assert.Equal("service.example", rule.Pattern);
    }

    [Fact]
    public void ParsedRulesShareSourceGroupConstraints()
    {
        SourceConfig source = SourceConfig.Parse(JsonDocument.Parse("""
        {
          "name": "scoped",
          "enable": true,
          "format": "rewrite-rules-json",
          "text": "placeholder",
          "groupNames": ["private", "edge"]
        }
        """).RootElement);
        int order = 0;

        RewriteRule[] rules = RuleParser.ParseRewriteRulesJsonSource(source, """
        [
          { "matchType": "suffix", "pattern": "one.example", "answers": [{ "type": "A", "value": "192.0.2.1" }] },
          { "matchType": "suffix", "pattern": "two.example", "answers": [{ "type": "A", "value": "192.0.2.2" }] }
        ]
        """, ref order).ToArray();

        Assert.All(rules, rule => Assert.Same(source.GroupNames, rule.SourceGroupNames));
    }

    [Fact]
    public void AppRecordRejectsExcessiveScopeSelectors()
    {
        string data = JsonSerializer.Serialize(new
        {
            sourceNames = Enumerable.Range(0, 65).Select(index => $"source-{index}").ToArray()
        });

        Assert.False(AppRecordOptions.TryParse(data, out _));
    }

    [Fact]
    public void JsonRuleRejectsExcessiveGroupConstraints()
    {
        SourceConfig source = CreateJsonSource();
        string[] groups = Enumerable.Range(0, 65).Select(index => $"group-{index}").ToArray();
        string content = JsonSerializer.Serialize(new
        {
            rules = new[]
            {
                new
                {
                    matchType = "suffix",
                    pattern = "service.example",
                    groupNames = groups,
                    answers = new[] { new { type = "A", value = "192.0.2.10" } }
                }
            }
        });
        int order = 0;

        Assert.Throws<FormatException>(() => RuleParser.ParseRewriteRulesJsonSource(source, content, ref order).ToArray());
    }

    [Theory]
    [InlineData(@"service(?=\.example)")]
    [InlineData(@"^(service)\1$")]
    public void AdGuardSourceRejectsBacktrackingOnlyRegexInsteadOfDroppingRule(string pattern)
    {
        SourceConfig source = CreateAdGuardSource();
        int order = 0;

        FormatException error = Assert.Throws<UnsupportedRegexConstructException>(() =>
            RuleParser.ParseAdGuardFilterSource(
                source,
                $"/{pattern}/$dnsrewrite=192.0.2.10\n||valid.example^$dnsrewrite=192.0.2.20",
                ref order).ToArray());

        Assert.Contains("cannot use constructs that require backtracking", error.Message);
        Assert.Equal(0, order);
    }

    [Fact]
    public void JsonSourceRejectsBacktrackingOnlyRegex()
    {
        SourceConfig source = CreateJsonSource();
        int order = 0;

        Assert.Throws<UnsupportedRegexConstructException>(() => RuleParser.ParseRewriteRulesJsonSource(source, """
{
  "rules": [{
    "matchType": "regex",
    "pattern": "service(?=\\\\.example)",
    "answers": [{ "type": "A", "value": "192.0.2.10" }]
  }]
}
""", ref order).ToArray());

        Assert.Equal(0, order);
    }

    [Theory]
    [InlineData(1, 99, 99, "answer")]
    [InlineData(99, 1, 99, "group-index")]
    [InlineData(99, 99, 1, "query-type")]
    public void JsonParserEnforcesAggregateMetadataBudgetsBeforeAddingSecondRule(
        int answerLimit,
        int groupLimit,
        int queryTypeLimit,
        string expectedLabel)
    {
        SourceConfig source = CreateJsonSource();
        RuleParseBudget budget = new RuleParseBudget(
            maxRules: 10,
            maxRegexRules: 10,
            maxAnswerMemberships: answerLimit,
            maxGroupIndexMemberships: groupLimit,
            maxQueryTypeMemberships: queryTypeLimit);
        int order = 0;

        RuleLimitException error = Assert.Throws<RuleLimitException>(() =>
            RuleParser.ParseRewriteRulesJsonSource(source, """
[
  {
    "matchType": "suffix",
    "pattern": "one.example",
    "answers": [{ "type": "A", "value": "192.0.2.1" }],
    "groupNames": ["private"],
    "queryTypes": ["A"]
  },
  {
    "matchType": "suffix",
    "pattern": "two.example",
    "answers": [{ "type": "A", "value": "192.0.2.2" }],
    "groupNames": ["private"],
    "queryTypes": ["A"]
  }
]
""", ref order, budget).ToArray());

        Assert.Contains(expectedLabel, error.Message, StringComparison.Ordinal);
        Assert.Equal(1, budget.RuleCount);
        Assert.Equal(1, order);
    }

    [Fact]
    public void AdGuardParserChargesSharedSourceGroupsForEveryIndexedRule()
    {
        SourceConfig source = SourceConfig.Parse(JsonDocument.Parse("""
{
  "name": "grouped",
  "enable": true,
  "format": "adguard-filter",
  "text": "placeholder",
  "groupNames": ["private"]
}
""").RootElement);
        RuleParseBudget budget = new RuleParseBudget(
            maxRules: 10,
            maxRegexRules: 10,
            maxAnswerMemberships: 10,
            maxGroupIndexMemberships: 1,
            maxQueryTypeMemberships: 10);
        int order = 0;

        RuleLimitException error = Assert.Throws<RuleLimitException>(() =>
            RuleParser.ParseAdGuardFilterSource(
                source,
                "||one.example^$dnsrewrite=192.0.2.1\n||two.example^$dnsrewrite=192.0.2.2",
                ref order,
                budget).ToArray());

        Assert.Contains("group-index", error.Message, StringComparison.Ordinal);
        Assert.Equal(1, budget.RuleCount);
        Assert.Equal(1, order);
    }

    static string CreateIncompleteAppRecordData()
    {
        return JsonSerializer.Serialize(new
        {
            enable = true,
            inlineSources = new[]
            {
                new
                {
                    name = "incomplete-json",
                    format = "rewrite-rules-json",
                    text = """
                    {
                      "rules": [{
                        "matchType": "suffix",
                        "pattern": "service.example",
                        "answers": [{ "type": "A" }]
                      }]
                    }
                    """
                }
            }
        });
    }

    static SourceConfig CreateJsonSource()
    {
        return CreateSource("rewrite-rules-json");
    }

    static SourceConfig CreateAdGuardSource()
    {
        return CreateSource("adguard-filter");
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

    static DnsDatagram CreateRequest(string name, DnsResourceRecordType type)
    {
        return new DnsDatagram(
            0x4242,
            false,
            DnsOpcode.StandardQuery,
            false,
            false,
            true,
            false,
            false,
            false,
            DnsResponseCode.NoError,
            [new DnsQuestionRecord(name, type, DnsClass.IN)]);
    }
}
