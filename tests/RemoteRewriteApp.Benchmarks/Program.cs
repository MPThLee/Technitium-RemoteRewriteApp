using System.Diagnostics;
using System.Net;
using RemoteRewrite;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

const int RuleCount = 12000;
const int MatchIterations = 25000;
const int ParseIterations = 250;

HashSet<string> noGroups = new(StringComparer.OrdinalIgnoreCase);
RewriteAnswer answer = new(DnsResourceRecordType.A, "192.0.2.10");
RewriteRule[] rules = BuildRules(answer, noGroups);

RunBenchmark(
    "rule-match suffix-hit",
    MatchIterations,
    () => RequireMatch("svc11999.suffix.example.com", rules, noGroups, noGroups));

RunBenchmark(
    "rule-match glob-hit",
    MatchIterations,
    () => RequireMatch("edge-42.glob.example.com", rules, noGroups, noGroups));

RunBenchmark(
    "rule-match regex-hit",
    MatchIterations,
    () => RequireMatch("node4242.regex.example.com", rules, noGroups, noGroups));

RunBenchmark(
    "rule-match miss",
    MatchIterations,
    () => RuleMatcher.Match(rules, "nope.example.net", noGroups, noGroups, noGroups) is null ? 1 : 0);

string adguardFilter = BuildLargeAdguardFilter();
SourceConfig adguardSource = SourceConfig.Parse(ParseJsonElement("""
{
  "name": "bench-adguard",
  "enable": true,
  "format": "adguard-filter",
  "url": "https://example.invalid/dns.txt"
}
"""));

RunBenchmark(
    "parse adguard-filter",
    ParseIterations,
    () =>
    {
        int order = 0;
        return RuleParser.ParseAdGuardFilterSource(adguardSource, adguardFilter, ref order).Count();
    });

string rewriteManifest = BuildLargeRewriteManifest();
SourceConfig manifestSource = SourceConfig.Parse(ParseJsonElement("""
{
  "name": "bench-manifest",
  "enable": true,
  "format": "rewrite-rules-json",
  "url": "https://example.invalid/rewrite.json"
}
"""));

RunBenchmark(
    "parse rewrite-rules-json",
    ParseIterations,
    () =>
    {
        int order = 0;
        return RuleParser.ParseRewriteRulesJsonSource(manifestSource, rewriteManifest, ref order).Count();
    });

static void RunBenchmark(string name, int iterations, Func<int> action)
{
    for (int warmup = 0; warmup < 3; warmup++)
    {
        action();
    }

    GC.Collect();
    GC.WaitForPendingFinalizers();
    GC.Collect();

    int checksum = 0;
    Stopwatch stopwatch = Stopwatch.StartNew();

    for (int i = 0; i < iterations; i++)
    {
        checksum += action();
    }

    stopwatch.Stop();

    double operationsPerSecond = iterations / stopwatch.Elapsed.TotalSeconds;
    double microsecondsPerOp = stopwatch.Elapsed.TotalMilliseconds * 1000d / iterations;

    Console.WriteLine(
        "{0,-26} {1,10} ops  {2,12:F2} ops/s  {3,10:F2} us/op  checksum={4}",
        name,
        iterations,
        operationsPerSecond,
        microsecondsPerOp,
        checksum);
}

static RewriteRule[] BuildRules(RewriteAnswer answer, HashSet<string> noGroups)
{
    List<RewriteRule> rules = new(RuleCount + 2);

    for (int i = 0; i < RuleCount; i++)
    {
        rules.Add(new RewriteRule("bench", i, RemoteRewrite.MatchType.Suffix, $"svc{i}.suffix.example.com", [answer], null, noGroups));
    }

    rules.Add(new RewriteRule("bench", RuleCount, RemoteRewrite.MatchType.Glob, "edge*.glob.example.com", [answer], null, noGroups));
    rules.Add(new RewriteRule("bench", RuleCount + 1, RemoteRewrite.MatchType.Regex, @"node[0-9]+\.regex\.example\.com", [answer], null, noGroups));
    return [.. rules];
}

static int RequireMatch(string qname, RewriteRule[] rules, HashSet<string> noGroups, HashSet<string> resolvedGroups)
{
    RewriteRule? rule = RuleMatcher.Match(rules, qname, noGroups, noGroups, resolvedGroups);
    if (rule is null)
        throw new InvalidOperationException($"expected match for {qname}");

    return rule.Pattern.Length;
}

static string BuildLargeAdguardFilter()
{
    List<string> lines = new(RuleCount + 2);

    for (int i = 0; i < RuleCount; i++)
    {
        lines.Add($"||svc{i}.suffix.example.com^$dnsrewrite=192.0.2.10");
    }

    lines.Add("||edge*.glob.example.com^$dnsrewrite=198.51.100.10");
    lines.Add(@"/node[0-9]+\.regex\.example\.com/$dnsrewrite=203.0.113.10");
    return string.Join('\n', lines);
}

static string BuildLargeRewriteManifest()
{
    List<string> rules = new(RuleCount + 2);

    for (int i = 0; i < RuleCount; i++)
    {
        rules.Add($$"""
        {"matchType":"suffix","pattern":"svc{{i}}.suffix.example.com","answers":[{"type":"A","value":"192.0.2.10"}]}
        """);
    }

    rules.Add("""
    {"matchType":"glob","pattern":"edge*.glob.example.com","answers":[{"type":"A","value":"198.51.100.10"}]}
    """);
    rules.Add("""
    {"matchType":"regex","pattern":"node[0-9]+\\.regex\\.example\\.com","answers":[{"type":"A","value":"203.0.113.10"}]}
    """);

    return "{\"rules\":[" + string.Join(',', rules) + "]}";
}

static System.Text.Json.JsonElement ParseJsonElement(string json)
{
    using System.Text.Json.JsonDocument document = System.Text.Json.JsonDocument.Parse(json);
    return document.RootElement.Clone();
}
