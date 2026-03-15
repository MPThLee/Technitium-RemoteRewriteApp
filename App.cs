using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace RemoteRewrite
{
    public sealed class App : IDnsApplication, IDnsAppRecordRequestHandler
    {
        static readonly HttpClient _http = new HttpClient();

        readonly SemaphoreSlim _refreshLock = new SemaphoreSlim(1, 1);
        readonly string _appRecordDataTemplate = """
{
  "enable": true,
  "sourceNames": [],
  "overrideTtl": null
}
""";

        Config _config = Config.Empty;
        Rule[] _rules = Array.Empty<Rule>();
        DateTime _nextRefreshUtc = DateTime.MinValue;
        bool _disposed;

        public void Dispose()
        {
            _disposed = true;
            _rules = Array.Empty<Rule>();
            _nextRefreshUtc = DateTime.MinValue;
            _refreshLock.Dispose();
        }

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _config = Config.Parse(config);
            await RefreshRulesAsync(force: true);
        }

        public async Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, string appRecordName, uint appRecordTtl, string appRecordData)
        {
            if (_disposed || !_config.Enable)
                return null;

            AppRecordOptions appOptions = AppRecordOptions.Parse(appRecordData);
            if (!appOptions.Enable)
                return null;

            await RefreshRulesAsync(force: false);

            DnsQuestionRecord question = request.Question[0];
            string qname = question.Name.ToLowerInvariant();

            if (!IsInZone(qname, zoneName) || !MatchesAppRecordScope(qname, appRecordName))
                return null;

            Rule rule = MatchRule(qname, appOptions);
            if (rule is null)
                return null;

            IReadOnlyList<DnsResourceRecord> answers = BuildAnswers(question, appRecordTtl, appOptions.OverrideTtl, _config.DefaultTtl, rule);
            if (answers.Count == 0)
                return null;

            return new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answers);
        }

        public string Description
        {
            get
            {
                return "Fetches remote rewrite sources and serves suffix, glob, and regex DNS overrides. Supports AdGuard-style dns.txt filter sources and rewrite-rules.json manifests.";
            }
        }

        public string ApplicationRecordDataTemplate
        {
            get { return _appRecordDataTemplate; }
        }

        static bool IsInZone(string qname, string zoneName)
        {
            if (string.IsNullOrWhiteSpace(zoneName))
                return true;

            zoneName = zoneName.ToLowerInvariant();
            return qname.Equals(zoneName, StringComparison.OrdinalIgnoreCase) || qname.EndsWith("." + zoneName, StringComparison.OrdinalIgnoreCase);
        }

        static bool MatchesAppRecordScope(string qname, string appRecordName)
        {
            if (string.IsNullOrWhiteSpace(appRecordName))
                return true;

            appRecordName = appRecordName.ToLowerInvariant();

            if (qname.Equals(appRecordName, StringComparison.OrdinalIgnoreCase))
                return true;

            if (appRecordName.Contains('*'))
                return GlobMatch(qname, appRecordName);

            return false;
        }

        Rule MatchRule(string qname, AppRecordOptions appOptions)
        {
            HashSet<string> enabledSources = appOptions.SourceNames;

            foreach (Rule rule in _rules)
            {
                if ((enabledSources.Count > 0) && !enabledSources.Contains(rule.SourceName))
                    continue;

                if (rule.IsMatch(qname))
                    return rule;
            }

            return null;
        }

        static IReadOnlyList<DnsResourceRecord> BuildAnswers(DnsQuestionRecord question, uint appRecordTtl, uint? overrideTtl, uint defaultTtl, Rule rule)
        {
            List<DnsResourceRecord> answers = new List<DnsResourceRecord>();
            uint ttl = overrideTtl ?? rule.Ttl ?? defaultTtl;
            if (ttl == 0)
                ttl = appRecordTtl;

            foreach (Answer answer in rule.Answers)
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

        async Task RefreshRulesAsync(bool force)
        {
            if (_disposed || !_config.Enable)
                return;

            if (!force && (DateTime.UtcNow < _nextRefreshUtc))
                return;

            await _refreshLock.WaitAsync();

            try
            {
                if (_disposed || !_config.Enable)
                    return;

                if (!force && (DateTime.UtcNow < _nextRefreshUtc))
                    return;

                List<Rule> rules = new List<Rule>();
                int order = 0;

                foreach (SourceConfig source in _config.Sources)
                {
                    if (!source.Enable)
                        continue;

                    string content = await _http.GetStringAsync(source.Url);

                    switch (source.Format)
                    {
                        case SourceFormat.AdGuardFilter:
                            foreach (Rule rule in ParseAdGuardFilterSource(source.Name, content, ref order))
                                rules.Add(rule);
                            break;

                        case SourceFormat.RewriteRulesJson:
                            foreach (Rule rule in ParseRewriteRulesJsonSource(source.Name, content, ref order))
                                rules.Add(rule);
                            break;
                    }
                }

                _rules = rules.OrderBy(static rule => rule.Order).ToArray();
                _nextRefreshUtc = DateTime.UtcNow.AddSeconds(_config.RefreshSeconds);
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        static IEnumerable<Rule> ParseAdGuardFilterSource(string sourceName, string content, ref int order)
        {
            List<Rule> rules = new List<Rule>();

            foreach (string rawLine in content.Split('\n'))
            {
                string line = rawLine.Trim();
                if ((line.Length == 0) || line.StartsWith("!") || line.StartsWith("#") || !line.Contains("$dnsrewrite="))
                    continue;

                Match regexMatch = Regex.Match(line, @"^/(.+)/\$dnsrewrite=([^,$]+)(?:,(.*))?$");
                if (regexMatch.Success)
                {
                    Answer answer = ParseAnswer(regexMatch.Groups[2].Value);
                    if (answer is not null)
                    {
                        rules.Add(new Rule(sourceName, order++, MatchType.Regex, regexMatch.Groups[1].Value, new[] { answer }, null));
                    }
                    continue;
                }

                Match hostMatch = Regex.Match(line, @"^(?:@@)?\|\|(.+?)\^\$dnsrewrite=([^,$]+)(?:,(.*))?$");
                if (!hostMatch.Success)
                    continue;

                Answer hostAnswer = ParseAnswer(hostMatch.Groups[2].Value);
                if (hostAnswer is null)
                    continue;

                string pattern = hostMatch.Groups[1].Value.Trim().ToLowerInvariant();
                MatchType matchType = pattern.Contains('*') ? MatchType.Glob : MatchType.Suffix;

                rules.Add(new Rule(sourceName, order++, matchType, pattern, new[] { hostAnswer }, null));
            }

            return rules;
        }

        static IEnumerable<Rule> ParseRewriteRulesJsonSource(string sourceName, string content, ref int order)
        {
            using JsonDocument document = JsonDocument.Parse(content);
            JsonElement root = document.RootElement;
            List<Rule> rules = new List<Rule>();

            foreach (JsonElement rule in root.GetProperty("rules").EnumerateArray())
            {
                Answer[] answers = rule.GetProperty("answers").EnumerateArray().Select(static item => new Answer(item)).ToArray();
                uint? ttl = null;

                if (rule.TryGetProperty("ttl", out JsonElement ttlElement) && (ttlElement.ValueKind == JsonValueKind.Number))
                    ttl = ttlElement.GetUInt32();

                rules.Add(new Rule(
                    sourceName,
                    order++,
                    Enum.Parse<MatchType>(rule.GetProperty("matchType").GetString(), ignoreCase: true),
                    rule.GetProperty("pattern").GetString(),
                    answers,
                    ttl
                ));
            }

            return rules;
        }

        static Answer ParseAnswer(string value)
        {
            string target = value.Trim().ToLowerInvariant();

            if (IPAddress.TryParse(target, out IPAddress address))
            {
                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                    return new Answer(DnsResourceRecordType.A, target);

                if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
                    return new Answer(DnsResourceRecordType.AAAA, target);

                return null;
            }

            return new Answer(DnsResourceRecordType.CNAME, target);
        }

        static bool GlobMatch(string qname, string pattern)
        {
            string regex = "^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$";
            return Regex.IsMatch(qname, regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        }

        sealed class Config
        {
            public static readonly Config Empty = new Config
            {
                Enable = true,
                DefaultTtl = 300,
                RefreshSeconds = 300,
                Sources = Array.Empty<SourceConfig>(),
            };

            public bool Enable { get; private set; }
            public uint DefaultTtl { get; private set; }
            public int RefreshSeconds { get; private set; }
            public SourceConfig[] Sources { get; private set; }

            public static Config Parse(string config)
            {
                using JsonDocument document = JsonDocument.Parse(config);
                JsonElement root = document.RootElement;

                return new Config
                {
                    Enable = root.TryGetProperty("enable", out JsonElement enable) ? enable.GetBoolean() : true,
                    DefaultTtl = root.TryGetProperty("defaultTtl", out JsonElement defaultTtl) ? defaultTtl.GetUInt32() : 300u,
                    RefreshSeconds = root.TryGetProperty("refreshSeconds", out JsonElement refreshSeconds) ? refreshSeconds.GetInt32() : 300,
                    Sources = root.GetProperty("sources").EnumerateArray().Select(static item => SourceConfig.Parse(item)).ToArray(),
                };
            }
        }

        sealed class SourceConfig
        {
            public string Name { get; private set; }
            public bool Enable { get; private set; }
            public SourceFormat Format { get; private set; }
            public string Url { get; private set; }

            public static SourceConfig Parse(JsonElement item)
            {
                return new SourceConfig
                {
                    Name = item.GetProperty("name").GetString().Trim().ToLowerInvariant(),
                    Enable = item.TryGetProperty("enable", out JsonElement enable) ? enable.GetBoolean() : true,
                    Format = item.TryGetProperty("format", out JsonElement format)
                        ? ParseFormat(format.GetString())
                        : SourceFormat.AdGuardFilter,
                    Url = item.GetProperty("url").GetString(),
                };
            }

            static SourceFormat ParseFormat(string value)
            {
                return value.ToLowerInvariant() switch
                {
                    "adguard-filter" => SourceFormat.AdGuardFilter,
                    "rewrite-rules-json" => SourceFormat.RewriteRulesJson,
                    _ => throw new NotSupportedException("Unsupported source format: " + value),
                };
            }
        }

        sealed class AppRecordOptions
        {
            public bool Enable { get; private set; }
            public HashSet<string> SourceNames { get; private set; }
            public uint? OverrideTtl { get; private set; }

            public static AppRecordOptions Parse(string appRecordData)
            {
                if (string.IsNullOrWhiteSpace(appRecordData))
                {
                    return new AppRecordOptions
                    {
                        Enable = true,
                        SourceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                        OverrideTtl = null,
                    };
                }

                using JsonDocument document = JsonDocument.Parse(appRecordData);
                JsonElement root = document.RootElement;

                return new AppRecordOptions
                {
                    Enable = root.TryGetProperty("enable", out JsonElement enable) ? enable.GetBoolean() : true,
                    SourceNames = root.TryGetProperty("sourceNames", out JsonElement sourceNames)
                        ? new HashSet<string>(sourceNames.EnumerateArray().Select(static item => item.GetString().Trim().ToLowerInvariant()), StringComparer.OrdinalIgnoreCase)
                        : new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                    OverrideTtl = root.TryGetProperty("overrideTtl", out JsonElement ttl) && (ttl.ValueKind == JsonValueKind.Number)
                        ? ttl.GetUInt32()
                        : null,
                };
            }
        }

        sealed class Rule
        {
            readonly Regex _regex;

            public Rule(string sourceName, int order, MatchType matchType, string pattern, Answer[] answers, uint? ttl)
            {
                SourceName = sourceName;
                Order = order;
                MatchType = matchType;
                Pattern = pattern.ToLowerInvariant();
                Answers = answers;
                Ttl = ttl;

                if (matchType == MatchType.Regex)
                    _regex = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant);
            }

            public string SourceName { get; }
            public int Order { get; }
            public MatchType MatchType { get; }
            public string Pattern { get; }
            public Answer[] Answers { get; }
            public uint? Ttl { get; }

            public bool IsMatch(string qname)
            {
                switch (MatchType)
                {
                    case MatchType.Suffix:
                        return qname.Equals(Pattern, StringComparison.OrdinalIgnoreCase) || qname.EndsWith("." + Pattern, StringComparison.OrdinalIgnoreCase);

                    case MatchType.Glob:
                        return GlobMatch(qname, Pattern);

                    case MatchType.Regex:
                        return _regex.IsMatch(qname);

                    default:
                        return false;
                }
            }
        }

        sealed class Answer
        {
            public Answer(DnsResourceRecordType type, string value)
            {
                Type = type;
                Value = value;
            }

            public Answer(JsonElement json)
            {
                Type = Enum.Parse<DnsResourceRecordType>(json.GetProperty("type").GetString(), ignoreCase: true);
                Value = json.GetProperty("value").GetString();
            }

            public DnsResourceRecordType Type { get; }
            public string Value { get; }
        }

        enum MatchType
        {
            Suffix,
            Glob,
            Regex
        }

        enum SourceFormat
        {
            AdGuardFilter,
            RewriteRulesJson
        }
    }
}
