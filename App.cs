using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Sockets;
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
        static readonly HttpClient _http = new HttpClient
        {
            Timeout = TimeSpan.FromSeconds(15)
        };
        const int MaxSourceBytes = 4 * 1024 * 1024;
        const int MinimumRetrySeconds = 30;

        readonly SemaphoreSlim _refreshLock = new SemaphoreSlim(1, 1);
        readonly string _appRecordDataTemplate = """
{
  "enable": true,
  "sourceNames": [],
  "groupNames": [],
  "overrideTtl": null
}
""";

        AppConfig _config = AppConfig.Empty;
        RewriteRule[] _rules = Array.Empty<RewriteRule>();
        DateTime _nextRefreshUtc = DateTime.MinValue;
        bool _disposed;

        public void Dispose()
        {
            _disposed = true;
            _rules = Array.Empty<RewriteRule>();
            _nextRefreshUtc = DateTime.MinValue;
            _refreshLock.Dispose();
        }

        public async Task InitializeAsync(IDnsServer dnsServer, string config)
        {
            _config = AppConfig.Parse(config);
            await RefreshRulesAsync(force: true);
        }

        public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed, string zoneName, string appRecordName, uint appRecordTtl, string appRecordData)
        {
            if (_disposed || !_config.Enable)
                return Task.FromResult<DnsDatagram>(null);

            if ((request?.Question is null) || (request.Question.Count == 0))
                return Task.FromResult<DnsDatagram>(null);

            AppRecordOptions appOptions = AppRecordOptions.Parse(appRecordData);
            if (!appOptions.Enable)
                return Task.FromResult<DnsDatagram>(null);

            TriggerRefreshIfNeeded();

            DnsQuestionRecord question = request.Question[0];
            string qname = question.Name.ToLowerInvariant();

            if (!DnsScope.IsInZone(qname, zoneName) || !DnsScope.MatchesAppRecordScope(qname, appRecordName))
                return Task.FromResult<DnsDatagram>(null);

            HashSet<string> resolvedGroups = _config.SplitHorizon.ResolveGroups(qname, remoteEP.Address);
            if (!appOptions.MatchesGroups(resolvedGroups))
                return Task.FromResult<DnsDatagram>(null);

            RewriteRule rule = RuleMatcher.Match(_rules, qname, appOptions.SourceNames, appOptions.GroupNames, resolvedGroups);
            if (rule is null)
                return Task.FromResult<DnsDatagram>(null);

            IReadOnlyList<DnsResourceRecord> answers = DnsResponseBuilder.BuildAnswers(question, appRecordTtl, appOptions.OverrideTtl, _config.DefaultTtl, rule);
            if (answers.Count == 0)
                return Task.FromResult<DnsDatagram>(null);

            return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answers));
        }

        public string Description
        {
            get
            {
                return "Fetches remote rewrite sources and serves suffix, glob, and regex DNS overrides. Supports AdGuard-style dns.txt filter sources, rewrite-rules.json manifests, and Split Horizon-compatible group scoping.";
            }
        }

        public string ApplicationRecordDataTemplate
        {
            get { return _appRecordDataTemplate; }
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

                List<RewriteRule> rules = new List<RewriteRule>();
                int order = 0;

                foreach (SourceConfig source in _config.Sources)
                {
                    if (!source.Enable)
                        continue;

                    string content = await DownloadSourceAsync(source.Url);

                    switch (source.Format)
                    {
                        case SourceFormat.AdGuardFilter:
                            foreach (RewriteRule rule in RuleParser.ParseAdGuardFilterSource(source, content, ref order))
                                rules.Add(rule);
                            break;

                        case SourceFormat.RewriteRulesJson:
                            foreach (RewriteRule rule in RuleParser.ParseRewriteRulesJsonSource(source, content, ref order))
                                rules.Add(rule);
                            break;
                    }
                }

                _rules = rules.OrderBy(static rule => rule.Order).ToArray();
                _nextRefreshUtc = DateTime.UtcNow.AddSeconds(_config.RefreshSeconds);
            }
            catch
            {
                _nextRefreshUtc = DateTime.UtcNow.AddSeconds(Math.Max(MinimumRetrySeconds, _config.RefreshSeconds));

                if ((_rules.Length == 0) || force)
                    throw;
            }
            finally
            {
                _refreshLock.Release();
            }
        }

        void TriggerRefreshIfNeeded()
        {
            if (_disposed || !_config.Enable)
                return;

            if (DateTime.UtcNow < _nextRefreshUtc)
                return;

            _ = RefreshRulesAsync(force: false);
        }

        static async Task<string> DownloadSourceAsync(string url)
        {
            if (!Uri.TryCreate(url, UriKind.Absolute, out Uri uri))
                throw new InvalidOperationException("Source URL must be an absolute URL.");

            if ((uri.Scheme != Uri.UriSchemeHttp) && (uri.Scheme != Uri.UriSchemeHttps))
                throw new InvalidOperationException("Source URL must use http or https.");

            using HttpResponseMessage response = await _http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead);
            response.EnsureSuccessStatusCode();

            if (response.Content.Headers.ContentLength is long contentLength && contentLength > MaxSourceBytes)
                throw new InvalidOperationException("Source exceeds maximum allowed size.");

            await using Stream stream = await response.Content.ReadAsStreamAsync();
            using MemoryStream buffer = new MemoryStream();
            byte[] chunk = new byte[8192];

            while (true)
            {
                int bytesRead = await stream.ReadAsync(chunk, 0, chunk.Length);
                if (bytesRead == 0)
                    break;

                if (buffer.Length + bytesRead > MaxSourceBytes)
                    throw new InvalidOperationException("Source exceeds maximum allowed size.");

                buffer.Write(chunk, 0, bytesRead);
            }

            buffer.Position = 0;

            using StreamReader reader = new StreamReader(buffer);
            return await reader.ReadToEndAsync();
        }
    }

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

    internal static class AppLimits
    {
        public static readonly TimeSpan RegexTimeout = TimeSpan.FromMilliseconds(100);
    }

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

    internal static class RuleParser
    {
        public static IEnumerable<RewriteRule> ParseAdGuardFilterSource(SourceConfig source, string content, ref int order)
        {
            List<RewriteRule> rules = new List<RewriteRule>();

            foreach (string rawLine in content.Split('\n'))
            {
                string line = rawLine.Trim();
                if ((line.Length == 0) || line.StartsWith("!") || line.StartsWith("#") || !line.Contains("$dnsrewrite="))
                    continue;

                Match regexMatch = Regex.Match(line, @"^/(.+)/\$dnsrewrite=([^,$]+)(?:,(.*))?$");
                if (regexMatch.Success)
                {
                    RewriteAnswer answer = ParseAnswer(regexMatch.Groups[2].Value);
                    if (answer is not null)
                    {
                        rules.Add(new RewriteRule(source.Name, order++, MatchType.Regex, regexMatch.Groups[1].Value, new[] { answer }, null, source.GroupNames));
                    }
                    continue;
                }

                Match hostMatch = Regex.Match(line, @"^(?:@@)?\|\|(.+?)\^\$dnsrewrite=([^,$]+)(?:,(.*))?$");
                if (!hostMatch.Success)
                    continue;

                RewriteAnswer hostAnswer = ParseAnswer(hostMatch.Groups[2].Value);
                if (hostAnswer is null)
                    continue;

                string pattern = hostMatch.Groups[1].Value.Trim().ToLowerInvariant();
                MatchType matchType = pattern.Contains('*') ? MatchType.Glob : MatchType.Suffix;

                rules.Add(new RewriteRule(source.Name, order++, matchType, pattern, new[] { hostAnswer }, null, source.GroupNames));
            }

            return rules;
        }

        public static IEnumerable<RewriteRule> ParseRewriteRulesJsonSource(SourceConfig source, string content, ref int order)
        {
            using JsonDocument document = JsonDocument.Parse(content);
            JsonElement root = document.RootElement;
            List<RewriteRule> rules = new List<RewriteRule>();

            foreach (JsonElement rule in root.GetProperty("rules").EnumerateArray())
            {
                RewriteAnswer[] answers = rule.GetProperty("answers").EnumerateArray().Select(static item => new RewriteAnswer(item)).ToArray();
                uint? ttl = null;

                if (rule.TryGetProperty("ttl", out JsonElement ttlElement) && (ttlElement.ValueKind == JsonValueKind.Number))
                    ttl = ttlElement.GetUInt32();

                rules.Add(new RewriteRule(
                    source.Name,
                    order++,
                    Enum.Parse<MatchType>(rule.GetProperty("matchType").GetString(), ignoreCase: true),
                    rule.GetProperty("pattern").GetString(),
                    answers,
                    ttl,
                    MergeGroupNames(source.GroupNames, ParseGroupNames(rule, "groupNames"))
                ));
            }

            return rules;
        }

        public static RewriteAnswer ParseAnswer(string value)
        {
            string target = value.Trim().ToLowerInvariant();

            if (IPAddress.TryParse(target, out IPAddress address))
            {
                if (address.AddressFamily == AddressFamily.InterNetwork)
                    return new RewriteAnswer(DnsResourceRecordType.A, target);

                if (address.AddressFamily == AddressFamily.InterNetworkV6)
                    return new RewriteAnswer(DnsResourceRecordType.AAAA, target);

                return null;
            }

            return new RewriteAnswer(DnsResourceRecordType.CNAME, target);
        }

        public static bool GlobMatch(string qname, string pattern)
        {
            string regex = "^" + Regex.Escape(pattern).Replace("\\*", ".*") + "$";
            return Regex.IsMatch(qname, regex, RegexOptions.IgnoreCase | RegexOptions.CultureInvariant, AppLimits.RegexTimeout);
        }

        static HashSet<string> ParseGroupNames(JsonElement item, string propertyName)
        {
            if (!item.TryGetProperty(propertyName, out JsonElement groupNames) || (groupNames.ValueKind != JsonValueKind.Array))
                return new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            return new HashSet<string>(
                groupNames.EnumerateArray()
                    .Where(static entry => entry.ValueKind == JsonValueKind.String)
                    .Select(static entry => entry.GetString()?.Trim().ToLowerInvariant())
                    .Where(static entry => !string.IsNullOrWhiteSpace(entry)),
                StringComparer.OrdinalIgnoreCase
            );
        }

        static HashSet<string> MergeGroupNames(HashSet<string> first, HashSet<string> second)
        {
            if ((first.Count == 0) && (second.Count == 0))
                return new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            HashSet<string> merged = new HashSet<string>(first, StringComparer.OrdinalIgnoreCase);
            merged.UnionWith(second);
            return merged;
        }
    }

    internal sealed class AppConfig
    {
        public static readonly AppConfig Empty = new AppConfig
        {
            Enable = true,
            DefaultTtl = 300,
            RefreshSeconds = 300,
            Sources = Array.Empty<SourceConfig>(),
            SplitHorizon = SplitHorizonConfig.Disabled
        };

        public bool Enable { get; private set; }
        public uint DefaultTtl { get; private set; }
        public int RefreshSeconds { get; private set; }
        public SourceConfig[] Sources { get; private set; }
        public SplitHorizonConfig SplitHorizon { get; private set; }

        public static AppConfig Parse(string config)
        {
            using JsonDocument document = JsonDocument.Parse(config);
            JsonElement root = document.RootElement;

            return new AppConfig
            {
                Enable = root.TryGetProperty("enable", out JsonElement enable) ? enable.GetBoolean() : true,
                DefaultTtl = root.TryGetProperty("defaultTtl", out JsonElement defaultTtl) ? defaultTtl.GetUInt32() : 300u,
                RefreshSeconds = root.TryGetProperty("refreshSeconds", out JsonElement refreshSeconds) ? refreshSeconds.GetInt32() : 300,
                Sources = root.TryGetProperty("sources", out JsonElement sources)
                    ? sources.EnumerateArray().Select(static item => SourceConfig.Parse(item)).ToArray()
                    : Array.Empty<SourceConfig>(),
                SplitHorizon = root.TryGetProperty("splitHorizon", out JsonElement splitHorizon)
                    ? SplitHorizonConfig.Parse(splitHorizon)
                    : SplitHorizonConfig.Disabled
            };
        }
    }

    internal sealed class SourceConfig
    {
        public string Name { get; private set; }
        public bool Enable { get; private set; }
        public SourceFormat Format { get; private set; }
        public string Url { get; private set; }
        public HashSet<string> GroupNames { get; private set; }

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
                GroupNames = item.TryGetProperty("groupNames", out JsonElement groupNames) && (groupNames.ValueKind == JsonValueKind.Array)
                    ? new HashSet<string>(
                        groupNames.EnumerateArray()
                            .Where(static entry => entry.ValueKind == JsonValueKind.String)
                            .Select(static entry => entry.GetString()?.Trim().ToLowerInvariant())
                            .Where(static entry => !string.IsNullOrWhiteSpace(entry)),
                        StringComparer.OrdinalIgnoreCase
                    )
                    : new HashSet<string>(StringComparer.OrdinalIgnoreCase)
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

    internal sealed class AppRecordOptions
    {
        public bool Enable { get; private set; }
        public HashSet<string> SourceNames { get; private set; }
        public HashSet<string> GroupNames { get; private set; }
        public uint? OverrideTtl { get; private set; }

        public static AppRecordOptions Parse(string appRecordData)
        {
            if (string.IsNullOrWhiteSpace(appRecordData))
            {
                return new AppRecordOptions
                {
                    Enable = true,
                    SourceNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                    GroupNames = new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                    OverrideTtl = null,
                };
            }

            using JsonDocument document = JsonDocument.Parse(appRecordData);
            JsonElement root = document.RootElement;

            return new AppRecordOptions
            {
                Enable = root.TryGetProperty("enable", out JsonElement enable) ? enable.GetBoolean() : true,
                SourceNames = root.TryGetProperty("sourceNames", out JsonElement sourceNames)
                    ? ParseStringArray(sourceNames)
                    : new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                GroupNames = root.TryGetProperty("groupNames", out JsonElement groupNames)
                    ? ParseStringArray(groupNames)
                    : new HashSet<string>(StringComparer.OrdinalIgnoreCase),
                OverrideTtl = root.TryGetProperty("overrideTtl", out JsonElement ttl) && (ttl.ValueKind == JsonValueKind.Number)
                    ? ttl.GetUInt32()
                    : null,
            };
        }

        public bool MatchesGroups(HashSet<string> resolvedGroups)
        {
            if (GroupNames.Count == 0)
                return true;

            return GroupNames.Overlaps(resolvedGroups);
        }

        static HashSet<string> ParseStringArray(JsonElement value)
        {
            if (value.ValueKind != JsonValueKind.Array)
                return new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            return new HashSet<string>(
                value.EnumerateArray()
                    .Where(static entry => entry.ValueKind == JsonValueKind.String)
                    .Select(static entry => entry.GetString()?.Trim().ToLowerInvariant())
                    .Where(static entry => !string.IsNullOrWhiteSpace(entry)),
                StringComparer.OrdinalIgnoreCase
            );
        }
    }

    internal sealed class SplitHorizonConfig
    {
        public static readonly SplitHorizonConfig Disabled = new SplitHorizonConfig
        {
            Enable = false,
            DefaultGroupName = null,
            PrivateGroupName = null,
            PublicGroupName = null,
            DomainGroupRules = Array.Empty<DomainGroupRule>(),
            NetworkGroupRules = Array.Empty<NetworkGroupRule>()
        };

        public bool Enable { get; private set; }
        public string DefaultGroupName { get; private set; }
        public string PrivateGroupName { get; private set; }
        public string PublicGroupName { get; private set; }
        public DomainGroupRule[] DomainGroupRules { get; private set; }
        public NetworkGroupRule[] NetworkGroupRules { get; private set; }

        public static SplitHorizonConfig Parse(JsonElement value)
        {
            List<DomainGroupRule> domainRules = new List<DomainGroupRule>();
            List<NetworkGroupRule> networkRules = new List<NetworkGroupRule>();

            if (value.TryGetProperty("domainGroupMap", out JsonElement domainGroupMap) && (domainGroupMap.ValueKind == JsonValueKind.Object))
            {
                foreach (JsonProperty property in domainGroupMap.EnumerateObject())
                {
                    if (property.Value.ValueKind != JsonValueKind.String)
                        continue;

                    domainRules.Add(new DomainGroupRule(property.Name, property.Value.GetString()));
                }
            }

            if (value.TryGetProperty("networkGroupMap", out JsonElement networkGroupMap) && (networkGroupMap.ValueKind == JsonValueKind.Object))
            {
                foreach (JsonProperty property in networkGroupMap.EnumerateObject())
                {
                    if (property.Value.ValueKind != JsonValueKind.String)
                        continue;

                    networkRules.Add(NetworkGroupRule.Parse(property.Name, property.Value.GetString()));
                }
            }

            return new SplitHorizonConfig
            {
                Enable = value.TryGetProperty("enable", out JsonElement enable) ? enable.GetBoolean() : true,
                DefaultGroupName = value.TryGetProperty("defaultGroupName", out JsonElement defaultGroupName) ? NormalizeGroupName(defaultGroupName.GetString()) : "default",
                PrivateGroupName = value.TryGetProperty("privateGroupName", out JsonElement privateGroupName) ? NormalizeGroupName(privateGroupName.GetString()) : "private",
                PublicGroupName = value.TryGetProperty("publicGroupName", out JsonElement publicGroupName) ? NormalizeGroupName(publicGroupName.GetString()) : "public",
                DomainGroupRules = domainRules.OrderByDescending(static item => item.Pattern.Length).ToArray(),
                NetworkGroupRules = networkRules.OrderByDescending(static item => item.PrefixLength).ToArray()
            };
        }

        public HashSet<string> ResolveGroups(string qname, IPAddress address)
        {
            HashSet<string> groups = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            if (!Enable)
                return groups;

            AddGroup(groups, DefaultGroupName);
            AddGroup(groups, NetworkClassifier.IsPrivateOrSpecial(address) ? PrivateGroupName : PublicGroupName);

            foreach (DomainGroupRule rule in DomainGroupRules)
            {
                if (rule.Matches(qname))
                    AddGroup(groups, rule.GroupName);
            }

            foreach (NetworkGroupRule rule in NetworkGroupRules)
            {
                if (rule.Matches(address))
                    AddGroup(groups, rule.GroupName);
            }

            return groups;
        }

        static void AddGroup(HashSet<string> groups, string name)
        {
            if (!string.IsNullOrWhiteSpace(name))
                groups.Add(name);
        }

        static string NormalizeGroupName(string value)
        {
            return string.IsNullOrWhiteSpace(value) ? null : value.Trim().ToLowerInvariant();
        }
    }

    internal static class NetworkClassifier
    {
        public static bool IsPrivateOrSpecial(IPAddress address)
        {
            if (address is null)
                return false;

            if (address.IsIPv4MappedToIPv6)
                address = address.MapToIPv4();

            if (IPAddress.IsLoopback(address))
                return true;

            if (address.AddressFamily == AddressFamily.InterNetwork)
            {
                byte[] bytes = address.GetAddressBytes();
                return bytes[0] == 10
                    || (bytes[0] == 172 && (bytes[1] >= 16) && (bytes[1] <= 31))
                    || (bytes[0] == 192 && bytes[1] == 168)
                    || (bytes[0] == 169 && bytes[1] == 254)
                    || bytes[0] == 127;
            }

            if (address.AddressFamily == AddressFamily.InterNetworkV6)
            {
                if (address.Equals(IPAddress.IPv6Loopback))
                    return true;

                byte[] bytes = address.GetAddressBytes();
                return (bytes[0] & 0xFE) == 0xFC || (bytes[0] == 0xFE && (bytes[1] & 0xC0) == 0x80);
            }

            return false;
        }
    }

    internal sealed class DomainGroupRule
    {
        public DomainGroupRule(string pattern, string groupName)
        {
            Pattern = pattern.Trim().TrimStart('.').ToLowerInvariant();
            GroupName = groupName.Trim().ToLowerInvariant();
        }

        public string Pattern { get; }
        public string GroupName { get; }

        public bool Matches(string qname)
        {
            return qname.Equals(Pattern, StringComparison.OrdinalIgnoreCase) || qname.EndsWith("." + Pattern, StringComparison.OrdinalIgnoreCase);
        }
    }

    internal sealed class NetworkGroupRule
    {
        NetworkGroupRule(IPAddress network, int prefixLength, string groupName)
        {
            Network = network;
            PrefixLength = prefixLength;
            GroupName = groupName.Trim().ToLowerInvariant();
        }

        public IPAddress Network { get; }
        public int PrefixLength { get; }
        public string GroupName { get; }

        public static NetworkGroupRule Parse(string pattern, string groupName)
        {
            string trimmed = pattern.Trim();
            if (trimmed.Contains('/'))
            {
                string[] parts = trimmed.Split('/', 2);
                IPAddress network = IPAddress.Parse(parts[0]);
                int prefixLength = int.Parse(parts[1]);
                return new NetworkGroupRule(network, prefixLength, groupName);
            }

            IPAddress address = IPAddress.Parse(trimmed);
            int prefixLengthValue = address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128;
            return new NetworkGroupRule(address, prefixLengthValue, groupName);
        }

        public bool Matches(IPAddress address)
        {
            if (address is null)
                return false;

            IPAddress candidate = address.IsIPv4MappedToIPv6 ? address.MapToIPv4() : address;
            IPAddress network = Network.IsIPv4MappedToIPv6 ? Network.MapToIPv4() : Network;

            if (candidate.AddressFamily != network.AddressFamily)
                return false;

            byte[] left = candidate.GetAddressBytes();
            byte[] right = network.GetAddressBytes();
            int remainingBits = PrefixLength;

            for (int i = 0; i < left.Length && remainingBits > 0; i++)
            {
                int bitsToCompare = Math.Min(8, remainingBits);
                int mask = 0xFF << (8 - bitsToCompare);

                if ((left[i] & mask) != (right[i] & mask))
                    return false;

                remainingBits -= bitsToCompare;
            }

            return true;
        }
    }

    internal sealed class RewriteRule
    {
        readonly Regex _regex;

        public RewriteRule(string sourceName, int order, MatchType matchType, string pattern, RewriteAnswer[] answers, uint? ttl, HashSet<string> groupNames)
        {
            SourceName = sourceName;
            Order = order;
            MatchType = matchType;
            Pattern = pattern.ToLowerInvariant();
            Answers = answers;
            Ttl = ttl;
            GroupNames = groupNames.Count == 0
                ? new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                : new HashSet<string>(groupNames, StringComparer.OrdinalIgnoreCase);

            if (matchType == MatchType.Regex)
                _regex = new Regex(pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled | RegexOptions.CultureInvariant, AppLimits.RegexTimeout);
        }

        public string SourceName { get; }
        public int Order { get; }
        public MatchType MatchType { get; }
        public string Pattern { get; }
        public RewriteAnswer[] Answers { get; }
        public uint? Ttl { get; }
        public HashSet<string> GroupNames { get; }

        public bool IsMatch(string qname)
        {
            switch (MatchType)
            {
                case MatchType.Suffix:
                    return qname.Equals(Pattern, StringComparison.OrdinalIgnoreCase) || qname.EndsWith("." + Pattern, StringComparison.OrdinalIgnoreCase);

                case MatchType.Glob:
                    return RuleParser.GlobMatch(qname, Pattern);

                case MatchType.Regex:
                    try
                    {
                        return _regex.IsMatch(qname);
                    }
                    catch (RegexMatchTimeoutException)
                    {
                        return false;
                    }

                default:
                    return false;
            }
        }
    }

    internal sealed class RewriteAnswer
    {
        public RewriteAnswer(DnsResourceRecordType type, string value)
        {
            Type = type;
            Value = value;
        }

        public RewriteAnswer(JsonElement json)
        {
            Type = Enum.Parse<DnsResourceRecordType>(json.GetProperty("type").GetString(), ignoreCase: true);
            Value = json.GetProperty("value").GetString();
        }

        public DnsResourceRecordType Type { get; }
        public string Value { get; }
    }

    internal enum MatchType
    {
        Suffix,
        Glob,
        Regex
    }

    internal enum SourceFormat
    {
        AdGuardFilter,
        RewriteRulesJson
    }
}
