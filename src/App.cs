using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace RemoteRewrite;

public sealed class App : IDnsApplication, IDnsAppRecordRequestHandler, IDnsApplicationPreference
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
  "overrideTtl": null,
  "inlineSources": [
    {
      "name": "record-inline",
      "enable": false,
      "format": "adguard-filter",
      "text": "||service.example^$dnsrewrite=192.0.2.10"
    }
  ],
  "splitHorizonMap": {
    "private": {
      "sourceNames": [],
      "groupNames": [],
      "overrideTtl": null,
      "inlineSources": [
        {
          "name": "private-inline",
          "enable": false,
          "format": "adguard-filter",
          "text": "||service.example^$dnsrewrite=10.0.0.10"
        }
      ]
    },
    "public": {
      "sourceNames": [],
      "groupNames": [],
      "overrideTtl": null,
      "inlineSources": []
    }
  }
}
""";

    AppConfig _config = AppConfig.Empty;
    RewriteRule[] _rules = Array.Empty<RewriteRule>();
    DateTime _nextRefreshUtc = DateTime.MinValue;
    bool _disposed;

    public string Description => "Fetches remote rewrite sources and serves suffix, glob, and regex DNS overrides. Supports AdGuard-style dns.txt filter sources, rewrite-rules.json manifests, and Split Horizon-compatible group scoping.";

    public string ApplicationRecordDataTemplate => _appRecordDataTemplate;
    public byte Preference => _config.AppPreference;

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
        _config.LoadSplitHorizonIntegration(dnsServer?.ApplicationFolder);
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
        AppRecordEffectiveOptions effectiveOptions = appOptions.Resolve(resolvedGroups);
        if (!effectiveOptions.Enable || !effectiveOptions.MatchesGroups(resolvedGroups))
            return Task.FromResult<DnsDatagram>(null);

        RewriteRule rule = RuleMatcher.Match(effectiveOptions.InlineRules, qname, effectiveOptions.SourceNames, effectiveOptions.GroupNames, resolvedGroups)
            ?? RuleMatcher.Match(_rules, qname, effectiveOptions.SourceNames, effectiveOptions.GroupNames, resolvedGroups);
        if (rule is null)
            return Task.FromResult<DnsDatagram>(null);

        IReadOnlyList<DnsResourceRecord> answers = DnsResponseBuilder.BuildAnswers(question, appRecordTtl, effectiveOptions.OverrideTtl, _config.DefaultTtl, rule);
        if (answers.Count == 0)
            return Task.FromResult<DnsDatagram>(null);

        return Task.FromResult(new DnsDatagram(request.Identifier, true, request.OPCODE, true, false, request.RecursionDesired, isRecursionAllowed, false, false, DnsResponseCode.NoError, request.Question, answers));
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

                string content = string.IsNullOrWhiteSpace(source.Text) ? await DownloadSourceAsync(source.Url) : source.Text;

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
