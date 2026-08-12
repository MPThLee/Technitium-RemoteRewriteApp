using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;

namespace RemoteRewrite;

public sealed class App : IDnsApplication, IDnsAppRecordRequestHandler, IDnsAuthoritativeRequestHandler, IDnsApplicationPreference
{
    static readonly HttpClient _http = new HttpClient(new HttpClientHandler
    {
        AllowAutoRedirect = false
    })
    {
        Timeout = Timeout.InfiniteTimeSpan
    };

    readonly SemaphoreSlim _refreshLock = new SemaphoreSlim(1, 1);
    readonly CancellationTokenSource _lifetime = new CancellationTokenSource();
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

    IDnsServer _dnsServer;
    RuntimeState _state = RuntimeState.Empty;
    Timer _refreshTimer;
    bool _disposed;

    public string Description => "Globally serves exact, suffix, glob, and regex DNS rewrites from remote or inline AdGuard and JSON sources, with optional APP-record and Split Horizon scoping.";
    public string ApplicationRecordDataTemplate => _appRecordDataTemplate;
    public byte Preference => _state.Config.AppPreference;

    public void Dispose()
    {
        if (_disposed)
            return;

        _disposed = true;
        _refreshTimer?.Dispose();
        _refreshTimer = null;
        _lifetime.Cancel();
        _state = RuntimeState.Empty;
        AppRecordOptions.ClearCache();
    }

    public async Task InitializeAsync(IDnsServer dnsServer, string config)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(App));

        AppConfig nextConfig = AppConfig.Parse(config);
        nextConfig.LoadSplitHorizonIntegration(dnsServer?.ApplicationFolder);

        await _refreshLock.WaitAsync(_lifetime.Token);
        try
        {
            RewriteRule[] nextRules = nextConfig.Enable
                ? await LoadRulesAsync(nextConfig, _lifetime.Token)
                : Array.Empty<RewriteRule>();

            _dnsServer = dnsServer;
            _state = new RuntimeState(nextConfig, nextRules);
            AppRecordOptions.ClearCache();
            ScheduleRefresh(nextConfig.Enable && nextConfig.RefreshSeconds > 0 ? nextConfig.RefreshSeconds : Timeout.Infinite);

            _dnsServer?.WriteLog($"Remote Rewrite App loaded {nextRules.Length} rule(s) from {nextConfig.EnabledSourceCount} enabled source(s).");
        }
        catch (Exception ex)
        {
            dnsServer?.WriteLog("Remote Rewrite App failed to load configuration; the previous configuration remains active.");
            dnsServer?.WriteLog(ex);
            throw;
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
    {
        RuntimeState state = _state;
        if (_disposed || !state.Config.Enable || !state.Config.GlobalMode)
            return Task.FromResult<DnsDatagram>(null);

        return ProcessRequestCoreAsync(request, remoteEP, isRecursionAllowed, 0, AppRecordEffectiveOptions.GlobalDefault, state);
    }

    public Task<DnsDatagram> ProcessRequestAsync(
        DnsDatagram request,
        IPEndPoint remoteEP,
        DnsTransportProtocol protocol,
        bool isRecursionAllowed,
        string zoneName,
        string appRecordName,
        uint appRecordTtl,
        string appRecordData)
    {
        RuntimeState state = _state;
        if (_disposed || !state.Config.Enable || request?.Question is null || request.Question.Count == 0)
            return Task.FromResult<DnsDatagram>(null);

        AppRecordOptions appOptions = AppRecordOptions.Parse(appRecordData);
        if (!appOptions.Enable)
            return Task.FromResult<DnsDatagram>(null);

        DnsQuestionRecord question = request.Question[0];
        string qname = NormalizeQname(question.Name);

        if (!DnsScope.IsInZone(qname, zoneName) || !DnsScope.MatchesAppRecordScope(qname, appRecordName))
            return Task.FromResult<DnsDatagram>(null);

        HashSet<string> resolvedGroups = state.Config.SplitHorizon.ResolveGroups(qname, remoteEP?.Address);
        AppRecordEffectiveOptions effectiveOptions = appOptions.Resolve(resolvedGroups);
        if (!effectiveOptions.Enable)
            return Task.FromResult<DnsDatagram>(null);

        return ProcessRequestCoreAsync(request, remoteEP, isRecursionAllowed, appRecordTtl, effectiveOptions, state);
    }

    async void RefreshTimerCallback(object state)
    {
        try
        {
            await RefreshCurrentRulesAsync();
        }
        catch (OperationCanceledException) when (_disposed)
        {
        }
        catch (Exception ex)
        {
            _dnsServer?.WriteLog("Remote Rewrite App refresh failed; continuing with the last known good rules.");
            _dnsServer?.WriteLog(ex);
            AppConfig config = _state.Config;
            if (config.RefreshSeconds > 0)
                ScheduleRefresh(Math.Max(AppLimits.MinimumRetrySeconds, config.RefreshSeconds));
        }
    }

    async Task RefreshCurrentRulesAsync()
    {
        RuntimeState initialState = _state;
        if (_disposed || !initialState.Config.Enable)
            return;

        await _refreshLock.WaitAsync(_lifetime.Token);
        try
        {
            RuntimeState currentState = _state;
            if (_disposed || !currentState.Config.Enable)
                return;

            AppConfig currentConfig = currentState.Config;
            RewriteRule[] nextRules = await LoadRulesAsync(currentConfig, _lifetime.Token);

            if (!ReferenceEquals(currentState, _state))
                return;

            _state = new RuntimeState(currentConfig, nextRules);
            _dnsServer?.WriteLog($"Remote Rewrite App refreshed {nextRules.Length} rule(s) from {currentConfig.EnabledSourceCount} enabled source(s).");
            ScheduleRefresh(currentConfig.RefreshSeconds);
        }
        finally
        {
            _refreshLock.Release();
        }
    }

    static async Task<RewriteRule[]> LoadRulesAsync(AppConfig config, CancellationToken cancellationToken)
    {
        List<RewriteRule> rules = new List<RewriteRule>();
        int order = 0;

        foreach (SourceConfig source in config.Sources)
        {
            if (!source.Enable)
                continue;

            cancellationToken.ThrowIfCancellationRequested();
            string content = string.IsNullOrWhiteSpace(source.Text)
                ? await DownloadSourceAsync(source.Url, cancellationToken)
                : source.Text;

            switch (source.Format)
            {
                case SourceFormat.AdGuardFilter:
                    rules.AddRange(RuleParser.ParseAdGuardFilterSource(source, content, ref order));
                    break;

                case SourceFormat.RewriteRulesJson:
                    rules.AddRange(RuleParser.ParseRewriteRulesJsonSource(source, content, ref order));
                    break;
            }
        }

        if (rules.Count > AppLimits.MaxRules)
            throw new FormatException($"Configured sources produced {rules.Count} rules; the limit is {AppLimits.MaxRules}.");

        return rules.ToArray();
    }

    static async Task<string> DownloadSourceAsync(string url, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri uri))
            throw new InvalidOperationException("Source URL must be an absolute URL.");

        if ((uri.Scheme != Uri.UriSchemeHttp) && (uri.Scheme != Uri.UriSchemeHttps))
            throw new InvalidOperationException("Source URL must use http or https.");

        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(AppLimits.SourceTimeout);

        using HttpResponseMessage response = await _http.GetAsync(uri, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        response.EnsureSuccessStatusCode();

        if (response.Content.Headers.ContentLength is long contentLength && contentLength > AppLimits.MaxSourceBytes)
            throw new InvalidOperationException("Source exceeds maximum allowed size.");

        await using Stream stream = await response.Content.ReadAsStreamAsync(timeout.Token);
        using MemoryStream buffer = new MemoryStream();
        byte[] chunk = new byte[8192];

        while (true)
        {
            int bytesRead = await stream.ReadAsync(chunk.AsMemory(0, chunk.Length), timeout.Token);
            if (bytesRead == 0)
                break;

            if (buffer.Length + bytesRead > AppLimits.MaxSourceBytes)
                throw new InvalidOperationException("Source exceeds maximum allowed size.");

            await buffer.WriteAsync(chunk.AsMemory(0, bytesRead), timeout.Token);
        }

        buffer.Position = 0;
        using StreamReader reader = new StreamReader(buffer);
        return await reader.ReadToEndAsync(timeout.Token);
    }

    Task<DnsDatagram> ProcessRequestCoreAsync(
        DnsDatagram request,
        IPEndPoint remoteEP,
        bool isRecursionAllowed,
        uint appRecordTtl,
        AppRecordEffectiveOptions options,
        RuntimeState state)
    {
        if (request?.Question is null || request.Question.Count == 0)
            return Task.FromResult<DnsDatagram>(null);

        DnsQuestionRecord question = request.Question[0];
        string qname = NormalizeQname(question.Name);
        HashSet<string> resolvedGroups = state.Config.SplitHorizon.ResolveGroups(qname, remoteEP?.Address);

        if (!options.MatchesGroups(resolvedGroups))
            return Task.FromResult<DnsDatagram>(null);

        RewriteMatch match = RuleMatcher.Match(
            options.InlineRules,
            state.Rules,
            qname,
            question.Type,
            options.SourceNames,
            options.GroupNames,
            resolvedGroups);
        if (match is null)
            return Task.FromResult<DnsDatagram>(null);

        IReadOnlyList<TechnitiumLibrary.Net.Dns.ResourceRecords.DnsResourceRecord> answers = DnsResponseBuilder.BuildAnswers(
            question,
            appRecordTtl,
            options.OverrideTtl,
            state.Config.DefaultTtl,
            match);

        return Task.FromResult(new DnsDatagram(
            request.Identifier,
            true,
            request.OPCODE,
            true,
            false,
            request.RecursionDesired,
            isRecursionAllowed,
            false,
            request.CheckingDisabled,
            match.ResponseCode,
            request.Question,
            answers));
    }

    void ScheduleRefresh(int delaySeconds)
    {
        if (_disposed)
            return;

        if (delaySeconds == Timeout.Infinite)
        {
            _refreshTimer?.Change(Timeout.Infinite, Timeout.Infinite);
            return;
        }

        int dueTime = checked(delaySeconds * 1000);
        if (_refreshTimer is null)
            _refreshTimer = new Timer(RefreshTimerCallback, null, dueTime, Timeout.Infinite);
        else
            _refreshTimer.Change(dueTime, Timeout.Infinite);
    }

    static string NormalizeQname(string qname)
    {
        return qname?.Trim().TrimEnd('.').ToLowerInvariant() ?? string.Empty;
    }

    sealed class RuntimeState
    {
        public static readonly RuntimeState Empty = new RuntimeState(AppConfig.Empty, Array.Empty<RewriteRule>());

        public RuntimeState(AppConfig config, RewriteRule[] rules)
        {
            Config = config;
            Rules = rules;
        }

        public AppConfig Config { get; }
        public RewriteRule[] Rules { get; }
    }
}
