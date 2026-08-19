using DnsServerCore.ApplicationCommon;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace RemoteRewrite;

public sealed class App : IDnsApplication, IDnsAppRecordRequestHandler, IDnsAuthoritativeRequestHandler, IDnsApplicationPreference
{
    static readonly HttpClient _publicSourceHttp = CreateSourceHttpClient(allowPrivateNetworkSources: false);
    static readonly HttpClient _privateNetworkSourceHttp = CreateSourceHttpClient(allowPrivateNetworkSources: true);

    readonly SemaphoreSlim _refreshLock = new SemaphoreSlim(1, 1);
    readonly CancellationTokenSource _lifetime = new CancellationTokenSource();
    readonly object _lifecycleGate = new object();
    CancellationTokenSource _refreshGeneration;
    readonly List<CancellationTokenSource> _retiredRefreshGenerations = new List<CancellationTokenSource>();
    bool _disposeCancellationIssued;
    bool _lifetimeDisposed;
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

    public App()
    {
        _refreshGeneration = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
    }

    IDnsServer _dnsServer;
    volatile RuntimeState _state = RuntimeState.Empty;
    Timer _refreshTimer;
    long _generation;
    int _activeGenerationUsers;
    volatile bool _disposed;

    public string Description => "Globally serves exact, suffix, glob, and regex DNS rewrites from remote or inline AdGuard and JSON sources, with optional APP-record and Split Horizon scoping.";
    public string ApplicationRecordDataTemplate => _appRecordDataTemplate;
    public byte Preference => _state.Config.AppPreference;

    public void Dispose()
    {
        Timer refreshTimer;
        CancellationTokenSource refreshGeneration;
        CancellationTokenSource[] retiredRefreshGenerations;

        lock (_lifecycleGate)
        {
            if (_disposed)
                return;

            _disposed = true;
            _generation++;
            refreshTimer = _refreshTimer;
            _refreshTimer = null;
            refreshGeneration = _refreshGeneration;
            retiredRefreshGenerations = _retiredRefreshGenerations.ToArray();
            _retiredRefreshGenerations.Add(refreshGeneration);
            _dnsServer = null;
            _state = RuntimeState.Empty;
        }

        try
        {
            _lifetime.Cancel();
            refreshGeneration.Cancel();
            foreach (CancellationTokenSource retired in retiredRefreshGenerations)
                retired.Cancel();
        }
        finally
        {
            try
            {
                refreshTimer?.Dispose();
            }
            finally
            {
                FinishDisposeCancellation();
                AppRecordOptions.ClearCache();
            }
        }
    }

    public async Task InitializeAsync(IDnsServer dnsServer, string config)
    {
        if (_disposed)
            throw new ObjectDisposedException(nameof(App));

        AppConfig nextConfig = AppConfig.Parse(config);
        nextConfig.LoadSplitHorizonIntegration(dnsServer?.ApplicationFolder);

        CancellationTokenSource previousRefreshGeneration;
        CancellationTokenSource nextRefreshGeneration;
        long initializationGeneration;
        lock (_lifecycleGate)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(App));

            previousRefreshGeneration = _refreshGeneration;
            nextRefreshGeneration = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
            _refreshGeneration = nextRefreshGeneration;
            _retiredRefreshGenerations.Add(previousRefreshGeneration);
            _activeGenerationUsers++;
            initializationGeneration = ++_generation;
        }

        bool lockTaken = false;
        try
        {
            previousRefreshGeneration.Cancel();
            await _refreshLock.WaitAsync(nextRefreshGeneration.Token);
            lockTaken = true;

            RewriteRule[] nextRules = nextConfig.Enable
                ? await LoadRulesAsync(nextConfig, nextRefreshGeneration.Token)
                : Array.Empty<RewriteRule>();

            nextRefreshGeneration.Token.ThrowIfCancellationRequested();

            long generation;
            lock (_lifecycleGate)
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(App));
                if (initializationGeneration != _generation || !ReferenceEquals(nextRefreshGeneration, _refreshGeneration))
                    throw new OperationCanceledException("Configuration load was superseded by a newer initialization.");

                _dnsServer = dnsServer;
                _state = new RuntimeState(nextConfig, nextRules);
                generation = initializationGeneration;
            }

            AppRecordOptions.ClearCache();
            ScheduleRefresh(nextConfig.Enable && nextConfig.RefreshSeconds > 0 ? nextConfig.RefreshSeconds : Timeout.Infinite, generation);

            _dnsServer?.WriteLog($"Remote Rewrite App loaded {nextRules.Length} rule(s) from {nextConfig.EnabledSourceCount} enabled source(s).");
        }
        catch (Exception ex)
        {
            long rollbackGeneration = 0;
            AppConfig rollbackConfig = null;
            lock (_lifecycleGate)
            {
                if (!_disposed
                    && initializationGeneration == _generation
                    && ReferenceEquals(nextRefreshGeneration, _refreshGeneration))
                {
                    _refreshGeneration = CancellationTokenSource.CreateLinkedTokenSource(_lifetime.Token);
                    _retiredRefreshGenerations.Add(nextRefreshGeneration);
                    rollbackGeneration = ++_generation;
                    rollbackConfig = _state.Config;
                }
            }

            if (rollbackConfig is not null)
                ScheduleRefresh(rollbackConfig.Enable && rollbackConfig.RefreshSeconds > 0 ? rollbackConfig.RefreshSeconds : Timeout.Infinite, rollbackGeneration);

            if (ex is not OperationCanceledException || _disposed || rollbackConfig is not null)
            {
                dnsServer?.WriteLog("Remote Rewrite App failed to load configuration; the previous configuration remains active.");
                dnsServer?.WriteLog(ex);
            }
            throw;
        }
        finally
        {
            if (lockTaken)
                _refreshLock.Release();
            RetireCompletedGenerationUser();
        }
    }

    public Task<DnsDatagram> ProcessRequestAsync(DnsDatagram request, IPEndPoint remoteEP, DnsTransportProtocol protocol, bool isRecursionAllowed)
    {
        RuntimeState state = _state;
        if (_disposed || !state.Config.Enable || !state.Config.GlobalMode || !IsSupportedRequest(request))
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
        if (_disposed || !state.Config.Enable || !IsSupportedRequest(request))
            return Task.FromResult<DnsDatagram>(null);

        DnsQuestionRecord question = request.Question[0];
        string qname = NormalizeQname(question.Name);

        if (!DnsScope.IsInZone(qname, zoneName) || !DnsScope.MatchesAppRecordScope(qname, appRecordName))
            return Task.FromResult<DnsDatagram>(null);

        if (!AppRecordOptions.TryParse(appRecordData, out AppRecordOptions appOptions))
            return Task.FromResult(BuildErrorResponse(request, isRecursionAllowed, DnsResponseCode.ServerFailure));

        if (!appOptions.Enable)
            return Task.FromResult<DnsDatagram>(null);

        HashSet<string> resolvedGroups = state.Config.SplitHorizon.ResolveGroups(qname, remoteEP?.Address);
        AppRecordEffectiveOptions effectiveOptions = appOptions.Resolve(
            resolvedGroups,
            state.Config.SplitHorizon.DefaultGroupName,
            state.Config.SplitHorizon.PrivateGroupName,
            state.Config.SplitHorizon.PublicGroupName);
        if (effectiveOptions.ResolutionFailed)
            return Task.FromResult(BuildErrorResponse(request, isRecursionAllowed, DnsResponseCode.ServerFailure));
        if (!effectiveOptions.Enable)
            return Task.FromResult<DnsDatagram>(null);

        return ProcessRequestCoreAsync(request, remoteEP, isRecursionAllowed, appRecordTtl, effectiveOptions, state);
    }

    async void RefreshTimerCallback(object state)
    {
        long generation = (long)state;
        if (!IsCurrentGeneration(generation))
            return;

        try
        {
            await RefreshCurrentRulesAsync(generation);
        }
        catch (OperationCanceledException) when (_disposed || !IsCurrentGeneration(generation))
        {
        }
        catch (Exception ex)
        {
            if (!IsCurrentGeneration(generation))
                return;

            _dnsServer?.WriteLog("Remote Rewrite App refresh failed; continuing with the last known good rules.");
            _dnsServer?.WriteLog(ex);
            AppConfig config = _state.Config;
            if (config.Enable && config.RefreshSeconds > 0)
                ScheduleRefresh(Math.Max(AppLimits.MinimumRetrySeconds, config.RefreshSeconds), generation);
        }
    }

    internal async Task RefreshCurrentRulesAsync(long generation)
    {
        if (!IsCurrentGeneration(generation))
            return;

        CancellationToken refreshWaitToken;
        lock (_lifecycleGate)
        {
            if (_disposed || generation != _generation)
                return;
            refreshWaitToken = _refreshGeneration.Token;
            _activeGenerationUsers++;
        }

        bool lockTaken = false;
        try
        {
            await _refreshLock.WaitAsync(refreshWaitToken);
            lockTaken = true;

            RuntimeState currentState = _state;
            if (!IsCurrentGeneration(generation) || !currentState.Config.Enable || currentState.Config.RefreshSeconds <= 0)
                return;

            AppConfig currentConfig = currentState.Config;
            RewriteRule[] nextRules = await LoadRulesAsync(currentConfig, refreshWaitToken);

            lock (_lifecycleGate)
            {
                if (_disposed || generation != _generation || !ReferenceEquals(currentState, _state))
                    return;

                _state = new RuntimeState(currentConfig, nextRules);
            }

            _dnsServer?.WriteLog($"Remote Rewrite App refreshed {nextRules.Length} rule(s) from {currentConfig.EnabledSourceCount} enabled source(s).");
            ScheduleRefresh(currentConfig.RefreshSeconds, generation);
        }
        finally
        {
            if (lockTaken)
                _refreshLock.Release();
            RetireCompletedGenerationUser();
        }
    }

    static async Task<RewriteRule[]> LoadRulesAsync(AppConfig config, CancellationToken cancellationToken)
    {
        List<RewriteRule> rules = new List<RewriteRule>();
        RuleParseBudget budget = new RuleParseBudget();
        int order = 0;

        foreach (SourceConfig source in config.Sources)
        {
            if (!source.Enable)
                continue;

            cancellationToken.ThrowIfCancellationRequested();
            string content = string.IsNullOrWhiteSpace(source.Text)
                ? await DownloadSourceAsync(source.Url, config.AllowPrivateNetworkSources, cancellationToken)
                : source.Text;

            if (string.IsNullOrWhiteSpace(content))
                throw new FormatException($"Source '{source.Name}' returned no content.");

            int ruleCountBeforeSource = budget.RuleCount;

            switch (source.Format)
            {
                case SourceFormat.AdGuardFilter:
                    rules.AddRange(RuleParser.ParseAdGuardFilterSource(source, content, ref order, budget));
                    break;

                case SourceFormat.RewriteRulesJson:
                    rules.AddRange(RuleParser.ParseRewriteRulesJsonSource(source, content, ref order, budget));
                    break;
            }

            if (budget.RuleCount == ruleCountBeforeSource)
                throw new FormatException($"Source '{source.Name}' produced no valid rewrite rules.");
        }

        if (rules.Count > AppLimits.MaxRules)
            throw new FormatException($"Configured sources produced {rules.Count} rules; the limit is {AppLimits.MaxRules}.");

        return rules.ToArray();
    }

    static async Task<string> DownloadSourceAsync(string url, bool allowPrivateNetworkSources, CancellationToken cancellationToken)
    {
        if (!Uri.TryCreate(url, UriKind.Absolute, out Uri uri))
            throw new InvalidOperationException("Source URL must be an absolute URL.");

        if ((uri.Scheme != Uri.UriSchemeHttp) && (uri.Scheme != Uri.UriSchemeHttps))
            throw new InvalidOperationException("Source URL must use http or https.");

        using CancellationTokenSource timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        timeout.CancelAfter(AppLimits.SourceTimeout);

        HttpClient http = allowPrivateNetworkSources ? _privateNetworkSourceHttp : _publicSourceHttp;
        using HttpRequestMessage request = new HttpRequestMessage(HttpMethod.Get, uri);
        using HttpResponseMessage response = await http.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, timeout.Token);
        if (response.StatusCode != HttpStatusCode.OK)
            throw new HttpRequestException($"Source returned HTTP {(int)response.StatusCode}; exactly 200 OK is required.");

        string mediaType = response.Content.Headers.ContentType?.MediaType;
        if (mediaType is not null && (mediaType.Equals("text/html", StringComparison.OrdinalIgnoreCase)
            || mediaType.Equals("application/xhtml+xml", StringComparison.OrdinalIgnoreCase)))
        {
            throw new InvalidOperationException("Source returned HTML instead of rewrite data.");
        }

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
        using StreamReader reader = new StreamReader(buffer, new UTF8Encoding(encoderShouldEmitUTF8Identifier: false, throwOnInvalidBytes: true));
        string content = await reader.ReadToEndAsync(timeout.Token);
        string prefix = content.TrimStart();
        if (prefix.StartsWith("<!doctype html", StringComparison.OrdinalIgnoreCase)
            || prefix.StartsWith("<html", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException("Source returned HTML instead of rewrite data.");
        }

        return content;
    }

    Task<DnsDatagram> ProcessRequestCoreAsync(
        DnsDatagram request,
        IPEndPoint remoteEP,
        bool isRecursionAllowed,
        uint appRecordTtl,
        AppRecordEffectiveOptions options,
        RuntimeState state)
    {
        if (!IsSupportedRequest(request))
            return Task.FromResult<DnsDatagram>(null);

        DnsQuestionRecord question = request.Question[0];
        string qname = NormalizeQname(question.Name);
        HashSet<string> resolvedGroups = state.Config.SplitHorizon.ResolveGroups(qname, remoteEP?.Address);

        if (!options.MatchesGroups(resolvedGroups))
            return Task.FromResult<DnsDatagram>(null);

        RewriteMatch match = RuleMatcher.Match(
            options.InlineRules,
            state.RuleSet.GetCandidates(qname, question.Type, options.SourceNames, resolvedGroups),
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

    void ScheduleRefresh(int delaySeconds, long generation)
    {
        Timer previousTimer;

        lock (_lifecycleGate)
        {
            if (_disposed || generation != _generation)
                return;

            previousTimer = _refreshTimer;
            _refreshTimer = delaySeconds > 0
                ? new Timer(RefreshTimerCallback, generation, TimeSpan.FromSeconds(delaySeconds), Timeout.InfiniteTimeSpan)
                : null;
        }

        previousTimer?.Dispose();
    }

    bool IsCurrentGeneration(long generation)
    {
        lock (_lifecycleGate)
            return !_disposed && generation == _generation;
    }

    internal long CurrentGeneration
    {
        get
        {
            lock (_lifecycleGate)
                return _generation;
        }
    }

    void RetireCompletedGenerationUser()
    {
        bool disposeLifetime = false;

        lock (_lifecycleGate)
        {
            _activeGenerationUsers--;
            if (_activeGenerationUsers == 0
                && _retiredRefreshGenerations.Count > 0
                && (!_disposed || _disposeCancellationIssued))
            {
                CancellationTokenSource[] completed = _retiredRefreshGenerations.ToArray();
                _retiredRefreshGenerations.Clear();
                foreach (CancellationTokenSource source in completed)
                    source.Dispose();
            }

            if (_disposed
                && _disposeCancellationIssued
                && _activeGenerationUsers == 0
                && !_lifetimeDisposed)
            {
                _lifetimeDisposed = true;
                disposeLifetime = true;
            }
        }

        if (disposeLifetime)
            _lifetime.Dispose();
    }

    void FinishDisposeCancellation()
    {
        bool disposeLifetime = false;

        lock (_lifecycleGate)
        {
            _disposeCancellationIssued = true;
            if (_activeGenerationUsers == 0 && _retiredRefreshGenerations.Count > 0)
            {
                CancellationTokenSource[] completed = _retiredRefreshGenerations.ToArray();
                _retiredRefreshGenerations.Clear();
                foreach (CancellationTokenSource source in completed)
                    source.Dispose();
            }

            if (_activeGenerationUsers == 0 && !_lifetimeDisposed)
            {
                _lifetimeDisposed = true;
                disposeLifetime = true;
            }
        }

        if (disposeLifetime)
            _lifetime.Dispose();
    }

    static HttpClient CreateSourceHttpClient(bool allowPrivateNetworkSources)
    {
        SocketsHttpHandler handler = new SocketsHttpHandler
        {
            AllowAutoRedirect = false,
            UseCookies = false,
            UseProxy = false,
            Credentials = null,
            PreAuthenticate = false,
            AutomaticDecompression = DecompressionMethods.None,
            ConnectTimeout = TimeSpan.FromSeconds(5),
            PooledConnectionLifetime = TimeSpan.FromMinutes(1),
            PooledConnectionIdleTimeout = TimeSpan.FromSeconds(30),
            ResponseDrainTimeout = TimeSpan.FromSeconds(2),
            MaxConnectionsPerServer = 4,
            MaxResponseHeadersLength = 16,
            SslOptions = new SslClientAuthenticationOptions
            {
                CertificateRevocationCheckMode = X509RevocationMode.Online
            },
            ConnectCallback = (context, cancellationToken) => ConnectToSourceAsync(
                context.DnsEndPoint,
                allowPrivateNetworkSources,
                cancellationToken)
        };

        return new HttpClient(handler, disposeHandler: true)
        {
            Timeout = Timeout.InfiniteTimeSpan
        };
    }

    static async ValueTask<Stream> ConnectToSourceAsync(
        DnsEndPoint endpoint,
        bool allowPrivateNetworkSources,
        CancellationToken cancellationToken)
    {
        IPAddress[] addresses = await Dns.GetHostAddressesAsync(endpoint.Host, cancellationToken);
        Exception lastError = null;
        int attempted = 0;

        foreach (IPAddress address in addresses)
        {
            cancellationToken.ThrowIfCancellationRequested();

            if (!allowPrivateNetworkSources && SourceNetworkPolicy.IsBlockedByDefault(address))
                continue;

            if (++attempted > 16)
                break;

            Socket socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp)
            {
                NoDelay = true
            };

            try
            {
                await socket.ConnectAsync(new IPEndPoint(address, endpoint.Port), cancellationToken);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception ex) when (ex is SocketException or IOException)
            {
                lastError = ex;
                socket.Dispose();
            }
            catch
            {
                socket.Dispose();
                throw;
            }
        }

        if (lastError is not null)
            throw new HttpRequestException("Unable to connect to an allowed source address.", lastError);

        throw new HttpRequestException("Source host did not resolve to an allowed public address.");
    }

    static string NormalizeQname(string qname)
    {
        return qname?.Trim().TrimEnd('.').ToLowerInvariant() ?? string.Empty;
    }

    static bool IsSupportedRequest(DnsDatagram request)
    {
        return request is not null
            && !request.IsResponse
            && request.OPCODE == DnsOpcode.StandardQuery
            && request.Question is not null
            && request.Question.Count == 1
            && request.Question[0].Class == DnsClass.IN
            && IsSupportedQuestionType(request.Question[0].Type);
    }

    static bool IsSupportedQuestionType(DnsResourceRecordType type)
    {
        return type is not (DnsResourceRecordType.AXFR or DnsResourceRecordType.IXFR);
    }

    static DnsDatagram BuildErrorResponse(DnsDatagram request, bool isRecursionAllowed, DnsResponseCode responseCode)
    {
        return new DnsDatagram(
            request.Identifier,
            true,
            DnsOpcode.StandardQuery,
            true,
            false,
            request.RecursionDesired,
            isRecursionAllowed,
            false,
            request.CheckingDisabled,
            responseCode,
            request.Question);
    }

    sealed class RuntimeState
    {
        public static readonly RuntimeState Empty = new RuntimeState(AppConfig.Empty, Array.Empty<RewriteRule>());

        public RuntimeState(AppConfig config, RewriteRule[] rules)
        {
            Config = config;
            Rules = rules;
            RuleSet = new RuleSet(rules);
        }

        public AppConfig Config { get; }
        public RewriteRule[] Rules { get; }
        public RuleSet RuleSet { get; }
    }
}
