using System.Net;
using RemoteRewrite;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace RemoteRewriteApp.Tests;

public sealed class LifecycleTests
{
    [Fact]
    public async Task FailedReloadKeepsPreviousConfigAndRulesActive()
    {
        App app = new App();
        await app.InitializeAsync(null!, """
{
  "globalMode": true,
  "refreshSeconds": 300,
  "sources": [
    {
      "name": "inline",
      "format": "adguard-filter",
      "text": "||stable.example^$dnsrewrite=192.0.2.10"
    }
  ]
}
""");
        long generationBeforeFailure = app.CurrentGeneration;

        await Assert.ThrowsAnyAsync<Exception>(() => app.InitializeAsync(null!, """
{
  "globalMode": false,
  "allowInsecureHttp": true,
  "allowPrivateNetworkSources": true,
  "sources": [
    {
      "name": "unavailable",
      "format": "adguard-filter",
      "url": "http://127.0.0.1:1/dns.txt"
    }
  ]
}
"""));
        Assert.True(app.CurrentGeneration > generationBeforeFailure);
        await app.RefreshCurrentRulesAsync(app.CurrentGeneration);

        DnsDatagram? response = await app.ProcessRequestAsync(
            CreateRequest("stable.example", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Loopback, 5300),
            DnsTransportProtocol.Udp,
            true);

        Assert.NotNull(response);
        DnsARecordData answer = Assert.IsType<DnsARecordData>(Assert.Single(response!.Answer).RDATA);
        Assert.Equal(IPAddress.Parse("192.0.2.10"), answer.Address);

        app.Dispose();
    }

    [Fact]
    public async Task DisposeIsIdempotentAndStopsRequestHandling()
    {
        App app = new App();
        await app.InitializeAsync(null!, """{ "enable": false }""");

        app.Dispose();
        app.Dispose();

        DnsDatagram? response = await app.ProcessRequestAsync(
            CreateRequest("service.example", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Loopback, 5300),
            DnsTransportProtocol.Udp,
            true);

        Assert.Null(response);
    }

    [Fact]
    public async Task StaleGenerationRefreshCannotReplaceReloadedRules()
    {
        App app = new App();
        await app.InitializeAsync(null!, """
{
  "globalMode": true,
  "refreshSeconds": 300,
  "sources": [
    {
      "name": "first",
      "format": "adguard-filter",
      "text": "||first.example^$dnsrewrite=192.0.2.10"
    }
  ]
}
""");
        long staleGeneration = app.CurrentGeneration;

        await app.InitializeAsync(null!, """
{
  "globalMode": true,
  "refreshSeconds": 300,
  "sources": [
    {
      "name": "second",
      "format": "adguard-filter",
      "text": "||second.example^$dnsrewrite=198.51.100.10"
    }
  ]
}
""");

        await app.RefreshCurrentRulesAsync(staleGeneration);

        DnsDatagram? staleResponse = await app.ProcessRequestAsync(
            CreateRequest("first.example", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Loopback, 5300),
            DnsTransportProtocol.Udp,
            true);
        DnsDatagram? currentResponse = await app.ProcessRequestAsync(
            CreateRequest("second.example", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Loopback, 5300),
            DnsTransportProtocol.Udp,
            true);

        Assert.Null(staleResponse);
        Assert.NotNull(currentResponse);
        app.Dispose();
    }

    [Fact]
    public async Task DisposeRevokesGenerationAndStaleRefreshIsANoOp()
    {
        App app = new App();
        await app.InitializeAsync(null!, """{ "enable": true, "refreshSeconds": 300, "sources": [] }""");
        long staleGeneration = app.CurrentGeneration;

        app.Dispose();
        await app.RefreshCurrentRulesAsync(staleGeneration);

        await Assert.ThrowsAsync<ObjectDisposedException>(() => app.InitializeAsync(null!, """{ "enable": false }"""));
    }

    [Fact]
    public async Task NewInitializationSupersedesAnOlderInitializationWaitingForTheRefreshLock()
    {
        App app = new App();
        SemaphoreSlim refreshLock = GetRefreshLock(app);
        await refreshLock.WaitAsync();

        Task firstInitialization = app.InitializeAsync(null!, """
{
  "globalMode": true,
  "refreshSeconds": 300,
  "sources": [{
    "name": "first",
    "format": "adguard-filter",
    "text": "||first.example^$dnsrewrite=192.0.2.10"
  }]
}
""");
        await WaitForGenerationAsync(app, 1);

        Task secondInitialization = app.InitializeAsync(null!, """
{
  "globalMode": true,
  "refreshSeconds": 300,
  "sources": [{
    "name": "second",
    "format": "adguard-filter",
    "text": "||second.example^$dnsrewrite=198.51.100.10"
  }]
}
""");
        await WaitForGenerationAsync(app, 2);
        refreshLock.Release();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => firstInitialization);
        await secondInitialization;

        Assert.Null(await app.ProcessRequestAsync(
            CreateRequest("first.example", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Loopback, 5300),
            DnsTransportProtocol.Udp,
            true));
        Assert.NotNull(await app.ProcessRequestAsync(
            CreateRequest("second.example", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Loopback, 5300),
            DnsTransportProtocol.Udp,
            true));

        app.Dispose();
    }

    [Fact]
    public async Task RepeatedInitializationAndDisposeDoesNotRaceCanceledGenerationTokens()
    {
        App app = new App();

        for (int index = 0; index < 100; index++)
        {
            await app.InitializeAsync(null!, $$"""
            {
              "globalMode": true,
              "refreshSeconds": 300,
              "sources": [{
                "name": "inline",
                "format": "adguard-filter",
                "text": "||service.example^$dnsrewrite=192.0.2.{{(index % 200) + 1}}"
              }]
            }
            """);
        }

        int retiredCount = Assert.IsAssignableFrom<System.Collections.ICollection>(typeof(App)
            .GetField("_retiredRefreshGenerations", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(app)).Count;
        Assert.Equal(0, retiredCount);

        app.Dispose();
        app.Dispose();
    }

    [Fact]
    public async Task DisposeCancelsAQueuedInitializationBeforeDisposingItsToken()
    {
        App app = new App();
        SemaphoreSlim refreshLock = GetRefreshLock(app);
        await refreshLock.WaitAsync();

        Task initialization = app.InitializeAsync(null!, """{ "enable": false }""");
        await WaitForGenerationAsync(app, 1);

        app.Dispose();
        refreshLock.Release();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => initialization);

        int retiredCount = Assert.IsAssignableFrom<System.Collections.ICollection>(typeof(App)
            .GetField("_retiredRefreshGenerations", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(app)).Count;
        bool lifetimeDisposed = Assert.IsType<bool>(typeof(App)
            .GetField("_lifetimeDisposed", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(app));
        Assert.Equal(0, retiredCount);
        Assert.True(lifetimeDisposed);
    }

    [Fact]
    public async Task DisposeWaitsForCancellationPhaseBeforeReclaimingGenerationTokens()
    {
        App app = new App();
        SemaphoreSlim refreshLock = GetRefreshLock(app);
        CancellationTokenSource lifetime = Assert.IsType<CancellationTokenSource>(typeof(App)
            .GetField("_lifetime", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(app));
        TaskCompletionSource cancellationPaused = new(TaskCreationOptions.RunContinuationsAsynchronously);
        TaskCompletionSource resumeCancellation = new(TaskCreationOptions.RunContinuationsAsynchronously);

        await refreshLock.WaitAsync();
        using CancellationTokenRegistration registration = lifetime.Token.Register(() =>
        {
            cancellationPaused.TrySetResult();
            resumeCancellation.Task.GetAwaiter().GetResult();
        });

        Task initialization = app.InitializeAsync(null!, """{ "enable": false }""");
        await WaitForGenerationAsync(app, 1);
        Task disposal = Task.Run(app.Dispose);

        try
        {
            await cancellationPaused.Task.WaitAsync(TimeSpan.FromSeconds(2));
            await Assert.ThrowsAnyAsync<OperationCanceledException>(async () =>
                await initialization.WaitAsync(TimeSpan.FromSeconds(2)));

            int retiredDuringCancellation = Assert.IsAssignableFrom<System.Collections.ICollection>(typeof(App)
                .GetField("_retiredRefreshGenerations", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
                .GetValue(app)).Count;
            bool cancellationIssued = Assert.IsType<bool>(typeof(App)
                .GetField("_disposeCancellationIssued", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
                .GetValue(app));
            bool lifetimeDisposedDuringCancellation = Assert.IsType<bool>(typeof(App)
                .GetField("_lifetimeDisposed", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
                .GetValue(app));

            Assert.True(retiredDuringCancellation > 0);
            Assert.False(cancellationIssued);
            Assert.False(lifetimeDisposedDuringCancellation);
        }
        finally
        {
            resumeCancellation.TrySetResult();
            refreshLock.Release();
        }

        await disposal.WaitAsync(TimeSpan.FromSeconds(2));
        Assert.Empty(Assert.IsAssignableFrom<System.Collections.IEnumerable>(typeof(App)
            .GetField("_retiredRefreshGenerations", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(app)));
        Assert.True(Assert.IsType<bool>(typeof(App)
            .GetField("_disposeCancellationIssued", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(app)));
        Assert.True(Assert.IsType<bool>(typeof(App)
            .GetField("_lifetimeDisposed", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(app)));
    }

    static SemaphoreSlim GetRefreshLock(App app)
    {
        return Assert.IsType<SemaphoreSlim>(typeof(App)
            .GetField("_refreshLock", System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)!
            .GetValue(app));
    }

    static async Task WaitForGenerationAsync(App app, long generation)
    {
        using CancellationTokenSource timeout = new CancellationTokenSource(TimeSpan.FromSeconds(2));
        while (app.CurrentGeneration < generation)
            await Task.Delay(1, timeout.Token);
    }

    static DnsDatagram CreateRequest(string name, DnsResourceRecordType type)
    {
        return new DnsDatagram(
            0x2200,
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
