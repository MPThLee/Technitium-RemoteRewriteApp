using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using RemoteRewrite;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace RemoteRewriteApp.Tests;

public sealed class AppRequestTests
{
    [Fact]
    public async Task ProcessRequestAsync_ReturnsARecordForSuffixRewrite()
    {
        await using TestHttpSource source = await TestHttpSource.StartAsync("""
||service.example^$dnsrewrite=192.0.2.10
""", "text/plain");

        App app = new App();
        await app.InitializeAsync(null!, JsonSerializer.Serialize(new
        {
            enable = true,
            defaultTtl = 300,
            refreshSeconds = 300,
            sources = new[]
            {
                new
                {
                    name = "remote-dns",
                    enable = true,
                    format = "adguard-filter",
                    url = source.Url
                }
            }
        }));

        DnsDatagram request = CreateRequest("service.example", DnsResourceRecordType.A);
        DnsDatagram? response = await app.ProcessRequestAsync(
            request,
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 5300),
            DnsTransportProtocol.Udp,
            true,
            "example",
            "*.example",
            120,
            """
{
  "enable": true,
  "sourceNames": [],
  "groupNames": [],
  "overrideTtl": null
}
""");

        Assert.NotNull(response);
        Assert.Single(response!.Answer);
        DnsARecordData data = Assert.IsType<DnsARecordData>(response.Answer[0].RDATA);
        Assert.Equal(IPAddress.Parse("192.0.2.10"), data.Address);

        app.Dispose();
    }

    [Fact]
    public async Task ProcessRequestAsync_HonorsSourceNameFilter()
    {
        await using TestHttpSource sourceA = await TestHttpSource.StartAsync("""
||service.example^$dnsrewrite=192.0.2.10
""", "text/plain");
        await using TestHttpSource sourceB = await TestHttpSource.StartAsync("""
||service.example^$dnsrewrite=198.51.100.10
""", "text/plain");

        App app = new App();
        await app.InitializeAsync(null!, JsonSerializer.Serialize(new
        {
            enable = true,
            defaultTtl = 300,
            refreshSeconds = 300,
            sources = new object[]
            {
                new
                {
                    name = "source-a",
                    enable = true,
                    format = "adguard-filter",
                    url = sourceA.Url
                },
                new
                {
                    name = "source-b",
                    enable = true,
                    format = "adguard-filter",
                    url = sourceB.Url
                }
            }
        }));

        DnsDatagram? response = await app.ProcessRequestAsync(
            CreateRequest("service.example", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 5300),
            DnsTransportProtocol.Udp,
            true,
            "example",
            "*.example",
            120,
            """
{
  "enable": true,
  "sourceNames": ["source-b"],
  "groupNames": [],
  "overrideTtl": null
}
""");

        DnsARecordData data = Assert.IsType<DnsARecordData>(Assert.Single(response!.Answer).RDATA);
        Assert.Equal(IPAddress.Parse("198.51.100.10"), data.Address);

        app.Dispose();
    }

    [Fact]
    public async Task ProcessRequestAsync_HonorsSplitHorizonGroups()
    {
        await using TestHttpSource source = await TestHttpSource.StartAsync("""
{
  "rules": [
    {
      "matchType": "suffix",
      "pattern": "service.example",
      "answers": [{ "type": "A", "value": "198.51.100.20" }],
      "groupNames": ["private"]
    },
    {
      "matchType": "suffix",
      "pattern": "service.example",
      "answers": [{ "type": "A", "value": "192.0.2.20" }],
      "groupNames": ["public"]
    }
  ]
}
""", "application/json");

        App app = new App();
        await app.InitializeAsync(null!, JsonSerializer.Serialize(new
        {
            enable = true,
            defaultTtl = 300,
            refreshSeconds = 300,
            splitHorizon = new
            {
                enable = true,
                defaultGroupName = "default",
                privateGroupName = "private",
                publicGroupName = "public"
            },
            sources = new[]
            {
                new
                {
                    name = "remote-manifest",
                    enable = true,
                    format = "rewrite-rules-json",
                    url = source.Url
                }
            }
        }));

        DnsDatagram? privateResponse = await app.ProcessRequestAsync(
            CreateRequest("service.example", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Parse("10.0.0.10"), 5300),
            DnsTransportProtocol.Udp,
            true,
            "example",
            "*.example",
            120,
            """
{
  "enable": true,
  "sourceNames": [],
  "groupNames": [],
  "overrideTtl": null
}
""");

        DnsDatagram? publicResponse = await app.ProcessRequestAsync(
            CreateRequest("service.example", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 5300),
            DnsTransportProtocol.Udp,
            true,
            "example",
            "*.example",
            120,
            """
{
  "enable": true,
  "sourceNames": [],
  "groupNames": [],
  "overrideTtl": null
}
""");

        Assert.Equal(IPAddress.Parse("198.51.100.20"), Assert.IsType<DnsARecordData>(Assert.Single(privateResponse!.Answer).RDATA).Address);
        Assert.Equal(IPAddress.Parse("192.0.2.20"), Assert.IsType<DnsARecordData>(Assert.Single(publicResponse!.Answer).RDATA).Address);

        app.Dispose();
    }

    [Fact]
    public async Task ProcessRequestAsync_RespectsRequestedGroupFilter()
    {
        await using TestHttpSource source = await TestHttpSource.StartAsync("""
{
  "rules": [
    {
      "matchType": "suffix",
      "pattern": "service.example",
      "answers": [{ "type": "A", "value": "198.51.100.20" }],
      "groupNames": ["private"]
    }
  ]
}
""", "application/json");

        App app = new App();
        await app.InitializeAsync(null!, JsonSerializer.Serialize(new
        {
            enable = true,
            defaultTtl = 300,
            refreshSeconds = 300,
            splitHorizon = new
            {
                enable = true,
                defaultGroupName = "default",
                privateGroupName = "private",
                publicGroupName = "public"
            },
            sources = new[]
            {
                new
                {
                    name = "remote-manifest",
                    enable = true,
                    format = "rewrite-rules-json",
                    url = source.Url
                }
            }
        }));

        DnsDatagram? response = await app.ProcessRequestAsync(
            CreateRequest("service.example", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Parse("10.0.0.10"), 5300),
            DnsTransportProtocol.Udp,
            true,
            "example",
            "*.example",
            120,
            """
{
  "enable": true,
  "sourceNames": [],
  "groupNames": ["public"],
  "overrideTtl": null
}
""");

        Assert.Null(response);

        app.Dispose();
    }

    [Fact]
    public async Task ProcessRequestAsync_ReturnsNullOutsideZoneOrScope()
    {
        await using TestHttpSource source = await TestHttpSource.StartAsync("""
||service.example^$dnsrewrite=192.0.2.10
""", "text/plain");

        App app = new App();
        await app.InitializeAsync(null!, JsonSerializer.Serialize(new
        {
            enable = true,
            defaultTtl = 300,
            refreshSeconds = 300,
            sources = new[]
            {
                new
                {
                    name = "remote-dns",
                    enable = true,
                    format = "adguard-filter",
                    url = source.Url
                }
            }
        }));

        DnsDatagram request = CreateRequest("service.example", DnsResourceRecordType.A);

        DnsDatagram? wrongZone = await app.ProcessRequestAsync(
            request,
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 5300),
            DnsTransportProtocol.Udp,
            true,
            "other",
            "*.example",
            120,
            """{"enable":true,"sourceNames":[],"groupNames":[],"overrideTtl":null}""");

        DnsDatagram? wrongScope = await app.ProcessRequestAsync(
            request,
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 5300),
            DnsTransportProtocol.Udp,
            true,
            "example",
            "other.example",
            120,
            """{"enable":true,"sourceNames":[],"groupNames":[],"overrideTtl":null}""");

        Assert.Null(wrongZone);
        Assert.Null(wrongScope);

        app.Dispose();
    }

    [Fact]
    public async Task ProcessRequestAsync_ReturnsNullWhenQuestionTypeDoesNotMatchAnswerType()
    {
        await using TestHttpSource source = await TestHttpSource.StartAsync("""
||service.example^$dnsrewrite=192.0.2.10
""", "text/plain");

        App app = new App();
        await app.InitializeAsync(null!, JsonSerializer.Serialize(new
        {
            enable = true,
            defaultTtl = 300,
            refreshSeconds = 300,
            sources = new[]
            {
                new
                {
                    name = "remote-dns",
                    enable = true,
                    format = "adguard-filter",
                    url = source.Url
                }
            }
        }));

        DnsDatagram? response = await app.ProcessRequestAsync(
            CreateRequest("service.example", DnsResourceRecordType.AAAA),
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 5300),
            DnsTransportProtocol.Udp,
            true,
            "example",
            "*.example",
            120,
            """{"enable":true,"sourceNames":[],"groupNames":[],"overrideTtl":null}""");

        Assert.Null(response);

        app.Dispose();
    }

    [Fact]
    public async Task ProcessRequestAsync_AppliesOverrideTtl()
    {
        await using TestHttpSource source = await TestHttpSource.StartAsync("""
||service.example^$dnsrewrite=192.0.2.10
""", "text/plain");

        App app = new App();
        await app.InitializeAsync(null!, JsonSerializer.Serialize(new
        {
            enable = true,
            defaultTtl = 300,
            refreshSeconds = 300,
            sources = new[]
            {
                new
                {
                    name = "remote-dns",
                    enable = true,
                    format = "adguard-filter",
                    url = source.Url
                }
            }
        }));

        DnsDatagram? response = await app.ProcessRequestAsync(
            CreateRequest("service.example", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 5300),
            DnsTransportProtocol.Udp,
            true,
            "example",
            "*.example",
            120,
            """{"enable":true,"sourceNames":[],"groupNames":[],"overrideTtl":45}""");

        Assert.NotNull(response);
        Assert.Equal<uint>(45, response!.Answer[0].TTL);

        app.Dispose();
    }

    static DnsDatagram CreateRequest(string name, DnsResourceRecordType type)
    {
        return new DnsDatagram(
            1,
            false,
            DnsOpcode.StandardQuery,
            false,
            false,
            true,
            false,
            false,
            false,
            DnsResponseCode.NoError,
            [new DnsQuestionRecord(name, type, DnsClass.IN)]
        );
    }

    sealed class TestHttpSource : IAsyncDisposable
    {
        readonly HttpListener _listener;
        readonly CancellationTokenSource _cts;
        readonly Task _serveTask;

        TestHttpSource(HttpListener listener, CancellationTokenSource cts, Task serveTask, string url)
        {
            _listener = listener;
            _cts = cts;
            _serveTask = serveTask;
            Url = url;
        }

        public string Url { get; }

        public static async Task<TestHttpSource> StartAsync(string content, string contentType)
        {
            int port = GetFreePort();
            string url = $"http://127.0.0.1:{port}/source";

            HttpListener listener = new HttpListener();
            listener.Prefixes.Add($"http://127.0.0.1:{port}/");
            listener.Start();

            CancellationTokenSource cts = new CancellationTokenSource();
            byte[] payload = Encoding.UTF8.GetBytes(content);

            Task serveTask = Task.Run(async () =>
            {
                while (!cts.IsCancellationRequested)
                {
                    HttpListenerContext context;

                    try
                    {
                        context = await listener.GetContextAsync();
                    }
                    catch (HttpListenerException)
                    {
                        break;
                    }
                    catch (ObjectDisposedException)
                    {
                        break;
                    }

                    context.Response.ContentType = contentType;
                    context.Response.ContentLength64 = payload.Length;
                    await context.Response.OutputStream.WriteAsync(payload, 0, payload.Length);
                    context.Response.OutputStream.Close();
                }
            }, cts.Token);

            await Task.Yield();
            return new TestHttpSource(listener, cts, serveTask, url);
        }

        public async ValueTask DisposeAsync()
        {
            _cts.Cancel();
            _listener.Stop();
            _listener.Close();

            try
            {
                await _serveTask;
            }
            catch
            {
            }

            _cts.Dispose();
        }

        static int GetFreePort()
        {
            using TcpListener listener = new TcpListener(IPAddress.Loopback, 0);
            listener.Start();
            return ((IPEndPoint)listener.LocalEndpoint).Port;
        }
    }
}
