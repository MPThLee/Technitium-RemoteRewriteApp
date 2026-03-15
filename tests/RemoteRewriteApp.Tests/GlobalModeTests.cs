using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using RemoteRewrite;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace RemoteRewriteApp.Tests;

public sealed class GlobalModeTests
{
    [Fact]
    public async Task ProcessRequestAsync_GlobalModeRewritesWithoutAppRecord()
    {
        await using TestHttpSource source = await TestHttpSource.StartAsync("""
{
  "rules": [
    {
      "matchType": "suffix",
      "pattern": "scpslgame.com",
      "answers": [{ "type": "A", "value": "104.16.181.45" }]
    }
  ]
}
""", "application/json");

        App app = new App();
        await app.InitializeAsync(null!, JsonSerializer.Serialize(new
        {
            enable = true,
            globalMode = true,
            defaultTtl = 300,
            refreshSeconds = 300,
            sources = new[]
            {
                new
                {
                    name = "greenlist-json",
                    enable = true,
                    format = "rewrite-rules-json",
                    url = source.Url
                }
            }
        }));

        DnsDatagram? response = await app.ProcessRequestAsync(
            CreateRequest("scpslgame.com", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 5300),
            DnsTransportProtocol.Udp,
            true);

        Assert.NotNull(response);
        DnsARecordData answer = Assert.IsType<DnsARecordData>(Assert.Single(response!.Answer).RDATA);
        Assert.Equal(IPAddress.Parse("104.16.181.45"), answer.Address);

        app.Dispose();
    }

    [Fact]
    public async Task ProcessRequestAsync_GlobalModeAppliesSplitHorizonGroups()
    {
        await using TestHttpSource source = await TestHttpSource.StartAsync("""
{
  "rules": [
    {
      "matchType": "suffix",
      "pattern": "service.example",
      "answers": [{ "type": "A", "value": "10.0.0.10" }],
      "groupNames": ["private"]
    },
    {
      "matchType": "suffix",
      "pattern": "service.example",
      "answers": [{ "type": "A", "value": "198.51.100.10" }],
      "groupNames": ["public"]
    }
  ]
}
""", "application/json");

        App app = new App();
        await app.InitializeAsync(null!, JsonSerializer.Serialize(new
        {
            enable = true,
            globalMode = true,
            defaultTtl = 300,
            refreshSeconds = 300,
            splitHorizon = new
            {
                enable = true,
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
            new IPEndPoint(IPAddress.Parse("10.0.0.25"), 5300),
            DnsTransportProtocol.Udp,
            true);

        DnsDatagram? publicResponse = await app.ProcessRequestAsync(
            CreateRequest("service.example", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Parse("203.0.113.25"), 5300),
            DnsTransportProtocol.Udp,
            true);

        Assert.Equal(IPAddress.Parse("10.0.0.10"), Assert.IsType<DnsARecordData>(Assert.Single(privateResponse!.Answer).RDATA).Address);
        Assert.Equal(IPAddress.Parse("198.51.100.10"), Assert.IsType<DnsARecordData>(Assert.Single(publicResponse!.Answer).RDATA).Address);

        app.Dispose();
    }

    [Fact]
    public async Task ProcessRequestAsync_GlobalModeDisabledFallsThrough()
    {
        await using TestHttpSource source = await TestHttpSource.StartAsync("""
{
  "rules": [
    {
      "matchType": "suffix",
      "pattern": "scpslgame.com",
      "answers": [{ "type": "A", "value": "104.16.181.45" }]
    }
  ]
}
""", "application/json");

        App app = new App();
        await app.InitializeAsync(null!, JsonSerializer.Serialize(new
        {
            enable = true,
            globalMode = false,
            defaultTtl = 300,
            refreshSeconds = 300,
            sources = new[]
            {
                new
                {
                    name = "greenlist-json",
                    enable = true,
                    format = "rewrite-rules-json",
                    url = source.Url
                }
            }
        }));

        DnsDatagram? response = await app.ProcessRequestAsync(
            CreateRequest("scpslgame.com", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Parse("203.0.113.10"), 5300),
            DnsTransportProtocol.Udp,
            true);

        Assert.Null(response);

        app.Dispose();
    }

    static DnsDatagram CreateRequest(string name, DnsResourceRecordType type)
    {
        return new DnsDatagram(
            0x1000,
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

        public static Task<TestHttpSource> StartAsync(string content, string contentType)
        {
            TcpListener tcp = new TcpListener(IPAddress.Loopback, 0);
            tcp.Start();
            int port = ((IPEndPoint)tcp.LocalEndpoint).Port;
            tcp.Stop();

            string url = $"http://127.0.0.1:{port}/";
            HttpListener listener = new HttpListener();
            listener.Prefixes.Add(url);
            listener.Start();

            CancellationTokenSource cts = new CancellationTokenSource();
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

                    byte[] body = Encoding.UTF8.GetBytes(content);
                    context.Response.ContentType = contentType;
                    context.Response.ContentLength64 = body.Length;
                    await context.Response.OutputStream.WriteAsync(body, 0, body.Length);
                    context.Response.OutputStream.Close();
                }
            });

            return Task.FromResult(new TestHttpSource(listener, cts, serveTask, url));
        }

        public async ValueTask DisposeAsync()
        {
            _cts.Cancel();
            _listener.Close();

            try
            {
                await _serveTask;
            }
            catch
            {
                // ignore disposal races in tests
            }

            _cts.Dispose();
        }
    }
}
