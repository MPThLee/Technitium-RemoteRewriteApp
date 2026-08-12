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
  "refreshSeconds": 0,
  "sources": [
    {
      "name": "inline",
      "format": "adguard-filter",
      "text": "||stable.example^$dnsrewrite=192.0.2.10"
    }
  ]
}
""");

        await Assert.ThrowsAnyAsync<Exception>(() => app.InitializeAsync(null!, """
{
  "globalMode": false,
  "sources": [
    {
      "name": "unavailable",
      "format": "adguard-filter",
      "url": "http://127.0.0.1:1/dns.txt"
    }
  ]
}
"""));

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
