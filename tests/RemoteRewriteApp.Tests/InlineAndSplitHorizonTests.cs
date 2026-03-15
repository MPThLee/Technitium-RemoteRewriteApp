using System.Net;
using System.Text.Json;
using RemoteRewrite;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using Xunit;

namespace RemoteRewriteApp.Tests;

public sealed class InlineAndSplitHorizonTests
{
    [Fact]
    public void AppConfig_ParseSupportsInlineSourceAndAppPreference()
    {
        AppConfig config = AppConfig.Parse("""
{
  "appPreference": 90,
  "enable": true,
  "defaultTtl": 300,
  "refreshSeconds": 300,
  "sources": [
    {
      "name": "inline-source",
      "enable": true,
      "format": "adguard-filter",
      "text": "||service.example^$dnsrewrite=192.0.2.10"
    }
  ]
}
""");

        Assert.Equal((byte)90, config.AppPreference);
        Assert.Equal("inline-source", config.Sources.Single().Name);
        Assert.Equal("||service.example^$dnsrewrite=192.0.2.10", config.Sources.Single().Text);
        Assert.Null(config.Sources.Single().Url);
    }

    [Fact]
    public void SplitHorizonConfig_LoadInstalledConfigImportsGroupMaps()
    {
        string rootDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        string remoteRewriteDir = Path.Combine(rootDir, "RemoteRewriteApp");
        string splitHorizonDir = Path.Combine(rootDir, "SplitHorizonApp");
        Directory.CreateDirectory(remoteRewriteDir);
        Directory.CreateDirectory(splitHorizonDir);

        try
        {
            File.WriteAllText(Path.Combine(splitHorizonDir, "dnsApp.config"), """
{
  "domainGroupMap": {
    "internal.example": "edge"
  },
  "networkGroupMap": {
    "198.51.100.0/24": "edge"
  }
}
""");

            SplitHorizonConfig config = SplitHorizonConfig.Parse(JsonDocument.Parse("""
{
  "enable": true,
  "importInstalledApp": true
}
""").RootElement);

            config.LoadInstalledConfig(remoteRewriteDir);

            Assert.Contains(config.ResolveGroups("service.internal.example", IPAddress.Parse("203.0.113.10")), group => group == "edge");
            Assert.Contains(config.ResolveGroups("service.example", IPAddress.Parse("198.51.100.10")), group => group == "edge");
        }
        finally
        {
            Directory.Delete(rootDir, recursive: true);
        }
    }

    [Fact]
    public void AppRecordOptions_ParseSupportsInlineSourcesAndSplitHorizonMap()
    {
        AppRecordOptions options = AppRecordOptions.Parse("""
{
  "enable": true,
  "inlineSources": [
    {
      "name": "whole-inline",
      "enable": true,
      "format": "adguard-filter",
      "text": "||service.example^$dnsrewrite=192.0.2.10"
    }
  ],
  "splitHorizonMap": {
    "private": {
      "inlineSources": [
        {
          "name": "private-inline",
          "enable": true,
          "format": "adguard-filter",
          "text": "||service.example^$dnsrewrite=10.0.0.10"
        }
      ]
    }
  }
}
""");

        AppRecordEffectiveOptions privateOptions = options.Resolve(new HashSet<string>(["private"], StringComparer.OrdinalIgnoreCase));
        AppRecordEffectiveOptions publicOptions = options.Resolve(new HashSet<string>(["public"], StringComparer.OrdinalIgnoreCase));

        Assert.Single(publicOptions.InlineRules);
        Assert.Equal("192.0.2.10", publicOptions.InlineRules.Single().Answers.Single().Value);
        Assert.Single(privateOptions.InlineRules);
        Assert.Equal("10.0.0.10", privateOptions.InlineRules.Single().Answers.Single().Value);
    }

    [Fact]
    public async Task ProcessRequestAsync_UsesSplitHorizonScopedInlineRules()
    {
        App app = new App();
        await app.InitializeAsync(null!, JsonSerializer.Serialize(new
        {
            appPreference = 100,
            enable = true,
            defaultTtl = 300,
            refreshSeconds = 300,
            splitHorizon = new
            {
                enable = true,
                privateGroupName = "private",
                publicGroupName = "public"
            },
            sources = Array.Empty<object>()
        }));

        const string appRecordData = """
{
  "enable": true,
  "inlineSources": [
    {
      "name": "whole-inline",
      "enable": true,
      "format": "adguard-filter",
      "text": "||service.example^$dnsrewrite=192.0.2.10"
    }
  ],
  "splitHorizonMap": {
    "private": {
      "inlineSources": [
        {
          "name": "private-inline",
          "enable": true,
          "format": "adguard-filter",
          "text": "||service.example^$dnsrewrite=10.0.0.10"
        }
      ]
    }
  }
}
""";

        DnsDatagram? privateResponse = await app.ProcessRequestAsync(
            CreateRequest("service.example", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Parse("10.0.0.25"), 5300),
            DnsTransportProtocol.Udp,
            true,
            "example",
            "*.example",
            120,
            appRecordData);

        DnsDatagram? publicResponse = await app.ProcessRequestAsync(
            CreateRequest("service.example", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Parse("203.0.113.25"), 5300),
            DnsTransportProtocol.Udp,
            true,
            "example",
            "*.example",
            120,
            appRecordData);

        Assert.Equal(IPAddress.Parse("10.0.0.10"), Assert.IsType<DnsARecordData>(Assert.Single(privateResponse!.Answer).RDATA).Address);
        Assert.Equal(IPAddress.Parse("192.0.2.10"), Assert.IsType<DnsARecordData>(Assert.Single(publicResponse!.Answer).RDATA).Address);

        app.Dispose();
    }

    static DnsDatagram CreateRequest(string name, DnsResourceRecordType type)
    {
        return new DnsDatagram(
            0x4242,
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
