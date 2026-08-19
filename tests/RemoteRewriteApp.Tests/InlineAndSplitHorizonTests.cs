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
        string splitHorizonDir = Path.Combine(rootDir, "Split Horizon");
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
    "198.51.100.0/24": "edge",
    "203.0.113.0/24": "disabled"
  },
  "groups": [
    { "name": "edge", "enabled": true },
    { "name": "disabled", "enabled": false }
  ]
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
            Assert.DoesNotContain(config.ResolveGroups("service.example", IPAddress.Parse("203.0.113.10")), group => group == "disabled");
        }
        finally
        {
            Directory.Delete(rootDir, recursive: true);
        }
    }

    [Theory]
    [InlineData("[]")]
    [InlineData("{ \"enable\": \"true\" }")]
    [InlineData("{ \"domainGroupMap\": [] }")]
    [InlineData("{ \"domainGroupMap\": { \"example.com\": 1 } }")]
    [InlineData("{ \"networkGroupMap\": { \"192.0.2.0/24\": false } }")]
    [InlineData("{ \"configFile\": 42 }")]
    public void SplitHorizonConfig_RejectsMalformedShapesAndTypes(string json)
    {
        using JsonDocument document = JsonDocument.Parse(json);
        Assert.Throws<FormatException>(() => SplitHorizonConfig.Parse(document.RootElement));
    }

    [Fact]
    public void SplitHorizonConfig_RejectsNormalizedDuplicateMappings()
    {
        Assert.Throws<FormatException>(() => SplitHorizonConfig.Parse(JsonDocument.Parse("""
        {
          "domainGroupMap": {
            "Example.COM.": "first",
            ".example.com": "second"
          }
        }
        """).RootElement));

        Assert.Throws<FormatException>(() => SplitHorizonConfig.Parse(JsonDocument.Parse("""
        {
          "networkGroupMap": {
            "2001:db8::/64": "first",
            "2001:0db8:0:0::/064": "second"
          }
        }
        """).RootElement));
    }

    [Fact]
    public void SplitHorizonConfig_RejectsInvalidDomainsNetworksAndGroups()
    {
        Assert.Throws<FormatException>(() => SplitHorizonConfig.Parse(JsonDocument.Parse("""
        { "domainGroupMap": { "bad..example": "group" } }
        """).RootElement));
        Assert.Throws<FormatException>(() => SplitHorizonConfig.Parse(JsonDocument.Parse("""
        { "networkGroupMap": { "192.0.2.1/24": "group" } }
        """).RootElement));

        string oversizedGroup = new string('g', AppLimits.MaxGroupNameLength + 1);
        Assert.Throws<FormatException>(() => SplitHorizonConfig.Parse(JsonDocument.Parse(
            JsonSerializer.Serialize(new { defaultGroupName = oversizedGroup })).RootElement));
    }

    [Fact]
    public void SplitHorizonConfig_CapsCombinedMapEntries()
    {
        Dictionary<string, string> map = Enumerable.Range(0, AppLimits.MaxSplitHorizonMapEntries + 1)
            .ToDictionary(static index => $"host-{index}.example", static _ => "edge");
        string json = JsonSerializer.Serialize(new { domainGroupMap = map });

        Assert.Throws<FormatException>(() => SplitHorizonConfig.Parse(JsonDocument.Parse(json).RootElement));
    }

    [Fact]
    public void SplitHorizonConfig_InstalledImportIsStrictAndCombinedSizeBounded()
    {
        string rootDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        string remoteRewriteDir = Path.Combine(rootDir, "RemoteRewriteApp");
        string splitHorizonDir = Path.Combine(rootDir, "Split Horizon");
        Directory.CreateDirectory(remoteRewriteDir);
        Directory.CreateDirectory(splitHorizonDir);

        try
        {
            File.WriteAllText(Path.Combine(splitHorizonDir, "dnsApp.config"),
                "{ \"domainGroupMap\": { \"imported.example\": 1 } }");
            SplitHorizonConfig malformed = SplitHorizonConfig.Parse(JsonDocument.Parse("""
            { "enable": true, "importInstalledApp": true }
            """).RootElement);
            Assert.Throws<FormatException>(() => malformed.LoadInstalledConfig(remoteRewriteDir));

            Dictionary<string, string> localMap = Enumerable.Range(0, AppLimits.MaxSplitHorizonMapEntries)
                .ToDictionary(static index => $"local-{index}.example", static _ => "edge");
            string localJson = JsonSerializer.Serialize(new
            {
                enable = true,
                importInstalledApp = true,
                domainGroupMap = localMap
            });
            File.WriteAllText(Path.Combine(splitHorizonDir, "dnsApp.config"),
                "{ \"domainGroupMap\": { \"imported.example\": \"edge\" } }");
            SplitHorizonConfig full = SplitHorizonConfig.Parse(JsonDocument.Parse(localJson).RootElement);
            Assert.Throws<FormatException>(() => full.LoadInstalledConfig(remoteRewriteDir));
        }
        finally
        {
            Directory.Delete(rootDir, recursive: true);
        }
    }

    [Fact]
    public void SplitHorizonConfig_RejectsInvalidUtf8AndOversizedInstalledConfig()
    {
        string rootDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        string remoteRewriteDir = Path.Combine(rootDir, "RemoteRewriteApp");
        string splitHorizonDir = Path.Combine(rootDir, "Split Horizon");
        Directory.CreateDirectory(remoteRewriteDir);
        Directory.CreateDirectory(splitHorizonDir);

        try
        {
            File.WriteAllBytes(Path.Combine(splitHorizonDir, "dnsApp.config"), [0x7b, 0x22, 0xff, 0x22, 0x3a, 0x31, 0x7d]);
            SplitHorizonConfig config = SplitHorizonConfig.Parse(JsonDocument.Parse("""
            { "enable": true, "importInstalledApp": true }
            """).RootElement);

            Assert.Throws<FormatException>(() => config.LoadInstalledConfig(remoteRewriteDir));

            File.WriteAllBytes(Path.Combine(splitHorizonDir, "dnsApp.config"), new byte[AppLimits.MaxAppRecordBytes + 1]);
            Assert.Throws<FormatException>(() => config.LoadInstalledConfig(remoteRewriteDir));
        }
        finally
        {
            Directory.Delete(rootDir, recursive: true);
        }
    }

    [Fact]
    public void SplitHorizonConfig_RejectsConfigFileSymlinkTraversal()
    {
        string rootDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        string remoteRewriteDir = Path.Combine(rootDir, "RemoteRewriteApp");
        string outsideDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(remoteRewriteDir);
        Directory.CreateDirectory(outsideDir);
        File.WriteAllText(Path.Combine(outsideDir, "dnsApp.config"), "{}");

        string linkPath = Path.Combine(remoteRewriteDir, "linked");
        try
        {
            try
            {
                Directory.CreateSymbolicLink(linkPath, outsideDir);
            }
            catch (Exception ex) when (ex is PlatformNotSupportedException or UnauthorizedAccessException or IOException)
            {
                return;
            }

            SplitHorizonConfig config = SplitHorizonConfig.Parse(JsonDocument.Parse("""
            {
              "enable": true,
              "importInstalledApp": true,
              "configFile": "linked/dnsApp.config"
            }
            """).RootElement);

            Assert.Throws<FormatException>(() => config.LoadInstalledConfig(remoteRewriteDir));
        }
        finally
        {
            if (Directory.Exists(linkPath))
                Directory.Delete(linkPath);
            Directory.Delete(rootDir, recursive: true);
            Directory.Delete(outsideDir, recursive: true);
        }
    }

    [Fact]
    public void SplitHorizonConfig_RejectsSymlinkSwapBetweenDiscoveryAndOpen()
    {
        string rootDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        string remoteRewriteDir = Path.Combine(rootDir, "RemoteRewriteApp");
        string splitHorizonDir = Path.Combine(rootDir, "Split Horizon");
        string outsideDir = Path.Combine(Path.GetTempPath(), Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(remoteRewriteDir);
        Directory.CreateDirectory(splitHorizonDir);
        Directory.CreateDirectory(outsideDir);

        string configPath = Path.Combine(splitHorizonDir, "dnsApp.config");
        string originalPath = Path.Combine(splitHorizonDir, "dnsApp.original");
        string outsidePath = Path.Combine(outsideDir, "dnsApp.config");
        string probePath = Path.Combine(splitHorizonDir, "symlink-probe");
        File.WriteAllText(configPath, "{}");
        File.WriteAllText(outsidePath, "{}");

        try
        {
            try
            {
                File.CreateSymbolicLink(probePath, outsidePath);
                File.Delete(probePath);
            }
            catch (Exception ex) when (ex is PlatformNotSupportedException or UnauthorizedAccessException or IOException)
            {
                return;
            }

            SplitHorizonConfig config = SplitHorizonConfig.Parse(JsonDocument.Parse("""
            { "enable": true, "importInstalledApp": true }
            """).RootElement);

            Assert.Throws<FormatException>(() => config.LoadInstalledConfig(remoteRewriteDir, () =>
            {
                File.Move(configPath, originalPath);
                File.CreateSymbolicLink(configPath, outsidePath);
            }));
        }
        finally
        {
            if (File.Exists(probePath))
                File.Delete(probePath);
            if (File.Exists(configPath))
                File.Delete(configPath);
            Directory.Delete(rootDir, recursive: true);
            Directory.Delete(outsideDir, recursive: true);
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
    public void AppRecordOptions_ScopeResolutionIsSpecificAndOrderIndependent()
    {
        static AppRecordOptions ParseWithScopes(string scopes) => AppRecordOptions.Parse($$"""
        {
          "inlineSources": [{
            "name": "root",
            "format": "adguard-filter",
            "text": "||service.example^$dnsrewrite=192.0.2.1"
          }],
          "splitHorizonMap": {
            {{scopes}}
          }
        }
        """);

        const string scopesA = """
        "default": { "inlineSources": [{ "name": "fallback", "format": "adguard-filter", "text": "||service.example^$dnsrewrite=192.0.2.2" }] },
        "private": { "inlineSources": [{ "name": "private", "format": "adguard-filter", "text": "||service.example^$dnsrewrite=10.0.0.2" }] },
        "edge": { "inlineSources": [{ "name": "edge", "format": "adguard-filter", "text": "||service.example^$dnsrewrite=10.0.0.3" }] }
        """;
        const string scopesB = """
        "edge": { "inlineSources": [{ "name": "edge", "format": "adguard-filter", "text": "||service.example^$dnsrewrite=10.0.0.3" }] },
        "private": { "inlineSources": [{ "name": "private", "format": "adguard-filter", "text": "||service.example^$dnsrewrite=10.0.0.2" }] },
        "default": { "inlineSources": [{ "name": "fallback", "format": "adguard-filter", "text": "||service.example^$dnsrewrite=192.0.2.2" }] }
        """;
        HashSet<string> groups = new HashSet<string>(["default", "private", "edge"], StringComparer.OrdinalIgnoreCase);

        AppRecordEffectiveOptions first = ParseWithScopes(scopesA).Resolve(groups);
        AppRecordEffectiveOptions second = ParseWithScopes(scopesB).Resolve(groups);

        Assert.Equal("10.0.0.3", first.InlineRules.Single().Answers.Single().Value);
        Assert.Equal("10.0.0.3", second.InlineRules.Single().Answers.Single().Value);
    }

    [Fact]
    public void AppRecordOptions_AmbiguousSamePriorityScopesFailClosed()
    {
        AppRecordOptions options = AppRecordOptions.Parse("""
        {
          "splitHorizonMap": {
            "edge": {},
            "office": {}
          }
        }
        """);

        AppRecordEffectiveOptions effective = options.Resolve(
            new HashSet<string>(["default", "private", "edge", "office"], StringComparer.OrdinalIgnoreCase));

        Assert.False(effective.Enable);
        Assert.True(effective.ResolutionFailed);
    }

    [Fact]
    public async Task ProcessRequestAsync_AmbiguousSamePriorityScopesReturnServerFailure()
    {
        App app = new App();
        await app.InitializeAsync(null!, """
        {
          "enable": true,
          "globalMode": false,
          "splitHorizon": {
            "enable": true,
            "domainGroupMap": { "service.example": "public" }
          },
          "sources": []
        }
        """);

        DnsDatagram? response = await app.ProcessRequestAsync(
            CreateRequest("service.example", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Parse("10.0.0.25"), 5300),
            DnsTransportProtocol.Udp,
            true,
            "example",
            "*.example",
            120,
            """
            {
              "splitHorizonMap": {
                "private": {},
                "public": {}
              }
            }
            """);

        Assert.NotNull(response);
        Assert.Equal(DnsResponseCode.ServerFailure, response!.RCODE);
        app.Dispose();
    }

    [Fact]
    public void AppRecordOptions_RejectsNormalizedDuplicateScopeNames()
    {
        Assert.False(AppRecordOptions.TryParse("""
        {
          "splitHorizonMap": {
            "Private": {},
            " private ": {}
          }
        }
        """, out _));
    }

    [Fact]
    public void AppRecordOptions_ScopeOmissionInheritsAndExplicitEmptyValuesClear()
    {
        AppRecordOptions options = AppRecordOptions.Parse("""
        {
          "sourceNames": ["remote-dns"],
          "groupNames": ["private"],
          "overrideTtl": 120,
          "inlineSources": [{
            "name": "root",
            "format": "adguard-filter",
            "text": "||service.example^$dnsrewrite=192.0.2.1"
          }],
          "splitHorizonMap": {
            "inherit": {},
            "clear": {
              "sourceNames": [],
              "groupNames": null,
              "overrideTtl": null,
              "inlineSources": []
            }
          }
        }
        """);

        AppRecordEffectiveOptions inherited = options.Resolve(new HashSet<string>(["inherit"], StringComparer.OrdinalIgnoreCase));
        AppRecordEffectiveOptions cleared = options.Resolve(new HashSet<string>(["clear"], StringComparer.OrdinalIgnoreCase));

        Assert.Contains("remote-dns", inherited.SourceNames);
        Assert.Contains("private", inherited.GroupNames);
        Assert.Equal<uint>(120, inherited.OverrideTtl!.Value);
        Assert.Single(inherited.InlineRules);
        Assert.Empty(cleared.SourceNames);
        Assert.Empty(cleared.GroupNames);
        Assert.Null(cleared.OverrideTtl);
        Assert.Empty(cleared.InlineRules);
    }

    [Fact]
    public void AppRecordOptions_CacheHitAtCapacityDoesNotClearAllEntries()
    {
        AppRecordOptions.ClearCache();
        try
        {
            AppRecordOptions first = AppRecordOptions.Parse("{\"overrideTtl\":1}");
            for (int index = 2; index <= AppLimits.MaxAppRecordCacheEntries; index++)
                AppRecordOptions.Parse($"{{\"overrideTtl\":{index}}}");

            Assert.Equal(AppLimits.MaxAppRecordCacheEntries, AppRecordOptions.CacheEntryCount);
            Assert.Same(first, AppRecordOptions.Parse("{\"overrideTtl\":1}"));

            AppRecordOptions.Parse("{\"overrideTtl\":65}");
            Assert.Equal(AppLimits.MaxAppRecordCacheEntries, AppRecordOptions.CacheEntryCount);
        }
        finally
        {
            AppRecordOptions.ClearCache();
        }
    }

    [Fact]
    public void AppRecordOptions_InlineSourcesSupportMultipleLines()
    {
        AppRecordOptions options = AppRecordOptions.Parse("""
{
  "enable": true,
  "inlineSources": [
    {
      "name": "multi-inline",
      "enable": true,
      "format": "adguard-filter",
      "text": "||one.example^$dnsrewrite=192.0.2.10\n||two.example^$dnsrewrite=192.0.2.20"
    }
  ]
}
""");

        Assert.Equal(2, options.InlineRules.Length);
        Assert.Contains(options.InlineRules, rule => rule.Pattern == "one.example" && rule.Answers.Single().Value == "192.0.2.10");
        Assert.Contains(options.InlineRules, rule => rule.Pattern == "two.example" && rule.Answers.Single().Value == "192.0.2.20");
    }

    [Fact]
    public void AppRecordOptions_RejectsOversizedTtlAndInput()
    {
        Assert.False(AppRecordOptions.TryParse($$"""{"overrideTtl":{{AppLimits.MaximumTtl + 1}}}""", out _));
        Assert.False(AppRecordOptions.TryParse(new string('x', AppLimits.MaxAppRecordBytes + 1), out _));
    }

    [Fact]
    public async Task ProcessRequestAsync_MalformedInScopeAppRecordReturnsServerFailure()
    {
        App app = new App();
        await app.InitializeAsync(null!, """{ "enable": true, "globalMode": false, "sources": [] }""");

        DnsDatagram? response = await app.ProcessRequestAsync(
            CreateRequest("service.example", DnsResourceRecordType.A),
            new IPEndPoint(IPAddress.Loopback, 5300),
            DnsTransportProtocol.Udp,
            true,
            "example",
            "*.example",
            120,
            "{not-json");

        Assert.NotNull(response);
        Assert.Equal(DnsResponseCode.ServerFailure, response!.RCODE);
        app.Dispose();
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
  "sourceNames": ["configured-only"],
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
