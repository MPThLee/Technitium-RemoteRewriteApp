using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;

if (args.Length != 4)
{
    throw new InvalidOperationException("usage: <base-url> <app-zip> <dns-txt-url> <rewrite-json-url>");
}

Uri baseUri = new(args[0].TrimEnd('/') + "/");
string appZipPath = Path.GetFullPath(args[1]);
string dnsTxtUrl = args[2];
string rewriteJsonUrl = args[3];
const string AppName = "RemoteRewriteApp";
const string ZoneName = "example.com";
const string NodeName = "this-server";

using HttpClient http = new()
{
    BaseAddress = baseUri,
    Timeout = TimeSpan.FromSeconds(30)
};

string token = await LoginWithRetryAsync();

try
{
    await InstallAppAsync(token, appZipPath);

    string classPath = await GetAppRecordClassPathAsync(token);

    string config = """
{
  "enable": true,
  "defaultTtl": 300,
  "refreshSeconds": 60,
  "sources": [
    {
      "name": "remote-dns",
      "enable": true,
      "format": "adguard-filter",
      "url": "__DNS_TXT_URL__"
    },
    {
      "name": "remote-manifest",
      "enable": true,
      "format": "rewrite-rules-json",
      "url": "__REWRITE_JSON_URL__"
    }
  ]
}
""".Replace("__DNS_TXT_URL__", dnsTxtUrl, StringComparison.Ordinal)
   .Replace("__REWRITE_JSON_URL__", rewriteJsonUrl, StringComparison.Ordinal);

    await SetAppConfigAsync(token, config);
    string savedConfig = await GetAppConfigAsync(token);
    AssertContains(savedConfig, dnsTxtUrl, "saved config");
    AssertContains(savedConfig, rewriteJsonUrl, "saved config");

    await CreatePrimaryZoneAsync(token, ZoneName);

    await AddAppRecordAsync(
        token,
        ZoneName,
        "rewrite.example.com",
        classPath,
        """
{
  "enable": true,
  "sourceNames": ["remote-dns"],
  "groupNames": [],
  "overrideTtl": 90
}
""");

    await AddAppRecordAsync(
        token,
        ZoneName,
        "*.wild.example.com",
        classPath,
        """
{
  "enable": true,
  "sourceNames": ["remote-dns"],
  "groupNames": [],
  "overrideTtl": null
}
""");

    await AddAppRecordAsync(
        token,
        ZoneName,
        "manifest.example.com",
        classPath,
        """
{
  "enable": true,
  "sourceNames": ["remote-manifest"],
  "groupNames": [],
  "overrideTtl": null
}
""");

    await WaitForResolveAsync(token, "rewrite.example.com", "192.0.2.55");
    await WaitForResolveAsync(token, "node.wild.example.com", "203.0.113.77");
    await WaitForResolveAsync(token, "manifest.example.com", "198.51.100.42");
}
finally
{
    await UninstallIfPresentAsync(token);
}

await EnsureAppRemovedAsync(token);

Console.WriteLine("Smoke test passed.");

async Task<string> LoginWithRetryAsync()
{
    Exception? lastError = null;

    for (int attempt = 1; attempt <= 60; attempt++)
    {
        try
        {
            using FormUrlEncodedContent form = new(new Dictionary<string, string>
            {
                ["user"] = "admin",
                ["pass"] = "admin",
                ["totp"] = string.Empty,
                ["includeInfo"] = "true"
            });

            using HttpResponseMessage response = await http.PostAsync("api/user/login", form);
            string body = await response.Content.ReadAsStringAsync();
            response.EnsureSuccessStatusCode();

            using JsonDocument document = JsonDocument.Parse(body);
            EnsureOk(document.RootElement, "login");

            if (!document.RootElement.TryGetProperty("token", out JsonElement tokenElement))
            {
                throw new InvalidOperationException("login response did not contain token");
            }

            return tokenElement.GetString() ?? throw new InvalidOperationException("login response token was empty");
        }
        catch (Exception ex)
        {
            lastError = ex;
            await Task.Delay(TimeSpan.FromSeconds(2));
        }
    }

    throw new InvalidOperationException("failed to login to Technitium after retries", lastError);
}

async Task InstallAppAsync(string tokenValue, string zipPath)
{
    using MultipartFormDataContent form = new();
    await using FileStream stream = File.OpenRead(zipPath);
    using StreamContent fileContent = new(stream);
    fileContent.Headers.ContentType = new MediaTypeHeaderValue("application/zip");
    form.Add(fileContent, "fileAppZip", Path.GetFileName(zipPath));

    using HttpResponseMessage response = await http.PostAsync($"api/apps/install?token={Uri.EscapeDataString(tokenValue)}&name={Uri.EscapeDataString(AppName)}", form);
    string body = await response.Content.ReadAsStringAsync();
    EnsureHttpSuccess(response, body, "app install");

    using JsonDocument document = JsonDocument.Parse(body);
    EnsureOk(document.RootElement, "app install");
}

async Task<string> GetAppRecordClassPathAsync(string tokenValue)
{
    using JsonDocument document = await GetJsonAsync($"api/apps/list?token={Uri.EscapeDataString(tokenValue)}", "app list");
    JsonElement apps = document.RootElement.GetProperty("response").GetProperty("apps");

    foreach (JsonElement app in apps.EnumerateArray())
    {
        if (!string.Equals(app.GetProperty("name").GetString(), AppName, StringComparison.Ordinal))
            continue;

        foreach (JsonElement dnsApp in app.GetProperty("dnsApps").EnumerateArray())
        {
            if (!dnsApp.TryGetProperty("isAppRecordRequestHandler", out JsonElement handlerElement) || !handlerElement.GetBoolean())
                continue;

            string? classPath = dnsApp.GetProperty("classPath").GetString();
            if (!string.IsNullOrWhiteSpace(classPath))
                return classPath;
        }
    }

    throw new InvalidOperationException("failed to find APP record class path for installed app");
}

async Task SetAppConfigAsync(string tokenValue, string configValue)
{
    Exception? lastError = null;

    for (int attempt = 1; attempt <= 30; attempt++)
    {
        try
        {
            using FormUrlEncodedContent form = new(new Dictionary<string, string>
            {
                ["config"] = configValue
            });

            using HttpResponseMessage response = await http.PostAsync($"api/apps/config/set?token={Uri.EscapeDataString(tokenValue)}&name={Uri.EscapeDataString(AppName)}", form);
            string body = await response.Content.ReadAsStringAsync();
            EnsureHttpSuccess(response, body, "app config set");

            using JsonDocument document = JsonDocument.Parse(body);
            EnsureOk(document.RootElement, "app config set");
            return;
        }
        catch (Exception ex)
        {
            lastError = ex;
            await Task.Delay(TimeSpan.FromSeconds(2));
        }
    }

    throw new InvalidOperationException("app config set did not succeed after retries", lastError);
}

async Task<string> GetAppConfigAsync(string tokenValue)
{
    using JsonDocument document = await GetJsonAsync($"api/apps/config/get?token={Uri.EscapeDataString(tokenValue)}&name={Uri.EscapeDataString(AppName)}&node={Uri.EscapeDataString(NodeName)}", "app config get");
    return document.RootElement.GetProperty("response").GetProperty("config").GetString() ?? string.Empty;
}

async Task CreatePrimaryZoneAsync(string tokenValue, string zoneName)
{
    using FormUrlEncodedContent form = new([]);
    using HttpResponseMessage response = await http.PostAsync($"api/zones/create?token={Uri.EscapeDataString(tokenValue)}&zone={Uri.EscapeDataString(zoneName)}&type=Primary&node={Uri.EscapeDataString(NodeName)}", form);
    string body = await response.Content.ReadAsStringAsync();
    response.EnsureSuccessStatusCode();

    using JsonDocument document = JsonDocument.Parse(body);
    EnsureOk(document.RootElement, "zone create");
}

async Task AddAppRecordAsync(string tokenValue, string zoneName, string domainName, string classPath, string recordData)
{
    string query =
        $"api/zones/records/add?token={Uri.EscapeDataString(tokenValue)}" +
        $"&zone={Uri.EscapeDataString(zoneName)}" +
        $"&domain={Uri.EscapeDataString(domainName)}" +
        "&type=APP" +
        "&ttl=300" +
        "&overwrite=true" +
        "&comments=" +
        "&expiryTtl=0" +
        $"&appName={Uri.EscapeDataString(AppName)}" +
        $"&classPath={Uri.EscapeDataString(classPath)}" +
        $"&recordData={Uri.EscapeDataString(recordData)}" +
        $"&node={Uri.EscapeDataString(NodeName)}";

    using JsonDocument document = await GetJsonAsync(query, $"add APP record {domainName}");
    _ = document.RootElement.GetProperty("response").GetProperty("addedRecord");
}

async Task WaitForResolveAsync(string tokenValue, string domainName, string expectedValue)
{
    Exception? lastError = null;

    for (int attempt = 1; attempt <= 30; attempt++)
    {
        try
        {
            string query =
                $"api/dnsClient/resolve?token={Uri.EscapeDataString(tokenValue)}" +
                "&server=this-server" +
                $"&domain={Uri.EscapeDataString(domainName)}" +
                "&type=A" +
                "&protocol=UDP" +
                "&dnssec=false" +
                "&eDnsClientSubnet=" +
                $"&node={Uri.EscapeDataString(NodeName)}";

            using JsonDocument document = await GetJsonAsync(query, $"resolve {domainName}");
            string payload = document.RootElement.GetProperty("response").GetProperty("result").GetRawText();
            AssertContains(payload, expectedValue, $"dns resolve result for {domainName}");
            return;
        }
        catch (Exception ex)
        {
            lastError = ex;
            await Task.Delay(TimeSpan.FromSeconds(2));
        }
    }

    throw new InvalidOperationException($"failed to resolve expected value for {domainName}", lastError);
}

async Task UninstallIfPresentAsync(string tokenValue)
{
    using JsonDocument document = await GetJsonAsync($"api/apps/list?token={Uri.EscapeDataString(tokenValue)}", "app list before uninstall");
    bool installed = document.RootElement
        .GetProperty("response")
        .GetProperty("apps")
        .EnumerateArray()
        .Any(static app => string.Equals(app.GetProperty("name").GetString(), AppName, StringComparison.Ordinal));

    if (!installed)
        return;

    using JsonDocument uninstall = await GetJsonAsync($"api/apps/uninstall?token={Uri.EscapeDataString(tokenValue)}&name={Uri.EscapeDataString(AppName)}", "app uninstall");
    EnsureOk(uninstall.RootElement, "app uninstall");
}

async Task EnsureAppRemovedAsync(string tokenValue)
{
    using JsonDocument document = await GetJsonAsync($"api/apps/list?token={Uri.EscapeDataString(tokenValue)}", "app list after uninstall");
    bool installed = document.RootElement
        .GetProperty("response")
        .GetProperty("apps")
        .EnumerateArray()
        .Any(static app => string.Equals(app.GetProperty("name").GetString(), AppName, StringComparison.Ordinal));

    if (installed)
    {
        throw new InvalidOperationException("app still present after uninstall");
    }
}

async Task<JsonDocument> GetJsonAsync(string pathAndQuery, string operation)
{
    using HttpResponseMessage response = await http.GetAsync(pathAndQuery);
    string body = await response.Content.ReadAsStringAsync();
    EnsureHttpSuccess(response, body, operation);

    JsonDocument document = JsonDocument.Parse(body);
    EnsureOk(document.RootElement, operation);
    return document;
}

static void EnsureHttpSuccess(HttpResponseMessage response, string body, string operation)
{
    if (response.IsSuccessStatusCode)
        return;

    string snippet = body.Length > 400 ? body[..400] : body;
    throw new InvalidOperationException($"{operation} failed with HTTP {(int)response.StatusCode} {response.ReasonPhrase}: {snippet}");
}

static void EnsureOk(JsonElement root, string operation)
{
    string? status = root.TryGetProperty("status", out JsonElement statusElement) ? statusElement.GetString() : null;
    if (string.Equals(status, "ok", StringComparison.Ordinal))
        return;

    string errorMessage = root.TryGetProperty("errorMessage", out JsonElement errorElement)
        ? errorElement.GetString() ?? "unknown error"
        : "missing status";

    throw new InvalidOperationException($"{operation} failed: {errorMessage}");
}

static void AssertContains(string content, string expected, string label)
{
    if (!content.Contains(expected, StringComparison.Ordinal))
    {
        throw new InvalidOperationException($"{label} did not contain expected value '{expected}'. Actual content: {content}");
    }
}
