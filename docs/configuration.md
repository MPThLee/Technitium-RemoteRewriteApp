# Configuration

There are two configuration surfaces:
- app-level config in `dnsApp.config`
- APP-record config in Technitium via the JSON template

## App config

Example:

```json
{
  "appPreference": 100,
  "enable": true,
  "globalMode": true,
  "allowInsecureHttp": false,
  "defaultTtl": 300,
  "refreshSeconds": 300,
  "splitHorizon": {
    "enable": false,
    "defaultGroupName": "default",
    "privateGroupName": "private",
    "publicGroupName": "public",
    "importInstalledApp": true,
    "configFile": null,
    "domainGroupMap": {
      "internal.example": "private"
    },
    "networkGroupMap": {
      "10.0.0.0/8": "private",
      "198.51.100.0/24": "edge"
    }
  },
  "sources": [
    {
      "name": "remote-dns",
      "enable": true,
      "format": "adguard-filter",
      "url": "https://example.invalid/dns.txt"
    },
    {
      "name": "remote-manifest",
      "enable": false,
      "format": "rewrite-rules-json",
      "url": "https://example.invalid/rewrite.json",
      "groupNames": ["private"]
    },
    {
      "name": "inline-overrides",
      "enable": false,
      "format": "adguard-filter",
      "text": "||service.example^$dnsrewrite=192.0.2.10"
    }
  ]
}
```

## Source fields

- `globalMode`: globally intercept matching names without per-zone setup; defaults to `true`
- `allowInsecureHttp`: permit trusted local `http://` sources; defaults to `false`
- `name`: source id used for filtering
- `enable`: source toggle
- `format`: `adguard-filter` or `rewrite-rules-json`
- `url`: remote source URL
- `text`: inline source text
- `groupNames`: optional group scoping

`refreshSeconds` accepts `0` to disable refresh or a value from 30 seconds through 7 days. A refresh downloads into a new snapshot; failures are logged and the last known good rules remain active. Each source is limited to 4 MiB, configuration is limited to 64 sources, and the combined result is limited to 250,000 rules.

Remote URLs must be direct HTTPS responses. Redirects are rejected so a trusted HTTPS source cannot silently downgrade to HTTP.

## AdGuard filter behavior

Supported forms include:

```text
|exact.example|$dnsrewrite=192.0.2.10
||example.net^$dnsrewrite=NOERROR;A;192.0.2.20
||alias.example^$dnsrewrite=NOERROR;CNAME;target.example
/node[0-9]+\.example/$dnsrewrite=198.51.100.10
||blocked-type.example^$dnstype=HTTPS,dnsrewrite=REFUSED
@@||example.net^$dnsrewrite
```

Multiple matching address rules produce multiple answers. CNAME takes priority. If a domain rewrite matches but has no record of the requested type, the app returns authoritative NODATA instead of exposing the upstream answer.

Client-targeted AdGuard modifiers such as `client`, `ctag`, and `denyallow` are skipped rather than applied globally. Use Split Horizon groups for client-dependent rewrites.

## Rewrite JSON

The source may be `{ "rules": [...] }` or a top-level array. Rules support `order`, `matchType`, `pattern`, `answers`, `ttl`, `groupNames`, `queryTypes`, `responseCode`, and `exception`.

## APP-record config

APP records are optional.

Use them only when you want scoped behavior on top of the default global matching path.

Example:

```json
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
    }
  }
}
```

## Inline multiline rules

Inline `text` supports multiple lines:

```text
||one.example^$dnsrewrite=192.0.2.10
||two.example^$dnsrewrite=192.0.2.20
```
