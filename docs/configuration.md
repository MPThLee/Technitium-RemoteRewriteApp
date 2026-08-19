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

`refreshSeconds` accepts `0` to disable refresh or a value from 30 seconds through 7 days. A refresh downloads into a new snapshot; failures are logged and the last known good rules remain active. Each source is limited to 4 MiB, configuration is limited to 64 sources, and the combined result is limited to 250,000 rules. Empty sources and AdGuard sources that produce no valid rewrites are rejected so a bad refresh cannot silently erase the active snapshot.

Remote URLs must be direct HTTPS responses with no embedded credentials or fragments. Redirects and non-`200 OK` responses are rejected so a trusted HTTPS source cannot silently downgrade or be replaced by a partial/error response. Inline sources receive the same 4 MiB limit. Resolved loopback, private/shared, link-local, documentation, benchmarking, multicast, reserved, and unsafe address-transition destinations are blocked by default and checked again when the socket connects. Globally reachable public-unicast ranges are not blocked merely because IANA assigned them a special purpose. Set `allowPrivateNetworkSources` to `true` only when every configured internal source is trusted; use the separate `allowInsecureHttp` switch only when one of those sources cannot provide HTTPS.

Remote glob and regex rules share a 1,024-rule quota, patterns are limited to 1,024 characters, and regexes use .NET's non-backtracking engine. Constructs that require backtracking, such as backreferences and lookarounds, reject the entire affected source so a refresh keeps the last known good snapshot instead of silently dropping only those rules. A response is capped at 64 unique answers and excessive matching fan-out fails closed with `SERVFAIL`.

Across all configured rules, answer, group-index (source plus rule), and query-type memberships are each capped at 500,000. APP-record inline rules use smaller 4,096-membership caps for each category. These aggregate limits prevent individually valid high-cardinality rules from exhausting memory.

Source-level and rule-level `groupNames` are independent constraints. When both are present, the client must match both sets; downloaded rule metadata cannot broaden an administrator-defined source scope.

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

Unknown applicability-changing modifiers and `badfilter` rules are also skipped rather than treated as globally applicable rewrites.

## Rewrite JSON

The source may be `{ "rules": [...] }` or a top-level array. Rules support `order`, `matchType`, `pattern`, `answers`, `ttl`, `groupNames`, `queryTypes`, `responseCode`, and `exception`.

## APP-record config

APP records are optional.

Use them only when you want scoped behavior on top of the default global matching path.

APP-record JSON is limited to 256 KiB, 64 inline sources, 2,048 inline rules, 128 glob/regex rules, and 64 Split Horizon scopes. Malformed in-scope APP-record data returns `SERVFAIL` instead of throwing on the DNS request path. All TTL inputs are capped at 7 days.

`sourceNames` selects configured app sources only; it does not filter the APP record's own `inlineSources`. Within a split-horizon scope, omitted fields inherit the whole-record value, while explicit `[]` or `null` clears an inherited array/value.

When multiple resolved groups have entries in `splitHorizonMap`, selection is deterministic: a custom domain/network-mapped group is preferred over `private`/`public`, which is preferred over `default`. Multiple matches at the same priority return `SERVFAIL`, and scope names that collide after trimming and case normalization are rejected. JSON property order never decides which scope applies.

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
