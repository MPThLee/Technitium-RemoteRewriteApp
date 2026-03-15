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

- `name`: source id used for filtering
- `enable`: source toggle
- `format`: `adguard-filter` or `rewrite-rules-json`
- `url`: remote source URL
- `text`: inline source text
- `groupNames`: optional group scoping

## APP-record config

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

