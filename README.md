# Technitium-RemoteRewriteApp

Remote rewrite engine for Technitium DNS Server.

Targets Technitium DNS Server 15.4 and .NET 10.

It exists for rewrite cases that do not fit native Technitium features well:
- AdGuard `$dnsrewrite` rules and exceptions
- exact, suffix, wildcard/glob, and regex matches
- A, AAAA, CNAME, NODATA, and response-code rewrites
- Split Horizon-aware rewrite selection

Global rewrite mode is on by default.

Use native Technitium features for:
- block and allow lists
- allowed zones
- conditional forwarders

## Quick start

1. Install `RemoteRewriteApp.zip` in Technitium
2. Configure `dnsApp.config`
3. Point the app at a remote `dns.txt`, `rewrite.json`, or inline rules
4. Add `APP` records only if you want optional scoped overrides

HTTPS is required for remote sources by default. Trusted local HTTP sources require `allowInsecureHttp: true`.

## Docs

- [Overview](docs/index.md)
- [Install](docs/install.md)
- [Configuration](docs/configuration.md)
- [Split Horizon](docs/split-horizon.md)
- [Releases](docs/releases.md)
- [Contributing](CONTRIBUTING.md)

## Status

- CI runs on push to `master`
- GitHub Release is published automatically on `v*` tags
- `CHANGELOG.md` is updated automatically from Git history
