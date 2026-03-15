# Technitium-RemoteRewriteApp

Remote rewrite engine for Technitium DNS Server.

It exists for rewrite cases that do not fit native Technitium features well:
- AdGuard-style `$dnsrewrite=` rules
- wildcard host rewrites
- regex rewrites
- Split Horizon-aware rewrite selection

Use native Technitium features for:
- block and allow lists
- allowed zones
- conditional forwarders

## Quick start

1. Install `RemoteRewriteApp.zip` in Technitium
2. Configure `dnsApp.config`
3. Add `APP` records where rewrite handling should apply
4. Point the app at a remote `dns.txt`, `rewrite.json`, or inline rules

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
