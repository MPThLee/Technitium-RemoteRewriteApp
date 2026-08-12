# Overview

`Technitium-RemoteRewriteApp` is a Technitium DNS App for rewrite rules that are awkward or impossible to model cleanly with native Technitium zones alone.

It supports:
- remote AdGuard-style `dns.txt` sources
- remote `rewrite.json` manifests
- inline rewrite text in app config
- inline rewrite text in APP records
- global rewrite matching by default
- exact, suffix, glob, and regex matching
- AdGuard exceptions, multiple answers, full `RCODE;RRTYPE;VALUE` syntax, and NODATA behavior
- Split Horizon-aware rewrite selection

It does not replace native Technitium features for:
- block and allow lists
- allowed zones
- conditional forwarders

## Main use cases

- migrate AdGuard Home `$dnsrewrite=` behavior to Technitium
- keep rewrite rules in a remote file that Technitium fetches
- keep a few rewrite rules inline in Technitium
- apply rewrites globally without creating per-domain zones
- return different rewrite answers for public, private, or custom Split Horizon groups

## Inputs

Supported source formats:
- `adguard-filter`
- `rewrite-rules-json`

Answers supported:
- `A`
- `AAAA`
- `CNAME`

Matched rewrites run before Technitium's recursive cache. A miss falls through to the cache and then normal upstream resolution.

## Next

- [Install](install.md)
- [Configuration](configuration.md)
- [Split Horizon](split-horizon.md)
