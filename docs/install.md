# Install

## Package

Build the app package:

```bash
sh scripts/package-app.sh
```

Result:
- `dist/RemoteRewriteApp.zip`

## Install in Technitium

1. Open the Technitium DNS Server web UI
2. Go to `Apps`
3. Install `dist/RemoteRewriteApp.zip`
4. Edit `dnsApp.config`
5. Use the app immediately in global mode, or create `APP` records only for scoped overrides

## Typical deployment pattern

1. Keep blocklists in native Technitium
2. Keep conditional forwarders in native Technitium
3. Use this app only for rewrite behavior
