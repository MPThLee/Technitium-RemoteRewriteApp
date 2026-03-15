# Contributing

## Scope

This repo builds a standalone Technitium DNS App for remote-managed rewrite rules.

Public usage docs live in `docs/`. Keep `README.md` short and high-signal.

Keep these boundaries intact:
- rewrite handling belongs here
- block/allow list handling stays in native Technitium features
- conditional forwarding stays in native Technitium features or official forwarding apps

## Project layout

- [src/App.cs](src/App.cs): app entrypoint and refresh flow
- [src/AppConfig.cs](src/AppConfig.cs): app config parsing
- [src/AppRecordOptions.cs](src/AppRecordOptions.cs): APP-record config parsing and Split Horizon overrides
- [src/RuleParser.cs](src/RuleParser.cs): AdGuard and manifest parsing
- [src/RuleMatcher.cs](src/RuleMatcher.cs): match selection
- [src/SplitHorizonConfig.cs](src/SplitHorizonConfig.cs): local and imported Split Horizon group resolution
- [tests/RemoteRewriteApp.Tests](tests/RemoteRewriteApp.Tests/RemoteRewriteApp.Tests.csproj): unit tests
- [tests/RemoteRewriteApp.SmokeTests](tests/RemoteRewriteApp.SmokeTests/RemoteRewriteApp.SmokeTests.csproj): live Technitium smoke test
- [tests/RemoteRewriteApp.Benchmarks](tests/RemoteRewriteApp.Benchmarks/RemoteRewriteApp.Benchmarks.csproj): benchmark harness

## Requirements

- .NET 9 SDK
- Docker-compatible runtime for smoke tests
- official Technitium SDK DLLs prepared under `vendor/technitium`

On this repo, Colima works for the smoke flow.

## Prepare SDK references

```bash
sh scripts/prepare-sdk.sh 14.3.0
```

## Build and package

```bash
sh scripts/package-app.sh
```

Output:
- `dist/RemoteRewriteApp/`
- `dist/RemoteRewriteApp.zip`

The ZIP is built in the same flat-file shape used by official Technitium app archives.

## Test

Unit tests:

```bash
sh scripts/test.sh
```

Live Technitium smoke test:

```bash
sh scripts/smoke-test.sh
```

If a Docker client or shell dies mid-run and you need forced cleanup:

```bash
sh scripts/smoke-cleanup.sh
```

The smoke test covers:
- package build
- app install through Technitium HTTP API
- app config save/reload
- primary zone creation
- APP record creation
- suffix rewrite resolution
- glob rewrite resolution
- regex rewrite resolution
- manifest rewrite resolution
- uninstall cleanup verification

## Benchmark

```bash
sh scripts/benchmark.sh
```

Current benchmark focus:
- parser throughput
- matcher throughput
- cached steady-state request throughput through `ProcessRequestAsync`

The benchmark shape that matters here is:
- initialize once
- fetch remote rules once
- run many repeated requests against the in-memory cached rule set

## Technitium integration notes

Follow upstream Technitium app contracts.

Relevant upstream source references:
- `IDnsApplication`
- `IDnsAppRecordRequestHandler`
- `IDnsApplicationPreference`
- `Apps/SplitHorizonApp`

## Contribution rules

- Preserve compatibility with Technitium `dnsApp.config` and APP-record JSON editing in the web UI
- Keep remote refresh failures safe for live DNS traffic
- Maintain smoke coverage for install/config/query/uninstall flow
- Add tests for any new parser or matching behavior
- Do not add native blocklist or forwarder responsibilities to this app
