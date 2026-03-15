# Split Horizon

This app supports Split Horizon in two modes.

## 1. Compatibility mode

Define local group rules in this app:
- `domainGroupMap`
- `networkGroupMap`

This is independent from the official `SplitHorizonApp`, but compatible with the same group naming model.

## 2. Import mode

If the official `SplitHorizonApp` is installed, this app can import its group maps from `dnsApp.config`.

Relevant app config fields:
- `splitHorizon.enable`
- `splitHorizon.importInstalledApp`
- `splitHorizon.configFile`

## APP record behavior

APP records can apply:
- one whole-record rewrite policy
- or per-group overrides in `splitHorizonMap`

That allows patterns like:
- `public` uses remote `dns.txt`
- `private` uses inline overrides
- `edge` uses a dedicated manifest source

If no group-specific override matches, the whole-record config is used as fallback.

