# Split Horizon

This app supports Split Horizon in two modes.

## 1. Compatibility mode

Define local group rules in this app:
- `domainGroupMap`
- `networkGroupMap`

This is independent from the official `SplitHorizonApp`, but compatible with the same group naming model.

## 2. Import mode

If the official `SplitHorizonApp` is installed, this app can import its group maps from `dnsApp.config`.

Technitium 15.4 installs it as `Split Horizon`; discovery uses that folder automatically and retains the older `SplitHorizonApp` folder as a compatibility fallback.

Relevant app config fields:
- `splitHorizon.enable`
- `splitHorizon.importInstalledApp`
- `splitHorizon.configFile`

The most-specific domain mapping wins. If no domain mapping matches, the most-specific client network mapping wins. Disabled groups from the official app are not imported. Explicit mappings in this app take precedence over imported mappings of equal specificity.

Domain and network maps are limited to 64 combined entries, including imported entries. Domain names and CIDR networks must be canonical and unambiguous; CIDRs with host bits set and duplicate normalized keys are rejected. Imported files must be valid UTF-8 JSON, are limited to 256 KiB, and may not traverse symbolic links outside the DNS applications directory.

## APP record behavior

APP records can apply:
- one whole-record rewrite policy
- or per-group overrides in `splitHorizonMap`

That allows patterns like:
- `public` uses remote `dns.txt`
- `private` uses inline overrides
- `edge` uses a dedicated manifest source

If no group-specific override matches, the whole-record config is used as fallback. If several scopes match, custom mapped groups take priority over `private`/`public`, which take priority over `default`; ties at one priority return `SERVFAIL`. This result does not depend on JSON property order.

Omitted scope fields inherit from the whole-record config. Explicit `[]` or `null` clears an inherited value. A scope's `sourceNames` filters configured app sources only and never filters that APP record's inline rules.
