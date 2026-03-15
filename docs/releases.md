# Releases

## CI

Pushes to `master` run:
- build
- tests
- smoke verification
- changelog update

## Changelog

`CHANGELOG.md` is maintained automatically from Git history.

The repo updates it on `master` after normal pushes.

## Release publishing

Pushing a tag matching `v*` runs the release workflow.

The workflow:
- prepares the Technitium SDK refs
- runs tests
- packages the app
- creates a GitHub Release
- attaches `dist/RemoteRewriteApp.zip`
- uses the matching section from `CHANGELOG.md` as the release body

## Versioning

Current repo convention:
- regular work lands on `master`
- publishable releases are tagged as `vX.Y.Z`
