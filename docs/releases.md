# Releases

## CI

Pushes to `master` run:
- build
- tests
- smoke verification

## Release publishing

Pushing a tag matching `v*` runs the release workflow.

The workflow:
- prepares the Technitium SDK refs
- runs tests
- packages the app
- creates a GitHub Release
- attaches `dist/RemoteRewriteApp.zip`
- generates release notes automatically

## Versioning

Current repo convention:
- regular work lands on `master`
- publishable releases are tagged as `vX.Y.Z`
