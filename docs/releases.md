# Releases

Configure the GitHub `release` environment with required reviewers, and protect
the `v*` tag namespace so only release maintainers can create release tags. Do
this before publishing: the workflow references that environment and will wait
or fail if it is unavailable. The workflow also rejects tags that do not match
the project version or point to a commit outside `master`.

## CI

Pushes to `master` run:
- build
- tests
- smoke verification
- changelog update

## Changelog

`CHANGELOG.md` is maintained automatically from Git history.

The repo updates it on `master` after normal pushes. Branch protection should
require this workflow and prevent direct pushes that bypass required review.

## Release publishing

Pushing a tag matching `v*` runs the release workflow.

The workflow:
- downloads and verifies the pinned Technitium SDK refs
- runs tests
- packages and smoke-tests the exact app archive
- transfers that archive from a read-only build job to a minimal write-enabled publish job
- creates a GitHub Release only after the build job succeeds
- attaches `RemoteRewriteApp.zip` and its SHA-256 checksum
- uses the matching section from `CHANGELOG.md` as the release body

Action revisions, container digests, the .NET SDK, NuGet lock files, and the
Technitium archive checksum are intentional supply-chain pins. Review upstream
release notes and provenance before updating any of them.

## Versioning

Current repo convention:
- regular work lands on `master`
- publishable releases are tagged as `vX.Y.Z`
