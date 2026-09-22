# Preparing a release

There is no build step: npm distributes the reviewed CommonJS source. Keep
release preparation in a focused PR and publish only after it is merged and
the exact commit passes CI. This guide does not trigger publication.

## Choose the version

Check npm and GitHub before choosing an unused version:

```bash
npm view capsurface versions --json
gh release list --repo VictorMartins3/capsurface
```

A registry 404 does not reserve the name or establish ownership. Move the
user-facing changes from `Unreleased` into an entry with the chosen version
and actual release date. Update package.json in the release PR; do not create
a tag as a side effect of editing the version.

Describe CLI and baseline compatibility, experimental features and known
limits in the notes. Link the measured results in [Verification](VERIFICATION.md)
rather than presenting test counts as a security guarantee. Replace the README's
pre-release setup with tested, version-pinned registry installation instructions
when publication is confirmed.

## Validate the package

Run from a clean checkout of the candidate commit, using Node 18 or newer:

```bash
npm test
npm run test:integration
npm run demo
npm install --no-save --package-lock=false --ignore-scripts --no-audit --no-fund acorn@8.15.0 acorn-typescript@1.4.13
npm run test:deep
```

The integration test packs and installs the CLI with an empty offline npm cache,
checks the shipped file list and engine fingerprint, and exercises archive
scanning, review and selective approval. It verifies that dependency hooks and
a competing project-local CLI never execute. Hosted CI additionally covers
Linux, macOS, Windows, optional parsers, the Action and the Node 14 CLI floor.

Create the candidate archive outside the repository (POSIX shell example):

```bash
release_dir=$(mktemp -d)
npm pack --ignore-scripts --json --pack-destination "$release_dir"
```

Inspect the file list, size and integrity printed by npm. Runtime files, linked
text documentation and the Action example belong in the package; tests, corpus
data, generated reports, caches and demo media do not. Keep the archive and
any validation reports outside Git. After any source or metadata change, repeat
packing and validate the new candidate rather than publishing a stale archive.

## Configure the release boundary

The workflow `.github/workflows/publish.yaml` runs on `v*` tags. It validates
that the tag matches a stable package version and that the commit belongs to
`main`, then runs unit, integration, demo and optional-parser tests. A separate
fresh job stages the reviewed source using npm OIDC and provenance. There is
no build step, dependency installation, shared cache or downloaded artifact in
the publishing job. No npm publishing token is required.

Before creating a release tag, configure the package at:
https://www.npmjs.com/package/capsurface/access

- Trusted Publisher: GitHub Actions.
- Organization or user: `VictorMartins3`.
- Repository: `capsurface`.
- Workflow filename: `publish.yaml` (not the full path).
- Environment: leave empty; this workflow does not use a GitHub environment.
- Allow only `npm stage publish`; disable direct `npm publish` for this trust.
- Publishing access: require two-factor authentication and disallow tokens.

Creating or inspecting trust relationships can require npm browser/2FA
reauthentication. Never add a token to work around this requirement. Review
existing publishing tokens in npm account settings and revoke unused ones.
Use a hardware security key or passkey for the maintainer account where possible.
GitHub account 2FA must be enabled separately. This repository belongs to an
individual account, so organization-wide 2FA policy does not apply.

Protect release tags in the repository rulesets: restrict creation, updates
and deletion to repository admins. Review changes to release workflows as
carefully as changes to shipped source. Keep third-party Actions pinned to
full commit SHAs; Dependabot proposes updates for review with a seven-day
cooldown for routine version updates.

The project `.npmrc` disables lifecycle scripts and sets a three-day release
age filter. The age filter requires a recent npm version; older npm versions
in the compatibility test matrix may not enforce it. Parser versions are also
explicitly pinned. Review time-sensitive security fixes rather than blindly
waiting for the filter to expire.

## Stage and approve a release

After merging a reviewed version change and passing CI, create a tag matching
the package version on that exact commit. Do not move an existing release tag.
Pushing a new tag starts validation and staging, not final npm publication.
The current published versions are not retroactively given provenance by
adding this workflow.

When the workflow completes, open **Staged Packages** from the npm account
menu. Inspect the candidate tarball, its diff and provenance, then approve
with the maintainer's 2FA. This is the final publication step. Reject a candidate
whose content or origin does not match the reviewed release.

Verify the resulting registry version, integrity and provenance. Install that
exact version in a fresh directory with scripts disabled and run the documented
smoke example. Create GitHub release notes for that same immutable tag, then
announce the release. Provenance attests origin, not package safety.

References:
- https://docs.npmjs.com/trusted-publishers/
- https://docs.npmjs.com/staged-publishing/
- https://evilmartians.com/chronicles/the-secure-way-to-release-an-npm-package
