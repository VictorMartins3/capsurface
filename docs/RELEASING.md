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

## Publish deliberately

Before publication, confirm access to the intended npm package and repository,
the final version, license and public security-reporting channel. The repository
must be public for users to read the source and use its Action. Repository
visibility, npm publication and GitHub release creation are separate maintainer
actions; merging the preparation PR does not perform them.

For automated publication, prefer npm's [trusted publishing](https://docs.npmjs.com/trusted-publishers/)
when available for the package, and configure the exact repository and workflow.
Follow npm's current bootstrap instructions for a first publication. Do not add
a long-lived publishing token merely to make the first release easier.
[Provenance](https://docs.npmjs.com/generating-provenance-statements/) requires a
public source repository matching package.json; trusted publishing generates it
automatically when supported. It attests publication origin, not package safety.

Once publication is authorized, publish the validated candidate using the
chosen authenticated release flow, tag that exact commit, and create a GitHub
release with the reviewed notes. Verify registry version, tarball integrity and
repository metadata, then install the exact version in a fresh directory with
scripts disabled and run the documented smoke example. Verify the Action at
its immutable commit too. Announce the release only after these checks pass.
