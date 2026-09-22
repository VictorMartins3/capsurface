# Contributing to capsurface

## How it fits together

Small modules, one direction of data flow, no framework. Small enough to read
in one sitting, which is the point: a security tool should be auditable by the
person adopting it.

```
bin/capsurface.js      CLI only: arguments, output, exit codes
      |
      v
lib/discovery.js       which directories are packages, and the symlink boundary
      |
      v
lib/scanner.js         one package directory -> one capability manifest
      |                (uses lib/categories.js for the rules)
      v
lib/diff.js            baseline manifest(s) vs current -> escalation report
```

Where to change what:

| You want to | Edit |
|---|---|
| Classify AST process launch modes | `lib/process-operations.js`, `lib/ast-imports.js` |
| Attribute filesystem operation detail | `lib/filesystem-operations.js` |
| Add or fix a detection rule | `lib/categories.js`, `lib/ast-capabilities.js` |
| Change how source is read or capabilities extracted | `lib/scanner.js` |
| Fold obfuscated specifiers before the rules see them | `lib/normalize.js` |
| Change what fails the build vs. what is only reported | `lib/diff.js` |
| Match an installation to its approved predecessor | `lib/comparison.js` |
| Explain changes or apply a selective approval | `lib/review.js`, `lib/approval.js` |
| Collect and explain file-level capability relationships | `lib/source-context.js`, `lib/scanner.js` |
| Explain potential import paths from installation scripts | `lib/install-context.js`, `lib/ast-imports.js` |
| Hash installed content or enforce approval expiry | `lib/content-integrity.js`, `lib/approval-policy.js` |
| Explain npm dependency origins | `lib/provenance.js` |
| Export review results to SARIF | `lib/sarif.js` |
| Run the GitHub review Action | `action.yml`, `bin/action-review.js` |
| Read and publish scan inventories | `lib/snapshot.js` |
| Change how packages are found on disk | `lib/discovery.js` |
| Change CLI flags, output, exit codes | `bin/capsurface.js` |

`lib/rules-version.js` hashes the detection rules and the scanner,
normalizer, discovery, diff, comparison, filesystem-operation, content-integrity
approval-policy, source-context, install-context AST import, typed-parser, process-operation and AST capability implementations (with line endings normalized).
Changing these changes that hash, and `check` warns that existing
baselines were written by different rules. That is intentional: edit the engine and
every committed baseline means something slightly different, which a security
gate must not hide.

Two decisions shape everything:

- **Detection is separate from gating.** `scanner.js` records what a package
  can do. `diff.js` decides whether a change in that is worth failing a build
  over. Reading an env var is worth recording and not worth blocking, so `env`
  carries `gatesOnAppear: false`. Record generously, gate narrowly.
- **Rules key on acquisition, not on a name.** `exec` matches
  `require('child_process')`, not `exec(`, because method names collide with
  unrelated APIs. `RegExp.prototype.exec`, lru-cache's `fetch(k, opts)`,
  rxjs's `connectable.connect()` and puppeteer's `$eval` all produced false
  positives when a rule matched a bare call. If a new rule must match a call
  site, expect it to be wrong on a corpus and check before shipping it.

## Setup

No install step. The default scanner has zero dependencies. Experimental AST analysis
uses optional, exact-version Acorn and acorn-typescript peers; no parser is
loaded in normal scans.

```bash
git clone <this repo>
cd capsurface
node bin/capsurface.js --help   # sanity check
npm test                        # needs Node >=18 for node:test; the CLI itself only needs >=14
```

## Before opening a PR

- `npm test` and `npm run test:integration` pass. The integration test needs
  npm and Git; it packs local fixtures and the CLI, installs them offline with
  lifecycle scripts disabled, and exercises review and selective approval.
- `./examples/run-demo.sh` still catches the bundled escalation fixture.
- New behavior has a regression test in `test/`. If you're fixing a bug, the
  test should fail on the old code and pass on the new code. That is what makes
  it a regression test rather than just a feature test.
- **A rule change is measured, not argued.** Scan a corpus of real packages
  with and without your change and diff the manifests: how many packages gain
  the capability, how many lose it, how many risk flags move. A rule that looks
  obviously right is how every one of the errors in `CHANGELOG.md` got written
  in the first place. The numbers go in the PR description.
- If you're touching `lib/scanner.js`'s `blankComments`, be especially careful.
  It is a hand-rolled comment and regex-literal aware character scanner, and its
  failure mode, a misjudged `/` desyncing state for the rest of the file, is
  subtle. Add a test that constructs the exact adversarial input, not just a
  description of the fix.

## Design constraints (please read before adding a dependency)

- **Zero runtime dependencies is a deliberate choice, not an accident.** It is
  most of the point: no install friction, no transitive supply-chain surface
  for a supply-chain security tool, small enough to read end to end. A PR
  adding a dependency needs a strong justification and will get real scrutiny.
- **No network calls.** Everything this tool does is local and offline. Do not
  add a feature that requires reaching a registry, an API, or any other network
  resource.
- Dev-only tooling (the test runner) can rely on Node's built-ins (`node:test`,
  `node:assert`) for the same reason. No new dev dependencies without a good
  reason either.

The optional AST mode uses Acorn instead of implementing or vendoring a JavaScript
parser. TypeScript/JSX use the acorn-typescript extension, whose only peer is
Acorn; neither adds mandatory dependencies to the default scanner. The extension
preserves source locations without compilation, source maps or project plugins.
Both versions are pinned in peer declarations and loaders; updates need AST
regressions and corpus measurements. To work on that mode:

```bash
npm install --no-save --package-lock=false --ignore-scripts acorn@8.15.0 acorn-typescript@1.4.13
npm run test:deep
```

Keep the normal regression and integration jobs independent of this install.

## Commits and pull requests

Use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/)
for commit subjects and PR titles:

```text
feat(review): add SARIF output
fix(scanner): reject incomplete scans
test(integration): cover selective approvals
```

Use `feat` for a new feature, `fix` for a bug fix, and `docs`, `test`, `ci`,
`refactor`, `perf`, `build`, `style`, `chore` or `revert` when appropriate.
Scopes are optional; use a module or subsystem when it clarifies the change.
Write a short imperative description in English, without a trailing period.
Add a body when the problem, tradeoff or compatibility impact needs explaining.
Mark incompatible public-interface changes with `!` and a `BREAKING CHANGE:`
footer describing the migration.

Keep commits focused and reviewable. The PR description should explain the
problem, resulting behavior, validation and compatibility impact using the
repository template. Include measurements for detection changes; do not
claim a benchmark or integration passed unless it was run. PR titles are
checked in CI. Keep author attribution accurate.

## Release notes and generated files

Update `CHANGELOG.md` for changes users need to know about, under `Unreleased`.
Describe the final behavior and migration, not the sequence of implementation
steps. Internal refactors and test-only changes usually need no release note.
Measurements belong in `docs/VERIFICATION.md`; check results belong in the PR.
Do not invent release dates or create a release during an ordinary code change.

Generated reports, scan inventories, package tarballs and profiling output
are not source files. Keep them in a temporary directory or `.capsurface/`.
The reviewed baseline is an intentional versioned input in consuming projects.
CI artifacts are temporary outputs; enable uploads only when they are useful
for review or debugging. Small deterministic test fixtures belong in `test/`
or `examples/` and should be clearly identified.

## Code style

- Plain CommonJS (`require`/`module.exports`), no build step, no TypeScript
  compilation. The source is what runs.
- Comments explain why, briefly, not what the code obviously does and not the
  history of how it got here. Explain bug history in the PR; keep source comments focused on current
  behavior and invariants.
- Match the existing style in the file you are editing over any personal
  preference.

## Reporting bugs vs. security issues

Regular bugs: open a GitHub issue. There are templates for the two that matter
most here, a false positive (capsurface reported something that is not real)
and a missed capability (it did not report something that is).

Anything that could let a malicious package evade detection, escape the scan
boundary, or otherwise compromise the scanner itself: see [SECURITY.md](SECURITY.md)
instead of a public issue.
