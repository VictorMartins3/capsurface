# Contributing to capsurface

## How it fits together

Five modules, one direction of data flow, no framework. Small enough to read
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
| Add or fix a detection rule | `lib/categories.js` |
| Change how source is read or capabilities extracted | `lib/scanner.js` |
| Fold obfuscated specifiers before the rules see them | `lib/normalize.js` |
| Change what fails the build vs. what is only reported | `lib/diff.js` |
| Change how packages are found on disk | `lib/discovery.js` |
| Change CLI flags, output, exit codes | `bin/capsurface.js` |

`lib/rules-version.js` hashes everything in `categories.js` that affects a
manifest. Touching a rule changes that hash, and `check` warns that existing
baselines were written by different rules. That is intentional: edit a rule and
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

No install step. The tool itself has zero dependencies.

```bash
git clone <this repo>
cd capsurface
node bin/capsurface.js --help   # sanity check
npm test                        # needs Node >=18 for node:test; the CLI itself only needs >=14
```

## Before opening a PR

- `npm test` passes (`node --test test/*.test.js`).
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

## Code style

- Plain CommonJS (`require`/`module.exports`), no build step, no TypeScript
  compilation. The source is what runs.
- Comments explain why, briefly, not what the code obviously does and not the
  history of how it got here. A long explanation of a bug it once had belongs in
  the PR description and `CHANGELOG.md`, not stacked in a doc comment forever.
- Match the existing style in the file you are editing over any personal
  preference.

## Reporting bugs vs. security issues

Regular bugs: open a GitHub issue. There are templates for the two that matter
most here, a false positive (capsurface reported something that is not real)
and a missed capability (it did not report something that is).

Anything that could let a malicious package evade detection, escape the scan
boundary, or otherwise compromise the scanner itself: see [SECURITY.md](SECURITY.md)
instead of a public issue.
