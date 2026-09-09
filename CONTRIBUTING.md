# Contributing to capsurface

Start with [ARCHITECTURE.md](ARCHITECTURE.md): five modules, one
direction of data flow, and a table of where to change what.

## Setup

No install step. The tool itself has zero dependencies.

```bash
git clone <this repo>
cd capsurface
node bin/capsurface.js --help   # sanity check
npm test                        # requires Node >=18 for node:test; the CLI itself only needs >=14
```

## Before opening a PR

- `npm test` passes (`node --test test/*.test.js`).
- `./examples/run-demo.sh` still catches the bundled escalation fixture.
- New behavior has a regression test in `test/`. If you're fixing a bug,
  the test should fail on the old code and pass on the new code. That's
  what makes it a regression test rather than just a feature test.
- If you're touching `lib/scanner.js`'s `blankComments`, be especially
  careful: it's a hand-rolled comment/regex-literal-aware character
  scanner, and its failure mode (a misjudged `/` desyncing state for the
  rest of the file) is subtle. Add a test that constructs the exact
  adversarial input, not just a description of the fix.

## Design constraints (please read before adding a dependency)

- **Zero runtime dependencies is a deliberate design choice, not an
  accident.** It's most of the point: no install friction, no transitive
  supply-chain surface for a supply-chain security tool, small enough to
  read end to end. A PR adding a dependency needs a strong justification
  and will get real scrutiny.
- **No network calls.** Everything this tool does is local and offline.
  Don't add a feature that requires reaching a registry, an API, or any
  other network resource.
- Dev-only tooling (the test runner) can rely on Node's built-ins
  (`node:test`, `node:assert`) for the same reason. No new dev
  dependencies without a good reason either.

## Code style

- Plain CommonJS (`require`/`module.exports`), no build step, no
  TypeScript compilation. The source is what runs.
- Comments should explain *why*, briefly, not narrate the history of how
  the code got here. If something is worth a long explanation of a bug it
  once had, that belongs in the PR description and `CHANGELOG.md`, not
  stacked in a doc comment forever.
- Match the existing style in the file you're editing over any personal
  preference.

## Reporting bugs vs. security issues

Regular bugs: open a GitHub issue with a minimal reproduction.

Anything that could let a malicious package evade detection, escape the
scan boundary, or otherwise compromise the scanner itself: see
[SECURITY.md](SECURITY.md) instead of a public issue.
