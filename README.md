# capsurface

[![ci](https://github.com/VictorMartins3/capsurface/actions/workflows/ci.yml/badge.svg)](https://github.com/VictorMartins3/capsurface/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/capsurface.svg)](https://www.npmjs.com/package/capsurface)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A capability-aware supply-chain scanner for npm packages. It statically
computes each dependency's capability surface (filesystem access, network
access, process execution, environment/credential access, dynamic code
execution, install-time lifecycle scripts) and flags escalation across
versions in CI, before a compromised release gets merged.

![capsurface catching a tampered dependency escalate its capabilities and fail the check in CI](https://raw.githubusercontent.com/VictorMartins3/capsurface/main/docs/demo.gif)

## Quick start

No dependencies, no build step.

```bash
npm ci --ignore-scripts
npx capsurface scan-tree node_modules --out .capsurface/manifests
```

```
Scanned 666 package install(s), including nested, symlinked and pnpm-store locations.

Runs code at install time: 5 of 666
  esbuild@0.28.2  risk=15
      postinstall: node install.js
  sharp@0.33.5  risk=10
      install: node install/check
  bcrypt@5.1.1  risk=4
      install: node-pre-gyp install --fallback-to-build
  ...
```

Approve that surface once, commit it, and let CI fail when it grows:

```bash
npx capsurface baseline .capsurface/manifests --out capsurface.lock.json
git add capsurface.lock.json

# in CI, before running dependency scripts or application code
npm ci --ignore-scripts
npx capsurface scan-tree node_modules --out .capsurface/manifests
npx capsurface check .capsurface/manifests --baseline capsurface.lock.json
```

Keep install scripts disabled until the scan and review finish, including
for packages already on a script allowlist. Approval of an older version
does not approve the new contents. Run required build scripts only after
review, under your package manager's explicit script policy.

When a dependency gains something it did not have, the check says what and
exits non-zero:

```
CAPABILITY ESCALATIONS (1):

  dotenv: 16.6.1 -> 16.6.99  [dotenv]  (risk delta +22)
    [capability-added] "Network access" was not present in 16.6.1 but appears in 16.6.99.
    [capability-added] "Sensitive credential/file targeting" was not present in 16.6.1 but appears in 16.6.99.
    [lifecycle-script-changed] script changed:
    previously approved: (none)
    now:                 "node ./lib/telemetry.js"
    [new-network-endpoints] new literal endpoint(s) referenced: https://telemetry-collector.example-exfil.net/v1/ingest
    new host(s): telemetry-collector.example-exfil.net
    [new-env-vars] new credential-shaped env var(s) referenced: NPM_TOKEN
    ⚠ NEW FLAG: CRITICAL: install-time lifecycle script (preinstall/install/postinstall) combined with
      network access and credential/env access, matching the self-propagating supply-chain worm pattern.
```

## Why

Supply-chain worms self-propagate across npm by the same pattern: a
trusted package gets a routine-looking point release that quietly adds a
postinstall script, network access, and credential harvesting, sometimes
with valid provenance attached. Provenance proves who published a package.
It says nothing about what new things the package can now do. A
capability-surface diff catches the second thing directly, on top of the
tooling developers already have (npm, package.json, JS source), with no
new language or runtime required.

## What npm 12 does not close

In August 2026 npm 12 began blocking install scripts by default, and pnpm
11, Yarn 4.14, Bun and Deno now do the same. You opt packages back in
through an allowlist (`allowScripts` in package.json, `allowBuilds` in
pnpm-workspace.yaml), and `npm ci --strict-allow-scripts` fails CI when a
new transitive dependency wants to run one.

That closed the vector most of this tooling was built for, and it means the
install-script question is largely answered by the package managers plus
[npm-script-lens](https://www.npmjs.com/package/npm-script-lens), which
statically analyses each pending install script so you can decide whether
to approve it. It is good, it parses with acorn rather than regexes, it
writes the native allowlist format for all four package managers, and it
has a `--diff` mode for capabilities gained across upgrades. If your
question is "which install scripts should I approve", use that.

capsurface does both halves of that. `capsurface allowlist` writes the list
for npm, pnpm and JSON consumers, with what each package reaches for
attached so the approval is an informed one rather than a rubber stamp.

The more interesting half is what is left after that door closes. The Semgrep writeup
of the npm 12 change puts it plainly: typosquatting, dependency confusion
and "plain old malicious runtime code" all survive it. Malicious runtime
code is not hypothetical, it is what the event-stream compromise actually
was: the payload lived in flatmap-stream's published files and ran when the
library was used, with no lifecycle script involved.

Verified rather than asserted. Given a package whose 3.1.0 is clean and
whose 3.1.1 reads `~/.npmrc` and `NPM_TOKEN` and POSTs them out on first
`require()`, with no install script anywhere:

| | result |
|---|---|
| npm-script-lens 1.16.0 | "1 with no risky install-time behavior", nothing to review |
| capsurface | exit 1, names the endpoint and `NPM_TOKEN`, HIGH exfiltration flag |

Neither is wrong. A tool scoped to install scripts should report nothing
when there is no install script. That scope is the difference: capsurface
diffs the capability surface of every file a package ships, so it sees a
payload that only runs at require time. `test/` and `docs/` are included on
purpose, since that is exactly where flatmap-stream hid.

## Install

No dependencies, no build step, just Node.js >= 14.

```bash
chmod +x bin/capsurface.js
./bin/capsurface.js --help
```

Run the test suite (needs Node >= 18 for the built-in `node:test` runner;
this is dev-only, the shipped CLI still needs only Node >= 14):

```bash
npm test
```

## Usage

Scan a single package:

```bash
capsurface scan node_modules/some-pkg --out manifest.json
```

Scan an entire `node_modules` tree:

```bash
capsurface scan-tree node_modules --out .capsurface/manifests
```

Prints a risk-ranked summary and writes one manifest per installed
package, including scoped packages. Follows nested `node_modules`,
symlinked packages, and pnpm's `.pnpm` store, all bounded to the project
directory: a symlink resolving outside it is reported and fails the run
instead of being followed (see CHANGELOG.md). In a monorepo, scanning a
workspace member's own `node_modules` still finds sibling workspace
packages through workspace-root detection; pass `--boundary <dir>` to
override this for layouts detection does not fit.

The output directory includes a `.capsurface-snapshot` inventory. Keep it
with the manifests: `baseline`, `check`, and `allowlist` use it to exclude
stale files from earlier scans and verify that the current files are intact.
Interrupted scans and concurrent writes fail rather than producing an
apparently clean inventory. After a crashed process leaves the directory
locked, rerun with a fresh output directory.

Manifest schema v4 includes `coverage`: files and bytes read, skipped files,
and I/O errors. Endpoints and env vars are collected beyond the report's
evidence samples. A resource limit or read failure marks analysis incomplete;
`scan`/`scan-tree` exit 2, and `baseline`/`allowlist` refuse to approve it.
`check` reports incomplete analysis as a failure even if it was already
present in the baseline. `--report-only` still reports those findings with
exit 0, but cannot suppress an invalid or unfinished snapshot.

Establish a baseline, once, after human review:

```bash
capsurface baseline .capsurface/manifests --out capsurface.lock.json
git add capsurface.lock.json
```

Gate CI on capability escalation before running dependency scripts:

```bash
npm ci --ignore-scripts
capsurface scan-tree node_modules --out .capsurface/manifests
capsurface check .capsurface/manifests --baseline capsurface.lock.json
```

Exits non-zero if any dependency's capability surface grew relative to the
committed baseline: new capability category, changed lifecycle script,
new network endpoint on a host it did not use before, new credential-shaped
env var. Add `--fail-on-new` to also fail on packages not yet in the
baseline, forcing an explicit review-and-rebaseline step.

`--json` emits the same report as a structured object: the rules
fingerprint, every escalation with its changes and new flags, and which mode
it ran in. A report nobody can aggregate is a report nobody keeps, and
`--report-only` only pays off if weeks of findings go somewhere other than a
CI log.

Start with `--report-only`. It prints the same report and exits 0, so you
can leave it in CI for a few weeks and see what it would have stopped
before you let it stop anything. A gate switched on blind, in a codebase
nobody has a baseline for yet, fires on the first upgrade and gets removed
the same week. Drop the flag once the findings look like ones you want to
block on.

Each installation is compared with its own baseline path first, then an
exact version or a single available predecessor. Several candidates with
identical approved surfaces are interchangeable; different surfaces require
explicit review. Permissions are never pooled across versions. pnpm store
paths change with versions, so upgrades with multiple possible predecessors
can require review until approved explicitly. Matching does not yet read
lockfile dependency edges.

A matching version is still scanned: a postinstall in one package can
rewrite a sibling's files without changing its version.

Produce the install-script allowlist npm 12 requires:

This includes npm's implicit `node-gyp rebuild` when a package ships
`binding.gyp` without an overriding `install`/`preinstall` or `gypfile: false`.
The manifest records the possible command, not whether local npm policy
authorizes it to run.

```bash
capsurface allowlist .capsurface/manifests
```

```
5 of 666 installed package(s) run code at install time.

Add to package.json:

  "allowScripts": [
    "bcrypt@5.1.1",
    "esbuild@0.25.12",
    "esbuild@0.28.2",
    "msgpackr-extract@3.0.4",
    "sharp@0.33.5"
  ]

What each one does at install time, from its own source:

  esbuild@0.28.2  (esbuild)
      postinstall node install.js
      reaches     filesystem, network, process execution, env
      talks to    https://registry.npmjs.org/..., https://nodejs.org/en/download/
      ⚠ HIGH: install-time lifecycle script combined with process execution.
```

Writing the list is the easy half and every tool in this space does it.
The half that takes judgement is deciding what belongs on it, so each entry
carries what that package's own source reaches for and where it talks to,
from the same manifests the gate uses. `--format pnpm` emits
`onlyBuiltDependencies` instead, `--format json` is machine readable and
carries the rules fingerprint, and `--names` drops the version pin.

Diff two manifests directly:

```bash
capsurface diff old-manifest.json new-manifest.json
```

## Limitations

This is static regex-based heuristic analysis, not a sound one.

- Cannot see through minification, or a specifier that only exists once the
  program runs (`require(process.env.MOD)`, a name built in a loop).
  `lib/normalize.js` folds the constructions that are statically known, so
  concatenation, a variable holding a literal, hex and unicode escapes,
  `String.fromCharCode`, array joins, string reversal, `atob` and
  `Buffer.from(..., 'base64'|'hex')` all resolve to the specifier the runtime
  will see. `test/evasion.test.js` asserts both directions, and the rows that
  are still misses are in there on purpose.
- Cannot see capabilities acquired only at runtime, such as dynamically
  fetched and `eval`'d code, beyond a generic "dynamic execution" flag.
- False-negative risk by construction. This is a triage signal for
  human/CI review, not an enforcement boundary. Pair it with runtime
  sandboxing (WASI, microVMs, egress allowlists) for actual enforcement.
- Category detection is a proxy, not ground truth. "exec" is detected via
  `require('child_process')` specifically to avoid colliding with
  unrelated APIs like `RegExp.prototype.exec()`.
- A plain `.ts` file that imports only types without writing `import type`
  still counts. `import type` and declaration files are erased because both
  are unambiguous; this case is not, and telling
  `import { SpawnOptions } from 'child_process'` from
  `import { execSync } from 'child_process'` needs type information rather
  than a naming convention. Measured at 87 of 20,039 packages, and guessing
  from casing would trade a small number of false positives for false
  negatives in the category where they cost most.
- The comment and regex-literal-aware scanner (`blankComments` in
  `lib/scanner.js`) is a hand-rolled character scanner, not a real parser.
  Regex-vs-division is ambiguous in JS without full parsing; see the doc
  comment there for what is and is not handled, and `${...}` template
  interpolation is a known blind spot.
- Yarn Berry's Plug'n'Play mode does not produce a `node_modules` directory
  at all, so it is not scannable as-is; set `nodeLinker: node-modules` in
  `.yarnrc.yml`, or use npm, pnpm, or classic Yarn. The other three layouts
  are verified against real installs, see [docs/VERIFICATION.md](docs/VERIFICATION.md).
- Scope is npm's install-time surface only: package.json scripts and the
  source of installed dependencies. No visibility into editor or IDE
  auto-execution hooks, which is the second vector the keyv/cacheable
  attack used and out of scope for a `node_modules` scan by design.

## How it compares

Where capsurface sits among the tools that already exist:

| | Detection basis | Timing model | Scope | Deps | Deployment |
|---|---|---|---|---|---|
| Socket | Behavioural analysis, registry-wide monitoring, threat intel | Proactive, can flag a compromised publish within minutes | whole package | n/a | Hosted SaaS |
| Semgrep Supply Chain | Lookup against 80,000+ known-malicious packages | Reactive, needs the package already in the database | whole package | n/a | Hosted SaaS |
| GuardDog 3.2 (Datadog) | YARA rules, plus an optional kernel sandbox and registry-metadata rules | Point-in-time, one version in isolation | whole package | Python + native | OSS CLI, local |
| js-x-ray 8.2 (NodeSecure) | AST with a variable tracer and constant folding | Point-in-time, per file | whole package | several | OSS library |
| wormguard 1.0.3 | AST with taint approximation, IoC corpus, script hashes | Delta on inventory and script hashes | install scripts | 7 | OSS CLI, local |
| capsurface | Source-text rules over folded literals | Delta on capability surface, vs a reviewed baseline | whole package | none | OSS CLI, local, offline |

Two things are solved better elsewhere, and capsurface does not compete on
either. Socket's real-time monitoring and Semgrep's malicious-package database
catch a compromised publish before `npm install` ever runs, and correlate
against maintainer behaviour and typosquatting, which a static offline tool
cannot. Dynamic sandboxing beats static analysis on obfuscated payloads, which
is why the OpenSSF's own [Package Analysis](https://github.com/ossf/package-analysis)
runs packages in gVisor.

Where it does compete: on the evasion corpus it resolves 14 of 14 obfuscated
`child_process` specifiers, against js-x-ray 9, wormguard 8, and GuardDog 3 (5
with two pending patches). And on the timing model. Point-in-time scanners ask
"is this version risky in isolation", so a package that legitimately uses the
network re-warns forever. capsurface asks "did this update add a capability the
version we already reviewed did not have", the same question `git diff` answers
for code. The unit of trust is a plain JSON file committed next to
`package-lock.json` and reviewed in PRs, not a hosted API. It is a cheap first
gate, not a replacement for Socket or Semgrep.

Full head-to-head numbers, the scope comparison, the GuardDog benchmark, and
the keyv/cacheable case study are in
[docs/VERIFICATION.md](docs/VERIFICATION.md).

## Verification

Everything above is measured, not asserted. In short: pressure-tested against
20,039 packages sampled across the registry, which turned up 11 rule errors,
each fixed and measured; scanned across four real production apps (5,853
packages, 2 CRITICALs, both legitimate); and held to a standing test of 82
popular packages diffed two years and a major version apart, so a routine
upgrade does not trip the gate.

The full writeup, every table, and the numbers behind each claim are in
[docs/VERIFICATION.md](docs/VERIFICATION.md). See also `test/` (`npm test`) and
[CHANGELOG.md](CHANGELOG.md).

## Example

`examples/malicious-pkg-v1` and `examples/malicious-pkg-v2` model a
believable benign package (`handy-color-utils`) compromised in a
routine-looking patch release. v2 adds a `postinstall` script that reads
`~/.npmrc`, `~/.ssh/id_rsa`, `NPM_TOKEN`, and `GITHUB_TOKEN`, beacons them
to a remote host, and attempts to self-publish with the harvested token,
modeled on the publicly reported Shai-Hulud npm worm family.

Run `examples/run-demo.sh` to see capsurface baseline v1, scan v2, and
fail the CI check with the exact capability diff.

## Design notes

- No dependencies. Zero install friction, the point of building this fast
  and cheap first.
- JSON in, JSON out. Manifests and the lock file diff cleanly in PRs and
  feed easily into other tooling.
- The baseline is keyed by package name, not pinned to a single version.
  A name can hold more than one approved manifest for packages installed
  at multiple versions in the same tree.
- Discovery follows real package-manager layouts, not a flat top-level
  listing: nested `node_modules`, symlinks, and pnpm's `.pnpm` store are
  all walked, deduplicated by realpath, and cycle-safe. See
  `test/discovery.test.js` and CHANGELOG.md.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md) covers how the pieces fit, where to change
what, and the one rule that matters most: a rule change is measured against
real packages, not argued, and the pull request template asks for the numbers.

Security issues go through [SECURITY.md](SECURITY.md), not a public issue.

## License

MIT, see [LICENSE](LICENSE).
