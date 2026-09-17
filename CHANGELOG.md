# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Initial capability-aware supply-chain scanner: `scan`, `scan-tree`,
  `baseline`, `check`, `diff` commands. Computes a per-package capability
  manifest (filesystem, network, exec, env/credential access, dynamic
  eval, native/FFI, lifecycle scripts) and gates CI on escalation between
  a committed baseline and the currently installed tree.
- `--boundary <dir>` flag on `scan-tree` to override the symlink-escape
  boundary for layouts the default heuristic does not fit.
- `capsurface allowlist`, which writes the install-script allowlist npm 12
  and its peers require, for npm, pnpm and JSON consumers, with what each
  package reaches for attached so the approval is informed.
- `--report-only` on `check`: the same report, exit 0. A blocking gate does
  not get switched on in an unfamiliar codebase on day one, and asking for
  that is how a tool gets evaluated for an afternoon and dropped.
- Lock file schema v2: `packages: {name: Manifest[]}`, supports a name
  installed at multiple versions in the same tree. A v1 lock file with a
  single manifest per name still loads.
- Manifest schema v3: `skippedLargeFiles` records any source file skipped
  for exceeding the 15 MB scan cap, so reduced coverage shows up in the
  manifest instead of staying silent.

### Fixed

Found by testing against real npm and pnpm installs and two rounds of
independent code review, not only the bundled demo fixture.

- Discovery gaps. `scan-tree` only listed the immediate children of the
  given root. `Dirent.isDirectory()` reports false for a symlink even when
  it points at a directory, so every `file:` dependency, workspace
  package, `npm link`, and pnpm's entire symlink-based node_modules layout
  was invisible. Nested `node_modules`, created routinely by
  version-conflict resolution, were never scanned either. Fixed with a
  realpath-deduplicated, cycle-safe walk that also understands pnpm's
  `.pnpm` store.
- Silently dropped duplicate manifests. Once discovery could find the same
  package name at multiple installed versions, the name-keyed `Map` used
  for baseline/check silently kept only the last one read. Fixed by keying
  on `Map<name, Manifest[]>` with a union-based diff, so a capability
  approved in any previously-baselined version is not treated as new.
- CI-gate bypass. `check` could exit 0 despite a new risk flag, for
  example a version bump adding only an obfuscated payload with no
  literal token for the category regexes to match, because `escalated`
  was only set by a tracked capability category flipping from absent to
  present. Fixed: any new risk flag now escalates.
- False CRITICAL flags on real, safe packages (`glob`, `axios`) from
  treating `prepare`/`prepublish` the same as
  `preinstall`/`install`/`postinstall`. Per npm's documented behavior,
  `prepare` does not run for a normal registry install, only local dev or
  a git-URL dependency. Fixed by scoring build-time-only scripts far lower
  than install-triggering ones.
- False positives from comments and a regex-literal parsing bug. Patterns
  matched inside `//`/`/* */` comments and JSDoc examples, for example a
  JSDoc example calling `fs.writeFileSync` read as real filesystem access
  on lodash. The comment stripper written to fix this had its own bug: it
  did not understand regex literals, so a character class containing a
  quote (lodash's own `/['\n\r\\]/g`) was misread as an unterminated
  string, desyncing comment detection for the rest of the file. Two
  further variants of the same class of bug (nested parens, a keyword
  immediately followed by a string or regex literal) were found in later
  review passes before the heuristic was fully closed.
- A path escape in the symlink-following discovery fix. A package's own
  node_modules is exactly where its postinstall script could plant a
  symlink; following it unbounded let `scan-tree` read and report on
  arbitrary filesystem locations outside the project. Fixed by bounding
  symlink targets to the project directory, with workspace-root detection
  so scanning a single monorepo member's node_modules still finds sibling
  packages, reporting an out-of-bounds symlink as a failure instead of a
  warning, and closing a related TOCTOU window by recording each package's
  validated realpath rather than its original symlink path.
- Minified or bundled build output (`*.min.js`, `dist/`, `umd/`, etc.) no
  longer trips the standalone obfuscation signal on its own. Legitimate
  and common enough to train reviewers to ignore the signal otherwise.
- `unionOfManifests` recomputed once per name instead of once per
  installed version in `check`. `scan-tree` on a nonexistent,
  non-directory, or unreadable root now fails loudly instead of silently
  reporting 0 packages scanned with exit 0. `unionOfManifests` shape now
  matches a real manifest's shape (`obfuscationSignal`,
  `lifecycleScripts.present`/`installTriggering`).

### Validated against 16 production open source projects

Scanned fastify, got, eslint, prettier, nest, express, koa, socket.io,
axios, chalk, hono, winston, zustand, pm2, commander and date-fns:
11,057 package installs, 4,580 distinct packages. Rather than reading
findings one at a time, every evidence entry now records which rule
produced it, so rules can be judged by what they actually match at scale.

Four rules were wrong and are fixed:

- Credential env detection keyed on vendor prefixes, so `NPM_` matched
  `npm_config_geckodriver_cdnurl`. npm passes its own configuration to
  install scripts that way, which pushed geckodriver and edgedriver to
  CRITICAL without either reading a credential, and would have counted
  `GITHUB_WORKSPACE` and `AWS_REGION` too. It now matches the noun that
  denotes a secret, not the vendor.
- Credential names now require an actual `process.env` read. The bare-name
  rules were matching help text telling users to set `GITHUB_TOKEN`,
  assertions in shipped tests, and string literals in config lists.
- `.connect(` and `.createConnection(` were removed, applying the rule
  already used for exec: key on the module import, not a call site whose
  name is shared with unrelated APIs. It was reporting inquirer's
  `this.process.connect()` and rxjs's `connectable.connect()` as network
  access. It did catch one real thing the module list missed,
  `http2.connect`, so `http2` was added.
- The obfuscation signal counted comment-blanked lines, because blanking
  preserves length to keep columns accurate. A 592-character JSDoc line
  became 592 spaces and still counted as long, so documentation was
  reported as obfuscation. It now measures trimmed code length and needs
  several long lines, since one long line is a data blob or a large regex.

Across those 4,580 packages the result is 1 CRITICAL, and it is true: nx
runs a postinstall, talks to the network, reads `process.env.GITHUB_TOKEN`
and the user's `.npmrc`.

The ecosystem-wide install-time surface is small and concentrated. Only
esbuild (9 of 16 projects) and unrs-resolver (7) are common, followed by a
long tail of one-offs: cypress, sharp, puppeteer, fsevents, workerd, re2,
core-js, geckodriver, edgedriver. Under npm 12 that is the list every
project now has to allowlist.

### Validated against 20,039 packages sampled across the registry

The 16-project campaign above reads dependency trees, which is the
population this tool runs on but not the population it can be wrong about.
This one samples the registry itself, stratified so the sample is not just
popular packages: the dependency closure of 245 well-known seeds, a uniform
random draw from all 4,431,335 published names, scoped packages, recent
publishes taken from the changes feed, and packages found by searching for
native and install-script tooling. 22,696 tarballs fetched, 20,039 with
source to read, 0 scan errors.

Eleven rules were wrong. Each was found by attributing every evidence entry
to the rule that produced it, then reading what that rule actually matches
at scale, and each fix was measured by scanning the whole corpus with and
without it.

Capabilities the scanner was crediting that do not exist:

- TypeScript syntax the compiler erases. A `.d.ts` file emits no JavaScript
  and `import type` is erased wherever it appears, but both were granting
  capabilities: `typescript` read as having process execution because of
  `import { ChildProcess } from 'child_process'` in a declaration file.
  23 packages of 5,761 in the sample at the time.
- `.node` matched any string literal ending that way, so
  `if (!source.endsWith('.node'))` counted as loading native code. Keying on
  the load instead removed 14 of those and found 13 packages it had been
  missing, `lmdb`, `bufferutil`, `argon2` and `classic-level` among them,
  which reach native code through `node-gyp-build` and `bindings`.
- `eval(` matched a property named eval and any identifier ending in one,
  because `$` is not a word character: puppeteer-core's `$eval`, Redis's
  `redis.eval(...)` running a Lua script, which is how `rate-limiter-flexible`
  tripped it. 71 packages had nothing else as evidence.
- `new Function("return this")` is how bundlers reach the global object. Its
  argument is a constant, so nothing an attacker chose is executed, and it
  was the entire dynamic-eval evidence for 122 packages.
- A credential path was counted when it was only named. 34 of the 75
  packages with that capability had no access at all: shikiji's syntax
  grammar listing `.ssh/config` as a file type, denylist regexes, a
  placeholder `C:/Users/your-name/.ssh/id_rsa`, and a security scanner's own
  documentation of the attack it detects.
- `echo` cannot execute anything, but a postinstall containing only one
  still marked the package as running code at install time. `aethercall` was
  CRITICAL on that basis.

Capabilities the scanner was missing:

- The `node:` prefix, outside the network category. `node:fs`,
  `node:child_process` and `node:vm` are the documented modern spelling, and
  `require('node:child_process')` was invisible to the process-execution
  rule: a complete bypass written in the syntax Node's own documentation
  recommends. 1,322 packages of 23,806, 5.6%, were missing a capability they
  genuinely have, 938 filesystem and 741 process execution, and 47 new HIGH
  flags came with them.

- Lifecycle script commands were recorded and never matched against
  anything. That hid the one package in the corpus that beacons out on
  install, `xhjxhjtestrce123`, whose preinstall and postinstall both run
  `curl http://<host>/?host=...` and whose manifest said network access was
  absent. It also hid `iso-process`, whose postinstall inlines
  `require('child_process').execSync('npm i', {cwd: join('..', 'esm')})`.
- Files a package ships in `bin`. They carry no extension because the shell
  runs them through their shebang, and 502 of the 4,502 packages that ship
  an executable, 11.2%, point `bin` at a file the extension filter never
  read. Re-fetching a sample of them and reading the file gave 26 of 158 a
  capability the manifest had missed; `turbo` picked up filesystem, process
  execution and env, `bunyan` picked up network, process execution and
  dynamic eval. For four of them the scanner had read no file at all and
  reported a risk score of 0.

Reporting fixes:

- Evidence snippets now centre on the match. A minified bundle is one
  enormous line, so the leading 200 characters routinely showed text with no
  relation to what matched: yarn's `lib/cli.js` reported `process.binding()`
  with an excerpt of an inline-import comment from elsewhere in the line.
- "Nothing was read" and "nothing was found" produced the same empty
  manifest, and 12.5% of the sample reads that way. The manifest now records
  `noReadableSource`, and it joins obfuscation and oversized files in the
  set of diff changes that gate, because all three mean there is code here
  we could not see.
- 1,919 of 31,128 extracted network endpoints carried junk: an escape
  sequence, since `"http://localhost:3000\n"` in source is a backslash and
  an n; sentence punctuation from an error message; markdown angle brackets;
  and a comma joining two URLs in one config string. `https://.` was also
  being recorded, because the host pattern accepted a bare dot.
- The obfuscation signal was reading generated-but-readable lines as packed
  code: declaration files with long type unions (22 packages, `twilio` and
  `typeorm` among them), tsc's `exports.a = exports.b = ...` re-export
  chain, ESM barrel re-exports, and a single long regex literal. Build
  output conventions were also incomplete; `bundles/`, `fesm2022/`,
  `esm2020/`, `coverage/` and `.yarn/releases/` are machine-generated and
  were being read as hand-authored source.

What the sample says about the ecosystem. 469 of 20,039 packages run
something at install time, 2.3%. 185 of those run a JavaScript file, 111 are
node-gyp or prebuild, 21 inline code with `node -e`, 8 only print a message,
and exactly one pipes a download into a shell. Of the 20,039, 8 are
CRITICAL and 231 HIGH.

That CRITICAL count was 37 before the last rule change, and the 29 that
moved are worth describing, because they are the reason the rule changed.
Almost all were agent and MCP command-line tools, a shape that barely
existed a year ago, which run a postinstall, talk to the network, and read
their own service key. The flag told figma-image-exporter, which runs a
postinstall, talks to api.figma.com and reads FIGMA_TOKEN, that it matched
Shai-Hulud. A worm propagates on credentials belonging to the environment
it lands in, an npm or GitHub token, an SSH key, AWS keys, ~/.npmrc, and
that is now what the flag requires. The other 29 are still reported, one
severity down and described as what they are. The 8 that remain, yarn, nx,
github-registry-auth, node-pty-prebuilt-multiarch, data-primals-engine,
railwise-ai, @deskpro/apps-dpat and sdl-mcp, all genuinely reach for
credentials that are not theirs.

### Does an ordinary upgrade still pass

Two standing regressions, because they answer different questions.

**A two-year jump.** 82 popular packages at their last release before
2024-09-01, diffed against the current release.

| | escalations of 82 |
|---|---|
| Before the fixes above | 5 |
| After the false-positive fixes | 3 |
| After the `node:` fix | 6 |

The number went up, and it went up because the scanner started seeing things
it had been blind to. `nanoid` 6 added a CLI that reads files with
`import { readFileSync } from 'node:fs'`, `vitest` spawns processes with
`node:child_process`, and neither was visible before. A capability a
dependency did not have two years ago is exactly what this is supposed to
raise once. The other three: `prisma`'s `preinstall` genuinely changed
across a major and it began reading `PRISMA_PLATFORM_AUTH_FILE`, `fastify`
reads `process.env.GITHUB_TOKEN` in `scripts/validate-ecosystem-links.js`, a
repository CI script it publishes inside its tarball, and `vite` 8 began
referencing `COPILOT_GITHUB_TOKEN` to detect whether it is running inside an
agent.

**Consecutive releases**, which is how teams actually upgrade: for the same
packages, every fifth release since 2024 diffed against the one before it.
396 upgrades, 19 escalations, 4.8%. About one upgrade in twenty asks for a
human glance, and the sample above says they are worth glancing at:
`prettier` 3.7 really did add a `fetch` call to its experimental CLI.

That test is also what found the `node:` blind spot. `glob` appeared to gain
filesystem access between two patch releases, which is not a thing that
happens, and the reason was that 13.0.1 spells it `node:fs`.

### Changed


Tuned against a real dependency upgrade rather than only the bundled
fixture. Installing 14 popular packages at two-year-old versions,
baselining, then upgrading all of them to current produced 16 escalations,
every one of them routine library evolution and none security relevant. A
gate that fires 16 times on an ordinary upgrade gets switched off, so these
classes are now reported without failing the build:

- A changed `prepare`/`prepublish` body no longer escalates. It does not run
  for a registry install at all, and eleven of the sixteen escalations were
  build-tooling swaps (tshy, husky, lefthook, ts-scripts).
- New env var reads escalate only for credential-shaped names. Upgrades
  routinely add `NO_COLOR`, `no_proxy`, `DOTENV_CONFIG_QUIET`.
- The `env` capability appearing on its own no longer escalates, for the
  same reason. Credential-shaped access is still covered by the
  sensitiveTargets category.
- A new network endpoint escalates only when the package also runs at
  install time or touches credentials, which is the exfiltration shape.
  Every new endpoint seen on the upgrade was a documentation or
  issue-tracker link in a comment or error message.
- `fetch` is no longer matched as a bare `fetch(`. lru-cache's cache-fill
  method is `fetch(k, opts)`, which made lru-cache and everything bundling
  it (glob, via path-scurry) read as having network access. Real uses of
  the web API are still matched, and node-fetch, undici, got, superagent
  and request were added to the network module list.
- `dist-node/`, `dist-esm/` and similar suffixed build directories now
  count as build output, so an ordinary minified build no longer trips the
  obfuscation signal.

After this, the same upgrade produces 0 escalations while the worm fixture
and every detection regression test still fail the gate.

`scan-tree` now prints the install-time execution surface before the risk
ranking. On a 215-package production tree exactly one package ran anything
at install time (bcrypt, via node-pre-gyp), and it scored 4, sorting below
twenty higher-scoring packages that cannot execute during install at all.
The aggregate score answers "how much can this package do"; the first
question a reviewer has is "what runs on npm install".

### Performance

Measured by profiling a 2,500-package scan and verified by re-scanning the
full 20,039-package corpus: every manifest is identical to the character
after each change. 84 to 161 packages/s single threaded, and the whole
corpus in 37.5s rather than 53.8s.

- `blankComments` appended every character of every scanned file to an
  array and joined it, which for a megabyte bundle means a million-element
  array and the garbage collection that follows. It was 28% of scan time.
  Only comment characters ever differ from the input, so the state machine
  now records where the comments are and the result is assembled from
  slices with blanks spliced over those ranges; a file with no comment is
  returned unchanged.
- Every file was split into lines twice, once blanked and once original, to
  use the original only where evidence gets recorded. Blanking preserves
  length and line breaks, so both share their boundaries: they are walked
  and the original is sliced on demand.
- The contextual rule added for credential paths ran its expensive context
  regex before its cheap match regex, on every line of every file, 12% of
  scan time.
- A capability category already present with a full evidence quota cannot
  learn anything from another match, but all of its patterns still ran
  against every remaining line. Saturated categories now drop out.
- Earlier: `blankComments`'s per-character identifier and whitespace checks,
  about 16% of total scan time on a 462 MB corpus by profile, replaced with
  charCode arithmetic instead of the regex engine, for an 18% CPU-time
  reduction on that corpus.

### Security

- Evasions that cost an attacker nothing. A template-literal specifier,
  ``require(`child_process`)``, a space before the paren, `process['binding']`
  in bracket notation, `globalThis['eval']` and the indirect `(0, eval)(s)`
  all read as nothing at all. Swapping a quote for a backtick is not an
  obfuscation technique, it is a typo an attacker would find by accident.
  Closing them changed no capability on 202 real packages, because no
  legitimate package writes that way.
- A gate bypass. `check` skipped any package whose version string already
  appeared in the baseline, on the assumption that a version number pins the
  content. That is the assumption an attacker subverts: a postinstall in one
  package rewriting a sibling's files never changes a version, so the diff
  never ran and the gate stayed silent for every dependency that had not
  been upgraded, which is most of them. Reproduced on a real workspaces
  install, where axios tampered in place to add a postinstall reading
  NPM_TOKEN passed with exit 0. An approved version is now compared against
  its own approved manifest; the union is kept for versions genuinely new to
  the baseline, so a capability approved for a sibling version cannot excuse
  tampering with this one.
- 15 MB per-file scan cap. This scanner's input is untrusted by
  definition, and nothing previously bounded how large a single file it
  would read fully into memory. A package could ship one oversized file
  specifically to stall or exhaust a CI runner.
- See the path-escape entry under Fixed above; it is also a security fix.

### Verification

- 164 automated tests (`npm test`) covering the discovery, diff,
  comment-scanning and rule bugs above as regressions.
- Scanned four production applications as they ship (uptime-kuma, documenso,
  outline, nocodb): 5,853 installed packages, 2 CRITICAL, both true and both
  legitimate (prisma's engine fetch, nx's release tooling). End-to-end test
  with a synthetic Shai-Hulud V2-style compromise of a quiet transitive
  dependency, obfuscated module names and all, caught with the full CRITICAL
  diff. No real malware fetched.
- Discovery verified against a real install from each package manager rather
  than a fixture: npm 11 hoisted, pnpm 12's symlinked `.pnpm` store, Yarn
  Berry 4.18 with `nodeLinker: node-modules`, and an npm workspaces monorepo
  whose members symlink out of `node_modules` entirely. Every difference
  against a naive walk is the walk over-counting `lib/cjs` stubs, vendored
  copies and benchmark directories; none is a missed package.
- `test/evasion.test.js`, a corpus of documented obfuscation techniques
  taken from the npm malicious-package benchmark (arXiv 2603.27549) and the
  JavaScript deobfuscation survey (arXiv 2512.14070). It asserts what is
  caught and, deliberately, what is not: a source-text matcher cannot
  resolve a specifier built at runtime, and that belongs in a test rather
  than in a footnote.
- Benchmarked against a real 118-package corpus of popular libraries and a
  462 MB / 428-package build-tooling tree: 0 false CRITICAL flags, down
  from 2 before the fixes above, sub-second scan time on the small corpus.
- Benchmarked against GuardDog (Datadog, open source) on the same corpus:
  about 47x faster, since GuardDog has no bulk-scan mode and pays a
  process-startup cost per package. Also found a specific detection gap;
  see the README's Verification section for the comparison and its
  caveats (GuardDog's dynamic sandbox and registry metadata were not
  tested).

## [0.1.0]

Initial local snapshot, before pressure-testing.
