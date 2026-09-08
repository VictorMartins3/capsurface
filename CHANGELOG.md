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

- `blankComments`'s per-character identifier and whitespace checks, about
  16% of total scan time on a 462 MB real-world corpus by profile,
  replaced with charCode arithmetic instead of the regex engine. Measured
  18% CPU-time reduction on the same corpus, isolated on identical Node
  version and machine.

### Security

- 15 MB per-file scan cap. This scanner's input is untrusted by
  definition, and nothing previously bounded how large a single file it
  would read fully into memory. A package could ship one oversized file
  specifically to stall or exhaust a CI runner.
- See the path-escape entry under Fixed above; it is also a security fix.

### Verification

- 65 automated tests (`npm test`) covering the discovery, diff, and
  comment-scanning bugs above as regressions.
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
