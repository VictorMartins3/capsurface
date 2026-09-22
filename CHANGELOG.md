# Changelog

Notable user-facing changes are recorded here using
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added

- Deep scans distinguish shell execution, direct process launches and unresolved
  launch modes in `child_process` calls. New detail requires review even when
  general process execution is already approved, with original call-site
  evidence in Markdown and SARIF.

- Optional TypeScript, declaration-file, JSX and TSX analysis through pinned
  acorn-typescript 1.4.13, with erased type syntax, typed aliases, scope handling
  and explicit unsupported runtime constructs. Missing typed-parser support
  keeps deep scans incomplete.
- Source discovery includes `.mts` and `.cts`, including declaration variants,
  in basic and deep scans.

- Experimental `scan --deep` and `scan-tree --deep` capability detection and
  import context, using optional Acorn 8.15.0 to resolve immutable loader aliases,
  `createRequire` and static templates with lexical scopes. Acquired modules
  contribute filesystem, network, process-execution, dynamic-evaluation and
  native-code capabilities with original source evidence.
- Potential local import paths from supported installation commands, with
  network/credential locations and unresolved-reference reasons in reviews.
- File-level correlation of network and credential indicators, with original
  locations and coverage limits in Markdown, JSON and SARIF reviews.
- Selective approvals bind installed file content and version, with optional
  UTC expiration through `approve --expires`. Changed content and expired
  approvals require a new review even when capabilities are unchanged.
- Filesystem read, write and removal capabilities, with per-operation evidence
  and gating even when general filesystem access was already approved.
- `review` reports dependency changes, blocking reasons and source evidence
  in Markdown, JSON and SARIF.
- `approve` accepts one dependency installation with a required justification
  and rejects stale reviews, incomplete scans and incompatible engines.
- npm lockfile v2/v3 dependency origins, including nested installations,
  aliases and workspace links.
- A GitHub Action that reviews against the PR target baseline and checks the
  proposed baseline separately. Code Scanning uploads are optional.
- Install-script allowlists for npm, pnpm and JSON consumers, including npm's
  implicit `node-gyp rebuild` command.
- Manifest coverage metadata and checksummed scan inventories.
- Detection of literal dynamic imports, optional `require` calls, internal
  module loaders and additional cloud, CI and container credential targets.

### Changed

- `--deep` analyzes all source files, including packages without install hooks.
  AST failures now make scans incomplete, exit with status 2 and prevent
  selective approval. Manifests record the analysis profile and bounded AST
  coverage details. Checks reject a basic scan against a deep baseline.
  Existing users of experimental deep scans must rescan before review.
- Manifest schema v9 includes filesystem operation detail, installed-content
  integrity and explanatory source/installation context. New selective
  approvals require a complete content digest. Context does not add risk
  points or blocking rules.
- Dependency approvals are matched by installation and version. Ambiguous
  predecessors require review instead of combining approved capabilities.
- Comparisons distinguish install-time scripts from build-only scripts and
  ordinary environment reads from credential-shaped reads.
- New endpoint hosts block when accompanied by install-time execution or
  sensitive-target access; other endpoint changes remain informational.
- Scan summaries show install-time execution before aggregate risk scores.
- Scanner and normalization improvements reduce repeated parsing and pattern
  matching. Measurements and limitations are in [Verification](docs/VERIFICATION.md).
- The engine fingerprint and manifest schema have changed. Existing baselines
  remain readable; rescan and review differences before accepting a new one.
  Scan commands exit with code 2 for incomplete coverage, and approval commands reject it. See
  [Reviewing dependency changes](docs/REVIEW.md).

### Fixed

- Incomplete reads and exhausted analysis budgets can no longer silently pass
  comparison or be accepted into a baseline.
- Endpoint and environment-variable collection no longer silently stops at
  20 and 40 entries, respectively.
- Reused scan directories no longer include stale manifests; interrupted or
  modified inventories are rejected.
- Discovery includes nested dependencies, workspace links and pnpm stores
  while rejecting symlink escapes outside the project boundary.
- Duplicate package installations retain separate manifests and approvals.
- Capability changes are checked even when the package version is unchanged.
- Detection handles comments, regular expressions, erased TypeScript syntax,
  `node:` module specifiers and common literal-obfuscation techniques more
  accurately.
- Git and Node directory aliases resolve consistently when locating lockfile
  entries on Windows.

## [0.1.0]

Initial local snapshot, before release validation.
