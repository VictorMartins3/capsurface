# Reviewing dependency changes

`baseline` creates the initial reviewed surface. For later updates,
`review` explains changes and `approve` accepts one installed package at a
time. Both run locally, without network requests or dependency execution.

## Scan and review

```bash
npm ci --ignore-scripts
capsurface scan-tree node_modules --out .capsurface/manifests
capsurface review .capsurface/manifests --baseline capsurface.lock.json --out review.md
```

The default output is Markdown. `--json` emits a structured report; `--out`
writes either format to a file. Entries include the predecessor selection,
capability changes, new risk flags, source evidence and scan coverage.
Nonblocking changes such as a new `NO_COLOR` read remain visible.

The exit codes follow `check`: 0 for a passing comparison, 1 for escalations
or ambiguous predecessors, 2 for invalid inputs. Add `--fail-on-new` to
block unapproved new packages. `--report-only` preserves the findings but
returns 0 for a completed comparison; invalid snapshots still fail.
The report file is written even when the comparison returns 1.

## Accept one installation

Copy its 32-character review ID from the report:

```bash
capsurface approve .capsurface/manifests --baseline capsurface.lock.json \
  --id <review-id> --reason "Reviewed the HTTP client added for telemetry"
capsurface check .capsurface/manifests --baseline capsurface.lock.json --fail-on-new
```

Review the baseline diff and commit it with the dependency update. Approval
accepts all observed changes for the selected installation, not the entire
tree. Approving individual fields within one package is not supported.
The baseline records the ID, installation, version, engine fingerprint,
content digest, reason and approval time. Unrelated package approvals are preserved.

An ID binds the observed manifest, its candidate baselines and engine
fingerprint. Rescanning identical input keeps the ID despite timestamp
changes. If the observed manifest or its candidate baselines change, rerun
review; the previous ID is rejected. IDs cannot be approved twice. A lock
and atomic replacement protect concurrent approval writes.

Incomplete scans, incomplete content digests and manifests from a different
engine cannot be approved. Fix coverage or integrity errors and rescan first.
Approval does not certify that code is safe and never runs scripts.

### Content and expiration

Selective approval binds the installation path, version and SHA-256 digest
of installed package files. A change to any of those requires another review,
even when detected capabilities stay the same. Review IDs include the digest,
so changing a data file or binary also invalidates an outstanding review ID.
Run a fresh scan after changing installed files; checks compare saved manifests,
not the live filesystem.

Optionally set an expiration using an explicit UTC timestamp:

```bash
capsurface approve .capsurface/manifests --baseline capsurface.lock.json \
  --id <review-id> --reason "Temporary exception during migration" \
  --expires 2030-01-15T00:00:00Z
```

The timestamp must be in the future. At or after that time, `check` and
`review` require approval again, including for unchanged packages. Renewal
uses the new review ID and a justification; audit history is retained.
Without `--expires`, the approval has no time limit. Expiry uses the machine's
UTC clock; use a correctly configured clock in CI.

Manifest schema v6 records `contentIntegrity`. Its `package-files-v1` scope
hashes relative file paths and exact bytes, including `package.json`, binary
assets, documentation and non-source files. Directory traversal is sorted;
timestamps, permissions and empty directories are excluded. Nested
`node_modules` and `.git` directories are excluded. Dependencies are reviewed
as separate installations. This is an installed-content digest, not the
registry tarball's integrity or a publisher signature.

Hashing streams files with a 1 GiB package budget, 100,000 directory entries
and a maximum directory depth of 128. Unreadable files, package-internal
symlinks, other non-regular files and exceeded budgets produce incomplete
content integrity and prevent selective approval. The package root may itself
be a resolved workspace link. The scan does not provide a filesystem snapshot:
scan a stable installation, with outputs outside the package being scanned.

General baselines created with `baseline`, including older baselines and
older selective approvals, retain capability-comparison behavior. They are
not silently converted into content pins. New selective approvals store an
enforced policy with the baseline manifest and an audit record alongside it.
Different policies cannot be combined as equivalent capability surfaces.
Use the current CLI/Action throughout CI; older releases do not enforce these
policies. Regenerating the entire baseline replaces selective policies, so
use `approve` for subsequent reviews and inspect baseline changes in the PR.

## Multiple versions

Comparison selects the matching installation path first. Without a path
match, it can use an exact version or the only available baseline. Several
candidates with identical approved surfaces are interchangeable. Different
surfaces produce an explicit ambiguity instead of combining permissions.

pnpm changes store paths when versions change, and the current matcher
does not read lockfile dependency edges. If several different predecessors
remain possible, the report lists them and requires review. Approving that
installation adds its own surface without deleting the candidate approvals.
A predecessor still used by another current installation is also retained.

Old schema-v1 baselines are readable. Approval writes schema v2 and retains
the unselected entries. A rules migration is shown in review and should be
assessed separately from an actual package capability change.

## File correlation

Manifest schema v7 adds `sourceContext`. It records source files where a
network capability indicator occurs alongside a sensitive-target indicator
or a credential-shaped environment variable. Markdown and SARIF show the
file and the original line of each indicator; JSON retains structured data.

The scanner collects the first relevant indicators while analyzing each
file, independently of package-wide evidence quotas. A file can therefore
appear in this context even when it is absent from the category's five
evidence samples. `matchingFiles` counts all matching files; `matches` retains
up to 20, with the remainder in `omittedFiles`. Human-readable reports show
up to five file pairs. `filesAnalyzed` and `complete` describe source coverage,
not the number of retained samples. Older manifests without this field show
correlation as unavailable and can be rescanned to collect it.

This is explanatory context, not another blocking rule. Existing capability
gates, scores and risk flags are unchanged. Co-occurrence does not establish
execution order, a shared call path or transfer of credential data. Two
indicators may belong to unrelated functions in the same file, especially in
bundles. Conversely, code may pass data between different files. A zero count
does not prove safety, and incomplete source coverage is explicitly shown.

Correlation uses the existing source-text rules, including literal folding
and their detection limits. Lifecycle command strings are excluded from file
correlation; a `postinstall` network command is not attributed to an unrelated
source file that reads credentials. Potential import paths from supported
installation commands are described separately below.

## Installation script paths

Manifest schema v8 adds `installContext`, an explanatory graph of literal
import references from `preinstall`, `install` and `postinstall`. It runs only
for packages with non-inert installation commands. It never executes a script
or loads package code. `prepare` is not treated as a registry-install entry.

Supported entries are direct commands such as `node install.js` and
`node "scripts/install file.js"`. Shell combinations, environment assignments,
Node flags, script arguments, inline code and native build commands are
reported as `unsupported-command`, including npm's implicit node-gyp build.

By default, for recognized entries, the scanner follows literal `require`, simple
single-line ESM imports/re-exports and literal `import()` references within
the package. CommonJS file lookup checks the exact filename, then `.js`,
`.json` and `.node`; only files included in source analysis become graph
nodes. ESM references use exact filenames, consistent with Node's
[extension requirement](https://nodejs.org/api/esm.html#mandatory-file-extensions).
This is a subset of [Node's module resolution](https://nodejs.org/api/modules.html#all-together):
directory resolution, package exports and aliases are not implemented.

Each hook reports its entry status, reached file count and sampled paths to
network or credential indicators, including indicators in separate files.
Unresolved observed references include reasons such as `external-module`,
`nonliteral-import`, `unscanned-file` and `symlink-reference`. No dependency
outside the package or internal symlink is followed. Built-in modules are
recognized using the Node runtime running the scanner.

The graph is bounded to 10,000 files and 100,000 references per package, with
a maximum path length of 32 files. It retains 20 indicator paths and 20
unresolved references per hook, with omitted counts; text reports show five
indicator paths. `truncated` reports graph budget exhaustion.
`sourceCoverageComplete` describes source scanning only, not completeness of
module resolution. Older manifests omit this context.

These are **syntactic, potential paths**, not a call graph or proof of runtime
execution. Conditions, function calls, shadowed loaders, aliases,
`createRequire`, escaped specifiers and template interpolation are not
resolved. Unrecognized syntax can leave references unreported, so zero
unresolved references does not establish a complete graph. Reaching network
and credential indicators does not demonstrate that credentials flow to the
network. Risk scores and blocking rules are unchanged.

### Experimental AST import analysis

`scan` and `scan-tree` accept `--deep` to replace the installation import lexer
with an [Acorn](https://github.com/acornjs/acorn/tree/master/acorn) AST pass and
add module-acquisition capability detection across every scanned source file.
Packages without installation scripts receive the same capability analysis.
Install the supported parser alongside your trusted capsurface installation:

```bash
# From a capsurface checkout; omit --deep to keep the dependency-free scanner.
npm install --no-save --package-lock=false --ignore-scripts acorn@8.15.0 acorn-typescript@1.4.13
node bin/capsurface.js scan /path/to/package --deep --out /tmp/package.json
node bin/capsurface.js scan-tree /path/to/node_modules --deep --out /tmp/manifests
```

For a packaged CLI, install `capsurface`, `acorn@8.15.0` and, for typed source,
`acorn-typescript@1.4.13` in the same trusted tool environment. Both parsers are
[optional peer dependencies](https://docs.npmjs.com/cli/v11/configuring-npm/package-json/#peerdependenciesmeta),
not installed automatically. Scans never download them. Missing Acorn or an
incompatible installed parser version fails before writing an inventory.
Missing acorn-typescript leaves typed files explicitly unavailable and makes
a deep scan incomplete; JavaScript-only deep scans still work with Acorn alone.
Parsers are resolved from capsurface's installation, not from the scanned package.

This mode resolves immutable `const` aliases of `require`, `createRequire`
from `module`/`node:module`, named and namespace imports, escaped string literals,
string concatenation and static template interpolation. `createRequire` must
use the current file's unshadowed `__filename` or `import.meta.url`; other bases
are explicitly unresolved. Lexical bindings, parameters, catch bindings and
hoisted `var` declarations shadow loaders. Reassigned bindings are not trusted.
It also visits actual calls inside template interpolation without treating
quoted examples as code.

JavaScript uses ECMAScript 2022 syntax. The optional
[acorn-typescript extension](https://github.com/TyrealHu/acorn-typescript)
adds TypeScript, declaration files, JSX and TSX. Both scan modes discover
`.mts` and `.cts`, including their declaration-file variants, in addition to
`.js`, `.cjs`, `.mjs`, `.ts`, `.tsx` and `.jsx`.

Type annotations, interfaces, type aliases, `import type` and `export type`
do not acquire modules. Declaration-file static imports are also erased.
Value imports remain acquisition candidates even when their named specifiers
are all marked `type`: TypeScript's
[verbatimModuleSyntax](https://www.typescriptlang.org/tsconfig/verbatimModuleSyntax.html)
can retain these imports for side effects. No type checker or compiler options
are consulted to guess additional import elision.

The AST pass follows typed immutable aliases, `as`/`satisfies` expressions,
non-null assertions, generic calls and supported external `import = require()`
declarations. Constructor parameter properties participate in lexical
shadowing. JSX expression containers and spread attributes are traversed;
JSX text and quoted attributes do not become AST imports. The underlying
source-text scanner remains additive and can still report its own false positives.

Non-ambient enums, namespaces and internal import-equals aliases are explicitly
unsupported rather than assigned guessed runtime semantics. The pinned parser
also rejects some valid TypeScript, including angle-bracket assertions and
certain interface/value declaration merges. Malformed files, dynamic scopes,
module-namespace mutations/escapes and resource limits still make deep analysis
unavailable. Declaration files are parsed, not skipped wholesale.

`.cjs`/`.cts` and `.mjs`/`.mts` determine CommonJS and ESM loader assumptions;
other files use the nearest package.json `type`. Typed syntax accepts module
declarations without assuming a particular emitted build. The scanner does
not read tsconfig/Babel configuration or emulate Node's syntax-based module
detection. Only the pinned parser extension is loaded; no project plugins,
compiler transforms or dependency code execute.

Each file has a 1 MiB source budget, 100,000-token/node/evaluation budgets and
32 levels of static value resolution, in addition to the graph's existing limits.

Deep context has `installContext.schemaVersion: 2`, `analysis: ast-import-graph`
and `ast` metadata with parser identities and processed/unavailable file counts.
Manifest schema v9 also records `analysisProfile` and package-wide `astCoverage`.
Reviews retain this context in Markdown, JSON and SARIF. A parsed file does **not** mean every import was resolved:
mutable aliases, wrapper functions, values passed across calls, object-held
loaders and runtime monkey-patching are not modeled. Existing package-local
resolution and installation-command restrictions still apply.

AST module acquisition supplements the source-text scanner. Recognized modules
add filesystem, network, process-execution, dynamic-evaluation or native-code
capabilities, with original file/line evidence and the resolved specifier.
Existing scoring and capability-escalation rules then apply. Network findings
also feed file correlation and installation-path context. Unknown specifiers
on recognized loaders contribute `unresolvedRequire`; they do not become an
invented capability. This pass does not yet attribute filesystem operations,
aliased `fetch`, environment enumeration or data flow, and does not remove
false positives from the source-text scanner.

`analysisProfile` is `source-v1` for basic scans and `source-ast-v1` for deep
scans. Older manifests without a profile are treated as basic scans. A current
basic scan fails comparison against a deep baseline, including when capabilities
are identical. Baselines with different profiles are not interchangeable when
matching duplicate installations. Rescan with `--deep` to retain that coverage.

`astCoverage` records parser identity, analyzed/failed file counts and up to ten
file/line/reason samples, retained in Markdown, JSON and SARIF. Unsupported
syntax, parse failures and resource limits now make the whole deep scan
incomplete: `scan`/`scan-tree` exit 2, checks fail and selective approval is
rejected. A successful parse still does not prove complete runtime visibility;
unsupported aliases and dynamic values remain analysis limitations.

This is a deliberate change from the earlier experimental context-only mode:
rescan both sides of a review before interpreting new capabilities as package
changes. Some production trees remain unsuitable for strict deep scans; see the
[measured coverage and remaining limitations](VERIFICATION.md).
The composite Action uses basic scanning and cannot satisfy a deep baseline;
use the CLI in CI with an explicitly provisioned trusted parser environment.
No parser is installed or fetched during a scan.

## Filesystem operations

Manifest schema v5 supplements the existing `filesystem` capability with:

| Capability | Examples of selected Node APIs |
| --- | --- |
| `filesystemRead` | `readFile`, `read`, `readdir`, `readlink`, `createReadStream` |
| `filesystemWrite` | `writeFile`, `appendFile`, `mkdir`, `copyFile`, `rename`, `truncate`, `createWriteStream` |
| `filesystemRemove` | `rm`, `rmdir`, `unlink` |

Synchronous variants and `fs/promises` are included. These flags describe API
selection in shipped source, not proof that an operation executes or that a
package is malicious. Named imports count even when a particular call is not
observed, consistent with the scanner's acquisition-based capability model.
Copying, renaming and truncation are classified as writes; deletion APIs are
classified as removal. The existing parent capability and risk score remain.
Operation detail does not add the same risk points a second time.

A newly selected operation blocks even when the parent `filesystem`
capability was already approved. For example, upgrading from
`fs.readFileSync(...)` to code that also selects `fs.rmSync(...)` reports a
new `filesystemRemove` capability, with the method's original file and line.
Review, SARIF and selective approval use the same operation-level change.

Detection supports direct literal `require('fs').method` accesses, named
ESM imports/re-exports, CommonJS destructuring and simple namespace bindings
such as `const disk = require('fs')` or `import * as disk from 'node:fs'`.
Member selection supports dotted access, literal bracket keys and `.promises`.
Comments, string examples, regex literals and recognized erased TypeScript
imports do not grant operation detail.

Namespace attribution is conservative and file-local. If a binding is
redeclared, used as a value, or its selected member is reassigned, its member
operations are not attributed. Function parameters that reuse its name also
prevent that attribution. This avoids guessing through shadowing or mutation;
it can miss legitimate operations in code that passes `fs` to a helper.

This is not AST or data-flow analysis. Indirect aliases, wrappers,
`createRequire`, dynamic imports, computed properties, template interpolation,
file-handle methods and `open` flags are not resolved into operation detail.
Lifecycle command strings keep their existing script-content gate but do not
receive these JavaScript operation flags. An absent flag means no supported
operation was recognized, not that the package cannot perform it.

Older baselines remain readable but lack these permissions. When a current
scan selects an operation absent from the baseline schema, the gate reports
`capability-detail-unreviewed` and asks for review of the engine migration.
It does not claim the dependency necessarily added that behavior. Rescan and
review with the new engine before approving; no operation permissions are
silently inherited from an older broad filesystem approval.

## Dependency origin and SARIF

Pass the installed tree's npm lockfile to explain who brought each dependency:

```bash
capsurface review .capsurface/manifests --baseline capsurface.lock.json \
  --lockfile package-lock.json --format markdown --out review.md
capsurface review .capsurface/manifests --baseline capsurface.lock.json \
  --lockfile package-lock.json --format sarif --out review.sarif
```

`--format` accepts `markdown`, `json` and `sarif`; `--json` remains an alias.
All formats preserve the same exit codes and gate decisions. `--report-only`
changes the exit status, not the SARIF severity or the reported reasons.

Origin resolution supports npm lockfile v2/v3. It follows physical install
locations, hoisting, nested copies, aliases, optional/peer edges and workspace
links. It reports one shortest root-to-package chain and up to 50 immediate
parents, with an explicit omitted count. Registry package dev dependencies
are not treated as installed consumer dependencies. Cycles terminate.
Missing paths, name/version mismatches and unreachable entries are reported
as unavailable; they never become an invented dependency chain. The limits
are 32 MiB per lockfile, 100,000 packages, 1,000,000 declared edges and 256
reported hops. Unsupported lockfile formats fail explicitly. pnpm, Yarn and
npm v1 provenance are not implemented. This explanation does not change the
baseline matcher or prove lockfile integrity.

Use `scan-tree` on the `node_modules` alongside the supplied lockfile. For
monorepos, `--project-root` sets the repository root used for SARIF paths;
it defaults to the current directory. The lockfile must be inside that root.
The Action sets this automatically from Git.

SARIF 2.1.0 contains stable rule IDs and installation fingerprints. Blocking
entries have level `error`; informational changes have level `note`. When
origin is resolved, the primary location is the package's version line in
the committed lockfile, so GitHub can associate the finding with a dependency
update. Source file/line evidence remains in the message and result properties.
Without a resolved lockfile entry, available package source locations are
used; these usually do not appear in a PR diff. Evidence is a category sample,
not proof of data flow or of execution during installation.

GitHub only shows inline PR alerts when their locations intersect the diff;
a valid SARIF file alone does not guarantee an annotation. See
[GitHub SARIF support](https://docs.github.com/en/code-security/reference/code-scanning/sarif-files/sarif-support).

## GitHub Action

The repository provides a composite [Action](../action.yml) and a complete
[adoption workflow](../examples/workflows/capsurface.yml). Pin the Action to
a reviewed full commit SHA. It runs its own bundled scanner using Node;
no npm publication or project-local Capsurface binary is needed.

Before enabling it, commit an initial baseline on the target branch. Check
out the repository with `fetch-depth: 0`, set up Node 18 or newer, and install
project dependencies with `npm ci --ignore-scripts`. The Action scans the
installed tree; it does not install dependencies or execute their scripts.

It reads the baseline from the PR target SHA, emits Markdown/JSON/SARIF,
appends the Markdown to the job summary, and then
checks the proposed baseline. Changes stay visible even when the PR also
updates its baseline. `fail-on-new` defaults to true and `report-only` defaults
to false. The adoption example enables observation mode explicitly. Invalid
or incomplete scans fail in either mode. Review baseline edits using normal
branch protection and code review.

Inputs include `project-directory`, `baseline`, `lockfile`, `base-ref`,
`fail-on-new`, `report-only`, `upload-sarif`, `upload-artifact` and
`artifact-name`. Baseline and
lockfile paths are relative to the project. `base-ref` defaults to the PR base
SHA; outside a PR, specify a full target SHA or use an empty value to compare
with the proposed baseline. Outputs `markdown`, `json` and `sarif` are local
report paths; `would-fail` describes the proposed-baseline gate. Use distinct
artifact names when enabling uploads for multiple projects/jobs. Summaries
exceeding the display budget are shortened with a notice; local report files
remain complete.

Reports are generated in the runner's temporary directory, not committed to
Git. Artifact upload is disabled by default; set `upload-artifact: 'true'`
when downloadable reports are useful. Uploaded artifacts expire after 14 days.
The job summary works without artifact upload.

Upload to Code Scanning is opt-in
with `upload-sarif: 'true'`, `security-events: write`, and `actions: read` for
private repositories. GitHub supports Code Scanning for public repositories
and eligible organization-owned private repositories with GitHub Code
Security enabled. A private repository does not automatically qualify. The
Action does not change settings or purchase access; Markdown and optional workflow artifacts
work without Code Scanning. See
[GitHub upload requirements](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).

The Action posts no PR comments and requires no comment-write permission.
When artifact upload is enabled, it retains `.capsurface-snapshot`; keep this hidden file when
copying or downloading scan inventories. SARIF and source evidence can
contain dependency source snippets, so artifact access follows repository
permissions.
