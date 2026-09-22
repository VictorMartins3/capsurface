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
