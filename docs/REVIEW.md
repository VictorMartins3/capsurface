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
reason and approval time. Unrelated package approvals are preserved.

An ID binds the observed manifest, its candidate baselines and engine
fingerprint. Rescanning identical input keeps the ID despite timestamp
changes. If the observed manifest or its candidate baselines change, rerun
review; the previous ID is rejected. IDs cannot be approved twice. A lock
and atomic replacement protect concurrent approval writes.

Incomplete scans and manifests from a different engine cannot be approved.
Fix coverage errors or rescan first. Review IDs fingerprint manifests, not
every byte in a package: approval is a capability review, not an integrity
attestation or a guarantee that code is safe. It never runs scripts.

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
appends the Markdown to the job summary, uploads a review artifact, and then
checks the proposed baseline. Changes stay visible even when the PR also
updates its baseline. `fail-on-new` defaults to true and `report-only` defaults
to false. The adoption example enables observation mode explicitly. Invalid
or incomplete scans fail in either mode. Review baseline edits using normal
branch protection and code review.

Inputs include `project-directory`, `baseline`, `lockfile`, `base-ref`,
`fail-on-new`, `report-only`, `upload-sarif` and `artifact-name`. Baseline and
lockfile paths are relative to the project. `base-ref` defaults to the PR base
SHA; outside a PR, specify a full target SHA or use an empty value to compare
with the proposed baseline. Outputs `markdown`, `json` and `sarif` are local
report paths; `would-fail` describes the proposed-baseline gate. Use distinct
artifact names for multiple projects/jobs. Summaries exceeding the display
budget are shortened with a notice; artifact reports remain complete.

SARIF is always retained as an artifact. Upload to Code Scanning is opt-in
with `upload-sarif: 'true'`, `security-events: write`, and `actions: read` for
private repositories. GitHub supports Code Scanning for public repositories
and eligible organization-owned private repositories with GitHub Code
Security enabled. A private repository does not automatically qualify. The
Action does not change settings or purchase access; Markdown and artifacts
work without Code Scanning. See
[GitHub upload requirements](https://docs.github.com/en/code-security/how-tos/find-and-fix-code-vulnerabilities/integrate-with-existing-tools/upload-sarif-file).

The Action posts no PR comments and requires no comment-write permission.
It retains `.capsurface-snapshot` in the artifact; keep this hidden file when
copying or downloading scan inventories. SARIF and source evidence can
contain dependency source snippets, so artifact access follows repository
permissions.
