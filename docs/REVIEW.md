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

## Pull request summaries

The [example workflow](../.github/workflows/capsurface.yml) reads the baseline
from the PR target commit for its review summary, then checks the proposed
baseline separately. This keeps requested permissions visible even when
the PR updates its own baseline. Commit an initial baseline on the target
branch before enabling the workflow.

The workflow retains its adoption-mode `--report-only` check. Remove that
flag from the check step to enforce the gate, and use branch protection and
code review for baseline changes. The summary does not automatically approve
or reject a proposed baseline change. Use a published Capsurface version
that includes these commands when adopting the pinned workflow.

Markdown is appended to `GITHUB_STEP_SUMMARY`, which GitHub renders in the
workflow run; it does not post a PR comment or need comment-write access.
See [GitHub's job summary documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-commands#adding-a-job-summary).

The artifact includes `.capsurface-snapshot` alongside the JSON manifests.
Keep this hidden file when downloading or copying scans. The example enables
`include-hidden-files` only for its scan/report paths, as described in the
[upload-artifact migration guide](https://github.com/actions/upload-artifact/blob/main/docs/MIGRATION.md#hidden-files).
