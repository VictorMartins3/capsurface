# GitLab merge request integration

The integration scans installed npm dependencies without executing their code,
compares against the target branch's committed baseline, and separately gates
against the baseline proposed by the merge request. Approvals in the MR do not
hide the target-branch review. JSON, Markdown, SARIF and scan inventories are
ordinary job artifacts, not GitLab vulnerability reports. A detected capability
is not a vulnerability verdict.

## Set up the pipeline

1. Commit a reviewed `capsurface.lock.json` and `package-lock.json` to the target
   branch. Generate the baseline with the same capsurface engine and basic/deep
   profile used by the job. Missing baselines fail; none are auto-approved.
2. Copy [the example job](../examples/workflows/gitlab-ci.yml) into your
   `.gitlab-ci.yml`. Set `CAPSURFACE_REF` to a reviewed full commit SHA containing
   this integration. The published 0.1.0 release does not contain it. The example
   deliberately has a placeholder rather than silently running a moving branch.
3. Open a same-project MR. The example fetches the target branch tip, installs
   project dependencies with `npm ci --ignore-scripts`, and invokes the separately
   checked-out scanner. It never invokes the project's own capsurface binary.

The example uses Node 22 and a Linux runner with Git. Pin your container image
by digest according to your runner policy. It supports **detached, same-project
MR pipelines**. Fork pipelines, merged-results pipelines and merge trains are
explicitly unsupported. Do not run fork code in a privileged parent pipeline.
The current wrapper uses installed npm dependencies and npm lockfile provenance;
pnpm `scan-lock` remains a separate CLI workflow.

Artifacts use `.capsurface/gitlab/`, upload even when the gate fails, and expire
in seven days. The directory must be empty at job start. Retain the hidden
`.capsurface-snapshot` file if you download manifests for later review. Artifacts
contain dependency source snippets; repository artifact permissions apply.

The job serializes runs by MR using `resource_group`. Keep distinct output
paths, resource groups and comment keys if adapting it for multiple projects.

## Inputs and exit codes

`bin/gitlab-review.js` reads GitLab's predefined MR/project/pipeline variables.
It requires `CAPSURFACE_BASE_REF` to contain the fetched target commit SHA and
checks the checkout against `CI_COMMIT_SHA`.

| Variable | Default | Purpose |
| --- | --- | --- |
| `CAPSURFACE_PROJECT` | `CI_PROJECT_DIR` | Directory containing the project |
| `CAPSURFACE_BASELINE` | `capsurface.lock.json` | Proposed baseline, relative to project |
| `CAPSURFACE_LOCKFILE` | `package-lock.json` | npm provenance, relative to project |
| `CAPSURFACE_OUTPUT` | `.capsurface/gitlab` | Dedicated empty artifact directory inside project |
| `CAPSURFACE_DEEP` | `false` | Optional AST analysis; install the pinned parsers in the tool checkout |
| `CAPSURFACE_FAIL_ON_NEW` | `true` | Gate packages without a baseline |
| `CAPSURFACE_REPORT_ONLY` | `false` | Permit completed findings without failing the job |

Exit codes: 0 passes, 1 requires review, 2 means invalid input, execution failure
or incomplete analysis. Report-only never turns incomplete analysis into success.
`status.json` is initially marked incomplete and only finalized after reports
are produced. It records the source/target commits and pipeline/job identity, so retries cannot publish a previous job's artifacts.
An early failure may leave only this status file and the job log.

## Optional persistent MR comment

Leave `CAPSURFACE_COMMENT_MR=false` for artifact-only operation. To enable a
comment in a trusted pipeline, set it to `true` and supply
`CAPSURFACE_GITLAB_TOKEN`, an access token with `api` scope and permission to
create/edit MR notes. Prefer a dedicated project bot identity. This integration
uses the access-token Notes API, not `CI_JOB_TOKEN`. The API base comes from
`CI_API_V4_URL`, supporting HTTPS self-managed GitLab instances as well.

**A same-project branch is not a credential trust boundary.** Its CI definition
can be edited by its author. Only expose this token to pipelines whose code and
CI configuration you trust. Masking does not prevent deliberate exfiltration.
Keep protected-variable restrictions; if a feature branch cannot receive the
token, retain artifact-only mode or run the publisher from a separately managed,
trusted job. Do not weaken secret protections merely to enable comments.

`bin/gitlab-comment.js` runs in `after_script` and does not change the review
job's exit status. It skips missing tokens and unsupported contexts, verifies
artifact identity, and handles API failures without printing tokens or response
bodies. Full results remain in artifacts.

The publisher uses `CAPSURFACE_COMMENT_KEY` (default `default`) to locate a note
owned by the token's authenticated user. Copied markers in other users' notes
are ignored. It creates once, updates on changed results, skips identical
content and initial clean reports, and shows PASS when an existing failure
clears. Review-ID-only churn does not create an edit. Long reports are shortened,
but the fingerprint covers all content. Pagination is bounded to 1,000 notes;
exceeding that bound fails the comment step rather than creating a duplicate.

Before writing it verifies that the MR remains open, belongs to the same
project, has the expected source commit and target branch, and that the target
branch tip still matches the reviewed commit. GitLab does not make this check
and the note write atomic; serialization reduces races but cannot eliminate
changes occurring during the write. Rerun after the target branch advances.

## Validation and references

Local tests exercise the packed wrapper in real Git/npm fixtures, including
blocked and approved baselines, report-only, missing baseline and fork rejection.
Mocked API tests cover note ownership, updates, stale commits, pagination and
permission errors. Hosted GitLab execution requires configuring an actual project;
local tests are not evidence of a successful hosted deployment.

Official references: [MR pipelines](https://docs.gitlab.com/ci/pipelines/merge_request_pipelines/),
[predefined variables](https://docs.gitlab.com/ci/variables/predefined_variables/),
[Notes API](https://docs.gitlab.com/api/notes/).
