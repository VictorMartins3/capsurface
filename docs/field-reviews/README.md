# Three real package updates, including the awkward results

These are source comparisons of six historical npm tarballs, not malware
verdicts, current-version recommendations or evidence of production adoption.
The packages were downloaded and integrity-checked, never installed or executed.
Only the named package was scanned in each snapshot; transitive dependencies
were deliberately excluded. The lockfiles are single-package study fixtures,
not complete application lockfiles.

| Update | Basic review | Deep analysis | Manual interpretation |
| --- | --- | --- | --- |
| [fastq 1.17.0 to 1.17.1](fastq.md) | No new indicators, exit 0 | Complete; review exit 0 | Queue behavior changed without acquiring new capabilities. |
| [write-file-atomic 2.4.3 to 3.0.3](write-file-atomic.md) | New write/remove indicators, exit 1 | Complete; same two additions, exit 1 | Existing operations became recognizable after graceful-fs was replaced with fs. This is review noise, not newly acquired authority. |
| [node-fetch 2.6.6 to 2.6.7](node-fetch.md) | No new indicators, exit 0 | Both scans incomplete, exit 2; baseline creation rejected | A documented redirect security fix is invisible to the basic capability delta. Deep mode cannot certify coverage here. |

## What this suggests changing

The generated write-file-atomic report says an operation was not present before.
The evidence supports the narrower statement that it was not *recognized* before.
The wording should distinguish newly observed indicators from newly introduced
behavior. A quiet report must also make clear that it is not a security sign-off.
These findings have not been fixed by this documentation change.

The node-fetch deep failure is separate: its `.es.js` distribution has ESM syntax
under a CommonJS package boundary, while its CommonJS build passes a module
namespace through a wrapper. Current parsing/escape rules decline these cases.
Improving coverage must preserve conservative handling rather than suppress errors.

## Reproduce

Recorded engine: commit `c1e6e86` (PR #21, not an npm release), rules fingerprint
`4263d17787f6`. Node/platform are in [environment.json](results/environment.json).
Parsers: Acorn 8.15.0 and acorn-typescript 1.4.13. Basic and deep baselines are
separate. No approval was forced for the incomplete node-fetch deep scan.
The complete basic baselines are comparison inputs, not independent security audits.

From a checkout containing these files and the optional parsers:

```sh
npm install --no-save --package-lock=false --ignore-scripts --no-audit --no-fund acorn@8.15.0 acorn-typescript@1.4.13
python3 docs/field-reviews/reproduce.py /tmp/capsurface-field-review-reproduction
```

The output directory must not already exist. The script downloads exactly the
archives in [inputs.json](inputs.json), verifies their pinned integrity, then
runs offline scans, baseline creation and reviews. It does not install target
dependencies or run their hooks. Network access is only used to obtain archives.
Using a different scanner engine may change the reports. Timestamps and review
IDs may differ; compare indicators, coverage, evidence locations and exit codes.

The [recorded results](results) include manifests, input lockfiles, commands,
stderr, exit codes, durations and Markdown/JSON reports. Tarball bytes are not
committed; their URLs and integrity hashes are pinned. Timings are single runs
on one machine, not benchmarks. Source locations in the case notes refer to
files inside those exact tarballs.

## Selection and limits

These cases were selected to illustrate different outcomes, not to estimate
accuracy. Exploratory comparisons also included fs-extra 9.1.0 to 10.0.0,
rimraf 3.0.2 to 4.0.0 and open 7.4.2 to 8.0.0. They are not counted as published
case studies. This is manual source review, without runtime exploit testing or
a full audit of every change. No maintainer has yet validated these interpretations.
