# node-fetch: a security fix without a new basic capability

Versions: 2.6.6 to 2.6.7. Historical comparison only; do not install these versions
as a recommendation. [Pinned archives and integrity](inputs.json).

The basic scans complete and the review exits 0 with no new indicators.
Both snapshots already have network access indicators. Yet the upstream release
documents a security fix that stops forwarding sensitive headers on certain
redirects. This behavior change does not require a new capability category.

Manual inspection of the published 2.6.7 `lib/index.js` finds the added
`isDomainOrSubdomain` helper at line 1413 and the redirect header-deletion branch
at lines 1566 onward. The old version lacks that branch. This corroborates the
release description, but is not a runtime test or a claim that all redirect
security issues were solved.

Deep mode does **not** produce a clean result. Both versions have four analyzed
files and two failures:

- `lib/index.es.js:3`: `ast-parse-error`. ESM source is shipped under a package
  boundary that the current analyzer treats as CommonJS.
- `lib/index.js:8`: `ast-module-escape`. A module namespace is passed to a wrapper;
  the analyzer conservatively declines attribution.

Both deep scans exit 2. Creating a deep baseline also exits 2 because analysis is
incomplete. No deep comparison baseline or clean deep report was manufactured.
These are coverage limitations, not evidence that the package is malicious.

- [Basic report](results/node-fetch/basic-review.md) and [JSON](results/node-fetch/basic-review.json)
- [Basic commands and timings](results/node-fetch/basic-runs.json)
- [Deep commands, failures and rejected baseline](results/node-fetch/deep-runs.json)
- [Upstream security patch release](https://github.com/node-fetch/node-fetch/releases/tag/v2.6.7)
- [Upstream comparison](https://github.com/node-fetch/node-fetch/compare/v2.6.6...v2.6.7)

Scan times before/after: basic 0.082/0.052 seconds; deep 0.194/0.189 seconds.

Review question: does the combination of a quiet basic diff and an incomplete
deep scan make the remaining manual work clear enough?
