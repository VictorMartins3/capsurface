# fastq: a normal behavior fix with no new indicators

Versions: 1.17.0 to 1.17.1. [Pinned archives and integrity](inputs.json).

Both basic and deep scans completed. Neither review reports new capability
indicators or blocks the update (exit 0). Deep mode analyzed eight source files
per version with zero failures.

Manual inspection of the published `queue.js` shows that `resume()` now handles
an empty queue explicitly at lines 96-100. The shipped test adds a pause/resume
case expecting the drain callback. This changes behavior without introducing a
filesystem, network or process operation recognized by the scanner.

This is an ordinary update that produces no capability escalation. It is not
proof of behavioral equivalence or overall safety.

- [Basic report](results/fastq/basic-review.md) and [JSON](results/fastq/basic-review.json)
- [Deep report](results/fastq/deep-review.md) and [JSON](results/fastq/deep-review.json)
- [Basic commands and timings](results/fastq/basic-runs.json)
- [Deep commands and timings](results/fastq/deep-runs.json)
- [Upstream release](https://github.com/mcollina/fastq/releases/tag/v1.17.1)
- [Upstream comparison](https://github.com/mcollina/fastq/compare/v1.17.0...v1.17.1)

Scan times before/after: basic 0.124/0.046 seconds; deep 0.309/0.314 seconds.
These are individual observations, not comparative performance claims.

Review question: does this report communicate that only the recognized capability
surface was unchanged, or could someone read it as approval of the whole update?
