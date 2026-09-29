# write-file-atomic: new findings, existing behavior

Versions: 2.4.3 to 3.0.3. [Pinned archives and integrity](inputs.json).

Both modes complete and report two additions: `filesystemWrite` and
`filesystemRemove`. Both reviews exit 1 and ask for review. This is a legitimate
source change producing new indicators, but the operations themselves are not new.

Manual inspection explains why:

| Published index.js | 2.4.3 | 3.0.3 |
| --- | --- | --- |
| Filesystem binding | graceful-fs at line 7 | fs at line 7 |
| Synchronous write | line 214 | line 213 |
| Synchronous unlink | line 40 | line 43 |
| Rename | line 155 | line 141 |

The older version already writes, renames and removes files through graceful-fs.
The new version selects core fs directly. Current operation attribution recognizes
the latter but not the former. Deep mode does not eliminate this limitation.
Other source changes exist; this explains these two findings, not the entire release.

The generated wording says the operations were "not present" in 2.4.3. That is
too strong if read as a statement about runtime behavior. The precise conclusion
is that these indicators were not recognized in the earlier snapshot. The report
does provide useful new source locations, but the reviewer still has to resolve
whether behavior is actually new.

- [Basic report](results/write-file-atomic/basic-review.md) and [JSON](results/write-file-atomic/basic-review.json)
- [Deep report](results/write-file-atomic/deep-review.md) and [JSON](results/write-file-atomic/deep-review.json)
- [Basic commands and timings](results/write-file-atomic/basic-runs.json)
- [Deep commands and timings](results/write-file-atomic/deep-runs.json)
- [Upstream comparison, including removal of graceful-fs](https://github.com/npm/write-file-atomic/compare/v2.4.3...v3.0.3)

Scan times before/after: basic 0.059/0.041 seconds; deep 0.074/0.078 seconds.
